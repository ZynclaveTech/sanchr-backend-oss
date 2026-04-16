use scylla::client::session::Session;
use scylla::response::{PagingState, PagingStateResponse};
use scylla::value::{CqlTimestamp, CqlTimeuuid};
use scylla::DeserializeRow;
use uuid::Uuid;

use super::SYNC_PAGE_SIZE;

/// A sealed outbox row returned by [`drain_sealed_outbox`].
/// Contains only the data available in a sealed message — the opaque
/// envelope and its server timestamp. Sender identity and conversation
/// are intentionally absent.
#[derive(Debug, Clone)]
pub struct SealedOutboxRow {
    pub message_id: CqlTimeuuid,
    pub ciphertext: Vec<u8>,
    pub server_ts: i64,
}

#[derive(Debug, Clone, DeserializeRow)]
pub struct DeviceOutboxRow {
    pub recipient_id: Uuid,
    pub recipient_device: i32,
    pub message_id: CqlTimeuuid,
    pub conversation_id: Uuid,
    pub sender_id: Uuid,
    pub sender_device: i32,
    pub ciphertext: Vec<u8>,
    pub content_type: String,
    pub server_ts: CqlTimestamp,
    pub expires_at: Option<CqlTimestamp>,
}

#[allow(clippy::too_many_arguments)]
pub async fn queue_outbox(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_id: CqlTimeuuid,
    conversation_id: Uuid,
    sender_id: Uuid,
    sender_device: i32,
    ciphertext: &[u8],
    content_type: &str,
    server_ts: i64,
    expires_at: Option<i64>,
    ttl_seconds: Option<i64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expires_at = expires_at.map(CqlTimestamp);

    if let Some(ttl_seconds) = ttl_seconds.filter(|ttl| *ttl > 0) {
        session
            .query_unpaged(
                "INSERT INTO device_outbox \
                 (recipient_id, recipient_device, message_id, conversation_id, sender_id, \
                  sender_device, ciphertext, content_type, server_ts, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?",
                (
                    recipient_id,
                    device_id,
                    message_id,
                    conversation_id,
                    sender_id,
                    sender_device,
                    ciphertext.to_vec(),
                    content_type.to_owned(),
                    CqlTimestamp(server_ts),
                    expires_at,
                    ttl_seconds as i32,
                ),
            )
            .await?;
    } else {
        session
            .query_unpaged(
                "INSERT INTO device_outbox \
                 (recipient_id, recipient_device, message_id, conversation_id, sender_id, \
                  sender_device, ciphertext, content_type, server_ts, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    recipient_id,
                    device_id,
                    message_id,
                    conversation_id,
                    sender_id,
                    sender_device,
                    ciphertext.to_vec(),
                    content_type.to_owned(),
                    CqlTimestamp(server_ts),
                    expires_at,
                ),
            )
            .await?;
    }

    Ok(())
}

pub async fn get_outbox_messages(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
) -> Result<Vec<DeviceOutboxRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT recipient_id, recipient_device, message_id, conversation_id, sender_id, \
             sender_device, ciphertext, content_type, server_ts, expires_at \
             FROM device_outbox \
             WHERE recipient_id = ? AND recipient_device = ?",
            (recipient_id, device_id),
        )
        .await?
        .into_rows_result()?;

    let rows = result
        .rows::<DeviceOutboxRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub async fn get_outbox_messages_page(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    paging_state: PagingState,
) -> Result<(Vec<DeviceOutboxRow>, PagingStateResponse), Box<dyn std::error::Error>> {
    let mut prepared = session
        .prepare(
            "SELECT recipient_id, recipient_device, message_id, conversation_id, sender_id, \
             sender_device, ciphertext, content_type, server_ts, expires_at \
             FROM device_outbox \
             WHERE recipient_id = ? AND recipient_device = ? \
             ORDER BY message_id ASC",
        )
        .await?;
    prepared.set_page_size(SYNC_PAGE_SIZE);

    let (result, paging_state_response) = session
        .execute_single_page(&prepared, (recipient_id, device_id), paging_state)
        .await?;

    let result = result.into_rows_result()?;
    let rows = result
        .rows::<DeviceOutboxRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok((rows, paging_state_response))
}

pub async fn delete_outbox_message(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_id: CqlTimeuuid,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "DELETE FROM device_outbox \
             WHERE recipient_id = ? AND recipient_device = ? AND message_id = ?",
            (recipient_id, device_id, message_id),
        )
        .await?;

    Ok(())
}

pub async fn delete_outbox_messages(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_ids: &[CqlTimeuuid],
) -> Result<(), Box<dyn std::error::Error>> {
    if message_ids.is_empty() {
        return Ok(());
    }

    let prepared = session
        .prepare(
            "DELETE FROM device_outbox \
             WHERE recipient_id = ? AND recipient_device = ? AND message_id = ?",
        )
        .await?;

    for message_id in message_ids {
        session
            .execute_unpaged(&prepared, (recipient_id, device_id, *message_id))
            .await?;
    }

    Ok(())
}

/// Queue a sealed message to the device outbox.
///
/// Stores an opaque `sealed_envelope` blob with sentinel values for columns
/// that carry no meaning for sealed messages:
/// - `sender_id`      → `Uuid::nil()`
/// - `conversation_id` → `Uuid::nil()`
/// - `sender_device`  → `0`
/// - `content_type`   → `"sealed"` (discriminator used by [`drain_sealed_outbox`])
///
/// A mandatory TTL is applied so sealed messages are automatically reaped.
pub async fn queue_sealed_outbox(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_id: CqlTimeuuid,
    sealed_envelope: &[u8],
    server_ts: i64,
    ttl_seconds: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "INSERT INTO device_outbox \
             (recipient_id, recipient_device, message_id, conversation_id, sender_id, \
              sender_device, ciphertext, content_type, server_ts, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TTL ?",
            (
                recipient_id,
                device_id,
                message_id,
                Uuid::nil(), // sentinel: no conversation for sealed messages
                Uuid::nil(), // sentinel: no sender identity for sealed messages
                0_i32,       // sentinel: no sender device for sealed messages
                sealed_envelope.to_vec(),
                "sealed".to_owned(),
                CqlTimestamp(server_ts),
                None::<CqlTimestamp>, // expires_at not applicable; TTL handles expiry
                ttl_seconds as i32,
            ),
        )
        .await?;

    Ok(())
}

/// Drain sealed messages from the device outbox.
///
/// Fetches all rows for the given `(recipient_id, device_id)` partition and
/// returns only those whose `content_type` equals `"sealed"`. Filtering is
/// performed in Rust to avoid `ALLOW FILTERING` on ScyllaDB.
///
/// Callers are responsible for deleting delivered rows via
/// [`delete_outbox_message`].
pub async fn drain_sealed_outbox(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
) -> Result<Vec<SealedOutboxRow>, Box<dyn std::error::Error>> {
    // We select only the columns we need. content_type is included so we can
    // filter client-side without ALLOW FILTERING.
    let result = session
        .query_unpaged(
            "SELECT message_id, ciphertext, server_ts, content_type \
             FROM device_outbox \
             WHERE recipient_id = ? AND recipient_device = ? \
             ORDER BY message_id ASC",
            (recipient_id, device_id),
        )
        .await?
        .into_rows_result()?;

    // Helper row type for deserialization — includes content_type for filtering.
    #[derive(scylla::DeserializeRow)]
    struct RawRow {
        message_id: CqlTimeuuid,
        ciphertext: Vec<u8>,
        server_ts: CqlTimestamp,
        content_type: String,
    }

    let rows = result.rows::<RawRow>()?.collect::<Result<Vec<_>, _>>()?;

    let sealed = rows
        .into_iter()
        .filter(|r| r.content_type == "sealed")
        .map(|r| SealedOutboxRow {
            message_id: r.message_id,
            ciphertext: r.ciphertext,
            server_ts: r.server_ts.0,
        })
        .collect();

    Ok(sealed)
}
