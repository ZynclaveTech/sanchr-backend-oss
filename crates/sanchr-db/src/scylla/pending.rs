use scylla::frame::value::{CqlTimestamp, CqlTimeuuid};
use scylla::statement::{PagingState, PagingStateResponse};
use scylla::FromRow;
use scylla::Session;
use uuid::Uuid;

use super::SYNC_PAGE_SIZE;

/// Row returned from the `pending_messages` table.
#[derive(Debug, Clone, FromRow)]
pub struct PendingMessageRow {
    pub recipient_id: Uuid,
    pub recipient_device: i32,
    pub message_id: CqlTimeuuid,
    pub conversation_id: Uuid,
    pub sender_id: Uuid,
    pub ciphertext: Vec<u8>,
    pub content_type: String,
    pub server_ts: CqlTimestamp,
}

/// Enqueue a message for an offline recipient device.
#[allow(clippy::too_many_arguments)]
pub async fn queue_pending(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_id: CqlTimeuuid,
    conversation_id: Uuid,
    sender_id: Uuid,
    ciphertext: &[u8],
    content_type: &str,
    server_ts: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "INSERT INTO pending_messages \
             (recipient_id, recipient_device, message_id, conversation_id, sender_id, \
              ciphertext, content_type, server_ts) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                recipient_id,
                device_id,
                message_id,
                conversation_id,
                sender_id,
                ciphertext.to_vec(),
                content_type.to_owned(),
                CqlTimestamp(server_ts),
            ),
        )
        .await?;

    Ok(())
}

/// Fetch pending messages for a recipient device without deleting them.
///
/// Deletion is performed on explicit client ack to avoid loss if sync stream
/// is interrupted after fetch but before client receives the payload.
pub async fn drain_pending(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
) -> Result<Vec<PendingMessageRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT recipient_id, recipient_device, message_id, conversation_id, sender_id, \
             ciphertext, content_type, server_ts \
             FROM pending_messages \
             WHERE recipient_id = ? AND recipient_device = ?",
            (recipient_id, device_id),
        )
        .await?;

    let rows = result
        .rows_typed::<PendingMessageRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub async fn get_pending_messages_page(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    paging_state: PagingState,
) -> Result<(Vec<PendingMessageRow>, PagingStateResponse), Box<dyn std::error::Error>> {
    let mut prepared = session
        .prepare(
            "SELECT recipient_id, recipient_device, message_id, conversation_id, sender_id, \
             ciphertext, content_type, server_ts \
             FROM pending_messages \
             WHERE recipient_id = ? AND recipient_device = ? \
             ORDER BY message_id ASC",
        )
        .await?;
    prepared.set_page_size(SYNC_PAGE_SIZE);

    let (result, paging_state_response) = session
        .execute_single_page(&prepared, (recipient_id, device_id), paging_state)
        .await?;

    let rows = result
        .rows_typed::<PendingMessageRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok((rows, paging_state_response))
}

/// Delete a single pending message by its full primary key.
pub async fn delete_single_pending(
    session: &Session,
    recipient_id: Uuid,
    device_id: i32,
    message_id: CqlTimeuuid,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "DELETE FROM pending_messages \
             WHERE recipient_id = ? AND recipient_device = ? AND message_id = ?",
            (recipient_id, device_id, message_id),
        )
        .await?;

    Ok(())
}

pub async fn delete_pending_messages(
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
            "DELETE FROM pending_messages \
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
