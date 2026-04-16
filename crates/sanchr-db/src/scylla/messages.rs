use scylla::client::session::Session;
use scylla::value::{CqlTimestamp, CqlTimeuuid};
use scylla::DeserializeRow;
use uuid::Uuid;

/// Row returned from the `messages` table.
#[derive(Debug, Clone, DeserializeRow)]
pub struct MessageRow {
    pub conversation_id: Uuid,
    pub message_id: CqlTimeuuid,
    pub sender_id: Uuid,
    pub sender_device: i32,
    pub ciphertext: Vec<u8>,
    pub content_type: String,
    pub server_ts: CqlTimestamp,
    pub expires_at: Option<CqlTimestamp>,
    pub is_deleted: bool,
    pub edited_at: Option<CqlTimestamp>,
}

/// Parameters for inserting a message.
pub struct InsertMessageParams<'a> {
    pub conversation_id: Uuid,
    pub message_id: CqlTimeuuid,
    pub sender_id: Uuid,
    pub sender_device: i32,
    pub ciphertext: &'a [u8],
    pub content_type: &'a str,
    pub expires_at: Option<i64>,
}

/// Insert a new message into the `messages` table.
///
/// `expires_at` is milliseconds since Unix epoch, or `None` if the message
/// never expires.
pub async fn insert_message(
    session: &Session,
    params: &InsertMessageParams<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_ts = CqlTimestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64,
    );
    let expires_at_cql: Option<CqlTimestamp> = params.expires_at.map(CqlTimestamp);

    session
        .query_unpaged(
            "INSERT INTO messages \
             (conversation_id, message_id, sender_id, sender_device, ciphertext, content_type, \
              server_ts, expires_at, is_deleted) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, false)",
            (
                params.conversation_id,
                params.message_id,
                params.sender_id,
                params.sender_device,
                params.ciphertext.to_vec(),
                params.content_type.to_owned(),
                server_ts,
                expires_at_cql,
            ),
        )
        .await?;

    Ok(())
}

/// Fetch up to `limit` non-deleted messages for a conversation, newest first.
pub async fn get_messages(
    session: &Session,
    conversation_id: Uuid,
    limit: i32,
) -> Result<Vec<MessageRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT conversation_id, message_id, sender_id, sender_device, ciphertext, \
             content_type, server_ts, expires_at, is_deleted, edited_at \
             FROM messages \
             WHERE conversation_id = ? \
             LIMIT ?",
            (conversation_id, limit),
        )
        .await?
        .into_rows_result()?;

    let rows = result
        .rows::<MessageRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub async fn get_message(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
) -> Result<Option<MessageRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT conversation_id, message_id, sender_id, sender_device, ciphertext, \
             content_type, server_ts, expires_at, is_deleted, edited_at \
             FROM messages \
             WHERE conversation_id = ? AND message_id = ?",
            (conversation_id, message_id),
        )
        .await?
        .into_rows_result()?;

    let row = result.maybe_first_row::<MessageRow>()?;
    Ok(row)
}

/// Hard-delete a message by removing the row entirely.
pub async fn delete_message(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "DELETE FROM messages \
             WHERE conversation_id = ? AND message_id = ?",
            (conversation_id, message_id),
        )
        .await?;

    Ok(())
}

/// Update the storage ciphertext of a message and record the edit timestamp.
///
/// `edited_at_ms` is milliseconds since Unix epoch.  The storage ciphertext
/// is the first-device ciphertext and is used only for server-side sync
/// (`SyncMessages`); per-device ciphertexts are routed via the live stream.
pub async fn edit_message(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
    new_ciphertext: &[u8],
    edited_at_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "UPDATE messages \
             SET ciphertext = ?, edited_at = ? \
             WHERE conversation_id = ? AND message_id = ?",
            (
                new_ciphertext.to_vec(),
                CqlTimestamp(edited_at_ms),
                conversation_id,
                message_id,
            ),
        )
        .await?;

    Ok(())
}
