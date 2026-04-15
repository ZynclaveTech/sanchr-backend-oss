use scylla::frame::value::{CqlTimestamp, CqlTimeuuid};
use scylla::FromRow;
use scylla::Session;
use uuid::Uuid;

/// Paper Section 5.2.1 bounds typing/read state to 5 minutes.
const RECEIPT_TTL_SECS: i64 = 300;

/// Row returned from the `message_receipts` table.
#[derive(Debug, Clone, FromRow)]
pub struct ReceiptRow {
    pub conversation_id: Uuid,
    pub message_id: CqlTimeuuid,
    pub recipient_id: Uuid,
    pub status: String,
    pub status_at: CqlTimestamp,
}

/// Insert or update a delivery/read receipt for a message.
pub async fn upsert_receipt(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
    recipient_id: Uuid,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_at = CqlTimestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64,
    );

    session
        .query_unpaged(
            "INSERT INTO message_receipts \
             (conversation_id, message_id, recipient_id, status, status_at) \
             VALUES (?, ?, ?, ?, ?) \
             USING TTL ?",
            (
                conversation_id,
                message_id,
                recipient_id,
                status.to_owned(),
                status_at,
                RECEIPT_TTL_SECS,
            ),
        )
        .await?;

    Ok(())
}

pub async fn get_receipt(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
    recipient_id: Uuid,
) -> Result<Option<ReceiptRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT conversation_id, message_id, recipient_id, status, status_at \
             FROM message_receipts \
             WHERE conversation_id = ? AND message_id = ? AND recipient_id = ?",
            (conversation_id, message_id, recipient_id),
        )
        .await?;

    let row = result.rows_typed::<ReceiptRow>()?.next().transpose()?;
    Ok(row)
}

/// Fetch all receipts for a given message.
pub async fn get_receipts(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
) -> Result<Vec<ReceiptRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT conversation_id, message_id, recipient_id, status, status_at \
             FROM message_receipts \
             WHERE conversation_id = ? AND message_id = ?",
            (conversation_id, message_id),
        )
        .await?;

    let rows = result
        .rows_typed::<ReceiptRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}
