use scylla::frame::value::{CqlTimestamp, CqlTimeuuid};
use scylla::FromRow;
use scylla::Session;
use uuid::Uuid;

/// Row returned from the `reactions` table.
#[derive(Debug, Clone, FromRow)]
pub struct ReactionRow {
    pub conversation_id: Uuid,
    pub message_id: CqlTimeuuid,
    pub user_id: Uuid,
    pub emoji: String,
    pub created_at: CqlTimestamp,
}

/// Add a reaction to a message. Uses INSERT to be idempotent — re-adding
/// the same (conversation_id, message_id, user_id, emoji) is a no-op.
pub async fn add_reaction(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
    user_id: Uuid,
    emoji: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let created_at = CqlTimestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64,
    );

    session
        .query_unpaged(
            "INSERT INTO reactions \
             (conversation_id, message_id, user_id, emoji, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            (
                conversation_id,
                message_id,
                user_id,
                emoji.to_owned(),
                created_at,
            ),
        )
        .await?;

    Ok(())
}

/// Remove a reaction from a message.
pub async fn remove_reaction(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
    user_id: Uuid,
    emoji: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "DELETE FROM reactions \
             WHERE conversation_id = ? AND message_id = ? AND user_id = ? AND emoji = ?",
            (conversation_id, message_id, user_id, emoji.to_owned()),
        )
        .await?;

    Ok(())
}

/// Get all reactions for a specific message.
pub async fn get_reactions(
    session: &Session,
    conversation_id: Uuid,
    message_id: CqlTimeuuid,
) -> Result<Vec<ReactionRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            "SELECT conversation_id, message_id, user_id, emoji, created_at \
             FROM reactions \
             WHERE conversation_id = ? AND message_id = ?",
            (conversation_id, message_id),
        )
        .await?;

    let rows = result
        .rows_typed::<ReactionRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}
