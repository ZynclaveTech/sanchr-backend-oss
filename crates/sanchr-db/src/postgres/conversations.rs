use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConversationRow {
    pub id: Uuid,
    #[sqlx(rename = "type")]
    pub type_: String,
    pub group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserConversation {
    pub id: Uuid,
    #[sqlx(rename = "type")]
    pub type_: String,
    pub unread_count: Option<i32>,
    pub pinned: Option<bool>,
    pub archived: Option<bool>,
}

pub async fn find_or_create_direct(
    pool: &PgPool,
    user_a: Uuid,
    user_b: Uuid,
) -> Result<ConversationRow, sqlx::Error> {
    let (lo, hi) = if user_a < user_b {
        (user_a, user_b)
    } else {
        (user_b, user_a)
    };

    let mut tx = pool.begin().await?;

    // Serialize concurrent creation for the same user pair. The advisory lock
    // key is a transient coordination token derived at runtime — it is never
    // written to disk, so it does not constitute a stored social-graph index.
    // (The direct_conversations pair-index table was dropped in migration 015.)
    sqlx::query(r#"SELECT pg_advisory_xact_lock(hashtext(($1::text || ':' || $2::text))::bigint)"#)
        .bind(lo.to_string())
        .bind(hi.to_string())
        .execute(&mut *tx)
        .await?;

    // Check for an existing direct conversation between the two participants.
    // conversation_participants is the sole source of truth since migration 015.
    if let Some(conv) = sqlx::query_as::<_, ConversationRow>(
        r#"
        SELECT c.id, c.type, c.group_id, c.created_at, c.updated_at
        FROM conversations c
        JOIN conversation_participants p1
          ON c.id = p1.conversation_id AND p1.user_id = $1
        JOIN conversation_participants p2
          ON c.id = p2.conversation_id AND p2.user_id = $2
        WHERE c.type = 'direct'
        LIMIT 1
        "#,
    )
    .bind(lo)
    .bind(hi)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.commit().await?;
        return Ok(conv);
    }

    // Create a new direct conversation and add both participants atomically.
    let conv = sqlx::query_as::<_, ConversationRow>(
        r#"
        INSERT INTO conversations (type)
        VALUES ('direct')
        RETURNING id, type, group_id, created_at, updated_at
        "#,
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO conversation_participants (conversation_id, user_id)
        VALUES ($1, $2), ($1, $3)
        "#,
    )
    .bind(conv.id)
    .bind(user_a)
    .bind(user_b)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(conv)
}

pub async fn get_user_conversations(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<UserConversation>, sqlx::Error> {
    sqlx::query_as::<_, UserConversation>(
        r#"
        SELECT c.id, c.type, cp.unread_count, cp.pinned, cp.archived
        FROM conversation_participants cp
        JOIN conversations c ON c.id = cp.conversation_id
        WHERE cp.user_id = $1
        ORDER BY c.updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn increment_unread(
    pool: &PgPool,
    conversation_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE conversation_participants
        SET unread_count = unread_count + 1
        WHERE conversation_id = $1 AND user_id = $2
        "#,
    )
    .bind(conversation_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn increment_unread_for_other_participants(
    pool: &PgPool,
    conversation_id: Uuid,
    sender_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE conversation_participants
        SET unread_count = unread_count + 1
        WHERE conversation_id = $1 AND user_id <> $2
        "#,
    )
    .bind(conversation_id)
    .bind(sender_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn touch_conversation(pool: &PgPool, conversation_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE conversations
        SET updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(conversation_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn reset_unread(
    pool: &PgPool,
    conversation_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE conversation_participants
        SET unread_count = 0, last_read_at = now()
        WHERE conversation_id = $1 AND user_id = $2
        "#,
    )
    .bind(conversation_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_participant(
    pool: &PgPool,
    conversation_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2",
    )
    .bind(conversation_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_conversation_participants(
    pool: &PgPool,
    conversation_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT user_id
        FROM conversation_participants
        WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn get_participants_for_conversations(
    pool: &PgPool,
    conversation_ids: &[Uuid],
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    if conversation_ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT conversation_id, user_id
        FROM conversation_participants
        WHERE conversation_id = ANY($1)
        "#,
    )
    .bind(conversation_ids)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn get_direct_peer_ids(pool: &PgPool, user_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT cp2.user_id
        FROM conversation_participants cp1
        JOIN conversations c
          ON c.id = cp1.conversation_id
        JOIN conversation_participants cp2
          ON cp2.conversation_id = c.id
        WHERE cp1.user_id = $1
          AND c.type = 'direct'
          AND cp2.user_id <> $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn filter_direct_peers(
    pool: &PgPool,
    user_id: Uuid,
    peer_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    if peer_ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT cp2.user_id
        FROM conversation_participants cp1
        JOIN conversations c
          ON c.id = cp1.conversation_id
        JOIN conversation_participants cp2
          ON cp2.conversation_id = c.id
        WHERE cp1.user_id = $1
          AND c.type = 'direct'
          AND cp2.user_id = ANY($2)
        "#,
    )
    .bind(user_id)
    .bind(peer_ids)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn set_device_conversation_muted(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    conversation_id: Uuid,
    muted: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO conversation_device_notification_prefs (
            user_id,
            device_id,
            conversation_id,
            muted,
            updated_at
        )
        SELECT $1, $2, $3, $4, now()
        WHERE EXISTS (
            SELECT 1
            FROM user_devices
            WHERE user_id = $1 AND device_id = $2
        )
        AND EXISTS (
            SELECT 1
            FROM conversation_participants
            WHERE conversation_id = $3 AND user_id = $1
        )
        ON CONFLICT (user_id, device_id, conversation_id)
        DO UPDATE SET
            muted = EXCLUDED.muted,
            updated_at = now()
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(conversation_id)
    .bind(muted)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn is_device_conversation_muted(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    conversation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let muted: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT muted
        FROM conversation_device_notification_prefs
        WHERE user_id = $1
          AND device_id = $2
          AND conversation_id = $3
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(conversation_id)
    .fetch_optional(pool)
    .await?;

    Ok(muted.unwrap_or(false))
}

pub async fn get_device_conversation_mutes(
    pool: &PgPool,
    conversation_id: Uuid,
    targets: &[(Uuid, i32)],
) -> Result<HashMap<(Uuid, i32), bool>, sqlx::Error> {
    if targets.is_empty() {
        return Ok(HashMap::new());
    }

    let user_ids: Vec<Uuid> = targets.iter().map(|(user_id, _)| *user_id).collect();
    let device_ids: Vec<i32> = targets.iter().map(|(_, device_id)| *device_id).collect();

    let rows: Vec<(Uuid, i32, bool)> = sqlx::query_as(
        r#"
        WITH targets AS (
            SELECT *
            FROM UNNEST($2::uuid[], $3::int[]) AS t(user_id, device_id)
        )
        SELECT
            t.user_id,
            t.device_id,
            COALESCE(p.muted, false) AS muted
        FROM targets t
        LEFT JOIN conversation_device_notification_prefs p
          ON p.user_id = t.user_id
         AND p.device_id = t.device_id
         AND p.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .bind(user_ids)
    .bind(device_ids)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(user_id, device_id, muted)| ((user_id, device_id), muted))
        .collect())
}
