use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MediaObjectRow {
    pub media_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub storage_key: String,
    pub content_type: String,
    pub file_size: i64,
    pub sha256_hash: String,
    pub is_confirmed: bool,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_media_object(
    pool: &PgPool,
    media_id: Uuid,
    owner_id: Uuid,
    purpose: &str,
    storage_key: &str,
    content_type: &str,
    file_size: i64,
    sha256_hash: &str,
) -> Result<MediaObjectRow, sqlx::Error> {
    sqlx::query_as::<_, MediaObjectRow>(
        r#"
        INSERT INTO media_objects (
            media_id,
            owner_id,
            purpose,
            storage_key,
            content_type,
            file_size,
            sha256_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(media_id)
    .bind(owner_id)
    .bind(purpose)
    .bind(storage_key)
    .bind(content_type)
    .bind(file_size)
    .bind(sha256_hash)
    .fetch_one(pool)
    .await
}

pub async fn get_media_object(
    pool: &PgPool,
    owner_id: Uuid,
    media_id: Uuid,
) -> Result<Option<MediaObjectRow>, sqlx::Error> {
    sqlx::query_as::<_, MediaObjectRow>(
        r#"
        SELECT *
        FROM media_objects
        WHERE owner_id = $1 AND media_id = $2
        "#,
    )
    .bind(owner_id)
    .bind(media_id)
    .fetch_optional(pool)
    .await
}

pub async fn mark_media_confirmed(
    pool: &PgPool,
    owner_id: Uuid,
    media_id: Uuid,
) -> Result<MediaObjectRow, sqlx::Error> {
    sqlx::query_as::<_, MediaObjectRow>(
        r#"
        UPDATE media_objects
        SET is_confirmed = true,
            confirmed_at = now()
        WHERE owner_id = $1 AND media_id = $2
        RETURNING *
        "#,
    )
    .bind(owner_id)
    .bind(media_id)
    .fetch_one(pool)
    .await
}

/// Fetch a confirmed media object by ID only, without an owner check.
/// Used exclusively for download URL generation: the media is E2EE so the
/// server cannot read its contents regardless of who requests the URL.
/// The media_id UUID is effectively a 128-bit capability token — only users
/// who received the message know it.
pub async fn get_confirmed_media_object(
    pool: &PgPool,
    media_id: Uuid,
) -> Result<Option<MediaObjectRow>, sqlx::Error> {
    sqlx::query_as::<_, MediaObjectRow>(
        r#"
        SELECT *
        FROM media_objects
        WHERE media_id = $1 AND is_confirmed = true
        "#,
    )
    .bind(media_id)
    .fetch_optional(pool)
    .await
}

/// Returns `true` iff a `media_objects` row exists with both the given
/// `media_id` AND `owner_id` matching. Used by the vault handlers to
/// enforce media ownership before wrapping a media object in a vault item.
pub async fn is_owned_by(
    pool: &PgPool,
    owner_id: Uuid,
    media_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let (exists,): (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM media_objects
            WHERE media_id = $1 AND owner_id = $2
        )
        "#,
    )
    .bind(media_id)
    .bind(owner_id)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

/// Deletes confirmed attachment media_objects older than the given threshold.
/// Avatars excluded. Matches EKF media class TTL (30 days).
/// Paper-safe: time-based only, no message-to-media linking.
pub async fn delete_stale_media_objects(
    pool: &PgPool,
    older_than_days: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM media_objects
        WHERE purpose = 'attachment'
          AND is_confirmed = true
          AND confirmed_at < now() - make_interval(days => $1)
        "#,
    )
    .bind(older_than_days as f64)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Deletes unconfirmed uploads (abandoned presigned URLs) older than threshold.
pub async fn delete_unconfirmed_uploads(
    pool: &PgPool,
    older_than_hours: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM media_objects
        WHERE is_confirmed = false
          AND created_at < now() - make_interval(hours => $1)
        "#,
    )
    .bind(older_than_hours as f64)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
