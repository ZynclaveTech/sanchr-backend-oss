use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BackupObjectRow {
    pub backup_id: Uuid,
    pub owner_id: Uuid,
    pub lineage_id: Uuid,
    pub format_version: i32,
    pub object_key: String,
    pub byte_size: i64,
    pub sha256_hash: String,
    pub opaque_metadata: Vec<u8>,
    pub reserved_forward_secrecy_metadata: Vec<u8>,
    pub is_committed: bool,
    pub created_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_pending_backup(
    pool: &PgPool,
    backup_id: Uuid,
    owner_id: Uuid,
    lineage_id: Uuid,
    format_version: i32,
    object_key: &str,
    byte_size: i64,
    sha256_hash: &str,
    opaque_metadata: &[u8],
    reserved_forward_secrecy_metadata: &[u8],
) -> Result<BackupObjectRow, sqlx::Error> {
    sqlx::query_as::<_, BackupObjectRow>(
        r#"
        INSERT INTO backup_objects (
            backup_id,
            owner_id,
            lineage_id,
            format_version,
            object_key,
            byte_size,
            sha256_hash,
            opaque_metadata,
            reserved_forward_secrecy_metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(backup_id)
    .bind(owner_id)
    .bind(lineage_id)
    .bind(format_version)
    .bind(object_key)
    .bind(byte_size)
    .bind(sha256_hash)
    .bind(opaque_metadata)
    .bind(reserved_forward_secrecy_metadata)
    .fetch_one(pool)
    .await
}

pub async fn get_backup(
    pool: &PgPool,
    owner_id: Uuid,
    backup_id: Uuid,
) -> Result<Option<BackupObjectRow>, sqlx::Error> {
    sqlx::query_as::<_, BackupObjectRow>(
        r#"
        SELECT *
        FROM backup_objects
        WHERE owner_id = $1 AND backup_id = $2
        "#,
    )
    .bind(owner_id)
    .bind(backup_id)
    .fetch_optional(pool)
    .await
}

pub async fn commit_backup(
    pool: &PgPool,
    owner_id: Uuid,
    backup_id: Uuid,
) -> Result<BackupObjectRow, sqlx::Error> {
    sqlx::query_as::<_, BackupObjectRow>(
        r#"
        UPDATE backup_objects
        SET is_committed = true,
            committed_at = now()
        WHERE owner_id = $1 AND backup_id = $2
        RETURNING *
        "#,
    )
    .bind(owner_id)
    .bind(backup_id)
    .fetch_one(pool)
    .await
}

pub async fn list_committed_backups(
    pool: &PgPool,
    owner_id: Uuid,
    limit: i64,
) -> Result<Vec<BackupObjectRow>, sqlx::Error> {
    sqlx::query_as::<_, BackupObjectRow>(
        r#"
        SELECT *
        FROM backup_objects
        WHERE owner_id = $1
          AND is_committed = true
        ORDER BY committed_at DESC NULLS LAST, created_at DESC
        LIMIT $2
        "#,
    )
    .bind(owner_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn delete_backup(
    pool: &PgPool,
    owner_id: Uuid,
    backup_id: Uuid,
) -> Result<Option<BackupObjectRow>, sqlx::Error> {
    sqlx::query_as::<_, BackupObjectRow>(
        r#"
        DELETE FROM backup_objects
        WHERE owner_id = $1 AND backup_id = $2
        RETURNING *
        "#,
    )
    .bind(owner_id)
    .bind(backup_id)
    .fetch_optional(pool)
    .await
}
