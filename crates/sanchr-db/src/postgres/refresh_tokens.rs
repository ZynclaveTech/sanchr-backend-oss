use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
}

/// Insert a new refresh token and return the generated row ID.
pub async fn create_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    token_hash: &[u8],
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO refresh_tokens (user_id, device_id, token_hash)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(token_hash)
    .fetch_one(pool)
    .await
}

/// Look up a non-revoked token by its hash.
pub async fn validate_refresh_token(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        SELECT id, user_id, device_id, created_at, last_used_at, revoked
        FROM refresh_tokens
        WHERE token_hash = $1
          AND revoked = false
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Atomically delete the old token and insert its replacement.
///
/// Both operations run inside a single transaction so there is never a window
/// where neither token exists, nor a window where both are valid.
pub async fn rotate_refresh_token(
    pool: &PgPool,
    old_token_hash: &[u8],
    new_token_hash: &[u8],
    user_id: Uuid,
    device_id: i32,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        DELETE FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(old_token_hash)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, device_id, token_hash)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(new_token_hash)
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

/// Soft-revoke a single token by its hash.
pub async fn revoke_refresh_token(pool: &PgPool, token_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked = true
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Soft-revoke every active token belonging to a user.
///
/// Returns the number of rows updated (useful for audit logging).
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked = true
        WHERE user_id = $1
          AND revoked = false
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Soft-revoke every active token for a specific (user, device) pair.
pub async fn revoke_for_device(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked = true
        WHERE user_id = $1
          AND device_id = $2
          AND revoked = false
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}
