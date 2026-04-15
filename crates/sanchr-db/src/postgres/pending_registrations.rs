use chrono::{DateTime, Utc};
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingRegistrationRow {
    pub phone_number: String,
    pub display_name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn upsert_pending_registration(
    pool: &PgPool,
    phone_number: &str,
    display_name: &str,
    email: Option<&str>,
    password_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<PendingRegistrationRow, sqlx::Error> {
    sqlx::query_as::<_, PendingRegistrationRow>(
        r#"
        INSERT INTO pending_registrations (
            phone_number,
            display_name,
            email,
            password_hash,
            created_at,
            expires_at
        )
        VALUES ($1, $2, $3, $4, now(), $5)
        ON CONFLICT (phone_number)
        DO UPDATE SET
            display_name = EXCLUDED.display_name,
            email = EXCLUDED.email,
            password_hash = EXCLUDED.password_hash,
            created_at = now(),
            expires_at = EXCLUDED.expires_at
        RETURNING *
        "#,
    )
    .bind(phone_number)
    .bind(display_name)
    .bind(email)
    .bind(password_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn get_pending_registration(
    pool: &PgPool,
    phone_number: &str,
) -> Result<Option<PendingRegistrationRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingRegistrationRow>(
        r#"
        SELECT *
        FROM pending_registrations
        WHERE phone_number = $1
        "#,
    )
    .bind(phone_number)
    .fetch_optional(pool)
    .await
}

/// Unconditionally delete any pending_registrations row for a phone number,
/// regardless of expiry. Used when a user deletes their account so a fresh
/// signup is not blocked by a stale pending row.
pub async fn delete_by_phone(pool: &PgPool, phone_number: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_registrations WHERE phone_number = $1")
        .bind(phone_number)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn take_pending_registration(
    pool: &PgPool,
    phone_number: &str,
) -> Result<Option<PendingRegistrationRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingRegistrationRow>(
        r#"
        DELETE FROM pending_registrations
        WHERE phone_number = $1
          AND expires_at > now()
        RETURNING *
        "#,
    )
    .bind(phone_number)
    .fetch_optional(pool)
    .await
}
