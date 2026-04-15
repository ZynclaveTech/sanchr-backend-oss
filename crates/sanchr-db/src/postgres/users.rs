use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub phone_number: String,
    pub phone_hash: Vec<u8>,
    pub display_name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub phone_verified_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub is_active: Option<bool>,
}

pub fn hash_phone(phone: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(phone.as_bytes());
    hasher.finalize().to_vec()
}

pub async fn create_user(
    pool: &PgPool,
    phone_number: &str,
    display_name: &str,
    email: Option<&str>,
    password_hash: &str,
) -> Result<UserRow, sqlx::Error> {
    let phone_hash = hash_phone(phone_number);

    sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (
            phone_number,
            phone_hash,
            display_name,
            email,
            password_hash,
            phone_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, now())
        RETURNING *
        "#,
    )
    .bind(phone_number)
    .bind(&phone_hash)
    .bind(display_name)
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await
}

pub async fn find_by_phone(
    pool: &PgPool,
    phone_number: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT * FROM users
        WHERE phone_number = $1
          AND is_active IS NOT false
          AND phone_verified_at IS NOT NULL
        "#,
    )
    .bind(phone_number)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: &Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT * FROM users
        WHERE id = $1
          AND is_active IS NOT false
          AND phone_verified_at IS NOT NULL
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Fetch multiple users by their IDs in a single query.
pub async fn find_by_ids(pool: &PgPool, ids: &[Uuid]) -> Result<Vec<UserRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT * FROM users
        WHERE id = ANY($1)
          AND is_active IS NOT false
        "#,
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}

/// Hard-delete a user row. Relies on `ON DELETE CASCADE` FK constraints to
/// clean up dependent rows in user_devices, user_settings, identity_keys,
/// signed_pre_keys, one_time_pre_keys, kyber_pre_keys, contacts (both sides),
/// conversation_participants, media_objects, and backup_objects.
///
/// Pending registrations are keyed by phone_number and must be cleaned up
/// separately via `pending_registrations::delete_by_phone`.
pub async fn delete_user(pool: &PgPool, user_id: &Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_phone_deterministic() {
        let h1 = hash_phone("+15550001234");
        let h2 = hash_phone("+15550001234");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_phone_different_inputs() {
        let h1 = hash_phone("+15550001234");
        let h2 = hash_phone("+15559998765");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_phone_is_sha256_length() {
        let h = hash_phone("+15550001234");
        assert_eq!(h.len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn hash_phone_empty_input() {
        let h = hash_phone("");
        assert_eq!(h.len(), 32);
    }
}
