use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContactRow {
    pub user_id: Uuid,
    pub contact_user_id: Uuid,
    pub display_name: Option<String>,
    pub is_blocked: Option<bool>,
    pub is_favorite: Option<bool>,
    pub synced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MatchedUser {
    pub id: Uuid,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    pub phone_number: String,
    pub profile_key: Option<Vec<u8>>,
    pub encrypted_display_name: Option<Vec<u8>>,
    pub encrypted_bio: Option<Vec<u8>>,
    pub encrypted_avatar_url: Option<Vec<u8>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContactWithProfile {
    pub contact_user_id: Uuid,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    pub phone_number: String,
    pub is_blocked: Option<bool>,
    pub is_favorite: Option<bool>,
    pub profile_key: Option<Vec<u8>>,
    pub encrypted_display_name: Option<Vec<u8>>,
    pub encrypted_bio: Option<Vec<u8>>,
    pub encrypted_avatar_url: Option<Vec<u8>>,
}

/// Match the given phone hashes against existing users, insert them as contacts
/// (idempotent), and return the matched user profiles.
pub async fn sync_contacts(
    pool: &PgPool,
    user_id: Uuid,
    phone_hashes: &[Vec<u8>],
) -> Result<Vec<MatchedUser>, sqlx::Error> {
    // Cast &[Vec<u8>] to &[&[u8]] so sqlx can bind it as BYTEA[].
    let hashes: Vec<&[u8]> = phone_hashes.iter().map(|v| v.as_slice()).collect();

    let matched: Vec<MatchedUser> = sqlx::query_as::<_, MatchedUser>(
        r#"
        SELECT id,
               display_name,
               avatar_url,
               status_text,
               phone_number,
               profile_key,
               encrypted_display_name,
               encrypted_bio,
               encrypted_avatar_url
        FROM users
        WHERE phone_hash = ANY($1)
          AND id != $2
          AND is_active = true
          AND phone_verified_at IS NOT NULL
        "#,
    )
    .bind(&hashes)
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    if matched.is_empty() {
        return Ok(matched);
    }

    let matched_ids: Vec<Uuid> = matched.iter().map(|m| m.id).collect();
    sqlx::query(
        r#"
        INSERT INTO contacts (user_id, contact_user_id, synced_at)
        SELECT $1, contact_user_id, now()
        FROM UNNEST($2::uuid[]) AS matched(contact_user_id)
        ON CONFLICT (user_id, contact_user_id) DO NOTHING
        "#,
    )
    .bind(user_id)
    .bind(&matched_ids)
    .execute(pool)
    .await?;

    Ok(matched)
}

/// Return the full contact list for a user, joined with live profile data.
pub async fn get_contacts(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ContactWithProfile>, sqlx::Error> {
    sqlx::query_as::<_, ContactWithProfile>(
        r#"
        SELECT c.contact_user_id,
               u.display_name,
               u.avatar_url,
               u.status_text,
               u.phone_number,
               c.is_blocked,
               c.is_favorite,
               u.profile_key,
               u.encrypted_display_name,
               u.encrypted_bio,
               u.encrypted_avatar_url
        FROM contacts c
        JOIN users u ON u.id = c.contact_user_id
        WHERE c.user_id = $1
          AND u.phone_verified_at IS NOT NULL
        ORDER BY u.display_name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Add a contact (or update an existing one) and set is_blocked = true.
pub async fn block_contact(
    pool: &PgPool,
    user_id: Uuid,
    contact_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO contacts (user_id, contact_user_id, is_blocked, synced_at)
        VALUES ($1, $2, true, now())
        ON CONFLICT (user_id, contact_user_id)
        DO UPDATE SET is_blocked = true
        "#,
    )
    .bind(user_id)
    .bind(contact_user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Clear the is_blocked flag for a contact (no-op if the row does not exist).
pub async fn unblock_contact(
    pool: &PgPool,
    user_id: Uuid,
    contact_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE contacts
        SET is_blocked = false
        WHERE user_id = $1 AND contact_user_id = $2
        "#,
    )
    .bind(user_id)
    .bind(contact_user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Return the E.164 phone numbers of every active, verified registered user.
///
/// Used by the OPRF-PSI discovery service to build the server-side bloom filter
/// and pre-computed registered set.
pub async fn get_all_registered_phones(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT phone_number FROM users WHERE is_active = true AND phone_verified_at IS NOT NULL",
    )
    .fetch_all(pool)
    .await
}

/// Return the UUIDs of every user blocked by the given user.
pub async fn get_blocked_list(pool: &PgPool, user_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT contact_user_id
        FROM contacts
        WHERE user_id = $1 AND is_blocked = true
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Returns `true` iff both `a` and `b` have each other in their `contacts`
/// table AND neither row has `is_blocked = true`.
///
/// This is the backing query for the `profile_photo_visibility = "contacts"`
/// privacy mode (Phase 2): a viewer must be a confirmed two-way contact of
/// the owner before the avatar URL is exposed. A unilateral block on either
/// side suppresses visibility.
///
/// Implementation: a single `SELECT COUNT(*)` over the bidirectional `OR`
/// predicate. The result is exactly `2` iff both rows exist and are unblocked,
/// `1` iff only one direction exists (or one is blocked), and `0` otherwise.
/// The PRIMARY KEY on `(user_id, contact_user_id)` guarantees the count
/// cannot exceed 2 for distinct `(a, b)` pairs.
///
/// Note: callers should not pass `a == b` — self-pairs are not meaningful for
/// this check. The query will return `false` in that case (only one row max).
pub async fn are_mutual_contacts(pool: &PgPool, a: Uuid, b: Uuid) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM contacts
        WHERE ((user_id = $1 AND contact_user_id = $2)
            OR (user_id = $2 AND contact_user_id = $1))
          AND is_blocked = false
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;

    Ok(count == 2)
}
