use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityKeyRow {
    pub user_id: Uuid,
    pub device_id: i32,
    pub registration_id: Option<i32>,
    pub identity_public_key: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SignedPreKeyRow {
    pub user_id: Uuid,
    pub device_id: i32,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct KyberPreKeyRow {
    pub user_id: Uuid,
    pub device_id: i32,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OneTimePreKeyRow {
    pub user_id: Uuid,
    pub device_id: i32,
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub registration_id: i32,
    pub identity_public_key: Vec<u8>,
    pub signed_pre_key: SignedPreKeyRow,
    pub one_time_pre_key: Option<OneTimePreKeyRow>,
    pub kyber_pre_key: KyberPreKeyRow,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SendableDeviceRow {
    pub device_id: i32,
    pub platform: String,
    pub supports_delivery_ack: bool,
    pub key_capable: bool,
    pub last_active_at: Option<DateTime<Utc>>,
}

pub async fn upsert_identity_key(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    registration_id: i32,
    identity_public_key: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO identity_keys (user_id, device_id, registration_id, identity_public_key)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, device_id)
        DO UPDATE SET
            registration_id = EXCLUDED.registration_id,
            identity_public_key = EXCLUDED.identity_public_key
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(registration_id)
    .bind(identity_public_key)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch the identity public key for a specific user + device.
///
/// Returns `None` when no key bundle has been uploaded for this device yet.
pub async fn get_identity_key(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT identity_public_key
        FROM identity_keys
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(key,)| key))
}

pub async fn upsert_signed_pre_key(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    key_id: i32,
    public_key: &[u8],
    signature: &[u8],
    timestamp_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO signed_pre_keys (user_id, device_id, key_id, public_key, signature, timestamp_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, device_id, key_id)
        DO UPDATE SET
            public_key = EXCLUDED.public_key,
            signature = EXCLUDED.signature,
            timestamp_ms = EXCLUDED.timestamp_ms
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(key_id)
    .bind(public_key)
    .bind(signature)
    .bind(timestamp_ms)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn upsert_kyber_pre_key(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    key_id: i32,
    public_key: &[u8],
    signature: &[u8],
    timestamp_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO kyber_pre_keys (user_id, device_id, key_id, public_key, signature, timestamp_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, device_id, key_id)
        DO UPDATE SET
            public_key = EXCLUDED.public_key,
            signature = EXCLUDED.signature,
            timestamp_ms = EXCLUDED.timestamp_ms
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(key_id)
    .bind(public_key)
    .bind(signature)
    .bind(timestamp_ms)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_one_time_pre_keys(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
    keys: &[(i32, Vec<u8>)],
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut inserted: u64 = 0;

    for (key_id, public_key) in keys {
        let result = sqlx::query(
            r#"
            INSERT INTO one_time_pre_keys (user_id, device_id, key_id, public_key)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, device_id, key_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(key_id)
        .bind(public_key.as_slice())
        .execute(&mut *tx)
        .await?;

        inserted += result.rows_affected();
    }

    tx.commit().await?;
    Ok(inserted)
}

pub async fn get_pre_key_bundle(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<PreKeyBundle, sqlx::Error> {
    let identity_row = sqlx::query_as::<_, IdentityKeyRow>(
        r#"
        SELECT user_id, device_id, registration_id, identity_public_key, registered_at
        FROM identity_keys
        WHERE user_id = $1
          AND device_id = $2
          AND registration_id IS NOT NULL
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    let signed_pre_key = sqlx::query_as::<_, SignedPreKeyRow>(
        r#"
        SELECT user_id, device_id, key_id, public_key, signature, timestamp_ms, created_at
        FROM signed_pre_keys
        WHERE user_id = $1 AND device_id = $2
        ORDER BY COALESCE(timestamp_ms, 0) DESC, key_id DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    let kyber_pre_key = sqlx::query_as::<_, KyberPreKeyRow>(
        r#"
        SELECT user_id, device_id, key_id, public_key, signature, timestamp_ms, created_at
        FROM kyber_pre_keys
        WHERE user_id = $1 AND device_id = $2
        ORDER BY COALESCE(timestamp_ms, 0) DESC, key_id DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    let mut tx = pool.begin().await?;

    let otpk_opt = sqlx::query_as::<_, OneTimePreKeyRow>(
        r#"
        SELECT user_id, device_id, key_id, public_key, uploaded_at
        FROM one_time_pre_keys
        WHERE user_id = $1 AND device_id = $2
        ORDER BY key_id ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(ref otpk) = otpk_opt {
        sqlx::query(
            r#"
            DELETE FROM one_time_pre_keys
            WHERE user_id = $1 AND device_id = $2 AND key_id = $3
            "#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(otpk.key_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(PreKeyBundle {
        registration_id: identity_row.registration_id.unwrap_or_default(),
        identity_public_key: identity_row.identity_public_key,
        signed_pre_key,
        one_time_pre_key: otpk_opt,
        kyber_pre_key,
    })
}

pub async fn count_one_time_pre_keys(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM one_time_pre_keys
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn delete_stale_one_time_pre_keys(
    pool: &PgPool,
    older_than_days: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM one_time_pre_keys
        WHERE uploaded_at < now() - make_interval(days => $1)
        "#,
    )
    .bind(older_than_days as f64)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn get_sendable_devices(
    pool: &PgPool,
    user_id: &Uuid,
) -> Result<Vec<SendableDeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, SendableDeviceRow>(
        r#"
        SELECT
            ud.device_id,
            ud.platform,
            ud.supports_delivery_ack,
            TRUE AS key_capable,
            ud.last_active_at
        FROM user_devices ud
        WHERE ud.user_id = $1
          AND EXISTS (
                SELECT 1
                FROM identity_keys ik
                WHERE ik.user_id = ud.user_id
                  AND ik.device_id = ud.device_id
                  AND ik.registration_id IS NOT NULL
                  AND octet_length(ik.identity_public_key) > 0
            )
          AND EXISTS (
                SELECT 1
                FROM signed_pre_keys spk
                WHERE spk.user_id = ud.user_id
                  AND spk.device_id = ud.device_id
                  AND octet_length(spk.public_key) > 0
                  AND octet_length(spk.signature) > 0
            )
          AND EXISTS (
                SELECT 1
                FROM kyber_pre_keys kpk
                WHERE kpk.user_id = ud.user_id
                  AND kpk.device_id = ud.device_id
                  AND octet_length(kpk.public_key) > 0
                  AND octet_length(kpk.signature) > 0
            )
        ORDER BY ud.device_id ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
