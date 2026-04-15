use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: i32,
    pub device_name: Option<String>,
    pub platform: String,
    pub installation_id: Option<String>,
    pub supports_delivery_ack: bool,
    pub push_token: Option<String>,
    pub voip_push_token: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_presence_state: String,
    pub last_presence_changed_at: Option<DateTime<Utc>>,
}

pub async fn upsert_device(
    pool: &PgPool,
    user_id: &Uuid,
    device_name: Option<&str>,
    platform: &str,
    installation_id: Option<&str>,
    supports_delivery_ack: bool,
) -> Result<DeviceRow, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Serialize device-id allocation per user so concurrent installs cannot
    // race on MAX(device_id) + 1 and trip the unique(user_id, device_id) index.
    sqlx::query(
        r#"
        SELECT pg_advisory_xact_lock(hashtext($1::text)::bigint)
        "#,
    )
    .bind(user_id.to_string())
    .execute(&mut *tx)
    .await?;

    if let Some(installation_id) = installation_id.filter(|value| !value.is_empty()) {
        if sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT *
            FROM user_devices
            WHERE user_id = $1 AND installation_id = $2
            "#,
        )
        .bind(user_id)
        .bind(installation_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            let updated = sqlx::query_as::<_, DeviceRow>(
                r#"
                UPDATE user_devices
                SET device_name = COALESCE($3, device_name),
                    platform = $4,
                    supports_delivery_ack = $5,
                    last_active_at = now()
                WHERE user_id = $1 AND installation_id = $2
                RETURNING *
                "#,
            )
            .bind(user_id)
            .bind(installation_id)
            .bind(device_name)
            .bind(platform)
            .bind(supports_delivery_ack)
            .fetch_one(&mut *tx)
            .await?;

            tx.commit().await?;
            return Ok(updated);
        }

        let inserted = sqlx::query_as::<_, DeviceRow>(
            r#"
            INSERT INTO user_devices (
                user_id,
                device_id,
                device_name,
                platform,
                installation_id,
                supports_delivery_ack,
                last_active_at
            )
            VALUES (
                $1,
                (SELECT COALESCE(MAX(device_id), 0) + 1 FROM user_devices WHERE user_id = $1),
                $2,
                $3,
                $4,
                $5,
                now()
            )
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(device_name)
        .bind(platform)
        .bind(installation_id)
        .bind(supports_delivery_ack)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(inserted);
    }

    let inserted = sqlx::query_as::<_, DeviceRow>(
        r#"
        INSERT INTO user_devices (
            user_id,
            device_id,
            device_name,
            platform,
            supports_delivery_ack,
            last_active_at
        )
        VALUES (
            $1,
            (SELECT COALESCE(MAX(device_id), 0) + 1 FROM user_devices WHERE user_id = $1),
            $2,
            $3,
            $4,
            now()
        )
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(device_name)
    .bind(platform)
    .bind(supports_delivery_ack)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(inserted)
}

pub async fn device_belongs_to_user(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM user_devices
            WHERE user_id = $1 AND device_id = $2
        )
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn get_device(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<Option<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT *
        FROM user_devices
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_devices_by_ids(
    pool: &PgPool,
    user_id: Uuid,
    device_ids: &[i32],
) -> Result<Vec<DeviceRow>, sqlx::Error> {
    if device_ids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT *
        FROM user_devices
        WHERE user_id = $1 AND device_id = ANY($2)
        "#,
    )
    .bind(user_id)
    .bind(device_ids)
    .fetch_all(pool)
    .await
}

pub async fn list_user_devices(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT *
        FROM user_devices
        WHERE user_id = $1
        ORDER BY device_id ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn update_push_token(
    pool: &PgPool,
    user_id: &Uuid,
    device_id: i32,
    token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE user_devices
        SET push_token = $1,
            push_token_rotated_at = now()
        WHERE user_id = $2 AND device_id = $3
        "#,
    )
    .bind(token)
    .bind(user_id)
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch only the push token for a single device. Cheaper than `get_device`
/// when no other fields are needed (e.g. when deciding whether to send APNs).
pub async fn get_push_token(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        r#"
        SELECT push_token
        FROM user_devices
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(token,)| token))
}

pub async fn update_voip_push_token(
    pool: &PgPool,
    user_id: &Uuid,
    device_id: i32,
    voip_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE user_devices
        SET voip_push_token = $1
        WHERE user_id = $2 AND device_id = $3
        "#,
    )
    .bind(voip_token)
    .bind(user_id)
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch all non-null VoIP push tokens for a user (one per device).
/// Used by the call bridge to wake offline devices via PushKit.
pub async fn list_user_voip_push_tokens(
    pool: &PgPool,
    user_id: &Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT voip_push_token
        FROM user_devices
        WHERE user_id = $1
          AND voip_push_token IS NOT NULL
          AND voip_push_token <> ''
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

pub async fn delete_device(
    pool: &PgPool,
    user_id: Uuid,
    device_id: i32,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Delete Signal keys first (order doesn't matter within the transaction,
    // but clearing dependents before the device row is conventional).
    sqlx::query("DELETE FROM one_time_pre_keys WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM signed_pre_keys WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM kyber_pre_keys WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM identity_keys WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

    let result = sqlx::query("DELETE FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(result.rows_affected() > 0)
}

pub async fn update_last_active(
    pool: &PgPool,
    user_id: &Uuid,
    device_id: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE user_devices
        SET last_active_at = now()
        WHERE user_id = $1 AND device_id = $2
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(())
}
