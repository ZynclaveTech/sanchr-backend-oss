use std::sync::Arc;

use fred::interfaces::KeysInterface;
use fred::types::Expiration;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::devices as pg_devices;
use sanchr_db::postgres::keys as pg_keys;
use sanchr_db::redis::rate_limit;
use sanchr_proto::keys::{
    DeviceInfo, KyberPreKey, OneTimePreKey, PreKeyBundleResponse, SignedPreKey,
};

use crate::messaging::stream::StreamManager;
use crate::server::AppState;

pub const MAX_ONE_TIME_PRE_KEYS_PER_UPLOAD: usize = 100;

pub struct UploadKeyBundleParams {
    pub user_id: Uuid,
    pub device_id: i32,
    pub registration_id: i32,
    pub identity_public_key: Vec<u8>,
    pub signed_pre_key: SignedPreKey,
    pub kyber_pre_key: KyberPreKey,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

/// Upload a full key bundle (identity key, signed pre-key, and one-time pre-keys).
pub async fn handle_upload_key_bundle(
    state: &Arc<AppState>,
    params: UploadKeyBundleParams,
) -> Result<(), Status> {
    let user_id = params.user_id;

    // Rate limit: max 10 key bundle uploads per hour
    let rate_key = format!("rate:keys:upload:{}", user_id);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 10, 3600)
        .await
        .map_err(|e| match e {
            sanchr_common::errors::AppError::RateLimited => {
                Status::resource_exhausted("key upload rate limited")
            }
            other => internal_status("rate limit check", other),
        })?;
    let device_id = params.device_id;
    let identity_public_key = params.identity_public_key;
    let signed_pre_key = params.signed_pre_key;
    let kyber_pre_key = params.kyber_pre_key;
    let one_time_pre_keys = params.one_time_pre_keys;

    validate_upload_payload(
        params.registration_id,
        &identity_public_key,
        &signed_pre_key,
        &kyber_pre_key,
    )
    .map_err(Status::invalid_argument)?;

    if one_time_pre_keys.len() > MAX_ONE_TIME_PRE_KEYS_PER_UPLOAD {
        return Err(Status::invalid_argument(format!(
            "one_time_pre_keys exceeds maximum of {MAX_ONE_TIME_PRE_KEYS_PER_UPLOAD}"
        )));
    }

    // Upsert identity key
    pg_keys::upsert_identity_key(
        &state.pg_pool,
        user_id,
        device_id,
        params.registration_id,
        &identity_public_key,
    )
    .await
    .map_err(|e| internal_status("failed to upsert identity key", e))?;

    // Upsert signed pre-key
    pg_keys::upsert_signed_pre_key(
        &state.pg_pool,
        user_id,
        device_id,
        signed_pre_key.key_id,
        &signed_pre_key.public_key,
        &signed_pre_key.signature,
        signed_pre_key.timestamp,
    )
    .await
    .map_err(|e| internal_status("failed to upsert signed pre-key", e))?;

    pg_keys::upsert_kyber_pre_key(
        &state.pg_pool,
        user_id,
        device_id,
        kyber_pre_key.key_id,
        &kyber_pre_key.public_key,
        &kyber_pre_key.signature,
        kyber_pre_key.timestamp,
    )
    .await
    .map_err(|e| internal_status("failed to upsert kyber pre-key", e))?;

    // Insert one-time pre-keys
    let otpk_tuples: Vec<(i32, Vec<u8>)> = one_time_pre_keys
        .into_iter()
        .map(|k| (k.key_id, k.public_key))
        .collect();

    pg_keys::insert_one_time_pre_keys(&state.pg_pool, user_id, device_id, &otpk_tuples)
        .await
        .map_err(|e| internal_status("failed to insert one-time pre-keys", e))?;

    // Update prekey count in Redis
    let count = pg_keys::count_one_time_pre_keys(&state.pg_pool, user_id, device_id)
        .await
        .map_err(|e| internal_status("failed to count pre-keys", e))?;

    let redis_key = format!("prekey_count:{user_id}:{device_id}");
    state
        .redis
        .set::<(), &str, i64>(
            &redis_key,
            count,
            Some(Expiration::EX(86400 * 7)), // 7-day TTL
            None,
            false,
        )
        .await
        .map_err(|e| internal_status("failed to update prekey count in Redis", e))?;

    Ok(())
}

/// Retrieve a pre-key bundle for a target user/device.
pub async fn handle_get_pre_key_bundle(
    state: &Arc<AppState>,
    stream_mgr: &StreamManager,
    target_user_id: Uuid,
    target_device_id: i32,
) -> Result<PreKeyBundleResponse, Status> {
    // Rate limit: max 60 pre-key bundle fetches per hour
    let rate_key = format!("rate:keys:get_bundle:{}", target_user_id);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 60, 3600)
        .await
        .map_err(|e| match e {
            sanchr_common::errors::AppError::RateLimited => {
                Status::resource_exhausted("pre-key bundle fetch rate limited")
            }
            other => internal_status("rate limit check", other),
        })?;

    let bundle = pg_keys::get_pre_key_bundle(&state.pg_pool, target_user_id, target_device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "pre-key bundle not found");
            Status::not_found("pre-key bundle not found")
        })?;

    // Decrement prekey count in Redis (the DB already consumed one OTP key)
    let redis_key = format!("prekey_count:{target_user_id}:{target_device_id}");
    let new_count: i64 = state.redis.decr::<i64, &str>(&redis_key).await.unwrap_or(0);

    if new_count < 20 {
        tracing::warn!(
            user_id = %target_user_id,
            device_id = target_device_id,
            remaining = new_count,
            "pre-key count is low"
        );
        // Push PreKeyCountLow event to the target user
        let event = sanchr_proto::messaging::ServerEvent {
            event: Some(
                sanchr_proto::messaging::server_event::Event::PreKeyCountLow(
                    sanchr_proto::messaging::PreKeyCountLow {
                        device_id: target_device_id,
                        remaining_count: new_count as i32,
                    },
                ),
            ),
        };
        let _ = stream_mgr
            .send_to_user(&target_user_id.to_string(), event)
            .await;
    }

    let signed = SignedPreKey {
        key_id: bundle.signed_pre_key.key_id,
        public_key: bundle.signed_pre_key.public_key,
        signature: bundle.signed_pre_key.signature,
        timestamp: bundle
            .signed_pre_key
            .timestamp_ms
            .unwrap_or_else(|| bundle.signed_pre_key.created_at.timestamp_millis()),
    };

    let otpk = bundle.one_time_pre_key.map(|k| OneTimePreKey {
        key_id: k.key_id,
        public_key: k.public_key,
    });

    let kyber = KyberPreKey {
        key_id: bundle.kyber_pre_key.key_id,
        public_key: bundle.kyber_pre_key.public_key,
        signature: bundle.kyber_pre_key.signature,
        timestamp: bundle
            .kyber_pre_key
            .timestamp_ms
            .unwrap_or_else(|| bundle.kyber_pre_key.created_at.timestamp_millis()),
    };

    Ok(PreKeyBundleResponse {
        identity_public_key: bundle.identity_public_key,
        signed_pre_key: Some(signed),
        one_time_pre_key: otpk,
        device_id: target_device_id,
        registration_id: bundle.registration_id,
        kyber_pre_key: Some(kyber),
    })
}

/// Upload additional one-time pre-keys and return the new count.
pub async fn handle_upload_one_time_pre_keys(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
    keys: Vec<OneTimePreKey>,
) -> Result<i32, Status> {
    // Rate limit: max 10 one-time pre-key uploads per hour
    let rate_key = format!("rate:keys:upload_otpk:{}", user_id);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 10, 3600)
        .await
        .map_err(|e| match e {
            sanchr_common::errors::AppError::RateLimited => {
                Status::resource_exhausted("one-time pre-key upload rate limited")
            }
            other => internal_status("rate limit check", other),
        })?;

    if keys.len() > MAX_ONE_TIME_PRE_KEYS_PER_UPLOAD {
        return Err(Status::invalid_argument(format!(
            "keys exceeds maximum of {MAX_ONE_TIME_PRE_KEYS_PER_UPLOAD}"
        )));
    }

    let otpk_tuples: Vec<(i32, Vec<u8>)> =
        keys.into_iter().map(|k| (k.key_id, k.public_key)).collect();

    pg_keys::insert_one_time_pre_keys(&state.pg_pool, user_id, device_id, &otpk_tuples)
        .await
        .map_err(|e| internal_status("failed to insert one-time pre-keys", e))?;

    let count = pg_keys::count_one_time_pre_keys(&state.pg_pool, user_id, device_id)
        .await
        .map_err(|e| internal_status("failed to count pre-keys", e))?;

    // Update Redis cache
    let redis_key = format!("prekey_count:{user_id}:{device_id}");
    let _ = state
        .redis
        .set::<(), &str, i64>(
            &redis_key,
            count,
            Some(Expiration::EX(86400 * 7)),
            None,
            false,
        )
        .await;

    Ok(count as i32)
}

/// Get the current pre-key count. Tries Redis first, falls back to Postgres.
pub async fn handle_get_pre_key_count(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
) -> Result<i32, Status> {
    let redis_key = format!("prekey_count:{user_id}:{device_id}");

    // Try Redis first
    if let Ok(Some(count)) = state.redis.get::<Option<i64>, _>(&redis_key).await {
        return Ok(count as i32);
    }

    // Fallback to Postgres
    let count = pg_keys::count_one_time_pre_keys(&state.pg_pool, user_id, device_id)
        .await
        .map_err(|e| internal_status("failed to count pre-keys", e))?;

    // Backfill Redis
    let _ = state
        .redis
        .set::<(), &str, i64>(
            &redis_key,
            count,
            Some(Expiration::EX(86400 * 7)),
            None,
            false,
        )
        .await;

    Ok(count as i32)
}

/// Get all device IDs for a user.
pub async fn handle_get_user_devices(
    state: &Arc<AppState>,
    target_user_id: Uuid,
) -> Result<Vec<DeviceInfo>, Status> {
    let rows = pg_keys::get_sendable_devices(&state.pg_pool, &target_user_id)
        .await
        .map_err(|e| internal_status("failed to get user devices", e))?;

    Ok(rows
        .into_iter()
        .map(|row| DeviceInfo {
            device_id: row.device_id,
            platform: row.platform,
            supports_delivery_ack: row.supports_delivery_ack,
            key_capable: row.key_capable,
            last_active_at: row
                .last_active_at
                .map(|ts| ts.timestamp())
                .unwrap_or_default(),
        })
        .collect())
}

/// Remove a device and all its associated Signal keys.
///
/// Refuses to remove the device the caller is currently authenticated on.
pub async fn handle_remove_device(
    state: &Arc<AppState>,
    user_id: Uuid,
    authenticated_device_id: i32,
    target_device_id: i32,
) -> Result<bool, Status> {
    if target_device_id == authenticated_device_id {
        return Err(Status::invalid_argument(
            "cannot remove the device you are currently using",
        ));
    }

    let belongs = pg_devices::device_belongs_to_user(&state.pg_pool, user_id, target_device_id)
        .await
        .map_err(|e| internal_status("failed to check device ownership", e))?;

    if !belongs {
        return Err(Status::not_found("device not found"));
    }

    let deleted = pg_devices::delete_device(&state.pg_pool, user_id, target_device_id)
        .await
        .map_err(|e| internal_status("failed to delete device", e))?;

    // Clean up the Redis prekey-count cache for the removed device.
    let redis_key = format!("prekey_count:{user_id}:{target_device_id}");
    let _ = state.redis.del::<(), &str>(&redis_key).await;

    Ok(deleted)
}

fn validate_upload_payload(
    registration_id: i32,
    identity_public_key: &[u8],
    signed_pre_key: &SignedPreKey,
    kyber_pre_key: &KyberPreKey,
) -> Result<(), &'static str> {
    if registration_id <= 0 {
        return Err("missing registration_id");
    }
    if identity_public_key.is_empty() {
        return Err("missing identity_public_key");
    }
    if signed_pre_key.key_id <= 0 {
        return Err("missing signed_pre_key.key_id");
    }
    if signed_pre_key.public_key.is_empty() {
        return Err("missing signed_pre_key.public_key");
    }
    if signed_pre_key.signature.is_empty() {
        return Err("missing signed_pre_key.signature");
    }
    if signed_pre_key.timestamp <= 0 {
        return Err("missing signed_pre_key.timestamp");
    }
    if kyber_pre_key.key_id <= 0 {
        return Err("missing kyber_pre_key.key_id");
    }
    if kyber_pre_key.public_key.is_empty() {
        return Err("missing kyber_pre_key.public_key");
    }
    if kyber_pre_key.signature.is_empty() {
        return Err("missing kyber_pre_key.signature");
    }
    if kyber_pre_key.timestamp <= 0 {
        return Err("missing kyber_pre_key.timestamp");
    }
    Ok(())
}
