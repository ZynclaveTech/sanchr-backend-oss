use std::sync::Arc;

use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::settings as pg_settings;
use sanchr_db::postgres::settings::UserSettingsRow;
use sanchr_db::redis::privacy_cache;
use sanchr_proto::settings::{
    ProfileResponse, SetRegistrationLockResponse, StorageUsageResponse, UserSettings,
};
use sanchr_server_crypto::password;

use crate::server::AppState;

/// Get user settings from Postgres.
pub async fn handle_get_settings(
    state: &Arc<AppState>,
    user_id: Uuid,
) -> Result<UserSettings, Status> {
    let row = pg_settings::get_settings(&state.pg_pool, user_id)
        .await
        .map_err(|e| internal_status("get_settings failed", e))?;

    Ok(settings_row_to_proto(&row))
}

/// Update user settings in Postgres.
pub async fn handle_update_settings(
    state: &Arc<AppState>,
    user_id: Uuid,
    settings: &UserSettings,
) -> Result<UserSettings, Status> {
    let row = proto_to_settings_row(user_id, settings);

    let updated = pg_settings::update_settings(&state.pg_pool, user_id, &row)
        .await
        .map_err(|e| internal_status("update_settings failed", e))?;

    // Invalidate Redis privacy cache so new settings take effect immediately
    privacy_cache::invalidate(&state.redis, &user_id).await;

    Ok(settings_row_to_proto(&updated))
}

/// Toggle Sanchr Mode on or off.
pub async fn handle_toggle_sanchr_mode(
    state: &Arc<AppState>,
    user_id: Uuid,
    enabled: bool,
) -> Result<UserSettings, Status> {
    let updated = if enabled {
        pg_settings::activate_sanchr_mode(&state.pg_pool, user_id).await
    } else {
        pg_settings::deactivate_sanchr_mode(&state.pg_pool, user_id).await
    }
    .map_err(|e| internal_status("toggle_sanchr_mode failed", e))?;

    // Invalidate Redis privacy cache
    privacy_cache::invalidate(&state.redis, &user_id).await;

    Ok(settings_row_to_proto(&updated))
}

/// Update user profile (display name, avatar, status, encrypted blobs).
#[allow(clippy::too_many_arguments)]
pub async fn handle_update_profile(
    state: &Arc<AppState>,
    user_id: Uuid,
    display_name: &str,
    avatar_url: &str,
    status_text: &str,
    profile_key: &[u8],
    encrypted_display_name: &[u8],
    encrypted_bio: &[u8],
    encrypted_avatar_url: &[u8],
) -> Result<ProfileResponse, Status> {
    let name = if display_name.is_empty() {
        None
    } else {
        Some(display_name)
    };
    let avatar = if avatar_url.is_empty() {
        None
    } else {
        Some(avatar_url)
    };
    let status = if status_text.is_empty() {
        None
    } else {
        Some(status_text)
    };
    // Only persist blobs when the client actually sent them (non-empty).
    let pk = if profile_key.is_empty() {
        None
    } else {
        Some(profile_key)
    };
    let edn = if encrypted_display_name.is_empty() {
        None
    } else {
        Some(encrypted_display_name)
    };
    let ebio = if encrypted_bio.is_empty() {
        None
    } else {
        Some(encrypted_bio)
    };
    let eau = if encrypted_avatar_url.is_empty() {
        None
    } else {
        Some(encrypted_avatar_url)
    };

    let profile = pg_settings::update_profile(
        &state.pg_pool,
        user_id,
        name,
        avatar,
        status,
        pk,
        edn,
        ebio,
        eau,
    )
    .await
    .map_err(|e| internal_status("update_profile failed", e))?;

    Ok(ProfileResponse {
        id: profile.id.to_string(),
        display_name: profile.display_name,
        avatar_url: profile.avatar_url.unwrap_or_default(),
        status_text: profile.status_text.unwrap_or_default(),
        profile_key: profile.profile_key.unwrap_or_default(),
        encrypted_display_name: profile.encrypted_display_name.unwrap_or_default(),
        encrypted_bio: profile.encrypted_bio.unwrap_or_default(),
        encrypted_avatar_url: profile.encrypted_avatar_url.unwrap_or_default(),
    })
}

pub async fn handle_get_storage_usage(
    _state: &Arc<AppState>,
    _user_id: Uuid,
) -> Result<StorageUsageResponse, Status> {
    // Forward-secure vault: the server cannot see media_type (it is inside
    // encrypted_metadata), so per-type storage breakdowns are no longer
    // computable on the server. This matches the spec non-goal
    // "Server-side per-user vault storage metrics".
    //
    // The RPC stays in settings.proto for wire compatibility; clients
    // compute their own breakdowns after decrypting vault metadata.
    // Everything is reported as zero until the RPC is either removed
    // entirely in a future round or replaced with a cross-DB join
    // between Postgres media_objects and Scylla vault_items.
    Ok(StorageUsageResponse {
        photos_bytes: 0,
        videos_bytes: 0,
        documents_bytes: 0,
        voice_bytes: 0,
        other_bytes: 0,
        total_bytes: 0,
        limit_bytes: 0,
    })
}

/// Enable or disable the Registration Lock PIN.
///
/// Rules:
/// - Enabling: `pin` must be non-empty.  It is hashed and stored.
/// - Disabling: `pin` must match the stored hash.  If no hash is stored (lock
///   was already off), we succeed silently (idempotent disable).
/// - Changing PIN (enable=true when already enabled): treated the same as
///   enabling — just overwrites the existing hash without PIN verification.
///   The iOS client enforces the current-PIN entry flow; the server trusts the
///   authentication layer to guard the RPC.
pub async fn handle_set_registration_lock(
    state: &Arc<AppState>,
    user_id: Uuid,
    enabled: bool,
    pin: &str,
) -> Result<SetRegistrationLockResponse, Status> {
    if enabled {
        if pin.is_empty() {
            return Err(Status::invalid_argument(
                "pin is required when enabling registration lock",
            ));
        }

        let pin_hash = password::hash_password(pin, &password::PasswordHasherConfig::default())
            .map_err(|e| internal_status("pin hashing failed", e))?;

        pg_settings::set_registration_lock(&state.pg_pool, user_id, true, Some(&pin_hash))
            .await
            .map_err(|e| internal_status("set_registration_lock failed", e))?;
    } else {
        // Fetch current state to verify the PIN before disabling.
        let row = pg_settings::get_settings(&state.pg_pool, user_id)
            .await
            .map_err(|e| internal_status("get_settings failed", e))?;

        if let Some(stored_hash) = &row.registration_lock_pin_hash {
            // Lock is active — require the correct PIN.
            if password::verify_password(pin, stored_hash).is_err() {
                return Ok(SetRegistrationLockResponse { success: false });
            }
        }
        // If stored_hash is None the lock was already off — succeed silently.

        pg_settings::set_registration_lock(&state.pg_pool, user_id, false, None)
            .await
            .map_err(|e| internal_status("set_registration_lock failed", e))?;
    }

    Ok(SetRegistrationLockResponse { success: true })
}

// ─── Conversion helpers ──────────────────────────────────────────────────────

fn settings_row_to_proto(row: &UserSettingsRow) -> UserSettings {
    UserSettings {
        read_receipts: row.read_receipts.unwrap_or(true),
        online_status_visible: row.online_status_visible.unwrap_or(true),
        typing_indicator: row.typing_indicator.unwrap_or(true),
        profile_photo_visibility: row
            .profile_photo_visibility
            .clone()
            .unwrap_or_else(|| "everyone".to_string()),
        sanchr_mode_enabled: row.sanchr_mode_enabled.unwrap_or(false),
        screen_lock_enabled: row.screen_lock_enabled.unwrap_or(false),
        screen_lock_timeout: row.screen_lock_timeout.unwrap_or(0),
        screenshot_protection: row.screenshot_protection.unwrap_or(false),
        biometric_lock: row.biometric_lock.unwrap_or(false),
        message_notifications: row.message_notifications.unwrap_or(true),
        group_notifications: row.group_notifications.unwrap_or(true),
        call_notifications: row.call_notifications.unwrap_or(true),
        notification_sound: row
            .notification_sound
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        notification_vibrate: row.notification_vibrate.unwrap_or(true),
        show_preview: row.show_preview.unwrap_or(true),
        theme: row.theme.clone().unwrap_or_else(|| "system".to_string()),
        font_size: row
            .font_size
            .clone()
            .unwrap_or_else(|| "medium".to_string()),
        chat_wallpaper: row.chat_wallpaper.clone().unwrap_or_default(),
        auto_download_wifi: row
            .auto_download_wifi
            .clone()
            .unwrap_or_else(|| "all".to_string()),
        auto_download_mobile: row
            .auto_download_mobile
            .clone()
            .unwrap_or_else(|| "photos".to_string()),
        auto_download_roaming: row
            .auto_download_roaming
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        low_data_mode: row.low_data_mode.unwrap_or(false),
        registration_lock_enabled: row.registration_lock_enabled.unwrap_or(false),
    }
}

fn proto_to_settings_row(user_id: Uuid, s: &UserSettings) -> UserSettingsRow {
    UserSettingsRow {
        user_id,
        read_receipts: Some(s.read_receipts),
        online_status_visible: Some(s.online_status_visible),
        typing_indicator: Some(s.typing_indicator),
        profile_photo_visibility: Some(s.profile_photo_visibility.clone()),
        sanchr_mode_enabled: Some(s.sanchr_mode_enabled),
        screen_lock_enabled: Some(s.screen_lock_enabled),
        screen_lock_timeout: Some(s.screen_lock_timeout),
        screenshot_protection: Some(s.screenshot_protection),
        biometric_lock: Some(s.biometric_lock),
        message_notifications: Some(s.message_notifications),
        group_notifications: Some(s.group_notifications),
        call_notifications: Some(s.call_notifications),
        notification_sound: Some(s.notification_sound.clone()),
        notification_vibrate: Some(s.notification_vibrate),
        show_preview: Some(s.show_preview),
        theme: Some(s.theme.clone()),
        font_size: Some(s.font_size.clone()),
        chat_wallpaper: Some(s.chat_wallpaper.clone()),
        auto_download_wifi: Some(s.auto_download_wifi.clone()),
        auto_download_mobile: Some(s.auto_download_mobile.clone()),
        auto_download_roaming: Some(s.auto_download_roaming.clone()),
        low_data_mode: Some(s.low_data_mode),
        // registration_lock_enabled and registration_lock_pin_hash are
        // immutable via update_settings; they are managed exclusively through
        // handle_set_registration_lock to enforce PIN verification.
        registration_lock_enabled: None,
        registration_lock_pin_hash: None,
        updated_at: chrono::Utc::now(),
    }
}
