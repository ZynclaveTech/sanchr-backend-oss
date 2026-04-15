use std::sync::Arc;

use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::conversations as pg_conversations;
use sanchr_db::postgres::devices as pg_devices;
use sanchr_db::postgres::settings as pg_settings;
use sanchr_proto::notifications::{
    SetConversationNotificationPrefsRequest, UpdateNotificationPrefsRequest,
};

use crate::server::AppState;

/// Register (or update) the push notification token for the authenticated
/// user's current device.  At least one of `token` or `voip_token` must be
/// non-empty; both may be provided in the same request.
pub async fn handle_register_push_token(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
    token: &str,
    _platform: &str,
    voip_token: &str,
) -> Result<(), Status> {
    if token.is_empty() && voip_token.is_empty() {
        return Err(Status::invalid_argument("token or voip_token is required"));
    }

    if !token.is_empty() {
        pg_devices::update_push_token(&state.pg_pool, &user_id, device_id, token)
            .await
            .map_err(|e| internal_status("update_push_token failed", e))?;
    }

    if !voip_token.is_empty() {
        pg_devices::update_voip_push_token(&state.pg_pool, &user_id, device_id, voip_token)
            .await
            .map_err(|e| internal_status("update_voip_push_token failed", e))?;
    }

    Ok(())
}

/// Update the notification preferences columns in `user_settings`.
pub async fn handle_update_notification_prefs(
    state: &Arc<AppState>,
    user_id: Uuid,
    prefs: &UpdateNotificationPrefsRequest,
) -> Result<(), Status> {
    pg_settings::update_notification_prefs(
        &state.pg_pool,
        user_id,
        &pg_settings::NotificationPrefs {
            message_notifications: prefs.message_notifications,
            group_notifications: prefs.group_notifications,
            call_notifications: prefs.call_notifications,
            notification_sound: &prefs.notification_sound,
            vibrate: prefs.vibrate,
            show_preview: prefs.show_preview,
        },
    )
    .await
    .map_err(|e| internal_status("update_notification_prefs failed", e))?;

    Ok(())
}

/// Update notification preferences for one conversation on the current device.
///
/// This is deliberately device-scoped: muting a chat on iPhone does not mute it
/// on iPad/Android unless those devices also call this RPC.
pub async fn handle_set_conversation_notification_prefs(
    state: &Arc<AppState>,
    user_id: Uuid,
    device_id: i32,
    prefs: &SetConversationNotificationPrefsRequest,
) -> Result<(), Status> {
    let conversation_id: Uuid = prefs
        .conversation_id
        .parse()
        .map_err(|_| Status::invalid_argument("invalid conversation_id"))?;

    let updated = pg_conversations::set_device_conversation_muted(
        &state.pg_pool,
        user_id,
        device_id,
        conversation_id,
        prefs.muted,
    )
    .await
    .map_err(|e| internal_status("set_conversation_notification_prefs failed", e))?;

    if !updated {
        return Err(Status::not_found("conversation or device not found"));
    }

    Ok(())
}
