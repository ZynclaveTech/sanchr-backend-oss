use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use scylla::value::CqlTimeuuid;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::conversations as pg_conversations;
use sanchr_db::postgres::devices as pg_devices;
use sanchr_db::redis::delivery_tokens;
use sanchr_db::scylla::outbox as sc_outbox;
use sanchr_proto::messaging::{
    server_event, SealedInboundMessage, SendSealedMessageRequest, SendSealedMessageResponse,
    ServerEvent,
};

use crate::server::AppState;

use super::stream::StreamManager;

/// 30-day TTL for sealed outbox entries.
const SEALED_TTL_SECS: i64 = 30 * 24 * 3600;
pub const MAX_SEALED_DEVICE_MESSAGES_PER_SEND: usize = 100;

/// Handle a sealed-sender message submission.
///
/// The caller is authenticated solely by a one-time delivery token — no JWT,
/// no user identity. For each target device the handler:
///
/// 1. Persists the sealed envelope in the device outbox (30-day TTL).
/// 2. Attempts live push via [`StreamManager`].
/// 3. Falls back to a NATS relay so another core instance can deliver.
pub async fn handle_send_sealed_message(
    state: &Arc<AppState>,
    stream_mgr: &Arc<StreamManager>,
    request: SendSealedMessageRequest,
) -> Result<SendSealedMessageResponse, Status> {
    if request.device_messages.is_empty() {
        return Err(Status::invalid_argument(
            "device_messages must contain at least one target",
        ));
    }
    if request.device_messages.len() > MAX_SEALED_DEVICE_MESSAGES_PER_SEND {
        return Err(Status::invalid_argument(format!(
            "device_messages exceeds maximum of {MAX_SEALED_DEVICE_MESSAGES_PER_SEND}"
        )));
    }

    // ── 1. Validate delivery token ──────────────────────────────────────
    let token_valid = delivery_tokens::validate_and_consume(&state.redis, &request.delivery_token)
        .await
        .map_err(|e| internal_status("delivery token check failed", e))?;

    if !token_valid {
        return Err(Status::unauthenticated("invalid or expired delivery token"));
    }

    // ── 2. Server timestamp ─────────────────────────────────────────────
    let server_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| internal_status("clock error", e))?
        .as_millis() as i64;

    // ── 3. Route each device message ────────────────────────────────────
    for dm in &request.device_messages {
        let recipient_id: Uuid = dm
            .recipient_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid recipient_id in device_message"))?;

        let msg_uuid = sanchr_common::new_timeuuid();
        let message_id = CqlTimeuuid::from(msg_uuid);

        // 3a. Persist to device outbox
        sc_outbox::queue_sealed_outbox(
            &state.scylla,
            recipient_id,
            dm.device_id,
            message_id,
            &dm.sealed_envelope,
            server_ts,
            SEALED_TTL_SECS,
        )
        .await
        .map_err(|e| internal_status("failed to enqueue sealed outbox", e))?;

        // 3b. Build inbound event for live push
        let inbound = SealedInboundMessage {
            sealed_envelope: dm.sealed_envelope.clone(),
            server_timestamp: server_ts,
            message_id: Uuid::from(message_id).to_string(),
        };

        let event = ServerEvent {
            event: Some(server_event::Event::SealedMessage(inbound)),
        };

        // 3c. Try live push; fall back to NATS relay
        let recipient_str = recipient_id.to_string();
        let delivered = stream_mgr
            .send_to(&recipient_str, dm.device_id, event)
            .await;

        if !delivered {
            // Publish a lightweight JSON relay so another core instance that
            // owns the recipient's stream can push it immediately.
            let relay = SealedRelayPayload {
                message_id: Uuid::from(message_id).to_string(),
                sealed_envelope: dm.sealed_envelope.clone(),
                server_timestamp: server_ts,
            };

            if let Ok(payload) = serde_json::to_vec(&relay) {
                let topic = format!("msg.sealed.{}.{}", recipient_str, dm.device_id);
                let _ = state.nats.publish(topic, payload.into()).await;
            }

            // Wake offline device via a silent APNs push. We use
            // content-available (no alert) because sealed-sender messages
            // carry no visible metadata the server can safely include — the
            // device wakes, syncs via gRPC, and surfaces a notification locally.
            if let Some(sender) = &state.push_sender {
                let notifications_muted = if dm.conversation_id.is_empty() {
                    false
                } else {
                    match dm.conversation_id.parse::<Uuid>() {
                        Ok(conversation_id) => pg_conversations::is_device_conversation_muted(
                            &state.pg_pool,
                            recipient_id,
                            dm.device_id,
                            conversation_id,
                        )
                        .await
                        .map_err(|e| internal_status("conversation mute lookup failed", e))?,
                        Err(_) => {
                            tracing::debug!(
                                recipient_id = %recipient_id,
                                device_id = dm.device_id,
                                "send_sealed_message: invalid conversation_id metadata; treating as unmuted"
                            );
                            false
                        }
                    }
                };

                if notifications_muted {
                    tracing::debug!(
                        recipient_id = %recipient_id,
                        device_id = dm.device_id,
                        conversation_id = %dm.conversation_id,
                        "send_sealed_message: skipping silent APNs for muted device conversation"
                    );
                    continue;
                }

                if let Ok(Some(token)) =
                    pg_devices::get_push_token(&state.pg_pool, recipient_id, dm.device_id).await
                {
                    let sender = Arc::clone(sender);
                    tokio::spawn(async move { sender.send_silent_push(&token).await });
                }
            }
        }
    }

    Ok(SendSealedMessageResponse {
        server_timestamp: server_ts,
    })
}

/// Minimal NATS relay payload for sealed messages.
///
/// Intentionally omits sender identity to preserve sealed-sender anonymity.
#[derive(serde::Serialize, serde::Deserialize)]
struct SealedRelayPayload {
    message_id: String,
    sealed_envelope: Vec<u8>,
    server_timestamp: i64,
}
