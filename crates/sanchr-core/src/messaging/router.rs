use std::sync::Arc;

use scylla::frame::value::CqlTimeuuid;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::redis::privacy_cache;
use sanchr_proto::messaging::{server_event, EncryptedEnvelope, ServerEvent};

use crate::messaging::relay_payload::RelayEnvelope;

use crate::server::AppState;

use super::stream::StreamManager;

pub struct ValidatedDeviceMessage {
    pub recipient_id: Uuid,
    pub device_id: i32,
    pub ciphertext: Vec<u8>,
    pub supports_delivery_ack: bool,
    /// APNs device token, if registered. Used to wake the device when it is
    /// offline. `None` means no push token on record.
    pub push_token: Option<String>,
    /// Device-local per-conversation mute state. Muted devices still receive
    /// durable/live message delivery, but the server must not trigger APNs.
    pub notifications_muted: bool,
}

pub struct RouteMessageParams<'a> {
    pub conversation_id: Uuid,
    pub message_id: CqlTimeuuid,
    pub sender_id: Uuid,
    pub sender_device: i32,
    pub device_messages: Vec<ValidatedDeviceMessage>,
    pub content_type: &'a str,
    pub server_ts: i64,
    pub expires_at: Option<i64>,
}

/// Route a message to each recipient device.
///
/// For each `DeviceMessage`:
/// 1. Build an `EncryptedEnvelope` wrapped in a `ServerEvent`.
/// 2. If the target device is currently connected, push via the stream.
/// 3. Otherwise, queue the message in ScyllaDB for later delivery.
pub async fn route_message(
    state: &AppState,
    stream_mgr: &StreamManager,
    params: RouteMessageParams<'_>,
) -> Result<(), Status> {
    let conversation_id = params.conversation_id;
    let message_id = params.message_id;
    let sender_id = params.sender_id;
    let sender_device = params.sender_device;
    let device_messages = params.device_messages;
    let content_type = params.content_type;
    let server_ts = params.server_ts;
    let expires_at = params.expires_at;

    // Phase 2 block enforcement (defense in depth): cache per-recipient block
    // decisions so recipients with multiple devices only trigger a single
    // privacy-flag lookup. `handle_send_message` already short-circuits 1:1
    // blocked sends before calling this function, but `route_message` is
    // reachable from additional paths (sync replay, forwarding, delivery
    // retry) where the same gate must apply.
    //
    // The sender is never blocked against themselves, so skip the lookup for
    // self-fanout (multi-device sync of the sender's own message).
    let sender_id_str = sender_id.to_string();
    let mut recipient_is_blocked: std::collections::HashMap<Uuid, bool> =
        std::collections::HashMap::new();

    for dm in device_messages {
        let recipient_id = dm.recipient_id;

        // Per-recipient silent-drop: skip enqueue + live delivery when the
        // recipient blocks the sender. Sender's own devices (multi-device
        // fanout) are always delivered, since the sender can never block
        // themselves.
        if recipient_id != sender_id {
            let blocked = match recipient_is_blocked.get(&recipient_id).copied() {
                Some(b) => b,
                None => {
                    let flags = privacy_cache::get_privacy_flags(
                        &state.redis,
                        &state.pg_pool,
                        recipient_id,
                    )
                    .await
                    .map_err(|e| internal_status("privacy cache", e))?;
                    let b = flags.is_blocking(&sender_id_str);
                    recipient_is_blocked.insert(recipient_id, b);
                    b
                }
            };

            if blocked {
                tracing::debug!(
                    sender_id = %sender_id,
                    recipient_id = %recipient_id,
                    device_id = dm.device_id,
                    "route_message: skipping blocked recipient device"
                );
                continue;
            }
        }

        let supports_delivery_ack = dm.supports_delivery_ack;

        let envelope = EncryptedEnvelope {
            conversation_id: conversation_id.to_string(),
            message_id: Uuid::from(message_id).to_string(),
            sender_id: sender_id.to_string(),
            sender_device,
            ciphertext: dm.ciphertext.clone(),
            content_type: content_type.to_owned(),
            server_timestamp: server_ts,
        };

        let event = ServerEvent {
            event: Some(server_event::Event::Message(envelope)),
        };

        let recipient_str = recipient_id.to_string();
        let connected = stream_mgr.is_connected(&recipient_str, dm.device_id).await;

        if supports_delivery_ack {
            let ttl_seconds = expires_at.and_then(|expires_at| {
                let remaining_ms = expires_at - server_ts;
                if remaining_ms <= 0 {
                    None
                } else {
                    Some((remaining_ms + 999) / 1000)
                }
            });

            if expires_at.is_some() && ttl_seconds.is_none() {
                crate::observability::metrics::record_device_outbox_expired();
                continue;
            }

            sanchr_db::scylla::outbox::queue_outbox(
                &state.scylla,
                recipient_id,
                dm.device_id,
                message_id,
                conversation_id,
                sender_id,
                sender_device,
                &dm.ciphertext,
                content_type,
                server_ts,
                expires_at,
                ttl_seconds,
            )
            .await
            .map_err(|e| internal_status("failed to enqueue device outbox message", e))?;

            crate::observability::metrics::record_device_outbox_enqueued();

            if connected {
                let _ = stream_mgr
                    .send_to(&recipient_str, dm.device_id, event.clone())
                    .await;
            } else {
                // Cross-node live fanout: publish relay so another core instance that owns
                // the recipient stream can deliver immediately.
                if let Ok(payload) = serde_json::to_vec(&RelayEnvelope {
                    conversation_id: conversation_id.to_string(),
                    message_id: Uuid::from(message_id).to_string(),
                    sender_id: sender_id.to_string(),
                    sender_device,
                    ciphertext: dm.ciphertext.clone(),
                    content_type: content_type.to_owned(),
                    server_timestamp: server_ts,
                }) {
                    let _ = state
                        .nats
                        .publish(
                            format!("msg.relay.{}.{}", recipient_str, dm.device_id),
                            payload.into(),
                        )
                        .await;
                }

                // Wake offline device via APNs.
                if !dm.notifications_muted {
                    if let (Some(sender), Some(token)) = (&state.push_sender, &dm.push_token) {
                        let sender = Arc::clone(sender);
                        let token = token.clone();
                        tokio::spawn(async move { sender.send_message_push(&token).await });
                    }
                } else {
                    tracing::debug!(
                        recipient_id = %recipient_id,
                        device_id = dm.device_id,
                        conversation_id = %conversation_id,
                        "route_message: skipping APNs for muted device conversation"
                    );
                }
            }
        } else {
            crate::observability::metrics::record_legacy_device_delivery();

            let delivered = if connected {
                stream_mgr
                    .send_to(&recipient_str, dm.device_id, event.clone())
                    .await
            } else {
                false
            };

            // Cross-node live fanout attempt for legacy path too.
            if !delivered {
                if let Ok(payload) = serde_json::to_vec(&RelayEnvelope {
                    conversation_id: conversation_id.to_string(),
                    message_id: Uuid::from(message_id).to_string(),
                    sender_id: sender_id.to_string(),
                    sender_device,
                    ciphertext: dm.ciphertext.clone(),
                    content_type: content_type.to_owned(),
                    server_timestamp: server_ts,
                }) {
                    let _ = state
                        .nats
                        .publish(
                            format!("msg.relay.{}.{}", recipient_str, dm.device_id),
                            payload.into(),
                        )
                        .await;
                }

                // Wake offline device via APNs.
                if !dm.notifications_muted {
                    if let (Some(sender), Some(token)) = (&state.push_sender, &dm.push_token) {
                        let sender = Arc::clone(sender);
                        let token = token.clone();
                        tokio::spawn(async move { sender.send_message_push(&token).await });
                    }
                } else {
                    tracing::debug!(
                        recipient_id = %recipient_id,
                        device_id = dm.device_id,
                        conversation_id = %conversation_id,
                        "route_message: skipping APNs for muted device conversation"
                    );
                }
            }

            if !delivered {
                sanchr_db::scylla::pending::queue_pending(
                    &state.scylla,
                    recipient_id,
                    dm.device_id,
                    message_id,
                    conversation_id,
                    sender_id,
                    &dm.ciphertext,
                    content_type,
                    server_ts,
                )
                .await
                .map_err(|e| internal_status("failed to queue pending message", e))?;

                crate::observability::metrics::record_message_pending();
            }
        }
    }

    Ok(())
}
