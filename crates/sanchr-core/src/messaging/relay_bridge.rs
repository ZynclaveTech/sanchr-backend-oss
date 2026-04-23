use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use sanchr_proto::messaging::{server_event, EncryptedEnvelope, SealedInboundMessage, ServerEvent};

use crate::messaging::relay_payload::RelayEnvelope;
use crate::messaging::service::envelope_kind_for;
use crate::server::AppState;

pub fn spawn_message_relay_bridge(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_message_relay_bridge(Arc::clone(&state)).await {
                tracing::error!(error = %error, "message relay bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

pub fn spawn_sealed_relay_bridge(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_sealed_relay_bridge(Arc::clone(&state)).await {
                tracing::error!(error = %error, "sealed relay bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

async fn run_message_relay_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state.nats.subscribe("msg.relay.*.*").await?;

    while let Some(message) = subscription.next().await {
        let mut parts = message.subject.split('.');
        let p0 = parts.next();
        let p1 = parts.next();
        let user_id = parts.next();
        let device_id = parts.next();

        if p0 != Some("msg") || p1 != Some("relay") {
            continue;
        }

        let (Some(user_id), Some(device_id_str)) = (user_id, device_id) else {
            continue;
        };

        let Ok(device_id) = device_id_str.parse::<i32>() else {
            continue;
        };

        let relay = match serde_json::from_slice::<RelayEnvelope>(&message.payload) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(error = %error, subject = %message.subject, "invalid relay envelope payload");
                continue;
            }
        };

        let envelope_kind =
            envelope_kind_for(&relay.content_type, &relay.sender_id, relay.sender_device);
        let event = ServerEvent {
            event: Some(server_event::Event::Message(EncryptedEnvelope {
                conversation_id: relay.conversation_id,
                message_id: relay.message_id,
                sender_id: relay.sender_id,
                sender_device: relay.sender_device,
                ciphertext: relay.ciphertext,
                content_type: relay.content_type,
                server_timestamp: relay.server_timestamp,
                envelope_kind,
            })),
        };

        let _ = state.stream_mgr.send_to(user_id, device_id, event).await;
    }

    Err(anyhow::anyhow!("message relay subscription ended"))
}

/// Mirror of the `SealedRelayPayload` published by `sealed_handler`.
///
/// `serde_json` encodes `Vec<u8>` as a base64 string, so deserialization here
/// automatically decodes back to raw bytes — no manual base64 step required.
#[derive(serde::Deserialize)]
struct SealedRelayPayload {
    message_id: String,
    sealed_envelope: Vec<u8>,
    server_timestamp: i64,
}

async fn run_sealed_relay_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state.nats.subscribe("msg.sealed.*.*").await?;

    while let Some(message) = subscription.next().await {
        let mut parts = message.subject.split('.');
        let p0 = parts.next();
        let p1 = parts.next();
        let user_id = parts.next();
        let device_id = parts.next();

        if p0 != Some("msg") || p1 != Some("sealed") {
            continue;
        }

        let (Some(user_id), Some(device_id_str)) = (user_id, device_id) else {
            continue;
        };

        let Ok(device_id) = device_id_str.parse::<i32>() else {
            continue;
        };

        let relay = match serde_json::from_slice::<SealedRelayPayload>(&message.payload) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(error = %error, subject = %message.subject, "invalid sealed relay payload");
                continue;
            }
        };

        let event = ServerEvent {
            event: Some(server_event::Event::SealedMessage(SealedInboundMessage {
                sealed_envelope: relay.sealed_envelope,
                server_timestamp: relay.server_timestamp,
                message_id: relay.message_id,
            })),
        };

        let _ = state.stream_mgr.send_to(user_id, device_id, event).await;
    }

    Err(anyhow::anyhow!("sealed relay subscription ended"))
}
