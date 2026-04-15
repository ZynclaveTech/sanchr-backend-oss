use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use sanchr_common::{CallLifecyclePayload, CallOfferPayload};
use sanchr_db::redis::call_events::{self, CallInboxEvent};
use sanchr_proto::messaging::{server_event, CallLifecycleEvent, CallOfferEvent, ServerEvent};

use crate::observability::metrics;
use crate::server::AppState;

const OFFER_REPLAY_TTL_SECS: i64 = 120;
const LIFECYCLE_REPLAY_TTL_SECS: i64 = 600;
const VOIP_PUSH_GRACE_MS: u64 = 1_500;
const OFFER_SIDE_EFFECT_QUEUE: &str = "sanchr-core-call-offer-side-effects";
const LIFECYCLE_SIDE_EFFECT_QUEUE: &str = "sanchr-core-call-lifecycle-side-effects";

pub fn spawn_call_event_bridges(state: Arc<AppState>) -> Vec<JoinHandle<()>> {
    let offer_live_state = Arc::clone(&state);
    let offer_live_handle = tokio::spawn(async move {
        loop {
            if let Err(error) = run_offer_live_bridge(Arc::clone(&offer_live_state)).await {
                tracing::error!(error = %error, "call offer live bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let offer_side_effect_state = Arc::clone(&state);
    let offer_side_effect_handle = tokio::spawn(async move {
        loop {
            if let Err(error) =
                run_offer_side_effect_bridge(Arc::clone(&offer_side_effect_state)).await
            {
                tracing::error!(error = %error, "call offer side-effect bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let lifecycle_live_state = Arc::clone(&state);
    let lifecycle_live_handle = tokio::spawn(async move {
        loop {
            if let Err(error) = run_lifecycle_live_bridge(Arc::clone(&lifecycle_live_state)).await {
                tracing::error!(error = %error, "call lifecycle live bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let lifecycle_side_effect_handle = tokio::spawn(async move {
        loop {
            if let Err(error) = run_lifecycle_side_effect_bridge(Arc::clone(&state)).await {
                tracing::error!(error = %error, "call lifecycle side-effect bridge exited");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    vec![
        offer_live_handle,
        offer_side_effect_handle,
        lifecycle_live_handle,
        lifecycle_side_effect_handle,
    ]
}

async fn run_offer_live_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state.nats.subscribe("call.offer.*").await?;

    while let Some(message) = subscription.next().await {
        let recipient_id = message
            .subject
            .split('.')
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("missing recipient in call.offer subject"))?;

        let payload = match serde_json::from_slice::<CallOfferPayload>(&message.payload) {
            Ok(payload) => payload,
            Err(error) => {
                metrics::record_call_event_dropped("offer_invalid_json");
                tracing::warn!(error = %error, subject = %message.subject, "dropping malformed call offer payload");
                continue;
            }
        };

        if payload.call_id.is_empty()
            || payload.caller_id.is_empty()
            || payload.call_type.is_empty()
            || (payload.encrypted_sdp_payload.is_empty() && payload.sdp_offer.is_empty())
        {
            metrics::record_call_event_dropped("offer_invalid_payload");
            tracing::warn!(subject = %message.subject, "dropping incomplete call offer payload");
            continue;
        }

        let sdp_offer = match decode_optional_bytes(&payload.sdp_offer, "sdp_offer") {
            Ok(bytes) => bytes,
            Err(error) => {
                metrics::record_call_event_dropped("offer_invalid_base64");
                tracing::warn!(error = %error, subject = %message.subject, "dropping call offer with invalid SDP");
                continue;
            }
        };
        let srtp_key_params = match decode_optional_bytes(
            &payload.srtp_key_params,
            "srtp_key_params",
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                metrics::record_call_event_dropped("offer_invalid_base64");
                tracing::warn!(error = %error, subject = %message.subject, "dropping call offer with invalid SRTP params");
                continue;
            }
        };
        let encrypted_sdp_payload = match decode_optional_bytes(
            &payload.encrypted_sdp_payload,
            "encrypted_sdp_payload",
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                metrics::record_call_event_dropped("offer_invalid_base64");
                tracing::warn!(error = %error, subject = %message.subject, "dropping call offer with invalid encrypted SDP payload");
                continue;
            }
        };

        let call_id = payload.call_id.clone();
        let caller_id = payload.caller_id.clone();
        let call_type = payload.call_type.clone();

        let event = ServerEvent {
            event: Some(server_event::Event::CallOffer(CallOfferEvent {
                call_id,
                caller_id,
                call_type,
                sdp_offer,
                srtp_key_params,
                encrypted_sdp_payload,
            })),
        };

        let delivered = state
            .stream_mgr
            .send_to_user(recipient_id, event.clone())
            .await;
        if delivered == 0 {
            metrics::record_call_event_dropped("offer");
            tracing::warn!(recipient_id, call_id = %payload.call_id, "no live stream for call offer");
        } else {
            tracing::info!(recipient_id, call_id = %payload.call_id, delivered, "call offer delivered live");
        }
    }

    Err(anyhow::anyhow!("call offer live subscription ended"))
}

async fn run_offer_side_effect_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state
        .nats
        .queue_subscribe("call.offer.*", OFFER_SIDE_EFFECT_QUEUE.to_string())
        .await?;

    while let Some(message) = subscription.next().await {
        let recipient_id = message
            .subject
            .split('.')
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("missing recipient in call.offer subject"))?
            .to_string();

        let payload = match serde_json::from_slice::<CallOfferPayload>(&message.payload) {
            Ok(payload) => payload,
            Err(error) => {
                metrics::record_call_event_dropped("offer_invalid_json");
                tracing::warn!(error = %error, subject = %message.subject, "dropping malformed call offer side-effect payload");
                continue;
            }
        };

        if payload.call_id.is_empty()
            || payload.caller_id.is_empty()
            || payload.call_type.is_empty()
            || (payload.encrypted_sdp_payload.is_empty() && payload.sdp_offer.is_empty())
        {
            metrics::record_call_event_dropped("offer_invalid_payload");
            tracing::warn!(subject = %message.subject, "dropping incomplete call offer side-effect payload");
            continue;
        }

        let event = CallInboxEvent::Offer {
            call_id: payload.call_id.clone(),
            caller_id: payload.caller_id.clone(),
            call_type: payload.call_type.clone(),
            sdp_offer: payload.sdp_offer.clone(),
            srtp_key_params: payload.srtp_key_params.clone(),
            encrypted_sdp_payload: payload.encrypted_sdp_payload.clone(),
        };
        if let Err(error) =
            call_events::push_call_event(&state.redis, &recipient_id, &event, OFFER_REPLAY_TTL_SECS)
                .await
        {
            tracing::warn!(error = %error, recipient_id, call_id = %payload.call_id, "failed to persist call offer");
            continue;
        }
        tracing::info!(recipient_id, call_id = %payload.call_id, "call offer persisted for acked replay");

        schedule_voip_push_if_unacked(
            Arc::clone(&state),
            recipient_id,
            payload.call_id,
            payload.caller_id,
            payload.call_type,
        );
    }

    Err(anyhow::anyhow!("call offer side-effect subscription ended"))
}

async fn run_lifecycle_live_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state.nats.subscribe("call.lifecycle.*").await?;

    while let Some(message) = subscription.next().await {
        let user_id = message
            .subject
            .split('.')
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("missing user in call.lifecycle subject"))?;

        let payload = match serde_json::from_slice::<CallLifecyclePayload>(&message.payload) {
            Ok(payload) => payload,
            Err(error) => {
                metrics::record_call_event_dropped("lifecycle_invalid_json");
                tracing::warn!(error = %error, subject = %message.subject, "dropping malformed call lifecycle payload");
                continue;
            }
        };

        if payload.call_id.is_empty()
            || payload.peer_id.is_empty()
            || payload.event_type.is_empty()
            || payload.actor_id.is_empty()
        {
            metrics::record_call_event_dropped("lifecycle_invalid_payload");
            tracing::warn!(subject = %message.subject, "dropping incomplete call lifecycle payload");
            continue;
        }

        let call_id = payload.call_id.clone();
        let peer_id = payload.peer_id.clone();
        let event_type = payload.event_type.clone();
        let actor_id = payload.actor_id.clone();

        let event = ServerEvent {
            event: Some(server_event::Event::CallLifecycle(CallLifecycleEvent {
                call_id,
                peer_id,
                event_type,
                actor_id,
            })),
        };

        let delivered = state.stream_mgr.send_to_user(user_id, event.clone()).await;
        if delivered == 0 {
            metrics::record_call_event_dropped("lifecycle");
            tracing::warn!(user_id, call_id = %payload.call_id, event_type = %payload.event_type, "no live stream for call lifecycle");
        } else {
            tracing::info!(user_id, call_id = %payload.call_id, event_type = %payload.event_type, delivered, "call lifecycle delivered live");
        }
    }

    Err(anyhow::anyhow!("call lifecycle live subscription ended"))
}

async fn run_lifecycle_side_effect_bridge(state: Arc<AppState>) -> anyhow::Result<()> {
    let mut subscription = state
        .nats
        .queue_subscribe("call.lifecycle.*", LIFECYCLE_SIDE_EFFECT_QUEUE.to_string())
        .await?;

    while let Some(message) = subscription.next().await {
        let user_id = message
            .subject
            .split('.')
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("missing user in call.lifecycle subject"))?
            .to_string();

        let payload = match serde_json::from_slice::<CallLifecyclePayload>(&message.payload) {
            Ok(payload) => payload,
            Err(error) => {
                metrics::record_call_event_dropped("lifecycle_invalid_json");
                tracing::warn!(error = %error, subject = %message.subject, "dropping malformed call lifecycle side-effect payload");
                continue;
            }
        };

        if payload.call_id.is_empty()
            || payload.peer_id.is_empty()
            || payload.event_type.is_empty()
            || payload.actor_id.is_empty()
        {
            metrics::record_call_event_dropped("lifecycle_invalid_payload");
            tracing::warn!(subject = %message.subject, "dropping incomplete call lifecycle side-effect payload");
            continue;
        }

        if is_terminal_lifecycle(&payload.event_type) {
            let _ =
                call_events::evict_offer_for_call(&state.redis, &user_id, &payload.call_id).await;
        }

        let event = CallInboxEvent::Lifecycle {
            call_id: payload.call_id.clone(),
            peer_id: payload.peer_id.clone(),
            event_type: payload.event_type.clone(),
            actor_id: payload.actor_id.clone(),
        };
        if let Err(error) =
            call_events::push_call_event(&state.redis, &user_id, &event, LIFECYCLE_REPLAY_TTL_SECS)
                .await
        {
            tracing::warn!(error = %error, user_id, call_id = %payload.call_id, "failed to persist call lifecycle");
            continue;
        }
        tracing::info!(user_id, call_id = %payload.call_id, event_type = %payload.event_type, "call lifecycle persisted for acked replay");
    }

    Err(anyhow::anyhow!(
        "call lifecycle side-effect subscription ended"
    ))
}

fn is_terminal_lifecycle(event_type: &str) -> bool {
    matches!(
        event_type,
        "ended" | "declined" | "cancelled" | "busy" | "missed" | "failed"
    )
}

fn schedule_voip_push_if_unacked(
    state: Arc<AppState>,
    recipient_id: String,
    call_id: String,
    caller_id: String,
    call_type: String,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(VOIP_PUSH_GRACE_MS)).await;
        if !offer_still_pending(&state, &recipient_id, &call_id).await {
            return;
        }

        let Some(push_sender) = &state.push_sender else {
            tracing::debug!(
                recipient_id,
                call_id,
                "VoIP push skipped because APNs is not configured"
            );
            return;
        };
        let Ok(recipient_uuid) = recipient_id.parse::<uuid::Uuid>() else {
            tracing::warn!(
                recipient_id,
                call_id,
                "VoIP push skipped because recipient id is invalid"
            );
            return;
        };

        match sanchr_db::postgres::devices::list_user_voip_push_tokens(
            &state.pg_pool,
            &recipient_uuid,
        )
        .await
        {
            Ok(tokens) if !tokens.is_empty() => {
                let mut sent_count = 0usize;
                for token in &tokens {
                    if !offer_still_pending(&state, &recipient_id, &call_id).await {
                        tracing::info!(
                            recipient_id,
                            call_id,
                            sent_count,
                            "VoIP push stopped because call offer was acked or evicted"
                        );
                        return;
                    }
                    push_sender
                        .send_voip_push(token, &call_id, &caller_id, &call_type)
                        .await;
                    sent_count += 1;
                }
                tracing::info!(
                    recipient_id,
                    call_id,
                    token_count = sent_count,
                    "VoIP push sent for unacked incoming call offer"
                );
            }
            Ok(_) => {
                tracing::debug!(recipient_id, call_id, "no VoIP push tokens for recipient");
            }
            Err(error) => {
                tracing::error!(error = %error, recipient_id, call_id, "failed to query voip push tokens");
            }
        }
    });
}

async fn offer_still_pending(state: &AppState, recipient_id: &str, call_id: &str) -> bool {
    match call_events::has_call_event(&state.redis, recipient_id, call_id, "offer").await {
        Ok(true) => true,
        Ok(false) => {
            tracing::info!(
                recipient_id,
                call_id,
                "VoIP push skipped because call offer was acked or evicted"
            );
            false
        }
        Err(error) => {
            tracing::warn!(error = %error, recipient_id, call_id, "VoIP push skipped because ack state could not be checked");
            false
        }
    }
}

fn decode_bytes(raw: &str, field_name: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|error| anyhow::anyhow!("invalid {} base64: {}", field_name, error))
}

fn decode_optional_bytes(raw: &str, field_name: &str) -> anyhow::Result<Vec<u8>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    decode_bytes(raw, field_name)
}
