mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::time::timeout;
use tonic::metadata::MetadataValue;
use tonic::Request;
use uuid::Uuid;

use sanchr_core::messaging::handlers::SendMessageParams;
use sanchr_core::messaging::stream::StreamManager;
use sanchr_db::redis::call_events;
use sanchr_db::scylla::messages as sc_messages;
use sanchr_proto::messaging::messaging_service_server::MessagingService as _;
use sanchr_proto::messaging::{server_event, AckedMessageRef, DeviceMessage, SendMessageRequest};

async fn create_test_user(
    state: &Arc<sanchr_core::server::AppState>,
    supports_delivery_ack: bool,
) -> (sanchr_core::auth::handlers::AuthResult, String) {
    let installation_id = format!("install-{}", Uuid::new_v4());
    common::register_and_verify_user_with_delivery_ack(
        state,
        "Password123!",
        "test-device",
        "ios",
        Some(&installation_id),
        supports_delivery_ack,
    )
    .await
}

async fn create_direct_conversation(
    state: &Arc<sanchr_core::server::AppState>,
    a: Uuid,
    b: Uuid,
) -> Uuid {
    sanchr_db::postgres::conversations::find_or_create_direct(&state.pg_pool, a, b)
        .await
        .expect("failed to create conversation")
        .id
}

fn build_send_message_request(
    conversation_id: Uuid,
    recipient_id: Uuid,
    recipient_device: i32,
    ciphertext: &[u8],
) -> SendMessageRequest {
    SendMessageRequest {
        conversation_id: conversation_id.to_string(),
        device_messages: vec![DeviceMessage {
            recipient_id: recipient_id.to_string(),
            device_id: recipient_device,
            ciphertext: ciphertext.to_vec(),
        }],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    }
}

fn authed_request(
    access_token: &str,
    idempotency_key: Option<&str>,
    req: SendMessageRequest,
) -> Request<SendMessageRequest> {
    let mut request = Request::new(req);
    let auth_value: MetadataValue<_> = format!("Bearer {access_token}")
        .parse()
        .expect("valid bearer metadata");
    request.metadata_mut().insert("authorization", auth_value);
    if let Some(key) = idempotency_key {
        request.metadata_mut().insert(
            "x-idempotency-key",
            key.parse().expect("valid idempotency metadata"),
        );
    }
    request
}

#[tokio::test]
async fn idempotent_send_retries_return_same_response_and_single_message_row() {
    let state = common::setup_test_state().await;
    let (sender_auth, _) = create_test_user(&state, true).await;
    let (recipient_auth, _) = create_test_user(&state, false).await;
    let conversation_id =
        create_direct_conversation(&state, sender_auth.user.id, recipient_auth.user.id).await;

    let service = sanchr_core::messaging::service::MessagingServiceImpl {
        state: Arc::clone(&state),
        stream_mgr: Arc::clone(&state.stream_mgr),
    };

    let idem_key = format!("idem-{}", Uuid::new_v4());

    let req_one = authed_request(
        &sender_auth.access_token,
        Some(&idem_key),
        build_send_message_request(
            conversation_id,
            recipient_auth.user.id,
            recipient_auth.device_id,
            b"hello-once",
        ),
    );

    let first = service
        .send_message(req_one)
        .await
        .expect("first send should succeed")
        .into_inner();

    let req_two = authed_request(
        &sender_auth.access_token,
        Some(&idem_key),
        build_send_message_request(
            conversation_id,
            recipient_auth.user.id,
            recipient_auth.device_id,
            b"hello-once",
        ),
    );

    let second = service
        .send_message(req_two)
        .await
        .expect("idempotent retry should succeed")
        .into_inner();

    assert_eq!(first.message_id, second.message_id);
    assert_eq!(first.server_timestamp, second.server_timestamp);

    let rows = sc_messages::get_messages(&state.scylla, conversation_id, 20)
        .await
        .expect("message query should succeed");
    assert_eq!(rows.len(), 1, "idempotent retry must not duplicate row");
}

#[tokio::test]
async fn relay_bridge_delivers_published_relay_payload_to_live_stream() {
    let state = common::setup_test_state().await;
    let (recipient_auth, _) = create_test_user(&state, false).await;

    sanchr_core::messaging::relay_bridge::spawn_message_relay_bridge(Arc::clone(&state));
    tokio::time::sleep(Duration::from_millis(120)).await;

    let mut rx = state
        .stream_mgr
        .register(
            &recipient_auth.user.id.to_string(),
            recipient_auth.device_id,
        )
        .await;

    let payload = sanchr_core::messaging::relay_payload::RelayEnvelope {
        conversation_id: Uuid::new_v4().to_string(),
        message_id: Uuid::new_v4().to_string(),
        sender_id: Uuid::new_v4().to_string(),
        sender_device: 1,
        ciphertext: b"relay-live".to_vec(),
        content_type: "text".to_string(),
        server_timestamp: chrono::Utc::now().timestamp_millis(),
    };

    state
        .nats
        .publish(
            format!(
                "msg.relay.{}.{}",
                recipient_auth.user.id, recipient_auth.device_id
            ),
            serde_json::to_vec(&payload)
                .expect("relay payload should serialize")
                .into(),
        )
        .await
        .expect("publish relay should succeed");
    state.nats.flush().await.expect("flush should succeed");

    let event = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for relayed event")
        .expect("stream unexpectedly closed");

    match event.event {
        Some(server_event::Event::Message(envelope)) => {
            assert_eq!(envelope.conversation_id, payload.conversation_id);
            assert_eq!(envelope.message_id, payload.message_id);
            assert_eq!(envelope.sender_id, payload.sender_id);
            assert_eq!(envelope.sender_device, payload.sender_device);
            assert_eq!(envelope.ciphertext, payload.ciphertext);
            assert_eq!(envelope.content_type, payload.content_type);
        }
        other => panic!("expected message event, got {other:?}"),
    }
}

#[tokio::test]
async fn missed_call_offer_is_queued_for_replay_and_drains_on_reconnect() {
    let state = common::setup_test_state().await;
    let (recipient_auth, _) = create_test_user(&state, false).await;

    sanchr_core::messaging::call_bridge::spawn_call_event_bridges(Arc::clone(&state));
    tokio::time::sleep(Duration::from_millis(120)).await;

    let payload = serde_json::json!({
        "call_id": "replay-call-1",
        "caller_id": Uuid::new_v4().to_string(),
        "call_type": "video",
        "encrypted_sdp_payload": base64::engine::general_purpose::STANDARD.encode(b"sealed-offer-replay"),
    });

    state
        .nats
        .publish(
            format!("call.offer.{}", recipient_auth.user.id),
            payload.to_string().into(),
        )
        .await
        .expect("failed to publish offer");
    state.nats.flush().await.expect("failed to flush nats");

    tokio::time::sleep(Duration::from_millis(120)).await;

    let replayed = call_events::peek_call_events(&state.redis, &recipient_auth.user.id.to_string())
        .await
        .expect("peek should succeed");

    assert_eq!(replayed.len(), 1);
    match &replayed[0] {
        call_events::CallInboxEvent::Offer {
            call_id,
            call_type,
            encrypted_sdp_payload,
            ..
        } => {
            assert_eq!(call_id, "replay-call-1");
            assert_eq!(call_type, "video");
            assert!(!encrypted_sdp_payload.is_empty());
        }
        other => panic!("expected queued offer event, got {other:?}"),
    }

    let replayed_again =
        call_events::peek_call_events(&state.redis, &recipient_auth.user.id.to_string())
            .await
            .expect("second peek should succeed");
    assert!(
        !replayed_again.is_empty(),
        "reconnect replay must not consume queued call events before ack"
    );

    call_events::ack_call_event(
        &state.redis,
        &recipient_auth.user.id.to_string(),
        "replay-call-1",
        "offer",
    )
    .await
    .expect("ack should succeed");

    let after_ack =
        call_events::peek_call_events(&state.redis, &recipient_auth.user.id.to_string())
            .await
            .expect("post-ack peek should succeed");
    assert!(after_ack.is_empty(), "ack should remove queued call event");
}

#[tokio::test]
async fn interrupted_sync_does_not_lose_legacy_pending_before_ack() {
    let state = common::setup_test_state().await;
    let (sender_auth, _) = create_test_user(&state, true).await;
    let (recipient_auth, _) = create_test_user(&state, false).await;
    let conversation_id =
        create_direct_conversation(&state, sender_auth.user.id, recipient_auth.user.id).await;

    let stream_mgr = StreamManager::new();
    let sent = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        SendMessageParams {
            sender_id: sender_auth.user.id,
            sender_device: sender_auth.device_id,
            conversation_id: conversation_id.to_string(),
            device_messages: vec![DeviceMessage {
                recipient_id: recipient_auth.user.id.to_string(),
                device_id: recipient_auth.device_id,
                ciphertext: b"legacy-safe".to_vec(),
            }],
            content_type: "text".to_string(),
            expires_after_secs: 0,
        },
    )
    .await
    .expect("send should succeed");

    // First sync receives row.
    let first = sanchr_core::messaging::handlers::handle_sync_messages(
        &state,
        recipient_auth.user.id,
        recipient_auth.device_id,
    )
    .await
    .expect("first sync should succeed");
    assert_eq!(first.len(), 1);

    // Simulate interrupted client before ack; second sync should still replay row.
    let second = sanchr_core::messaging::handlers::handle_sync_messages(
        &state,
        recipient_auth.user.id,
        recipient_auth.device_id,
    )
    .await
    .expect("second sync should succeed");
    assert_eq!(second.len(), 1);
    assert_eq!(first[0].message_id, second[0].message_id);

    // Ack and ensure row is removed.
    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &stream_mgr,
        recipient_auth.user.id,
        recipient_auth.device_id,
        vec![AckedMessageRef {
            conversation_id: conversation_id.to_string(),
            message_id: sent.message_id,
        }],
    )
    .await
    .expect("ack should succeed");

    let third = sanchr_core::messaging::handlers::handle_sync_messages(
        &state,
        recipient_auth.user.id,
        recipient_auth.device_id,
    )
    .await
    .expect("third sync should succeed");
    assert!(third.is_empty(), "pending should clear after ack");
}
