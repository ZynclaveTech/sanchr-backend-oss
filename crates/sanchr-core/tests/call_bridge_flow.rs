mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::time::timeout;
use uuid::Uuid;

use sanchr_proto::messaging::server_event;

async fn create_test_user(state: &Arc<sanchr_core::server::AppState>) -> (Uuid, i32) {
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, _) = common::register_and_verify_user(
        state,
        "Password123!",
        "test-device",
        "ios",
        Some(&installation_id),
    )
    .await;

    (auth.user.id, auth.device_id)
}

#[tokio::test]
async fn call_offer_events_reach_live_message_streams() {
    let state = common::setup_test_state().await;
    let (recipient_id, recipient_device) = create_test_user(&state).await;
    let caller_id = Uuid::new_v4();

    sanchr_core::messaging::call_bridge::spawn_call_event_bridges(Arc::clone(&state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut rx = state
        .stream_mgr
        .register(&recipient_id.to_string(), recipient_device)
        .await;

    let payload = serde_json::json!({
        "call_id": "call-offer-1",
        "caller_id": caller_id.to_string(),
        "call_type": "video",
        "encrypted_sdp_payload": base64::engine::general_purpose::STANDARD.encode(b"sealed-offer-sdp"),
    });

    state
        .nats
        .publish(
            format!("call.offer.{recipient_id}"),
            payload.to_string().into(),
        )
        .await
        .expect("failed to publish offer");
    state.nats.flush().await.expect("failed to flush NATS");

    let event = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for offer event")
        .expect("message stream closed unexpectedly");

    match event.event {
        Some(server_event::Event::CallOffer(offer)) => {
            assert_eq!(offer.call_id, "call-offer-1");
            assert_eq!(offer.caller_id, caller_id.to_string());
            assert_eq!(offer.call_type, "video");
            assert_eq!(offer.encrypted_sdp_payload, b"sealed-offer-sdp");
        }
        other => panic!("expected call offer event, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_call_offer_does_not_kill_bridge() {
    let state = common::setup_test_state().await;
    let (recipient_id, recipient_device) = create_test_user(&state).await;

    sanchr_core::messaging::call_bridge::spawn_call_event_bridges(Arc::clone(&state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut rx = state
        .stream_mgr
        .register(&recipient_id.to_string(), recipient_device)
        .await;

    state
        .nats
        .publish(
            format!("call.offer.{recipient_id}"),
            br#"{"call_id":"broken","caller_id":123}"#.as_slice().into(),
        )
        .await
        .expect("failed to publish malformed offer");

    let valid_payload = serde_json::json!({
        "call_id": "call-offer-after-invalid",
        "caller_id": Uuid::new_v4().to_string(),
        "call_type": "audio",
        "encrypted_sdp_payload": base64::engine::general_purpose::STANDARD.encode(b"sealed-offer-after-invalid"),
    });

    state
        .nats
        .publish(
            format!("call.offer.{recipient_id}"),
            valid_payload.to_string().into(),
        )
        .await
        .expect("failed to publish valid offer");
    state.nats.flush().await.expect("failed to flush NATS");

    let event = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for offer after malformed payload")
        .expect("message stream closed unexpectedly");

    match event.event {
        Some(server_event::Event::CallOffer(offer)) => {
            assert_eq!(offer.call_id, "call-offer-after-invalid");
            assert_eq!(offer.call_type, "audio");
            assert_eq!(offer.encrypted_sdp_payload, b"sealed-offer-after-invalid");
        }
        other => panic!("expected call offer event, got {other:?}"),
    }
}

#[tokio::test]
async fn call_lifecycle_events_reach_live_message_streams() {
    let state = common::setup_test_state().await;
    let (user_id, device_id) = create_test_user(&state).await;
    let peer_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();

    sanchr_core::messaging::call_bridge::spawn_call_event_bridges(Arc::clone(&state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut rx = state
        .stream_mgr
        .register(&user_id.to_string(), device_id)
        .await;

    let payload = serde_json::json!({
        "call_id": "call-lifecycle-1",
        "peer_id": peer_id.to_string(),
        "event_type": "ended",
        "actor_id": actor_id.to_string(),
    });

    state
        .nats
        .publish(
            format!("call.lifecycle.{user_id}"),
            payload.to_string().into(),
        )
        .await
        .expect("failed to publish lifecycle event");
    state.nats.flush().await.expect("failed to flush NATS");

    let event = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for lifecycle event")
        .expect("message stream closed unexpectedly");

    match event.event {
        Some(server_event::Event::CallLifecycle(lifecycle)) => {
            assert_eq!(lifecycle.call_id, "call-lifecycle-1");
            assert_eq!(lifecycle.peer_id, peer_id.to_string());
            assert_eq!(lifecycle.event_type, "ended");
            assert_eq!(lifecycle.actor_id, actor_id.to_string());
        }
        other => panic!("expected call lifecycle event, got {other:?}"),
    }
}
