mod common;

use std::sync::Arc;
use uuid::Uuid;

use sanchr_core::messaging::handlers::SendMessageParams;
use sanchr_db::scylla::messages as sc_messages;
use sanchr_db::scylla::outbox as sc_outbox;

async fn create_test_user(state: &Arc<sanchr_core::server::AppState>) -> (Uuid, String, i32) {
    create_test_user_with_delivery_ack(state, false).await
}

async fn create_test_user_with_delivery_ack(
    state: &Arc<sanchr_core::server::AppState>,
    supports_delivery_ack: bool,
) -> (Uuid, String, i32) {
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, phone) = common::register_and_verify_user_with_delivery_ack(
        state,
        "Password123!",
        "test-device",
        "ios",
        Some(&installation_id),
        supports_delivery_ack,
    )
    .await;

    (auth.user.id, phone, auth.device_id)
}

async fn create_conversation(
    state: &Arc<sanchr_core::server::AppState>,
    user_a: Uuid,
    user_b: Uuid,
) -> Uuid {
    let conv =
        sanchr_db::postgres::conversations::find_or_create_direct(&state.pg_pool, user_a, user_b)
            .await
            .expect("failed to create conversation");
    conv.id
}

fn send_params(
    sender_id: Uuid,
    sender_device: i32,
    conv_id: Uuid,
    recipient_id: Uuid,
    recipient_device: i32,
    ciphertext: &[u8],
) -> SendMessageParams {
    SendMessageParams {
        sender_id,
        sender_device,
        conversation_id: conv_id.to_string(),
        device_messages: vec![sanchr_proto::messaging::DeviceMessage {
            recipient_id: recipient_id.to_string(),
            device_id: recipient_device,
            ciphertext: ciphertext.to_vec(),
        }],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    }
}

#[tokio::test]
async fn send_message_to_valid_conversation() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();

    let result = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            user_b_device,
            b"encrypted-content",
        ),
    )
    .await;

    assert!(result.is_ok(), "send should succeed: {:?}", result.err());
    let msg = result.unwrap();
    assert!(!msg.message_id.is_empty());
    assert!(msg.server_timestamp > 0);
}

#[tokio::test]
async fn send_message_non_member_rejected() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, _) = create_test_user(&state).await;
    let (user_c, _, user_c_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();

    let result = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_c,
            user_c_device,
            conv_id,
            user_a,
            user_a_device,
            b"hacked",
        ),
    )
    .await;

    assert!(result.is_err(), "non-member should be rejected");
    let err = match result {
        Err(error) => error,
        Ok(_) => panic!("expected an error but got Ok"),
    };
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn send_message_duplicate_target_rejected() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let params = SendMessageParams {
        sender_id: user_a,
        sender_device: user_a_device,
        conversation_id: conv_id.to_string(),
        device_messages: vec![
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: user_b_device,
                ciphertext: b"first".to_vec(),
            },
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: user_b_device,
                ciphertext: b"second".to_vec(),
            },
        ],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    };

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let result =
        sanchr_core::messaging::handlers::handle_send_message(&state, &stream_mgr, params).await;

    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("duplicate targets should be rejected"),
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn send_message_foreign_device_rejected() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;
    let nonexistent_device = user_b_device + 100;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let result = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            nonexistent_device,
            b"wrong-device",
        ),
    )
    .await;

    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("foreign device should be rejected"),
    };
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn pending_messages_queued_for_offline_device() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();

    sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            user_b_device,
            b"offline-message",
        ),
    )
    .await
    .expect("send should succeed");

    let synced =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, user_b_device)
            .await
            .expect("sync should succeed");

    assert!(!synced.is_empty());
    assert_eq!(synced[0].conversation_id, conv_id.to_string());
}

#[tokio::test]
async fn ack_capable_device_outbox_persists_until_ack_even_when_connected() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user_with_delivery_ack(&state, true).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let mut rx = stream_mgr
        .register(&user_b.to_string(), user_b_device)
        .await;

    let sent = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            user_b_device,
            b"durable-live-message",
        ),
    )
    .await
    .expect("send should succeed");

    let live_event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("live event should arrive")
        .expect("stream should yield an event");
    assert!(matches!(
        live_event.event,
        Some(sanchr_proto::messaging::server_event::Event::Message(_))
    ));

    let outbox_rows = sc_outbox::get_outbox_messages(&state.scylla, user_b, user_b_device)
        .await
        .expect("outbox query should succeed");
    assert_eq!(
        outbox_rows.len(),
        1,
        "connected ack-capable device should still retain outbox row"
    );

    let replayed =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, user_b_device)
            .await
            .expect("sync should replay durable outbox");
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].message_id, sent.message_id);

    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &stream_mgr,
        user_b,
        user_b_device,
        vec![sanchr_proto::messaging::AckedMessageRef {
            conversation_id: conv_id.to_string(),
            message_id: sent.message_id.clone(),
        }],
    )
    .await
    .expect("ack should succeed");

    let remaining = sc_outbox::get_outbox_messages(&state.scylla, user_b, user_b_device)
        .await
        .expect("outbox query should succeed");
    assert!(
        remaining.is_empty(),
        "ack should delete the device outbox row"
    );
}

#[tokio::test]
async fn ack_deletes_only_authenticated_device_row() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, phone_b, device_one) = create_test_user_with_delivery_ack(&state, true).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let device_two_auth = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone_b,
        "Password123!",
        Some("second-device"),
        "ios",
        Some("ack-device-two"),
        true,
        "",
    )
    .await
    .expect("second ack-capable login should succeed");
    let device_two = device_two_auth.device_id;

    let params = SendMessageParams {
        sender_id: user_a,
        sender_device: user_a_device,
        conversation_id: conv_id.to_string(),
        device_messages: vec![
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: device_one,
                ciphertext: b"device-one-copy".to_vec(),
            },
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: device_two,
                ciphertext: b"device-two-copy".to_vec(),
            },
        ],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    };

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let sent = sanchr_core::messaging::handlers::handle_send_message(&state, &stream_mgr, params)
        .await
        .expect("send should succeed");

    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &stream_mgr,
        user_b,
        device_one,
        vec![sanchr_proto::messaging::AckedMessageRef {
            conversation_id: conv_id.to_string(),
            message_id: sent.message_id.clone(),
        }],
    )
    .await
    .expect("first device ack should succeed");

    let device_one_rows = sc_outbox::get_outbox_messages(&state.scylla, user_b, device_one)
        .await
        .expect("device one outbox query should succeed");
    let device_two_rows = sc_outbox::get_outbox_messages(&state.scylla, user_b, device_two)
        .await
        .expect("device two outbox query should succeed");

    assert!(device_one_rows.is_empty());
    assert_eq!(
        device_two_rows.len(),
        1,
        "sibling device row must remain until that device acks"
    );
}

#[tokio::test]
async fn mixed_version_devices_use_outbox_and_legacy_pending_paths() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, phone_b, legacy_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let ack_device_auth = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone_b,
        "Password123!",
        Some("ack-device"),
        "ios",
        Some("ack-capable-device"),
        true,
        "",
    )
    .await
    .expect("ack-capable login should succeed");
    let ack_device = ack_device_auth.device_id;

    let params = SendMessageParams {
        sender_id: user_a,
        sender_device: user_a_device,
        conversation_id: conv_id.to_string(),
        device_messages: vec![
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: legacy_device,
                ciphertext: b"legacy-copy".to_vec(),
            },
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: ack_device,
                ciphertext: b"ack-copy".to_vec(),
            },
        ],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    };

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let sent = sanchr_core::messaging::handlers::handle_send_message(&state, &stream_mgr, params)
        .await
        .expect("send should succeed");

    let legacy_first =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, legacy_device)
            .await
            .expect("legacy sync should succeed");
    let legacy_second =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, legacy_device)
            .await
            .expect("legacy re-sync should succeed");

    assert_eq!(legacy_first.len(), 1);
    assert_eq!(
        legacy_second.len(),
        1,
        "legacy path should replay until explicit ack to avoid loss on interrupted sync"
    );

    // Ack legacy-delivered message, then ensure it is removed.
    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &stream_mgr,
        user_b,
        legacy_device,
        vec![sanchr_proto::messaging::AckedMessageRef {
            conversation_id: conv_id.to_string(),
            message_id: sent.message_id.clone(),
        }],
    )
    .await
    .expect("legacy ack should succeed");

    let legacy_after_ack =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, legacy_device)
            .await
            .expect("legacy sync after ack should succeed");
    assert!(
        legacy_after_ack.is_empty(),
        "legacy row should clear after ack"
    );

    let ack_first =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, ack_device)
            .await
            .expect("ack-capable sync should succeed");
    let ack_second =
        sanchr_core::messaging::handlers::handle_sync_messages(&state, user_b, ack_device)
            .await
            .expect("ack-capable re-sync should succeed");

    assert_eq!(ack_first.len(), 1);
    assert_eq!(
        ack_second.len(),
        1,
        "ack-capable path should replay until acked"
    );
    assert_eq!(ack_second[0].message_id, sent.message_id);
}

#[tokio::test]
async fn delivered_transition_emits_once_and_does_not_override_read() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, phone_b, device_one) = create_test_user_with_delivery_ack(&state, true).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let device_two_auth = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone_b,
        "Password123!",
        Some("second-device"),
        "ios",
        Some("delivered-device-two"),
        true,
        "",
    )
    .await
    .expect("second ack-capable login should succeed");
    let device_two = device_two_auth.device_id;

    let sender_stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let mut sender_rx = sender_stream_mgr
        .register(&user_a.to_string(), user_a_device)
        .await;

    let params = SendMessageParams {
        sender_id: user_a,
        sender_device: user_a_device,
        conversation_id: conv_id.to_string(),
        device_messages: vec![
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: device_one,
                ciphertext: b"device-one".to_vec(),
            },
            sanchr_proto::messaging::DeviceMessage {
                recipient_id: user_b.to_string(),
                device_id: device_two,
                ciphertext: b"device-two".to_vec(),
            },
        ],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    };

    let sent =
        sanchr_core::messaging::handlers::handle_send_message(&state, &sender_stream_mgr, params)
            .await
            .expect("send should succeed");

    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &sender_stream_mgr,
        user_b,
        device_one,
        vec![sanchr_proto::messaging::AckedMessageRef {
            conversation_id: conv_id.to_string(),
            message_id: sent.message_id.clone(),
        }],
    )
    .await
    .expect("first ack should succeed");

    let delivered_event = tokio::time::timeout(std::time::Duration::from_secs(2), sender_rx.recv())
        .await
        .expect("sender should receive delivered update")
        .expect("sender stream should yield receipt event");
    let receipt = match delivered_event.event {
        Some(sanchr_proto::messaging::server_event::Event::Receipt(receipt)) => receipt,
        other => panic!("expected receipt event, got {:?}", other),
    };
    assert_eq!(receipt.status, "delivered");

    sanchr_core::messaging::handlers::handle_ack_messages(
        &state,
        &sender_stream_mgr,
        user_b,
        device_two,
        vec![sanchr_proto::messaging::AckedMessageRef {
            conversation_id: conv_id.to_string(),
            message_id: sent.message_id.clone(),
        }],
    )
    .await
    .expect("second ack should succeed");

    let duplicate =
        tokio::time::timeout(std::time::Duration::from_millis(250), sender_rx.recv()).await;
    assert!(
        duplicate.is_err(),
        "second device ack must not emit duplicate delivered update"
    );
    // Read receipts are now sent sealed-sender client-to-client (Sub-phase 5);
    // server-side handle_send_receipt was removed. Delivery-only path tested above.
}

#[tokio::test]
async fn online_device_receives_via_stream() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let mut rx = stream_mgr
        .register(&user_b.to_string(), user_b_device)
        .await;

    sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            user_b_device,
            b"live-message",
        ),
    )
    .await
    .expect("send should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("should receive within timeout");

    assert!(event.is_some());
}

// send_receipt_updates_status and receipt_from_non_member_rejected were removed
// in Sub-phase 5 (Sealed Receipts): handle_send_receipt no longer exists.
// Read receipts are now sent sealed-sender client-to-client with 0-30 s jitter.

#[tokio::test]
async fn get_conversations_returns_user_conversations() {
    let state = common::setup_test_state().await;
    let (user_a, _, _) = create_test_user(&state).await;
    let (user_b, _, _) = create_test_user(&state).await;

    let conv_id = create_conversation(&state, user_a, user_b).await;

    let conversations = sanchr_core::messaging::handlers::handle_get_conversations(&state, user_a)
        .await
        .expect("should get conversations");

    assert!(!conversations.is_empty());
    assert!(conversations.iter().any(|c| c.id == conv_id.to_string()));
}

#[tokio::test]
async fn delete_message_hard_deletes_for_sender_only() {
    let state = common::setup_test_state().await;
    let (user_a, _, user_a_device) = create_test_user(&state).await;
    let (user_b, _, user_b_device) = create_test_user(&state).await;
    let conv_id = create_conversation(&state, user_a, user_b).await;

    let stream_mgr = sanchr_core::messaging::stream::StreamManager::new();
    let msg = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &stream_mgr,
        send_params(
            user_a,
            user_a_device,
            conv_id,
            user_b,
            user_b_device,
            b"delete-me",
        ),
    )
    .await
    .unwrap();

    let forbidden = sanchr_core::messaging::handlers::handle_delete_message(
        &state,
        user_b,
        &conv_id.to_string(),
        &msg.message_id,
    )
    .await;
    assert!(forbidden.is_err());
    assert_eq!(forbidden.unwrap_err().code(), tonic::Code::PermissionDenied);

    sanchr_core::messaging::handlers::handle_delete_message(
        &state,
        user_a,
        &conv_id.to_string(),
        &msg.message_id,
    )
    .await
    .expect("sender delete should succeed");

    let deleted = sc_messages::get_message(
        &state.scylla,
        conv_id,
        scylla::frame::value::CqlTimeuuid::from(msg.message_id.parse::<Uuid>().unwrap()),
    )
    .await
    .expect("scylla get should succeed");

    assert!(deleted.is_none(), "message should be hard deleted");
}
