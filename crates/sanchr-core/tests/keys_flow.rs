mod common;

use sanchr_proto::keys::{KyberPreKey, OneTimePreKey, SignedPreKey};

async fn upload_full_bundle(
    state: &std::sync::Arc<sanchr_core::server::AppState>,
    user_id: uuid::Uuid,
    device_id: i32,
    registration_id: i32,
) {
    sanchr_core::keys::handlers::handle_upload_key_bundle(
        state,
        sanchr_core::keys::handlers::UploadKeyBundleParams {
            user_id,
            device_id,
            registration_id,
            identity_public_key: vec![1, 2, 3, 4],
            signed_pre_key: SignedPreKey {
                key_id: 11,
                public_key: vec![5, 6, 7],
                signature: vec![8, 9, 10],
                timestamp: 1_710_000_000_000,
            },
            kyber_pre_key: KyberPreKey {
                key_id: 22,
                public_key: vec![11, 12, 13],
                signature: vec![14, 15, 16],
                timestamp: 1_710_000_000_500,
            },
            one_time_pre_keys: vec![
                OneTimePreKey {
                    key_id: 31,
                    public_key: vec![17, 18, 19],
                },
                OneTimePreKey {
                    key_id: 32,
                    public_key: vec![20, 21, 22],
                },
            ],
        },
    )
    .await
    .expect("bundle upload should succeed");
}

#[tokio::test]
async fn full_bundle_upload_roundtrips_with_registration_and_kyber() {
    let state = common::setup_test_state().await;
    let installation_id = format!("install-{}", uuid::Uuid::new_v4());
    let (auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "ios-device",
        "ios",
        Some(&installation_id),
    )
    .await;

    upload_full_bundle(&state, auth.user.id, auth.device_id, 4242).await;

    let response = sanchr_core::keys::handlers::handle_get_pre_key_bundle(
        &state,
        &state.stream_mgr,
        auth.user.id,
        auth.device_id,
    )
    .await
    .expect("bundle fetch should succeed");

    assert_eq!(response.registration_id, 4242);
    assert_eq!(response.device_id, auth.device_id);
    assert!(response.signed_pre_key.is_some());
    assert!(response.kyber_pre_key.is_some());
    assert!(response.one_time_pre_key.is_some());
    assert_eq!(
        response.signed_pre_key.as_ref().map(|k| k.timestamp),
        Some(1_710_000_000_000)
    );
    assert_eq!(
        response.kyber_pre_key.as_ref().map(|k| k.timestamp),
        Some(1_710_000_000_500)
    );
}

#[tokio::test]
async fn get_user_devices_only_returns_complete_sendable_devices() {
    let state = common::setup_test_state().await;
    let (auth, phone) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device-a",
        "ios",
        Some(&format!("install-{}", uuid::Uuid::new_v4())),
    )
    .await;

    sanchr_core::auth::handlers::handle_verify_otp(
        &state,
        &phone,
        &sanchr_server_crypto::otp::generate_otp(
            &state.config.auth.otp_secret,
            &phone,
            chrono::Utc::now().timestamp(),
            state.config.auth.otp_ttl,
        )
        .expect("otp generation should succeed"),
        Some("device-b"),
        "ios",
        Some(&format!("install-{}", uuid::Uuid::new_v4())),
        false,
        "",
    )
    .await
    .expect("second device registration should succeed");

    let before = sanchr_core::keys::handlers::handle_get_user_devices(&state, auth.user.id)
        .await
        .expect("device list should load");
    assert!(
        before.is_empty(),
        "legacy/incomplete devices should be filtered"
    );

    upload_full_bundle(&state, auth.user.id, auth.device_id, 31337).await;

    let after = sanchr_core::keys::handlers::handle_get_user_devices(&state, auth.user.id)
        .await
        .expect("device list should load");

    assert_eq!(after.len(), 1);
    assert_eq!(after[0].device_id, auth.device_id);
    assert!(after[0].key_capable);
}

#[tokio::test]
async fn upload_key_bundle_rejects_missing_registration_or_kyber_material() {
    let state = common::setup_test_state().await;
    let installation_id = format!("install-{}", uuid::Uuid::new_v4());
    let (auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "ios-device",
        "ios",
        Some(&installation_id),
    )
    .await;

    let err = sanchr_core::keys::handlers::handle_upload_key_bundle(
        &state,
        sanchr_core::keys::handlers::UploadKeyBundleParams {
            user_id: auth.user.id,
            device_id: auth.device_id,
            registration_id: 0,
            identity_public_key: vec![1],
            signed_pre_key: SignedPreKey {
                key_id: 1,
                public_key: vec![2],
                signature: vec![3],
                timestamp: 1,
            },
            kyber_pre_key: KyberPreKey {
                key_id: 2,
                public_key: Vec::new(),
                signature: vec![4],
                timestamp: 1,
            },
            one_time_pre_keys: Vec::new(),
        },
    )
    .await
    .expect_err("invalid bundle should be rejected");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
