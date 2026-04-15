mod common;

use std::sync::Arc;

use sanchr_db::postgres::{pending_registrations, users};
use tokio::sync::Barrier;

#[tokio::test]
async fn register_creates_pending_registration_and_no_verified_user() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();
    let name = common::unique_name();

    let result =
        sanchr_core::auth::handlers::handle_register(&state, &phone, &name, "Password123!", None)
            .await
            .expect("registration should succeed");

    assert!(result.user.is_none());
    assert!(
        pending_registrations::get_pending_registration(&state.pg_pool, &phone)
            .await
            .unwrap()
            .is_some()
    );
    assert!(users::find_by_phone(&state.pg_pool, &phone)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn register_then_verify_otp_returns_tokens_and_creates_verified_user() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();
    let name = common::unique_name();

    sanchr_core::auth::handlers::handle_register(&state, &phone, &name, "Password123!", None)
        .await
        .expect("registration failed");

    let now = chrono::Utc::now().timestamp();
    let otp = sanchr_server_crypto::otp::generate_otp(
        &state.config.auth.otp_secret,
        &phone,
        now,
        state.config.auth.otp_ttl,
    )
    .expect("otp generation failed");

    let auth = sanchr_core::auth::handlers::handle_verify_otp(
        &state,
        &phone,
        &otp,
        Some("test-device"),
        "ios",
        Some("install-verify"),
        false,
        "",
    )
    .await
    .expect("OTP verification failed");

    assert!(!auth.access_token.is_empty());
    assert!(!auth.refresh_token.is_empty());
    assert_eq!(auth.user.phone_number, phone);
    assert!(
        pending_registrations::get_pending_registration(&state.pg_pool, &phone)
            .await
            .unwrap()
            .is_none()
    );
    assert!(users::find_by_phone(&state.pg_pool, &phone)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn login_with_correct_password_succeeds() {
    let state = common::setup_test_state().await;
    let (verified, phone) = common::register_and_verify_user(
        &state,
        "StrongPass123!",
        "device-1",
        "ios",
        Some("install-login-1"),
    )
    .await;

    let auth = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone,
        "StrongPass123!",
        Some("device-2"),
        "android",
        Some("install-login-2"),
        false,
        "",
    )
    .await
    .expect("login should succeed");

    assert!(!auth.access_token.is_empty());
    assert_eq!(auth.user.id, verified.user.id);
}

#[tokio::test]
async fn login_with_wrong_password_fails() {
    let state = common::setup_test_state().await;
    let (_auth, phone) = common::register_and_verify_user(
        &state,
        "CorrectPass1!",
        "device-1",
        "ios",
        Some("install-wrong-password"),
    )
    .await;

    let result = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone,
        "WrongPassword!",
        Some("device"),
        "ios",
        None,
        false,
        "",
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn refresh_token_rotation_works() {
    let state = common::setup_test_state().await;
    let (auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device",
        "ios",
        Some("install-refresh"),
    )
    .await;

    let refreshed = sanchr_core::auth::handlers::handle_refresh_token(&state, &auth.refresh_token)
        .await
        .expect("refresh should succeed");

    assert!(!refreshed.access_token.is_empty());
    assert_ne!(refreshed.access_token, auth.access_token);
    assert_ne!(refreshed.refresh_token, auth.refresh_token);
}

#[tokio::test]
async fn old_refresh_token_rejected_after_rotation() {
    let state = common::setup_test_state().await;
    let (auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device",
        "ios",
        Some("install-rotation"),
    )
    .await;

    let old_refresh = auth.refresh_token.clone();

    sanchr_core::auth::handlers::handle_refresh_token(&state, &old_refresh)
        .await
        .unwrap();

    let result = sanchr_core::auth::handlers::handle_refresh_token(&state, &old_refresh).await;
    assert!(result.is_err(), "old refresh token should be rejected");
}

#[tokio::test]
async fn duplicate_registration_for_verified_user_returns_generic_response() {
    let state = common::setup_test_state().await;
    let (_auth, phone) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device",
        "ios",
        Some("install-duplicate"),
    )
    .await;

    let result = sanchr_core::auth::handlers::handle_register(
        &state,
        &phone,
        "Second",
        "Password456!",
        None,
    )
    .await
    .expect("duplicate register should not error");

    assert!(result.user.is_none());
    assert!(
        pending_registrations::get_pending_registration(&state.pg_pool, &phone)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn same_installation_id_reuses_device_id() {
    let state = common::setup_test_state().await;
    let (verified, phone) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device",
        "ios",
        Some("stable-installation"),
    )
    .await;

    let reused = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone,
        "Password123!",
        Some("device"),
        "ios",
        Some("stable-installation"),
        false,
        "",
    )
    .await
    .expect("login with same installation_id should succeed");

    let fresh = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone,
        "Password123!",
        Some("device"),
        "ios",
        Some("new-installation"),
        false,
        "",
    )
    .await
    .expect("login with new installation_id should succeed");

    assert_eq!(verified.device_id, reused.device_id);
    assert_ne!(verified.device_id, fresh.device_id);
}

#[tokio::test]
async fn rate_limiting_blocks_excessive_requests() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();

    for _ in 0..5 {
        let _ = sanchr_core::auth::handlers::handle_login(
            &state,
            &phone,
            "wrong",
            Some("device"),
            "ios",
            None,
            false,
            "",
        )
        .await;
    }

    let result = sanchr_core::auth::handlers::handle_login(
        &state,
        &phone,
        "wrong",
        Some("device"),
        "ios",
        None,
        false,
        "",
    )
    .await;

    assert!(result.is_err());
    let err_str = format!("{:?}", result.err().unwrap());
    assert!(
        err_str.contains("RateLimited") || err_str.contains("rate"),
        "should be rate limited, got: {}",
        err_str
    );
}

#[tokio::test]
async fn concurrent_new_installations_get_distinct_device_ids() {
    let state = common::setup_test_state().await;
    let (_auth, phone) = common::register_and_verify_user(
        &state,
        "Password123!",
        "device",
        "ios",
        Some("install-concurrency-base"),
    )
    .await;

    let barrier = Arc::new(Barrier::new(5));
    let mut tasks = Vec::new();

    for idx in 0..4 {
        let state = Arc::clone(&state);
        let phone = phone.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let auth = sanchr_core::auth::handlers::handle_login(
                &state,
                &phone,
                "Password123!",
                Some("parallel-device"),
                "ios",
                Some(&format!("parallel-installation-{idx}")),
                false,
                "",
            )
            .await
            .expect("concurrent login should succeed");
            auth.device_id
        }));
    }

    barrier.wait().await;

    let mut device_ids = Vec::new();
    for task in tasks {
        device_ids.push(task.await.expect("task should not panic"));
    }

    let unique_ids: std::collections::HashSet<_> = device_ids.iter().copied().collect();
    assert_eq!(unique_ids.len(), device_ids.len());
}
