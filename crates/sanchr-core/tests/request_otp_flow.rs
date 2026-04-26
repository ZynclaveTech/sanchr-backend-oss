mod common;

use sanchr_db::postgres::{pending_registrations, users};

#[tokio::test]
async fn request_otp_new_phone_creates_pending_registration_with_defaults() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();

    let result = sanchr_core::auth::handlers::handle_request_otp(&state, &phone)
        .await
        .expect("request_otp should succeed for a new phone");

    assert!(!result.existing_user, "new phone must report existing_user=false");
    assert!(
        result.expires_in_seconds > 0,
        "expires_in_seconds must be positive"
    );

    let pending = pending_registrations::get_pending_registration(&state.pg_pool, &phone)
        .await
        .unwrap()
        .expect("pending_registrations row should exist");

    assert_eq!(pending.display_name, "Sanchr User");
    assert!(pending.email.is_none());
    assert!(
        !pending.password_hash.is_empty(),
        "password_hash must be populated to satisfy NOT NULL"
    );
    assert!(
        pending.password_hash.starts_with("$argon2"),
        "password_hash should be an argon2 PHC string"
    );

    assert!(users::find_by_phone(&state.pg_pool, &phone)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn request_otp_existing_phone_returns_existing_user_true_and_does_not_modify_user() {
    let state = common::setup_test_state().await;
    let (verified, phone) = common::register_and_verify_user(
        &state,
        "OriginalPass1!",
        "device",
        "ios",
        Some("install-request-otp-existing"),
    )
    .await;

    let before = users::find_by_phone(&state.pg_pool, &phone)
        .await
        .unwrap()
        .expect("verified user should exist");

    let result = sanchr_core::auth::handlers::handle_request_otp(&state, &phone)
        .await
        .expect("request_otp should succeed for existing phone");

    assert!(result.existing_user, "existing phone must report existing_user=true");
    assert!(result.expires_in_seconds > 0);

    let after = users::find_by_phone(&state.pg_pool, &phone)
        .await
        .unwrap()
        .expect("user should still exist");

    assert_eq!(before.id, verified.user.id);
    assert_eq!(before.id, after.id);
    assert_eq!(before.display_name, after.display_name);
    assert_eq!(before.password_hash, after.password_hash);

    // No pending_registrations row should be left behind for an already
    // verified user — the OTP is for login, not registration.
    assert!(
        pending_registrations::get_pending_registration(&state.pg_pool, &phone)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn request_otp_then_verify_otp_succeeds_for_new_user() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();

    let issued = sanchr_core::auth::handlers::handle_request_otp(&state, &phone)
        .await
        .expect("request_otp should succeed");
    assert!(!issued.existing_user);

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
        Some("install-request-otp-verify"),
        false,
        "",
    )
    .await
    .expect("verify_otp should promote pending registration to user");

    assert!(!auth.access_token.is_empty());
    assert!(!auth.refresh_token.is_empty());
    assert_eq!(auth.user.phone_number, phone);
    assert_eq!(
        auth.user.display_name, "Sanchr User",
        "verified user inherits the placeholder until UpdateProfile runs"
    );

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
async fn request_otp_rate_limited() {
    let state = common::setup_test_state().await;
    let phone = common::unique_phone();

    for _ in 0..5 {
        sanchr_core::auth::handlers::handle_request_otp(&state, &phone)
            .await
            .expect("request_otp under the limit should succeed");
    }

    let blocked = sanchr_core::auth::handlers::handle_request_otp(&state, &phone).await;
    assert!(blocked.is_err(), "6th call must be rate limited");
    let err_str = format!("{:?}", blocked.err().unwrap());
    assert!(
        err_str.contains("RateLimited") || err_str.contains("rate"),
        "expected rate-limit error, got: {}",
        err_str
    );
}

#[tokio::test]
async fn request_otp_invalid_phone_format() {
    let state = common::setup_test_state().await;

    let missing_plus =
        sanchr_core::auth::handlers::handle_request_otp(&state, "15550001234").await;
    assert!(missing_plus.is_err());
    let err_str = format!("{:?}", missing_plus.err().unwrap());
    assert!(
        err_str.contains("InvalidInput"),
        "expected InvalidInput, got: {}",
        err_str
    );

    let too_short = sanchr_core::auth::handlers::handle_request_otp(&state, "+123").await;
    assert!(too_short.is_err());

    let empty = sanchr_core::auth::handlers::handle_request_otp(&state, "").await;
    assert!(empty.is_err());
}
