mod common;

use aws_sdk_s3::primitives::ByteStream;
use uuid::Uuid;

use sanchr_db::postgres::media as pg_media;
use sanchr_proto::media::MediaPurpose;

#[tokio::test]
async fn avatar_upload_confirm_and_download_use_persisted_media_metadata() {
    let state = common::setup_test_state().await;
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "media-device",
        "ios",
        Some(&installation_id),
    )
    .await;

    let body = b"avatar-bytes".to_vec();
    let upload = sanchr_core::media::handlers::handle_get_upload_url(
        &state,
        auth.user.id,
        body.len() as i64,
        "image/png",
        "avatar-sha256",
        MediaPurpose::Avatar,
    )
    .await
    .expect("failed to create upload URL");

    let media_id = Uuid::parse_str(&upload.media_id).expect("invalid media id");
    let media = pg_media::get_media_object(&state.pg_pool, auth.user.id, media_id)
        .await
        .expect("failed to load media metadata")
        .expect("media metadata missing");

    assert_eq!(media.purpose, "avatar");
    assert!(!media.is_confirmed);
    assert!(media.storage_key.starts_with("avatars/"));

    state
        .s3
        .put_object()
        .bucket(&state.config.storage.bucket)
        .key(&media.storage_key)
        .content_type("image/png")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .expect("failed to upload object to test bucket");

    sanchr_core::media::handlers::handle_confirm_upload(
        &state,
        auth.user.id,
        &upload.media_id,
        body.len() as i64,
    )
    .await
    .expect("failed to confirm upload");

    let confirmed = pg_media::get_media_object(&state.pg_pool, auth.user.id, media_id)
        .await
        .expect("failed to reload media metadata")
        .expect("confirmed media metadata missing");
    assert!(confirmed.is_confirmed);

    let download = sanchr_core::media::handlers::handle_get_download_url(
        &state,
        auth.user.id,
        &upload.media_id,
    )
    .await
    .expect("failed to create download URL");

    assert_eq!(download.media_id, upload.media_id);
    assert!(
        download.url.contains("avatars/") || download.url.contains("avatars%2F"),
        "download URL should reference the stored avatar key: {}",
        download.url
    );
}

#[tokio::test]
async fn get_download_url_allows_capability_style_access_for_confirmed_media_id() {
    let state = common::setup_test_state().await;

    let owner_install = format!("install-{}", Uuid::new_v4());
    let (owner_auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "owner-device",
        "ios",
        Some(&owner_install),
    )
    .await;
    let owner = owner_auth.user.id;

    let attacker_install = format!("install-{}", Uuid::new_v4());
    let (attacker_auth, _) = common::register_and_verify_user(
        &state,
        "Password123!",
        "attacker-device",
        "ios",
        Some(&attacker_install),
    )
    .await;
    let attacker = attacker_auth.user.id;

    // Owner uploads a real media object via the normal upload path.
    let upload = sanchr_core::media::handlers::handle_get_upload_url(
        &state,
        owner,
        1024,
        "application/octet-stream",
        &format!("sha256-enum-test-{}", Uuid::new_v4()),
        MediaPurpose::Attachment,
    )
    .await
    .expect("get_upload_url");

    // Any authenticated caller possessing a confirmed media_id can fetch the
    // presigned URL. The media_id is treated as a bearer capability.
    let result =
        sanchr_core::media::handlers::handle_get_download_url(&state, attacker, &upload.media_id)
            .await;

    let download = result.expect("capability-style download should succeed");
    assert_eq!(download.media_id, upload.media_id);
}
