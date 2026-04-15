mod common;

use std::sync::Arc;
use uuid::Uuid;

async fn create_test_user(state: &Arc<sanchr_core::server::AppState>) -> (Uuid, String) {
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, phone) = common::register_and_verify_user(
        state,
        "Password123!",
        "test-device",
        "ios",
        Some(&installation_id),
    )
    .await;
    (auth.user.id, phone)
}

// ── Contact Tests ─────────────────────────────────────────────────

#[tokio::test]
async fn sync_contacts_finds_registered_users() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;
    let (user_b, phone_b) = create_test_user(&state).await;

    // Hash user_b's phone number (as the client would)
    let hash_b = sanchr_db::postgres::users::hash_phone(&phone_b);

    // User A syncs contacts with user B's hash
    let matched =
        sanchr_core::contacts::handlers::handle_sync_contacts(&state, user_a, vec![hash_b])
            .await
            .expect("sync should succeed");

    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].user_id, user_b.to_string());
}

#[tokio::test]
async fn sync_contacts_unregistered_phone_not_matched() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;

    let fake_hash = sanchr_db::postgres::users::hash_phone("+19999999999");

    let matched =
        sanchr_core::contacts::handlers::handle_sync_contacts(&state, user_a, vec![fake_hash])
            .await
            .expect("sync should succeed");

    assert!(matched.is_empty());
}

#[tokio::test]
async fn block_and_unblock_contact() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;
    let (user_b, phone_b) = create_test_user(&state).await;

    // Sync to add as contact first
    let hash_b = sanchr_db::postgres::users::hash_phone(&phone_b);
    sanchr_core::contacts::handlers::handle_sync_contacts(&state, user_a, vec![hash_b])
        .await
        .unwrap();

    // Block
    sanchr_core::contacts::handlers::handle_block_contact(&state, user_a, user_b)
        .await
        .expect("block should succeed");

    let blocked = sanchr_core::contacts::handlers::handle_get_blocked_list(&state, user_a)
        .await
        .expect("get blocked should succeed");
    assert!(blocked.contains(&user_b.to_string()));

    // Unblock
    sanchr_core::contacts::handlers::handle_unblock_contact(&state, user_a, user_b)
        .await
        .expect("unblock should succeed");

    let blocked_after = sanchr_core::contacts::handlers::handle_get_blocked_list(&state, user_a)
        .await
        .unwrap();
    assert!(!blocked_after.contains(&user_b.to_string()));
}

#[tokio::test]
async fn get_contacts_returns_synced_users() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;
    let (_, phone_b) = create_test_user(&state).await;

    let hash_b = sanchr_db::postgres::users::hash_phone(&phone_b);
    sanchr_core::contacts::handlers::handle_sync_contacts(&state, user_a, vec![hash_b])
        .await
        .unwrap();

    let contacts = sanchr_core::contacts::handlers::handle_get_contacts(&state, user_a)
        .await
        .expect("get contacts should succeed");

    assert!(!contacts.is_empty());
}

// ── Settings Tests ────────────────────────────────────────────────

#[tokio::test]
async fn get_settings_returns_defaults() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;

    let settings = sanchr_core::settings::handlers::handle_get_settings(&state, user_a)
        .await
        .expect("get settings should succeed");

    // Default settings: read_receipts defaults to true, sanchr_mode_enabled defaults to false
    assert!(settings.read_receipts);
    assert!(!settings.sanchr_mode_enabled);
}

#[tokio::test]
async fn toggle_sanchr_mode_on_and_off() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;

    // Enable Sanchr Mode
    let settings = sanchr_core::settings::handlers::handle_toggle_sanchr_mode(&state, user_a, true)
        .await
        .expect("enable sanchr mode should succeed");

    assert!(settings.sanchr_mode_enabled);
    assert!(settings.screenshot_protection);
    assert!(!settings.online_status_visible);
    assert!(!settings.read_receipts);
    assert!(!settings.typing_indicator);
    assert!(!settings.show_preview);

    // Disable Sanchr Mode
    let settings =
        sanchr_core::settings::handlers::handle_toggle_sanchr_mode(&state, user_a, false)
            .await
            .expect("disable sanchr mode should succeed");

    assert!(!settings.sanchr_mode_enabled);
    assert!(settings.online_status_visible);
    assert!(settings.read_receipts);
}

#[tokio::test]
async fn update_profile_changes_display_name() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;

    // handle_update_profile takes plain &str for all three params;
    // empty string means "no change" for that field.
    // Encrypted blob params are all empty — this test only exercises plaintext update.
    let profile = sanchr_core::settings::handlers::handle_update_profile(
        &state,
        user_a,
        "NewName",
        "",
        "busy",
        &[],
        &[],
        &[],
        &[],
    )
    .await
    .expect("update profile should succeed");

    assert_eq!(profile.display_name, "NewName");
    assert_eq!(profile.status_text, "busy");
}

// ── Vault Tests (rewritten for the forward-secure proto) ──────────

async fn seed_owned_media(
    state: &std::sync::Arc<sanchr_core::server::AppState>,
    user_id: uuid::Uuid,
) -> String {
    let upload = sanchr_core::media::handlers::handle_get_upload_url(
        state,
        user_id,
        1024,
        "application/octet-stream",
        &format!("sha256-test-{}", uuid::Uuid::new_v4()),
        sanchr_proto::media::MediaPurpose::Attachment,
    )
    .await
    .expect("seed media upload url");
    upload.media_id
}

#[tokio::test]
async fn create_and_retrieve_vault_item() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;
    let media_id = seed_owned_media(&state, user_a).await;

    let vault_item_id = uuid::Uuid::new_v4().to_string();
    let req = sanchr_proto::vault::CreateVaultItemRequest {
        vault_item_id: vault_item_id.clone(),
        media_id: media_id.clone(),
        encrypted_metadata: b"test-encrypted-metadata-blob".to_vec(),
        expires_at: chrono::Utc::now().timestamp_millis() + 30 * 24 * 60 * 60 * 1000,
    };

    let item = sanchr_core::vault::handlers::handle_create_vault_item(&state, user_a, &req)
        .await
        .expect("create vault item should succeed");

    // The create response is built in-memory from the request, so assert
    // everything round-trips bytewise.
    assert_eq!(item.vault_item_id, vault_item_id);
    assert_eq!(item.media_id, media_id);
    assert_eq!(item.encrypted_metadata, req.encrypted_metadata);
    assert_eq!(item.expires_at, req.expires_at);
    assert!(item.created_at > 0);

    // Re-read via the listing path and verify the row that actually came
    // out of Scylla matches the request. This catches regressions in the
    // Scylla insert/read path or in row_to_proto that wouldn't be visible
    // when checking only the in-memory create response.
    let list = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user_a,
        &sanchr_proto::vault::GetVaultItemsRequest {
            limit: 20,
            paging_token: String::new(),
        },
    )
    .await
    .expect("list vault items should succeed");

    let listed = list
        .items
        .iter()
        .find(|i| i.vault_item_id == vault_item_id)
        .expect("newly created item should appear in the list");
    assert_eq!(listed.media_id, media_id);
    assert_eq!(listed.encrypted_metadata, req.encrypted_metadata);
    assert_eq!(listed.expires_at, req.expires_at);
    assert!(listed.created_at > 0);
}

#[tokio::test]
async fn delete_vault_item_is_idempotent() {
    let state = common::setup_test_state().await;
    let (user_a, _) = create_test_user(&state).await;
    let media_id = seed_owned_media(&state, user_a).await;

    let vault_item_id = uuid::Uuid::new_v4().to_string();
    sanchr_core::vault::handlers::handle_create_vault_item(
        &state,
        user_a,
        &sanchr_proto::vault::CreateVaultItemRequest {
            vault_item_id: vault_item_id.clone(),
            media_id,
            encrypted_metadata: b"to-delete".to_vec(),
            expires_at: 0,
        },
    )
    .await
    .expect("create");

    // First delete: removes the row.
    sanchr_core::vault::handlers::handle_delete_vault_item(&state, user_a, &vault_item_id)
        .await
        .expect("delete should succeed");

    // Second delete: no-op, still returns Ok.
    sanchr_core::vault::handlers::handle_delete_vault_item(&state, user_a, &vault_item_id)
        .await
        .expect("second delete should be idempotent");

    // Verify the item is gone from the listing.
    let list = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user_a,
        &sanchr_proto::vault::GetVaultItemsRequest {
            limit: 20,
            paging_token: String::new(),
        },
    )
    .await
    .expect("list");
    assert!(
        !list.items.iter().any(|i| i.vault_item_id == vault_item_id),
        "deleted item should not appear in the list"
    );
}
