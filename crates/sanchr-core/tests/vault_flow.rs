//! Dedicated integration tests for the forward-secure VaultService.
//!
//! Covers edge cases that the smoke tests in contacts_settings_vault.rs do not:
//! idempotent retry, validation failures, cross-user enumeration defense,
//! pagination, and delete idempotency on missing rows. Each test creates its
//! own fresh user(s) so parallel execution against the shared Scylla container
//! is safe.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use uuid::Uuid;

use sanchr_core::server::AppState;
use sanchr_proto::vault::{CreateVaultItemRequest, GetVaultItemsRequest};

/// Create a fresh test user. Matches the helper in contacts_settings_vault.rs.
/// Each test must call this to avoid cross-test contamination.
async fn create_test_user(state: &Arc<AppState>) -> Uuid {
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, _) = common::register_and_verify_user(
        state,
        "Password123!",
        "vault-device",
        "ios",
        Some(&installation_id),
    )
    .await;
    auth.user.id
}

/// Seed an owned media object for `user_id` and return its media_id string.
/// Used as the `media_id` handle for vault items. The media object is created
/// via the real upload-url path so ownership is correctly persisted in
/// Postgres, matching what `handle_create_vault_item` checks.
async fn seed_media(state: &Arc<AppState>, user_id: Uuid) -> String {
    let upload = sanchr_core::media::handlers::handle_get_upload_url(
        state,
        user_id,
        1024,
        "application/octet-stream",
        &format!("sha256-vault-flow-{}", Uuid::new_v4()),
        sanchr_proto::media::MediaPurpose::Attachment,
    )
    .await
    .expect("seed media upload url");
    upload.media_id
}

fn make_metadata(label: &str) -> Vec<u8> {
    format!("aes-gcm-ciphertext:{label}").into_bytes()
}

/// 30 days from now, in Unix milliseconds. Matches the convention used in the
/// smoke tests.
fn expiry_30_days() -> i64 {
    chrono::Utc::now().timestamp_millis() + 30 * 24 * 60 * 60 * 1000
}

// ── CreateVaultItem ────────────────────────────────────────────────────────

#[tokio::test]
async fn create_vault_item_happy_path() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let vault_item_id = Uuid::new_v4().to_string();
    let metadata = make_metadata("happy-path");
    let expires_at = expiry_30_days();
    let req = CreateVaultItemRequest {
        vault_item_id: vault_item_id.clone(),
        media_id: media_id.clone(),
        encrypted_metadata: metadata.clone(),
        expires_at,
    };

    let item = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect("create vault item should succeed");

    assert_eq!(item.vault_item_id, vault_item_id);
    assert_eq!(item.media_id, media_id);
    assert_eq!(item.encrypted_metadata, metadata);
    assert_eq!(item.expires_at, expires_at);
    assert!(item.created_at > 0);

    // The list RPC must also see the newly created row.
    let list = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user,
        &GetVaultItemsRequest {
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
        .expect("created item should appear in listing");
    assert_eq!(listed.media_id, media_id);
    assert_eq!(listed.encrypted_metadata, metadata);
    assert_eq!(listed.expires_at, expires_at);
}

#[tokio::test]
async fn create_vault_item_is_idempotent() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let vault_item_id = Uuid::new_v4().to_string();
    let metadata = make_metadata("idempotent-retry");
    let expires_at = expiry_30_days();
    let req = CreateVaultItemRequest {
        vault_item_id: vault_item_id.clone(),
        media_id: media_id.clone(),
        encrypted_metadata: metadata.clone(),
        expires_at,
    };

    // First call: real insert.
    let first = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect("first create should succeed");

    // Second call with the same vault_item_id: should return the existing row
    // verbatim (no duplicate insert, no error).
    let second = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect("second create should be idempotent");

    // Byte-identical: same ids, same blob, same timestamps. If the server
    // silently re-stamped `created_at` we would see drift here.
    assert_eq!(second.vault_item_id, first.vault_item_id);
    assert_eq!(second.media_id, first.media_id);
    assert_eq!(second.encrypted_metadata, first.encrypted_metadata);
    assert_eq!(second.created_at, first.created_at);
    assert_eq!(second.expires_at, first.expires_at);
}

#[tokio::test]
async fn create_vault_item_rejects_foreign_media_id() {
    let state = common::setup_test_state().await;
    let user_a = create_test_user(&state).await;
    let user_b = create_test_user(&state).await;

    // A uploads a media object; B tries to wrap it in a vault item.
    let media_id = seed_media(&state, user_a).await;

    let req = CreateVaultItemRequest {
        vault_item_id: Uuid::new_v4().to_string(),
        media_id,
        encrypted_metadata: make_metadata("foreign-media"),
        expires_at: expiry_30_days(),
    };

    let err = sanchr_core::vault::handlers::handle_create_vault_item(&state, user_b, &req)
        .await
        .expect_err("user B should be denied wrapping user A's media");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PermissionDenied, got {:?}: {}",
        err.code(),
        err.message()
    );
}

#[tokio::test]
async fn create_vault_item_rejects_empty_metadata() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let req = CreateVaultItemRequest {
        vault_item_id: Uuid::new_v4().to_string(),
        media_id,
        encrypted_metadata: vec![],
        expires_at: 0,
    };

    let err = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect_err("empty metadata should be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument, got {:?}: {}",
        err.code(),
        err.message()
    );
}

#[tokio::test]
async fn create_vault_item_rejects_oversize_metadata() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    // One byte over the 64 KiB hard cap enforced by the handler.
    let oversize = vec![0u8; 64 * 1024 + 1];
    let req = CreateVaultItemRequest {
        vault_item_id: Uuid::new_v4().to_string(),
        media_id,
        encrypted_metadata: oversize,
        expires_at: 0,
    };

    let err = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect_err("oversize metadata should be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument, got {:?}: {}",
        err.code(),
        err.message()
    );
}

#[tokio::test]
async fn create_vault_item_rejects_bad_uuid() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let req = CreateVaultItemRequest {
        vault_item_id: "not-a-uuid".to_string(),
        media_id,
        encrypted_metadata: make_metadata("bad-uuid"),
        expires_at: 0,
    };

    let err = sanchr_core::vault::handlers::handle_create_vault_item(&state, user, &req)
        .await
        .expect_err("non-UUID vault_item_id should be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument, got {:?}: {}",
        err.code(),
        err.message()
    );
}

// ── GetVaultItem ───────────────────────────────────────────────────────────

#[tokio::test]
async fn get_vault_item_roundtrip() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let vault_item_id = Uuid::new_v4().to_string();
    let metadata = make_metadata("roundtrip");
    let expires_at = expiry_30_days();
    let created = sanchr_core::vault::handlers::handle_create_vault_item(
        &state,
        user,
        &CreateVaultItemRequest {
            vault_item_id: vault_item_id.clone(),
            media_id: media_id.clone(),
            encrypted_metadata: metadata.clone(),
            expires_at,
        },
    )
    .await
    .expect("create should succeed");

    let fetched = sanchr_core::vault::handlers::handle_get_vault_item(&state, user, &vault_item_id)
        .await
        .expect("get should succeed");

    // Field-for-field equality: this is the contract the client depends on.
    assert_eq!(fetched.vault_item_id, created.vault_item_id);
    assert_eq!(fetched.media_id, media_id);
    assert_eq!(fetched.encrypted_metadata, metadata);
    assert_eq!(fetched.expires_at, expires_at);
    assert_eq!(fetched.created_at, created.created_at);
    assert!(fetched.created_at > 0);
}

#[tokio::test]
async fn get_vault_item_denies_cross_user_enumeration() {
    let state = common::setup_test_state().await;
    let owner = create_test_user(&state).await;
    let attacker = create_test_user(&state).await;
    let media_id = seed_media(&state, owner).await;

    let vault_item_id = Uuid::new_v4().to_string();
    sanchr_core::vault::handlers::handle_create_vault_item(
        &state,
        owner,
        &CreateVaultItemRequest {
            vault_item_id: vault_item_id.clone(),
            media_id,
            encrypted_metadata: make_metadata("owned-by-A"),
            expires_at: expiry_30_days(),
        },
    )
    .await
    .expect("owner create should succeed");

    // Attacker knows (or guesses) the vault_item_id. The server MUST return
    // PermissionDenied — NOT NotFound — to avoid leaking existence of
    // specific vault_item_ids across user boundaries.
    let err = sanchr_core::vault::handlers::handle_get_vault_item(&state, attacker, &vault_item_id)
        .await
        .expect_err("attacker should be denied");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PermissionDenied (not NotFound, which would leak existence), got {:?}: {}",
        err.code(),
        err.message()
    );
}

// ── GetVaultItems (list) ───────────────────────────────────────────────────

#[tokio::test]
async fn list_vault_items_returns_created_items() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let mut inserted: HashSet<String> = HashSet::new();
    for i in 0..5 {
        let vault_item_id = Uuid::new_v4().to_string();
        sanchr_core::vault::handlers::handle_create_vault_item(
            &state,
            user,
            &CreateVaultItemRequest {
                vault_item_id: vault_item_id.clone(),
                media_id: media_id.clone(),
                encrypted_metadata: make_metadata(&format!("list-basic-{i}")),
                expires_at: expiry_30_days(),
            },
        )
        .await
        .expect("create should succeed");
        inserted.insert(vault_item_id);
    }

    let list = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user,
        &GetVaultItemsRequest {
            limit: 20,
            paging_token: String::new(),
        },
    )
    .await
    .expect("list should succeed");

    // Each of our 5 inserted ids must be present. Do not assert exact length
    // because the per-test user is fresh, but future edits to this test could
    // inadvertently share a user — a set-containment check is robust either
    // way.
    for id in &inserted {
        assert!(
            list.items.iter().any(|i| &i.vault_item_id == id),
            "inserted id {id} missing from list"
        );
    }
}

#[tokio::test]
async fn list_vault_items_pagination_produces_cursor() {
    let state = common::setup_test_state().await;
    // Fresh user per pagination test — Scylla is a persistent shared store
    // and any residual rows from prior test runs on a reused user would
    // break length-based assertions. The HashSet ground truth below is the
    // real guarantee.
    let user = create_test_user(&state).await;
    let media_id = seed_media(&state, user).await;

    let mut inserted: HashSet<String> = HashSet::new();
    for i in 0..10 {
        let vault_item_id = Uuid::new_v4().to_string();
        sanchr_core::vault::handlers::handle_create_vault_item(
            &state,
            user,
            &CreateVaultItemRequest {
                vault_item_id: vault_item_id.clone(),
                media_id: media_id.clone(),
                encrypted_metadata: make_metadata(&format!("list-page-{i}")),
                expires_at: expiry_30_days(),
            },
        )
        .await
        .expect("create should succeed");
        inserted.insert(vault_item_id);
    }

    // First page — request 4 items.
    let page1 = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user,
        &GetVaultItemsRequest {
            limit: 4,
            paging_token: String::new(),
        },
    )
    .await
    .expect("list page 1 should succeed");

    assert_eq!(
        page1.items.len(),
        4,
        "page 1 should return exactly 4 items (requested limit)"
    );
    assert!(
        !page1.next_cursor.is_empty(),
        "page 1 next_cursor should be non-empty when more items exist"
    );

    let page1_ids: HashSet<String> = page1
        .items
        .iter()
        .map(|i| i.vault_item_id.clone())
        .collect();

    // Second page — forward the cursor.
    let page2 = sanchr_core::vault::handlers::handle_get_vault_items(
        &state,
        user,
        &GetVaultItemsRequest {
            limit: 4,
            paging_token: page1.next_cursor.clone(),
        },
    )
    .await
    .expect("list page 2 should succeed");

    assert_eq!(
        page2.items.len(),
        4,
        "page 2 should return exactly 4 items (requested limit)"
    );

    let page2_ids: HashSet<String> = page2
        .items
        .iter()
        .map(|i| i.vault_item_id.clone())
        .collect();

    // Disjoint pages: no vault_item_id appears in both pages.
    let overlap: HashSet<_> = page1_ids.intersection(&page2_ids).collect();
    assert!(
        overlap.is_empty(),
        "pages must be disjoint, but these ids appear in both: {overlap:?}"
    );

    // Both pages' ids must belong to the 10 we inserted — there is no way
    // this freshly created user sees anything else.
    for id in page1_ids.iter().chain(page2_ids.iter()) {
        assert!(
            inserted.contains(id),
            "listed id {id} was not one of the 10 we inserted"
        );
    }
}

// ── DeleteVaultItem ────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_vault_item_is_idempotent_on_missing_row() {
    let state = common::setup_test_state().await;
    let user = create_test_user(&state).await;

    // Never created — purely random UUID.
    let ghost_id = Uuid::new_v4().to_string();

    sanchr_core::vault::handlers::handle_delete_vault_item(&state, user, &ghost_id)
        .await
        .expect("delete of nonexistent row should be a no-op Ok");
}
