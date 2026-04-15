//! End-to-end integration tests for Phase 2 privacy enforcement.
//!
//! Covers:
//! - Block enforcement: silent-drop in `handle_send_message`, per-recipient
//!   filtering in `handle_typing`.
//! - Profile photo visibility (`nobody` / `contacts(non-mutual)` /
//!   `contacts(mutual)` / `everyone`) across `handle_get_conversations`,
//!   `handle_sync_contacts`, and `handle_get_contacts`.
//! - OPRF rate limit: 21st `check_rate_limit` call returns
//!   `AppError::RateLimited`.
//! - OPRF batch cap: 501-point request to `handle_oprf_discover` returns
//!   `Status::invalid_argument` before any per-point validation.
//!
//! These tests follow the same harness pattern as
//! `contacts_settings_vault.rs`, `messaging_flow.rs`, and `presence_flow.rs`:
//! they spin up a real Postgres + Redis + ScyllaDB + NATS + S3 stack via
//! `common::setup_test_state`, register users through the auth handlers, and
//! call domain handlers directly (Option A from the task brief). gRPC service
//! wrappers are NOT exercised here — they're already covered by the existing
//! flow tests, and the Phase 2 invariants live below the service layer.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use uuid::Uuid;

use sanchr_db::postgres::contacts as pg_contacts;
use sanchr_db::postgres::conversations as pg_conv;
use sanchr_db::postgres::settings as pg_settings;
use sanchr_db::postgres::users as pg_users;
use sanchr_db::redis::privacy_cache;
use sanchr_db::redis::rate_limit;
use sanchr_proto::messaging::{server_event, DeviceMessage, ServerEvent};

use sanchr_core::messaging::handlers::SendMessageParams;

// ─── Test fixtures ──────────────────────────────────────────────────────────

/// Create a registered, OTP-verified user with one device.
async fn create_test_user(state: &Arc<sanchr_core::server::AppState>) -> (Uuid, String, i32) {
    let installation_id = format!("install-{}", Uuid::new_v4());
    let (auth, phone) = common::register_and_verify_user(
        state,
        "Password123!",
        "test-device",
        "ios",
        Some(&installation_id),
    )
    .await;
    (auth.user.id, phone, auth.device_id)
}

/// Set the avatar URL on a user row directly via `update_profile`. The
/// `update_profile` handler treats an empty string as "no change", so callers
/// pass the literal URL they want stored.
async fn set_avatar(state: &Arc<sanchr_core::server::AppState>, user_id: Uuid, avatar_url: &str) {
    pg_settings::update_profile(
        &state.pg_pool,
        user_id,
        None,
        Some(avatar_url),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("update_profile (avatar) should succeed");
    // Force the privacy cache to refresh on next read so the test sees the
    // newly written profile rather than a stale empty avatar.
    privacy_cache::invalidate(&state.redis, &user_id).await;
}

/// Update only the `profile_photo_visibility` flag on a user, leaving every
/// other setting at its current value. Goes through `handle_update_settings`
/// so the privacy cache is invalidated as a side effect.
async fn set_photo_visibility(
    state: &Arc<sanchr_core::server::AppState>,
    user_id: Uuid,
    visibility: &str,
) {
    let mut settings = sanchr_core::settings::handlers::handle_get_settings(state, user_id)
        .await
        .expect("get_settings should succeed");
    settings.profile_photo_visibility = visibility.to_string();
    sanchr_core::settings::handlers::handle_update_settings(state, user_id, &settings)
        .await
        .expect("update_settings should succeed");
}

/// Make `viewer` and `target` mutual contacts by calling `handle_sync_contacts`
/// in both directions on each user's phone hash. The handler is the most
/// faithful path because it also adds the row to `contacts` with
/// `is_blocked = false`, which is exactly what `are_mutual_contacts` checks.
async fn make_mutual_contacts(
    state: &Arc<sanchr_core::server::AppState>,
    user_a: Uuid,
    phone_a: &str,
    user_b: Uuid,
    phone_b: &str,
) {
    let hash_b = sanchr_db::postgres::users::hash_phone(phone_b);
    sanchr_core::contacts::handlers::handle_sync_contacts(state, user_a, vec![hash_b])
        .await
        .expect("sync a -> b should succeed");

    let hash_a = sanchr_db::postgres::users::hash_phone(phone_a);
    sanchr_core::contacts::handlers::handle_sync_contacts(state, user_b, vec![hash_a])
        .await
        .expect("sync b -> a should succeed");

    debug_assert!(
        pg_contacts::are_mutual_contacts(&state.pg_pool, user_a, user_b)
            .await
            .unwrap_or(false),
        "harness: make_mutual_contacts must result in are_mutual_contacts == true"
    );
}

/// Create a one-way contact relationship from `viewer` to `target`. Used in
/// the `contacts(non-mutual)` test to prove that a unilateral contact entry
/// is NOT enough to reveal the avatar.
async fn make_oneway_contact(
    state: &Arc<sanchr_core::server::AppState>,
    viewer: Uuid,
    target_phone: &str,
) {
    let hash = sanchr_db::postgres::users::hash_phone(target_phone);
    sanchr_core::contacts::handlers::handle_sync_contacts(state, viewer, vec![hash])
        .await
        .expect("one-way sync should succeed");
}

/// Build a `SendMessageParams` for a single 1:1 device target.
fn send_params_1to1(
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
        device_messages: vec![DeviceMessage {
            recipient_id: recipient_id.to_string(),
            device_id: recipient_device,
            ciphertext: ciphertext.to_vec(),
        }],
        content_type: "text".to_string(),
        expires_after_secs: 0,
    }
}

/// Locate the `Participant` entry in a conversation by user id, panicking
/// with a useful error message if not found. The participant list is
/// populated by `handle_get_conversations`, so the call site should be
/// confident the lookup will succeed.
fn find_participant(
    conv: &sanchr_proto::messaging::Conversation,
    user_id: Uuid,
) -> &sanchr_proto::messaging::Participant {
    let needle = user_id.to_string();
    conv.participants
        .iter()
        .find(|p| p.user_id == needle)
        .unwrap_or_else(|| panic!("participant {needle} missing from conversation"))
}

/// Drain a `ServerEvent` receiver until a typing indicator arrives, or
/// timeout. Returns `Some(typing)` if a typing event for the expected
/// `(conversation_id, user_id)` was observed, otherwise `None`.
async fn await_typing_event(
    rx: &mut tokio::sync::mpsc::Receiver<ServerEvent>,
    duration: Duration,
) -> Option<sanchr_proto::messaging::TypingIndicator> {
    timeout(duration, async {
        loop {
            match rx.recv().await {
                Some(ServerEvent {
                    event: Some(server_event::Event::Typing(t)),
                }) => return Some(t),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

// ─── Test 1: block silently drops direct message ────────────────────────────

#[tokio::test]
async fn block_silently_drops_direct_message() {
    let state = common::setup_test_state().await;
    let (alice, _, alice_device) = create_test_user(&state).await;
    let (bob, _, bob_device) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    // Bob blocks Alice. Goes through the handler so privacy cache is
    // invalidated as a side effect — without this the next send_message
    // would still see the cached "not blocked" flags.
    sanchr_core::contacts::handlers::handle_block_contact(&state, bob, alice)
        .await
        .expect("bob blocks alice");

    // Alice sends a 1:1 message to Bob. The handler must return Ok with a
    // valid-looking message_id and timestamp (silent-drop is
    // indistinguishable from success on the sender side).
    let result = sanchr_core::messaging::handlers::handle_send_message(
        &state,
        &state.stream_mgr,
        send_params_1to1(
            alice,
            alice_device,
            conv.id,
            bob,
            bob_device,
            b"hello-from-blocked-alice",
        ),
    )
    .await
    .expect("send_message must return Ok even when silently dropped");

    assert!(
        !result.message_id.is_empty(),
        "silent-drop must still return a non-empty message_id"
    );
    assert!(
        result.server_timestamp > 0,
        "silent-drop must still return a positive server_timestamp"
    );
    // The fake message_id must parse as a UUID — clients use it as a sentinel.
    assert!(
        result.message_id.parse::<Uuid>().is_ok(),
        "silent-drop message_id must parse as a UUID"
    );

    // Bob's inbox must be empty: nothing was stored to ScyllaDB and nothing
    // was routed to his device. handle_sync_messages drains the legacy
    // pending path (or the device outbox for ack-capable devices); a
    // freshly-registered ios device with default settings uses the legacy
    // path, so this also implicitly verifies that route_message was not
    // called.
    let envelopes = sanchr_core::messaging::handlers::handle_sync_messages(&state, bob, bob_device)
        .await
        .expect("sync_messages should succeed");

    assert!(
        envelopes.is_empty(),
        "block must silently drop the message: bob's inbox should be empty, got {:?}",
        envelopes.iter().map(|e| &e.message_id).collect::<Vec<_>>()
    );
}

// ─── Test 2: block filters typing indicator ─────────────────────────────────

#[tokio::test]
async fn block_filters_typing_indicator() {
    let state = common::setup_test_state().await;
    let (alice, _, _alice_device) = create_test_user(&state).await;
    let (bob, _, bob_device) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    // Bob blocks Alice (privacy cache invalidated by the handler).
    sanchr_core::contacts::handlers::handle_block_contact(&state, bob, alice)
        .await
        .expect("bob blocks alice");

    // Register Bob's device on the SHARED state.stream_mgr — handle_typing
    // takes an explicit &Arc<StreamManager>, so we must pass the same
    // instance we register on.
    let mut bob_rx = state
        .stream_mgr
        .register(&bob.to_string(), bob_device)
        .await;

    // Alice starts typing in the conversation she shares with Bob.
    sanchr_core::presence::handlers::handle_typing(
        &state,
        &state.stream_mgr,
        alice,
        &conv.id.to_string(),
        true,
    )
    .await;

    // Bob must NOT receive Alice's typing indicator.
    let observed = await_typing_event(&mut bob_rx, Duration::from_millis(300)).await;
    assert!(
        observed.is_none(),
        "block must filter typing: bob received {observed:?}"
    );
}

// ─── Test 3 (removed): block_filters_presence_broadcast
// Server-side presence broadcast was removed in Sub-phase 3 (P2P Presence).
// Presence is now delivered as sealed-sender envelopes; the server never
// sees or routes PresenceUpdate events, so this test is no longer applicable.

// ─── Test 4: profile_photo_visibility=nobody hides avatar in get_conversations

#[tokio::test]
async fn profile_photo_visibility_nobody_hides_avatar_in_get_conversations() {
    let state = common::setup_test_state().await;
    let (alice, _, _) = create_test_user(&state).await;
    let (bob, _, _) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    set_avatar(&state, bob, "https://cdn.example/bob.png").await;
    set_photo_visibility(&state, bob, "nobody").await;

    let conversations = sanchr_core::messaging::handlers::handle_get_conversations(&state, alice)
        .await
        .expect("get_conversations should succeed");

    let target_conv = conversations
        .iter()
        .find(|c| c.id == conv.id.to_string())
        .expect("conversation should appear in alice's list");
    let bob_participant = find_participant(target_conv, bob);

    assert_eq!(
        bob_participant.avatar_url, "",
        "visibility=nobody must hide bob's avatar from alice"
    );

    // Sanity: bob should still see his own avatar via the same handler.
    let bob_view = sanchr_core::messaging::handlers::handle_get_conversations(&state, bob)
        .await
        .expect("get_conversations should succeed for bob");
    let same_conv = bob_view
        .iter()
        .find(|c| c.id == conv.id.to_string())
        .expect("conversation should appear in bob's list");
    let bob_self = find_participant(same_conv, bob);
    assert_eq!(
        bob_self.avatar_url, "https://cdn.example/bob.png",
        "owner-identity short-circuit must reveal bob's own avatar"
    );
}

// ─── Test 5: visibility=contacts hides avatar for non-mutual viewer ─────────

#[tokio::test]
async fn profile_photo_visibility_contacts_hides_avatar_for_non_mutual() {
    let state = common::setup_test_state().await;
    let (alice, _, _) = create_test_user(&state).await;
    let (bob, _, _) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    set_avatar(&state, bob, "https://cdn.example/bob-contacts.png").await;
    set_photo_visibility(&state, bob, "contacts").await;

    // No sync_contacts in either direction → not mutual.
    let mutual = pg_contacts::are_mutual_contacts(&state.pg_pool, alice, bob)
        .await
        .expect("are_mutual_contacts");
    assert!(!mutual, "precondition: alice and bob must NOT be mutuals");

    let conversations = sanchr_core::messaging::handlers::handle_get_conversations(&state, alice)
        .await
        .expect("get_conversations should succeed");
    let target_conv = conversations
        .iter()
        .find(|c| c.id == conv.id.to_string())
        .expect("conversation should appear in alice's list");
    let bob_participant = find_participant(target_conv, bob);

    assert_eq!(
        bob_participant.avatar_url, "",
        "visibility=contacts + non-mutual must hide bob's avatar"
    );
}

// ─── Test 6: visibility=contacts shows avatar for mutual viewer ─────────────

#[tokio::test]
async fn profile_photo_visibility_contacts_shows_avatar_for_mutual() {
    let state = common::setup_test_state().await;
    let (alice, phone_a, _) = create_test_user(&state).await;
    let (bob, phone_b, _) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    set_avatar(&state, bob, "https://cdn.example/bob-mutual.png").await;
    // Establish two-way contact relationship FIRST so that the avatar
    // visibility check sees the mutual flag once visibility flips. We then
    // flip visibility to "contacts" and invalidate Bob's privacy cache.
    make_mutual_contacts(&state, alice, &phone_a, bob, &phone_b).await;
    set_photo_visibility(&state, bob, "contacts").await;

    let conversations = sanchr_core::messaging::handlers::handle_get_conversations(&state, alice)
        .await
        .expect("get_conversations should succeed");
    let target_conv = conversations
        .iter()
        .find(|c| c.id == conv.id.to_string())
        .expect("conversation should appear in alice's list");
    let bob_participant = find_participant(target_conv, bob);

    assert_eq!(
        bob_participant.avatar_url, "https://cdn.example/bob-mutual.png",
        "visibility=contacts + mutual must reveal bob's avatar"
    );
}

// ─── Test 7: visibility=everyone shows avatar to anyone ─────────────────────

#[tokio::test]
async fn profile_photo_visibility_everyone_shows_avatar_to_anyone() {
    let state = common::setup_test_state().await;
    let (alice, _, _) = create_test_user(&state).await;
    let (bob, _, _) = create_test_user(&state).await;

    let conv = pg_conv::find_or_create_direct(&state.pg_pool, alice, bob)
        .await
        .expect("create direct conversation");

    set_avatar(&state, bob, "https://cdn.example/bob-public.png").await;
    set_photo_visibility(&state, bob, "everyone").await;

    let conversations = sanchr_core::messaging::handlers::handle_get_conversations(&state, alice)
        .await
        .expect("get_conversations should succeed");
    let target_conv = conversations
        .iter()
        .find(|c| c.id == conv.id.to_string())
        .expect("conversation should appear in alice's list");
    let bob_participant = find_participant(target_conv, bob);

    assert_eq!(
        bob_participant.avatar_url, "https://cdn.example/bob-public.png",
        "visibility=everyone must reveal bob's avatar to non-contacts"
    );
}

// ─── Test 8: visibility=nobody hides avatar in sync_contacts ────────────────

#[tokio::test]
async fn profile_photo_visibility_nobody_hides_avatar_in_sync_contacts() {
    let state = common::setup_test_state().await;
    let (alice, _, _) = create_test_user(&state).await;
    let (bob, phone_b, _) = create_test_user(&state).await;

    set_avatar(&state, bob, "https://cdn.example/bob-sync.png").await;
    set_photo_visibility(&state, bob, "nobody").await;

    let hash_b = pg_users::hash_phone(&phone_b);
    let matched =
        sanchr_core::contacts::handlers::handle_sync_contacts(&state, alice, vec![hash_b])
            .await
            .expect("sync_contacts should succeed");

    assert_eq!(matched.len(), 1, "alice should match bob");
    let m = &matched[0];
    assert_eq!(m.user_id, bob.to_string());
    assert_eq!(
        m.avatar_url, "",
        "visibility=nobody must hide bob's avatar in sync_contacts"
    );
}

// ─── Test 9: visibility=nobody hides avatar in get_contacts ─────────────────

#[tokio::test]
async fn profile_photo_visibility_nobody_hides_avatar_in_get_contacts() {
    let state = common::setup_test_state().await;
    let (alice, _, _) = create_test_user(&state).await;
    let (bob, phone_b, _) = create_test_user(&state).await;

    set_avatar(&state, bob, "https://cdn.example/bob-getcontacts.png").await;

    // First make alice -> bob a contact entry, THEN flip visibility. The
    // sync_contacts call also touches the privacy cache as a side effect
    // (it's a Postgres-only operation here, but the order matters because
    // set_photo_visibility invalidates the cache afterwards).
    make_oneway_contact(&state, alice, &phone_b).await;
    set_photo_visibility(&state, bob, "nobody").await;

    let contacts = sanchr_core::contacts::handlers::handle_get_contacts(&state, alice)
        .await
        .expect("get_contacts should succeed");

    let bob_contact = contacts
        .iter()
        .find(|c| c.user_id == bob.to_string())
        .expect("bob should appear in alice's contact list");
    assert_eq!(
        bob_contact.avatar_url, "",
        "visibility=nobody must hide bob's avatar in get_contacts"
    );
}

// ─── Test 10: OPRF discover rate limit ──────────────────────────────────────

#[tokio::test]
async fn oprf_discover_rate_limit_blocks_over_limit() {
    // The rate limit is enforced at the SERVICE level
    // (`crates/sanchr-core/src/discovery/service.rs`), not at the handler
    // level. Calling `handle_oprf_discover` directly bypasses it.
    //
    // Per the task brief, we exercise the rate limiter directly against the
    // Redis client using the same key shape and limits the service uses
    // (`rate:oprf_discover:{user_id}`, 20 requests per 3600s). This proves
    // the underlying primitive enforces the cap. The wire-level binding is
    // a one-line call site in the service module that doesn't add new
    // logic worth re-testing here.
    let state = common::setup_test_state().await;
    let (user_id, _, _) = create_test_user(&state).await;

    let key = format!("rate:oprf_discover:{}", user_id);
    // Use a fresh key per test run by appending a random suffix; without
    // this, repeated test runs against a long-lived Redis would observe
    // residual counters and fail intermittently.
    let key = format!("{key}:{}", Uuid::new_v4());

    // First 20 calls must all succeed.
    for i in 0..20 {
        rate_limit::check_rate_limit(&state.redis, &key, 20, 3600)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "call #{} should succeed within the 20-per-hour limit: {e:?}",
                    i + 1
                )
            });
    }

    // 21st call must trip the limit.
    let twenty_first = rate_limit::check_rate_limit(&state.redis, &key, 20, 3600).await;
    assert!(
        matches!(
            twenty_first,
            Err(sanchr_common::errors::AppError::RateLimited)
        ),
        "21st call must return AppError::RateLimited, got {twenty_first:?}"
    );
}

// ─── Test 11: OPRF discover rejects batches over 500 ────────────────────────

#[tokio::test]
async fn oprf_discover_rejects_batch_over_500() {
    // The batch-size check fires BEFORE per-point validation AND before the
    // oprf_secret-configured check. We can therefore exercise it without
    // populating state.oprf_secret (which is None in the test harness).
    //
    // 501 entries of 32 zero bytes each: well-formed enough to make it
    // through any "wrong size" validation that came after the batch cap,
    // but irrelevant — the cap fires first and rejects the request.
    let state = common::setup_test_state().await;

    let blinded: Vec<Vec<u8>> = (0..501).map(|_| vec![0u8; 32]).collect();
    assert_eq!(blinded.len(), 501, "test fixture should be 501 entries");

    let result = sanchr_core::discovery::handlers::handle_oprf_discover(&state, blinded).await;

    let err = match result {
        Ok(_) => panic!("501-point batch must be rejected, got Ok"),
        Err(s) => s,
    };

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "oversized batch must return InvalidArgument, got {:?}",
        err.code()
    );

    let msg = err.message();
    assert!(
        msg.contains("500") && msg.contains("batch size"),
        "error message must mention batch size and the 500 cap, got {msg:?}"
    );
}
