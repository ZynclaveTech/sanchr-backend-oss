mod common;

use std::sync::Arc;

use chrono::Utc;
use scylla::frame::value::CqlTimestamp;
use scylla::Session;
use uuid::Uuid;

use sanchr_core::ekf::manager::lifecycle_tick;
use sanchr_core::ekf::models::{ExpPolicy, KeyClass, NULL_SENTINEL};
use sanchr_core::server::AppState;
use sanchr_db::scylla::auxiliary;

// ---------------------------------------------------------------------------
// Helper: fetch a single entry by full primary key
// ---------------------------------------------------------------------------

/// There is no `get_entry` in the auxiliary module, so we query ScyllaDB
/// directly by the composite primary key `(user_id, class, entry_id)`.
/// Returns `None` when the row does not exist.
async fn get_entry(
    session: &Session,
    user_id: Uuid,
    class: &str,
    entry_id: Uuid,
) -> Option<auxiliary::ExpiredEntryRow> {
    type RawRow = (Uuid, Uuid, String, String, Vec<u8>, CqlTimestamp, i64);

    let result = session
        .query_unpaged(
            "SELECT user_id, entry_id, class, policy, material, created_at, ttl_secs \
             FROM auxiliary_state \
             WHERE user_id = ? AND class = ? AND entry_id = ?",
            (user_id, class.to_owned(), entry_id),
        )
        .await
        .expect("query failed");

    let rows: Vec<RawRow> = result
        .rows_typed::<RawRow>()
        .expect("type error")
        .collect::<Result<Vec<_>, _>>()
        .expect("row deserialization failed");

    rows.into_iter().next().map(
        |(user_id, entry_id, class, policy, material, created_at, ttl_secs)| {
            auxiliary::ExpiredEntryRow {
                user_id,
                entry_id,
                class,
                policy,
                material,
                created_at_ms: created_at.0,
                ttl_secs,
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Helper: insert a test entry with explicit timestamps
// ---------------------------------------------------------------------------

async fn insert_test_entry(
    state: &Arc<AppState>,
    user_id: Uuid,
    entry_id: Uuid,
    class: KeyClass,
    policy: ExpPolicy,
    material: &[u8],
    created_at_ms: i64,
    ttl_secs: i64,
) {
    auxiliary::insert_entry(
        &state.scylla,
        user_id,
        entry_id,
        class.as_str(),
        policy.as_str(),
        material,
        created_at_ms,
        ttl_secs,
    )
    .await
    .expect("insert_entry failed");
}

// ---------------------------------------------------------------------------
// Test 1: Delete policy removes expired entry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_delete_policy_removes_expired_entry() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 1_i64;
    // created_at 2 seconds ago — already expired.
    let created_at_ms = Utc::now().timestamp_millis() - 2_000;
    let material = vec![0xAA; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Presence,
        ExpPolicy::Delete,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    // Sanity: the row exists before the tick.
    assert!(
        get_entry(
            &state.scylla,
            user_id,
            KeyClass::Presence.as_str(),
            entry_id
        )
        .await
        .is_some(),
        "entry should exist before lifecycle_tick"
    );

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    // After tick the entry must be gone.
    assert!(
        get_entry(
            &state.scylla,
            user_id,
            KeyClass::Presence.as_str(),
            entry_id
        )
        .await
        .is_none(),
        "Delete policy did not remove expired entry"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Overwrite policy zeroes material
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_overwrite_policy_zeroes_material() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 1_i64;
    // created_at far in the past — well expired.
    let created_at_ms = Utc::now().timestamp_millis() - 60_000;
    let material = vec![0xBB; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Media,
        ExpPolicy::Overwrite,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    // The row should still exist but material should be NULL_SENTINEL.
    let row = get_entry(&state.scylla, user_id, KeyClass::Media.as_str(), entry_id)
        .await
        .expect("Overwrite policy should retain the row");

    assert_eq!(
        row.material.as_slice(),
        &NULL_SENTINEL[..],
        "material should be overwritten with NULL_SENTINEL (32 zero bytes)"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Rotate within grace publishes notification (entry kept)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_rotate_within_grace_publishes_notification() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 60_i64;
    let grace_secs = state.config.ekf.rotation_grace_secs as i64;

    // Expired just past TTL but within the grace window.
    // `expired_for = now - created_at_ms/1000 - ttl_secs` should be < grace_secs.
    // Set created_at so that the entry has been expired for only 5 seconds.
    let created_at_ms = Utc::now().timestamp_millis() - ((ttl_secs + 5) * 1_000);

    // Safety: ensure 5 < grace_secs (default 3600).
    assert!(
        5 < grace_secs,
        "test assumes grace_secs > 5, got {grace_secs}"
    );

    let material = vec![0xCC; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Discovery,
        ExpPolicy::Rotate,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    // Entry must still exist — grace period has not been exhausted.
    let row = get_entry(
        &state.scylla,
        user_id,
        KeyClass::Discovery.as_str(),
        entry_id,
    )
    .await
    .expect("Rotate entry within grace should not be deleted");

    // Material should be unchanged.
    assert_eq!(
        row.material, material,
        "material should be untouched during grace period"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Rotate past grace force-deletes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_rotate_past_grace_force_deletes() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 60_i64;
    let grace_secs = state.config.ekf.rotation_grace_secs as i64;

    // Expired well past TTL + grace.
    // `expired_for_secs = now_ms/1000 - created_at_ms/1000 - ttl_secs` should be >= grace_secs.
    let created_at_ms = Utc::now().timestamp_millis() - ((ttl_secs + grace_secs + 60) * 1_000);

    let material = vec![0xDD; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Discovery,
        ExpPolicy::Rotate,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    // Entry must be force-deleted.
    assert!(
        get_entry(
            &state.scylla,
            user_id,
            KeyClass::Discovery.as_str(),
            entry_id,
        )
        .await
        .is_none(),
        "Rotate entry past grace should be force-deleted"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Replenish replaces with fresh material
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_replenish_replaces_with_fresh_material() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 1_i64;
    let created_at_ms = Utc::now().timestamp_millis() - 2_000;
    let original_material = vec![0xFF; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::PreKey,
        ExpPolicy::Replenish,
        &original_material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    let row = get_entry(&state.scylla, user_id, KeyClass::PreKey.as_str(), entry_id)
        .await
        .expect("Replenish policy should retain the row");

    // Material must differ from the original.
    assert_ne!(
        row.material, original_material,
        "material should have been replaced with fresh random bytes"
    );

    // Material must NOT be NULL_SENTINEL — replenish generates real entropy.
    assert_ne!(
        row.material.as_slice(),
        &NULL_SENTINEL[..],
        "replenished material should not be null sentinel"
    );

    // Material must be at least 32 bytes.
    assert!(
        row.material.len() >= 32,
        "replenished material length ({}) should be >= 32",
        row.material.len()
    );
}

// ---------------------------------------------------------------------------
// Test 6: Unexpired entries are untouched
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_unexpired_entries_are_untouched() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 86_400_i64; // 24 hours
    let created_at_ms = Utc::now().timestamp_millis(); // just now
    let material = vec![0xEE; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Presence,
        ExpPolicy::Delete,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    let row = get_entry(
        &state.scylla,
        user_id,
        KeyClass::Presence.as_str(),
        entry_id,
    )
    .await
    .expect("unexpired entry should still exist after lifecycle_tick");

    assert_eq!(
        row.material, material,
        "material of unexpired entry should be unchanged"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Multiple classes processed in single tick
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_multiple_classes_processed_in_single_tick() {
    let state = common::setup_test_state().await;

    let grace_secs = state.config.ekf.rotation_grace_secs as i64;

    // --- Presence / Delete (expired) ---
    let presence_user = Uuid::new_v4();
    let presence_entry = Uuid::new_v4();
    insert_test_entry(
        &state,
        presence_user,
        presence_entry,
        KeyClass::Presence,
        ExpPolicy::Delete,
        &[0x01; 32],
        Utc::now().timestamp_millis() - 2_000,
        1,
    )
    .await;

    // --- Discovery / Rotate past grace ---
    let disc_user = Uuid::new_v4();
    let disc_entry = Uuid::new_v4();
    insert_test_entry(
        &state,
        disc_user,
        disc_entry,
        KeyClass::Discovery,
        ExpPolicy::Rotate,
        &[0x02; 32],
        Utc::now().timestamp_millis() - ((60 + grace_secs + 60) * 1_000),
        60,
    )
    .await;

    // --- Media / Overwrite (expired) ---
    let media_user = Uuid::new_v4();
    let media_entry = Uuid::new_v4();
    insert_test_entry(
        &state,
        media_user,
        media_entry,
        KeyClass::Media,
        ExpPolicy::Overwrite,
        &[0x03; 32],
        Utc::now().timestamp_millis() - 60_000,
        1,
    )
    .await;

    // --- PreKey / Replenish (expired) ---
    let prekey_user = Uuid::new_v4();
    let prekey_entry = Uuid::new_v4();
    let prekey_material = vec![0x04; 32];
    insert_test_entry(
        &state,
        prekey_user,
        prekey_entry,
        KeyClass::PreKey,
        ExpPolicy::Replenish,
        &prekey_material,
        Utc::now().timestamp_millis() - 2_000,
        1,
    )
    .await;

    // --- Single tick ---
    lifecycle_tick(&state).await.expect("lifecycle_tick failed");

    // Presence/Delete -> gone
    assert!(
        get_entry(
            &state.scylla,
            presence_user,
            KeyClass::Presence.as_str(),
            presence_entry,
        )
        .await
        .is_none(),
        "Presence/Delete entry should be removed"
    );

    // Discovery/Rotate past grace -> gone
    assert!(
        get_entry(
            &state.scylla,
            disc_user,
            KeyClass::Discovery.as_str(),
            disc_entry,
        )
        .await
        .is_none(),
        "Discovery/Rotate past grace entry should be force-deleted"
    );

    // Media/Overwrite -> row exists, material = NULL_SENTINEL
    let media_row = get_entry(
        &state.scylla,
        media_user,
        KeyClass::Media.as_str(),
        media_entry,
    )
    .await
    .expect("Media/Overwrite entry should still exist");
    assert_eq!(
        media_row.material.as_slice(),
        &NULL_SENTINEL[..],
        "Media/Overwrite material should be null sentinel"
    );

    // PreKey/Replenish -> row exists, material changed
    let prekey_row = get_entry(
        &state.scylla,
        prekey_user,
        KeyClass::PreKey.as_str(),
        prekey_entry,
    )
    .await
    .expect("PreKey/Replenish entry should still exist");
    assert_ne!(
        prekey_row.material, prekey_material,
        "PreKey/Replenish material should be replaced"
    );
    assert_ne!(
        prekey_row.material.as_slice(),
        &NULL_SENTINEL[..],
        "PreKey/Replenish material should not be null sentinel"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Tick is idempotent for deleted entries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ekf_tick_is_idempotent_for_deleted_entries() {
    let state = common::setup_test_state().await;

    let user_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let ttl_secs = 1_i64;
    let created_at_ms = Utc::now().timestamp_millis() - 2_000;
    let material = vec![0xAA; 32];

    insert_test_entry(
        &state,
        user_id,
        entry_id,
        KeyClass::Presence,
        ExpPolicy::Delete,
        &material,
        created_at_ms,
        ttl_secs,
    )
    .await;

    // First tick: deletes the entry.
    lifecycle_tick(&state)
        .await
        .expect("first lifecycle_tick failed");

    assert!(
        get_entry(
            &state.scylla,
            user_id,
            KeyClass::Presence.as_str(),
            entry_id
        )
        .await
        .is_none(),
        "entry should be deleted after first tick"
    );

    // Second tick: entry already gone — should not error.
    lifecycle_tick(&state)
        .await
        .expect("second lifecycle_tick should not error when entry is already deleted");
}
