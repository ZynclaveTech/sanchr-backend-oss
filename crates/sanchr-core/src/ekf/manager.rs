use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{error, info, warn};

use rand::Rng;

use super::models::{ExpPolicy, KeyClass, NULL_SENTINEL};
use crate::server::AppState;
use sanchr_db::scylla::auxiliary;

/// Spawns a periodic tick loop that runs [`lifecycle_tick`] every
/// `tick_interval`.  Uses [`MissedTickBehavior::Skip`] so that catch-up ticks
/// are dropped when the system is under load rather than bursting.
pub async fn run_lifecycle_loop(state: Arc<AppState>, tick_interval: Duration) {
    info!(
        tick_interval_secs = tick_interval.as_secs(),
        "EKF lifecycle loop started"
    );

    let mut ticker = interval(tick_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(e) = lifecycle_tick(&state).await {
            error!(error = %e, "EKF lifecycle tick failed");
        }
    }
}

/// Scans all four key classes for expired entries and applies the configured
/// expiry policy to each:
///
/// - **Rotate** — logs a rotation warning.  If the entry is also past the
///   configured grace period (i.e. it has been sitting expired without a
///   fresh rotation arriving), the entry is force-deleted.
/// - **Delete** — removes the row entirely via
///   [`auxiliary::delete_entry`].
/// - **Overwrite** — zero-fills the material with [`NULL_SENTINEL`] and
///   resets `created_at` via [`auxiliary::overwrite_entry`].
pub async fn lifecycle_tick(state: &Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let now_millis = now.timestamp_millis();

    let grace_secs = state.config.ekf.rotation_grace_secs as i64;

    let key_classes = [
        KeyClass::Presence,
        KeyClass::Discovery,
        KeyClass::PreKey,
        KeyClass::Media,
    ];

    for class in key_classes {
        let class_str = class.as_str();

        let expired_rows =
            match auxiliary::fetch_expired_entries(&state.scylla, class_str, now_millis).await {
                Ok(rows) => rows,
                Err(e) => {
                    error!(
                        error = %e,
                        class = class_str,
                        "failed to fetch expired EKF entries"
                    );
                    continue;
                }
            };

        if expired_rows.is_empty() {
            continue;
        }

        info!(
            class = class_str,
            count = expired_rows.len(),
            "EKF lifecycle: processing expired entries"
        );

        for row in expired_rows {
            let policy = match row.policy.parse::<ExpPolicy>() {
                Ok(p) => p,
                Err(()) => {
                    warn!(
                        entry_id = %row.entry_id,
                        raw_policy = %row.policy,
                        "unknown expiry policy — skipping entry"
                    );
                    continue;
                }
            };

            match policy {
                ExpPolicy::Rotate => {
                    // Calculate how long this entry has been sitting expired.
                    let expired_for_secs = (now_millis - row.created_at_ms) / 1_000 - row.ttl_secs;

                    if expired_for_secs >= grace_secs {
                        // Grace period exhausted — force-delete.
                        warn!(
                            entry_id = %row.entry_id,
                            user_id = %row.user_id,
                            class = class_str,
                            expired_for_secs,
                            "EKF: rotation grace period exceeded, force-deleting entry"
                        );
                        if let Err(e) = auxiliary::delete_entry(
                            &state.scylla,
                            row.user_id,
                            class_str,
                            row.entry_id,
                        )
                        .await
                        {
                            error!(
                                error = %e,
                                entry_id = %row.entry_id,
                                "failed to force-delete stale rotate entry"
                            );
                        }
                    } else {
                        info!(
                            entry_id = %row.entry_id,
                            user_id = %row.user_id,
                            class = class_str,
                            expired_for_secs,
                            grace_secs,
                            "EKF: rotation needed — waiting for client to supply fresh material"
                        );
                        let expired_at_ms = row.created_at_ms + row.ttl_secs * 1_000;
                        if let Err(e) = super::notifications::publish_rotation_needed(
                            &state.nats,
                            &row.user_id.to_string(),
                            class_str,
                            row.entry_id.to_string(),
                            expired_at_ms,
                        )
                        .await
                        {
                            error!(
                                error = %e,
                                entry_id = %row.entry_id,
                                user_id = %row.user_id,
                                "failed to publish EKF rotation_needed notification"
                            );
                        }
                    }
                }

                ExpPolicy::Delete => {
                    if let Err(e) =
                        auxiliary::delete_entry(&state.scylla, row.user_id, class_str, row.entry_id)
                            .await
                    {
                        error!(
                            error = %e,
                            entry_id = %row.entry_id,
                            "failed to delete expired EKF entry"
                        );
                    } else {
                        info!(
                            entry_id = %row.entry_id,
                            user_id = %row.user_id,
                            class = class_str,
                            "EKF: deleted expired entry"
                        );
                    }
                }

                ExpPolicy::Overwrite => {
                    let new_created_at_ms = now_millis;
                    if let Err(e) = auxiliary::overwrite_entry(
                        &state.scylla,
                        row.user_id,
                        class_str,
                        row.entry_id,
                        &NULL_SENTINEL,
                        new_created_at_ms,
                    )
                    .await
                    {
                        error!(
                            error = %e,
                            entry_id = %row.entry_id,
                            "failed to overwrite expired EKF entry"
                        );
                    } else {
                        info!(
                            entry_id = %row.entry_id,
                            user_id = %row.user_id,
                            class = class_str,
                            "EKF: overwritten expired entry with null sentinel"
                        );
                    }
                }

                ExpPolicy::Replenish => {
                    // Generate fresh random bytes matching the original material
                    // length.  For pre-key entries this keeps the key slot alive
                    // with real entropy rather than a zero sentinel, so the server
                    // always has a non-zero supply without a client round-trip.
                    let material_len = row.material.len().max(32);
                    let mut new_material = vec![0u8; material_len];
                    rand::rng().fill_bytes(&mut new_material);

                    if let Err(e) = auxiliary::overwrite_entry(
                        &state.scylla,
                        row.user_id,
                        class_str,
                        row.entry_id,
                        &new_material,
                        now_millis,
                    )
                    .await
                    {
                        error!(
                            error = %e,
                            entry_id = %row.entry_id,
                            "failed to replenish expired EKF entry"
                        );
                    } else {
                        info!(
                            entry_id = %row.entry_id,
                            user_id = %row.user_id,
                            class = class_str,
                            material_len,
                            "EKF: replenished expired entry with fresh random material"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
