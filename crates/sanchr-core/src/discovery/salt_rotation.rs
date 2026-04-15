use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, MissedTickBehavior};
use tracing::info;

use sanchr_db::scylla::auxiliary;
use sanchr_psi::bloom::generate_daily_salt;
use uuid::Uuid;

use crate::server::AppState;

const DISCOVERY_STATE_USER_ID: Uuid = Uuid::from_u128(0);
const DISCOVERY_SALT_ENTRY_ID: Uuid = Uuid::from_u128(2);

/// Rotation interval: 24 hours.
const ROTATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Background task that rotates `discovery_daily_salt` every 24 hours.
///
/// Uses [`MissedTickBehavior::Skip`] so that catch-up ticks are dropped when
/// the system is under load rather than bursting.  The first tick is skipped
/// because the salt was already generated at startup.
///
/// # Panics
///
/// Panics (debug-only assertion) if `state.discovery_daily_salt` is `None`.
/// Callers must only spawn this task when OPRF discovery is enabled.
pub async fn run_salt_rotation_loop(state: Arc<AppState>) {
    debug_assert!(
        state.discovery_daily_salt.is_some(),
        "salt_rotation spawned without discovery_daily_salt"
    );

    info!(
        interval_secs = ROTATION_INTERVAL.as_secs(),
        "daily salt rotation loop started"
    );

    let mut ticker = interval(ROTATION_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Skip the first tick — salt was just generated at startup.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let new_salt = generate_daily_salt();
        info!(salt_len = new_salt.len(), "rotating daily discovery salt");

        if let Some(arc_swap) = &state.discovery_daily_salt {
            arc_swap.store(Arc::new(new_salt));
            state.discovery_snapshot_cache.invalidate().await;
            let now_ms = chrono::Utc::now().timestamp_millis();
            if let Err(error) = auxiliary::insert_entry(
                &state.scylla,
                DISCOVERY_STATE_USER_ID,
                DISCOVERY_SALT_ENTRY_ID,
                "discovery",
                "rotate",
                &arc_swap.load().to_vec(),
                now_ms,
                24 * 60 * 60,
            )
            .await
            {
                tracing::warn!(error = %error, "failed to refresh discovery salt lifecycle entry");
            }
        }
    }
}
