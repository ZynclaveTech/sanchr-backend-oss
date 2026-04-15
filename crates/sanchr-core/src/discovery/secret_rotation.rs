use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, MissedTickBehavior};
use tracing::info;

use sanchr_db::scylla::auxiliary;
use sanchr_psi::oprf::OprfServerSecret;
use uuid::Uuid;

use crate::server::AppState;

const DISCOVERY_STATE_USER_ID: Uuid = Uuid::from_u128(0);
const DISCOVERY_OPRF_ENTRY_ID: Uuid = Uuid::from_u128(1);

/// Background task that replaces the OPRF server secret on a configurable
/// interval (default: 7 days).
///
/// Uses [`MissedTickBehavior::Skip`] so that catch-up ticks are dropped when
/// the system is under load rather than bursting. The first tick is skipped
/// because the secret was just loaded at startup.
///
/// On each rotation:
/// 1. Generates a fresh `OprfServerSecret` via the OS CSPRNG.
/// 2. Atomically swaps it into `AppState.oprf_secret` via `ArcSwap::store`.
/// 3. Invalidates the discovery snapshot cache so the next request rebuilds
///    the registered-set with the new secret.
///
/// # Panics
///
/// Panics (debug-only assertion) if `state.oprf_secret` is `None`.
/// Callers must only spawn this task when OPRF discovery is enabled.
pub async fn run_oprf_secret_rotation_loop(state: Arc<AppState>, rotation_interval: Duration) {
    debug_assert!(
        state.oprf_secret.is_some(),
        "oprf_secret_rotation spawned without oprf_secret"
    );

    info!(
        interval_secs = rotation_interval.as_secs(),
        "OPRF secret rotation loop started"
    );

    let mut ticker = interval(rotation_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Skip the first tick — secret was just loaded at startup.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let new_secret = OprfServerSecret::generate();

        if let Some(arc_swap) = &state.oprf_secret {
            arc_swap.store(Arc::new(new_secret));
            state.discovery_snapshot_cache.invalidate().await;
            let ttl_secs = state
                .config
                .discovery
                .as_ref()
                .map(|d| d.oprf_rotation_interval_secs as i64)
                .unwrap_or(7 * 24 * 60 * 60)
                .max(1);
            let now_ms = chrono::Utc::now().timestamp_millis();
            if let Err(error) = auxiliary::insert_entry(
                &state.scylla,
                DISCOVERY_STATE_USER_ID,
                DISCOVERY_OPRF_ENTRY_ID,
                "discovery",
                "rotate",
                &arc_swap.load().to_bytes(),
                now_ms,
                ttl_secs,
            )
            .await
            {
                tracing::warn!(error = %error, "failed to refresh OPRF lifecycle entry");
            }
            info!("OPRF server secret rotated; snapshot cache invalidated");
        }
    }
}
