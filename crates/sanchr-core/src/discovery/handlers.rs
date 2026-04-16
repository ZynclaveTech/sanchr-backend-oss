use std::sync::Arc;

use curve25519_dalek::ristretto::CompressedRistretto;
use tonic::Status;

use sanchr_common::errors::internal_status;

use crate::server::AppState;

/// Maximum number of blinded points per OPRF discover request.
/// Matches paper §3.2.3 "Vectorized scalar multiplication for 500+ contacts" —
/// also serves as a DoS bound on the per-request CPU cost of evaluate_batch.
const MAX_OPRF_BATCH_SIZE: usize = 500;

/// OPRF batch evaluation handler.
///
/// Validates that each blinded point is exactly 32 bytes, converts to
/// `CompressedRistretto`, calls `oprf_secret.evaluate_batch()`, and returns
/// the evaluated points as raw byte vectors.
///
/// Returns `Status::unavailable` if the OPRF secret has not been configured
/// on this server.
pub async fn handle_oprf_discover(
    state: &Arc<AppState>,
    blinded_point_bytes: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, Status> {
    // Phase 2: cap batch size to prevent DoS via oversized requests. Runs
    // before any per-point validation so a malicious caller can't waste
    // server cycles on a million-point batch only to be rejected at the end.
    if blinded_point_bytes.len() > MAX_OPRF_BATCH_SIZE {
        return Err(Status::invalid_argument(format!(
            "blinded_points batch size {} exceeds maximum {}",
            blinded_point_bytes.len(),
            MAX_OPRF_BATCH_SIZE
        )));
    }

    // load_full() returns Arc<OprfServerSecret> which is Send, safe across .await.
    let oprf = state
        .oprf_secret
        .as_ref()
        .ok_or_else(|| Status::unavailable("OPRF-PSI discovery is not configured on this server"))?
        .load_full();

    // Validate and convert each blinded point.
    let mut compressed_points = Vec::with_capacity(blinded_point_bytes.len());
    for (i, bytes) in blinded_point_bytes.iter().enumerate() {
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "blinded_points[{}]: expected 32 bytes, got {}",
                i,
                bytes.len()
            ))
        })?;
        compressed_points.push(CompressedRistretto(arr));
    }

    // Server-side OPRF evaluation.
    let evaluated = oprf.evaluate_batch(&compressed_points).map_err(|e| {
        tracing::error!(error = %e, "OPRF evaluation failed");
        Status::invalid_argument("OPRF evaluation failed")
    })?;

    Ok(evaluated
        .into_iter()
        .map(|p| p.as_bytes().to_vec())
        .collect())
}

/// Bloom filter fetch handler.
///
/// Fetches all registered phone numbers from Postgres, builds a
/// `SaltedBloomFilter` keyed with today's `discovery_daily_salt`, and returns
/// `(filter_bits, num_hashes, num_bits, daily_salt, generated_at_unix)`.
///
/// Returns `Status::unavailable` if the daily salt has not been configured.
pub async fn handle_get_bloom_filter(
    state: &Arc<AppState>,
) -> Result<(Vec<u8>, u32, u64, Vec<u8>, i64), Status> {
    // load_full() returns Arc<OprfServerSecret> which is Send, safe across .await.
    let oprf = state
        .oprf_secret
        .as_ref()
        .ok_or_else(|| Status::unavailable("OPRF-PSI discovery is not configured on this server"))?
        .load_full();
    let daily_salt = state
        .discovery_daily_salt
        .as_ref()
        .ok_or_else(|| Status::unavailable("OPRF-PSI discovery is not configured on this server"))?
        .load();
    let daily_salt: Vec<u8> = (**daily_salt).clone();

    let snapshot = state
        .discovery_snapshot_cache
        .get_or_rebuild(&state.pg_pool, &oprf, daily_salt)
        .await
        .map_err(|e| internal_status("discovery snapshot rebuild failed", e))?;

    Ok((
        snapshot.filter_bits.clone(),
        snapshot.num_hashes,
        snapshot.num_bits,
        snapshot.daily_salt.clone(),
        snapshot.generated_at,
    ))
}

/// Registered-set fetch handler.
///
/// Fetches all registered phone numbers from Postgres, computes
/// `oprf_secret.compute_set_element()` for each, and returns the set as
/// raw 32-byte vectors. The client can compare its unblinded OPRF outputs
/// against this set to determine which contacts are registered.
///
/// Returns `Status::unavailable` if the OPRF secret has not been configured.
pub async fn handle_get_registered_set(state: &Arc<AppState>) -> Result<Vec<Vec<u8>>, Status> {
    // load_full() returns Arc<OprfServerSecret> which is Send, safe across .await.
    let oprf = state
        .oprf_secret
        .as_ref()
        .ok_or_else(|| Status::unavailable("OPRF-PSI discovery is not configured on this server"))?
        .load_full();

    let daily_salt = state
        .discovery_daily_salt
        .as_ref()
        .ok_or_else(|| Status::unavailable("OPRF-PSI discovery is not configured on this server"))?
        .load();
    let daily_salt: Vec<u8> = (**daily_salt).clone();

    let snapshot = state
        .discovery_snapshot_cache
        .get_or_rebuild(&state.pg_pool, &oprf, daily_salt)
        .await
        .map_err(|e| internal_status("discovery snapshot rebuild failed", e))?;

    Ok(snapshot.registered_set.clone())
}
