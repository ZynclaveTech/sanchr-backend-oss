use std::sync::Arc;

use tonic::{Request, Response, Status};

use sanchr_common::errors::internal_status;
use sanchr_db::redis::rate_limit;
use sanchr_proto::discovery::discovery_service_server::DiscoveryService as DiscoveryServiceTrait;
use sanchr_proto::discovery::{
    GetBloomFilterRequest, GetBloomFilterResponse, GetRegisteredSetRequest,
    GetRegisteredSetResponse, OprfDiscoverRequest, OprfDiscoverResponse,
};

use crate::middleware::auth;
use crate::server::AppState;

use super::handlers;

/// Per-user, per-hour cap on `oprf_discover`. With MAX_OPRF_BATCH_SIZE = 500
/// blinded points per request (Task 10), this allows up to 10 000 contact
/// lookups per hour — enough for daily contact sync plus manual refreshes.
const OPRF_DISCOVER_LIMIT: u64 = 20;
/// Per-user, per-hour cap on `get_bloom_filter`. The filter rotates daily
/// (24h EKF), so a few fetches per hour is plenty for normal clients.
const OPRF_BLOOM_LIMIT: u64 = 6;
/// Per-user, per-hour cap on `get_registered_set`. Same rotation cadence
/// as the bloom filter — clients only need a handful of pulls.
const OPRF_SET_LIMIT: u64 = 6;
/// Window for all OPRF rate limits, in seconds (1 hour).
const OPRF_WINDOW_SECS: i64 = 3600;

/// Map a `check_rate_limit` failure into a tonic `Status`. Mirrors the
/// pattern in `contacts::handlers::handle_sync_contacts` so the wire-level
/// behaviour is consistent across rate-limited endpoints.
fn rate_limit_status(label: &str, e: sanchr_common::errors::AppError) -> Status {
    match e {
        sanchr_common::errors::AppError::RateLimited => {
            Status::resource_exhausted(format!("{label} rate limited"))
        }
        other => internal_status("rate limit check failed", other),
    }
}

pub struct DiscoveryService {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl DiscoveryServiceTrait for DiscoveryService {
    /// Evaluate a batch of client-blinded Ristretto255 points under the server
    /// OPRF secret and return the resulting points.
    async fn oprf_discover(
        &self,
        request: Request<OprfDiscoverRequest>,
    ) -> Result<Response<OprfDiscoverResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // Phase 2: per-user rate limit. Applied AFTER auth so anonymous
        // callers don't drain the authenticated user's quota.
        let rate_key = format!("rate:oprf_discover:{}", user.user_id);
        rate_limit::check_rate_limit(
            &self.state.redis,
            &rate_key,
            OPRF_DISCOVER_LIMIT,
            OPRF_WINDOW_SECS,
        )
        .await
        .map_err(|e| rate_limit_status("oprf_discover", e))?;

        let blinded_points = request.into_inner().blinded_points;

        let evaluated_points = handlers::handle_oprf_discover(&self.state, blinded_points).await?;

        Ok(Response::new(OprfDiscoverResponse { evaluated_points }))
    }

    /// Return the current salted Bloom filter over all registered phone numbers.
    async fn get_bloom_filter(
        &self,
        request: Request<GetBloomFilterRequest>,
    ) -> Result<Response<GetBloomFilterResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // Phase 2: per-user rate limit. Bloom filter rotates daily so a
        // small per-hour budget is sufficient.
        let rate_key = format!("rate:get_bloom_filter:{}", user.user_id);
        rate_limit::check_rate_limit(
            &self.state.redis,
            &rate_key,
            OPRF_BLOOM_LIMIT,
            OPRF_WINDOW_SECS,
        )
        .await
        .map_err(|e| rate_limit_status("get_bloom_filter", e))?;

        let (filter_bits, num_hashes, num_bits, daily_salt, generated_at) =
            handlers::handle_get_bloom_filter(&self.state).await?;

        Ok(Response::new(GetBloomFilterResponse {
            filter_bits,
            num_hashes,
            num_bits,
            daily_salt,
            generated_at,
        }))
    }

    /// Return the pre-computed OPRF set elements for all registered users.
    async fn get_registered_set(
        &self,
        request: Request<GetRegisteredSetRequest>,
    ) -> Result<Response<GetRegisteredSetResponse>, Status> {
        let user = auth::authenticate(&self.state, &request).await?;

        // Phase 2: per-user rate limit. Set rotates daily, same cadence
        // as the bloom filter.
        let rate_key = format!("rate:get_registered_set:{}", user.user_id);
        rate_limit::check_rate_limit(
            &self.state.redis,
            &rate_key,
            OPRF_SET_LIMIT,
            OPRF_WINDOW_SECS,
        )
        .await
        .map_err(|e| rate_limit_status("get_registered_set", e))?;

        let set_elements = handlers::handle_get_registered_set(&self.state).await?;

        Ok(Response::new(GetRegisteredSetResponse { set_elements }))
    }
}
