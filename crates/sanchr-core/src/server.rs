use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use fred::clients::Client;
use fred::interfaces::ClientLike;
use metrics_exporter_prometheus::PrometheusHandle;
use scylla::client::session::Session;
use sqlx::PgPool;

use sanchr_common::config::AppConfig;
use sanchr_psi::oprf::OprfServerSecret;
use sanchr_server_crypto::jwt::JwtManager;
use sanchr_server_crypto::provider::CryptoProvider;
use sanchr_server_crypto::sealed_sender::SealedSenderSigner;

use crate::auth::challenge::ChallengeProvider;
use crate::discovery::cache::DiscoverySnapshotCache;
use crate::messaging::stream::StreamManager;
use crate::push::ApnsSender;

/// Shared application state available to all handlers and services.
pub struct AppState {
    pub config: AppConfig,
    pub pg_pool: PgPool,
    pub redis: Client,
    pub jwt: JwtManager,
    pub scylla: Session,
    pub nats: async_nats::Client,
    pub stream_mgr: Arc<StreamManager>,
    pub s3: aws_sdk_s3::Client,
    /// Handle for rendering the Prometheus `/metrics` endpoint.
    pub metrics_handle: PrometheusHandle,
    /// OPRF server secret for Private Contact Discovery (Defense 1).
    /// Wrapped in `ArcSwap` for lock-free atomic weekly rotation by the
    /// background secret-rotation task. `None` if OPRF is not configured;
    /// the discovery service returns `Status::unavailable` in that case.
    pub oprf_secret: Option<Arc<ArcSwap<OprfServerSecret>>>,
    /// Daily rotating salt used for the salted Bloom filter.
    /// Wrapped in `ArcSwap` for lock-free atomic rotation by the
    /// background salt-rotation task.
    /// `None` if OPRF is not configured.
    pub discovery_daily_salt: Option<ArcSwap<Vec<u8>>>,
    /// Cached Bloom filter and OPRF registered-set snapshot for the active
    /// discovery salt.
    pub discovery_snapshot_cache: Arc<DiscoverySnapshotCache>,
    /// Ed25519 signer for issuing `SenderCertificate` protos used by the
    /// sealed-sender message flow.
    pub sealed_sender_signer: Arc<SealedSenderSigner>,
    /// APNs push sender. `None` when `apns_key_path` is not configured
    /// (local dev without credentials).
    pub push_sender: Option<Arc<ApnsSender>>,
    /// Proof-of-work challenge provider for abuse detection in registration.
    /// `None` when `challenge.enabled` is false.
    pub challenge_provider: Option<Arc<dyn ChallengeProvider>>,
    /// Abstraction layer over all server-side cryptographic operations.
    /// Existing call sites still use the individual fields (`jwt`,
    /// `sealed_sender_signer`) directly; this provider is additive and
    /// will be adopted incrementally.
    pub crypto_provider: Arc<dyn CryptoProvider>,
}

/// Build the HTTP router with health, readiness, and metrics endpoints.
pub fn http_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics_handler_with_auth))
        .with_state(state)
}

async fn metrics_handler_with_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(expected_token) = &state.config.server.metrics_token {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match auth {
            Some(token) if token == expected_token => {}
            _ => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
        }
    }
    crate::observability::metrics::metrics_handler(State(state))
        .await
        .into_response()
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, StatusCode> {
    // Check Postgres connectivity
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("SELECT 1").execute(&state.pg_pool),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Check Redis connectivity
    tokio::time::timeout(Duration::from_secs(2), state.redis.ping::<String>(None))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    tokio::time::timeout(
        Duration::from_secs(2),
        state
            .scylla
            .query_unpaged("SELECT key FROM system.local LIMIT 1", &[]),
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    tokio::time::timeout(Duration::from_secs(2), state.nats.flush())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // S3 is media-only — a degraded S3 connection must not block messaging.
    // Log a warning but do not fail readiness.
    if let Ok(Err(e)) = tokio::time::timeout(
        Duration::from_secs(2),
        state
            .s3
            .head_bucket()
            .bucket(&state.config.storage.bucket)
            .send(),
    )
    .await
    {
        tracing::warn!(error = %e, "S3 readiness check failed (media degraded, messaging unaffected)");
    }

    Ok("ok")
}
