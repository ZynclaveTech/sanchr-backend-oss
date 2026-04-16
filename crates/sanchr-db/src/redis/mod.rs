pub mod call_events;
pub mod call_state;
pub mod delivery_tokens;
pub mod idempotency;
pub mod privacy_cache;
pub mod rate_limit;
pub mod sessions;
pub mod typing;

use std::time::Duration;

use fred::clients::Client;
use fred::error::Error;
use fred::interfaces::ClientLike;
use fred::types::config::{Config as FredConfig, PerformanceConfig, ReconnectPolicy};
use sanchr_common::config::RedisConfig as AppRedisConfig;

pub async fn create_client(config: &AppRedisConfig) -> Result<Client, Error> {
    let fred_config = FredConfig::from_url(&config.url)?;

    // Reconnect with exponential backoff (100 ms → 30 s) on any connection drop.
    // `max_attempts = 0` means unlimited retries — the caller can impose a higher-level
    // timeout (e.g. gRPC deadline) if a bounded failure window is needed.
    let policy = ReconnectPolicy::new_exponential(0, 100, 30_000, 2);

    // 5-second hard timeout per command so handlers get a concrete error instead of
    // hanging indefinitely when Redis is transiently unreachable.
    let perf = PerformanceConfig {
        default_command_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = Client::new(fred_config, Some(perf), None, Some(policy));
    client.connect();
    client.wait_for_connect().await?;
    Ok(client)
}
