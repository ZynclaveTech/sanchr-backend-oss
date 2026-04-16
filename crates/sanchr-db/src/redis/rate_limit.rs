use fred::clients::Client;
use fred::interfaces::LuaInterface;
use sanchr_common::errors::AppError;

/// Lua script for atomic rate limiting using INCR + conditional EXPIRE.
/// Returns the current count after increment.
const RATE_LIMIT_LUA: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"#;

/// Atomic rate limit check using a Lua script.
///
/// Increments the counter for `key` and sets TTL atomically on first request.
/// Returns the remaining allowed requests, or `AppError::RateLimited`.
pub async fn check_rate_limit(
    client: &Client,
    key: &str,
    max_requests: u64,
    window_seconds: i64,
) -> Result<u64, AppError> {
    let current: u64 = client
        .eval(
            RATE_LIMIT_LUA,
            vec![key.to_string()],
            vec![window_seconds.to_string()],
        )
        .await
        .map_err(|e| AppError::Internal(format!("rate limit script error: {e}")))?;

    if current > max_requests {
        return Err(AppError::RateLimited);
    }

    Ok(max_requests.saturating_sub(current))
}
