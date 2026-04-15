use bytes::Bytes;
use fred::clients::RedisClient;
use fred::error::RedisError;
use fred::interfaces::{KeysInterface, SetsInterface};
use fred::types::RedisValue;
use rand::RngCore;

const DELIVERY_TOKENS_KEY: &str = "sealed:delivery_tokens";
const TOKEN_TTL_SECS: i64 = 86_400;
const MAX_TOKENS: u32 = 100;

/// Issue up to `count` anonymous 32-byte delivery tokens.
///
/// Tokens are stored in the Redis SET `sealed:delivery_tokens` with a 24-hour
/// TTL. The count is silently capped at 100 to bound memory use per call.
/// Tokens carry no user identity — they are fully anonymous.
pub async fn issue_tokens(redis: &RedisClient, count: u32) -> Result<Vec<Vec<u8>>, RedisError> {
    let count = count.min(MAX_TOKENS) as usize;
    if count == 0 {
        return Ok(Vec::new());
    }

    // Generate tokens in a sync block so the non-Send `ThreadRng` is
    // dropped before any `.await`, satisfying tonic's `Send` bound.
    let tokens: Vec<Vec<u8>> = {
        let mut rng = rand::thread_rng();
        (0..count)
            .map(|_| {
                let mut token = vec![0u8; 32];
                rng.fill_bytes(&mut token);
                token
            })
            .collect()
    };

    // fred 9.x maps Vec<Vec<u8>> → RedisValue::Array which is rejected by
    // Redis SADD. Each member must be RedisValue::Bytes so the client sends
    // a flat bulk-string list, not a nested array.
    let members: Vec<RedisValue> = tokens
        .iter()
        .map(|t| RedisValue::Bytes(Bytes::copy_from_slice(t)))
        .collect();
    redis.sadd::<(), _, _>(DELIVERY_TOKENS_KEY, members).await?;

    // Refresh TTL on every issue call so the set doesn't expire mid-batch.
    redis
        .expire::<(), _>(DELIVERY_TOKENS_KEY, TOKEN_TTL_SECS)
        .await?;

    Ok(tokens)
}

/// Atomically check and consume a delivery token.
///
/// Returns `true` if the token existed in the set and was removed (i.e. valid),
/// or `false` if the token was unknown or already consumed.
/// `SREM` is atomic at the Redis command level — no Lua needed.
pub async fn validate_and_consume(redis: &RedisClient, token: &[u8]) -> Result<bool, RedisError> {
    let removed: i64 = redis
        .srem(
            DELIVERY_TOKENS_KEY,
            RedisValue::Bytes(Bytes::copy_from_slice(token)),
        )
        .await?;

    Ok(removed == 1)
}
