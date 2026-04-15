use fred::clients::RedisClient;
use fred::error::RedisError;
use fred::interfaces::KeysInterface;
use fred::types::Expiration;

fn lock_key(scope: &str, key: &str) -> String {
    format!("idem:lock:{scope}:{key}")
}

fn result_key(scope: &str, key: &str) -> String {
    format!("idem:result:{scope}:{key}")
}

/// Acquire a short-lived lock for an idempotent request.
///
/// Returns true if lock acquired; false if another request currently owns it.
pub async fn try_acquire_lock(
    client: &RedisClient,
    scope: &str,
    key: &str,
    ttl_secs: i64,
) -> Result<bool, RedisError> {
    let lock = lock_key(scope, key);

    let acquired: bool = client.setnx(&lock, "1").await?;
    if acquired {
        let _ = client.expire::<(), _>(&lock, ttl_secs).await;
    }

    Ok(acquired)
}

pub async fn get_cached_result(
    client: &RedisClient,
    scope: &str,
    key: &str,
) -> Result<Option<String>, RedisError> {
    let result = result_key(scope, key);
    client.get(&result).await
}

pub async fn store_result_and_release_lock(
    client: &RedisClient,
    scope: &str,
    key: &str,
    value: &str,
    result_ttl_secs: i64,
) -> Result<(), RedisError> {
    let result = result_key(scope, key);
    let lock = lock_key(scope, key);

    client
        .set::<(), _, _>(
            &result,
            value,
            Some(Expiration::EX(result_ttl_secs)),
            None,
            false,
        )
        .await?;
    client.del::<(), _>(&lock).await?;
    Ok(())
}

pub async fn release_lock(client: &RedisClient, scope: &str, key: &str) -> Result<(), RedisError> {
    let lock = lock_key(scope, key);
    client.del::<(), _>(&lock).await?;
    Ok(())
}
