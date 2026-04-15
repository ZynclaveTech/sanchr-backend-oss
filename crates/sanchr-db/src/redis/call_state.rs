use fred::interfaces::LuaInterface;
use fred::prelude::*;
use serde::{Deserialize, Serialize};

const MISSED_DEADLINES_KEY: &str = "call:missed_deadlines";
const SIGNAL_REPLAY_TTL_SECS: i64 = 120;
const SIGNAL_REPLAY_MAX: i64 = 128;
const BEGIN_ACTIVE_CALL_LUA: &str = r#"
if redis.call('EXISTS', KEYS[2]) == 1 or redis.call('EXISTS', KEYS[3]) == 1 then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[3], ARGV[2], 'EX', ARGV[3])
redis.call('ZADD', KEYS[4], ARGV[4], ARGV[2])
return 1
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveCall {
    pub call_id: String,
    pub caller_id: String,
    pub recipient_id: String,
    pub call_type: String,
    pub status: String,
    pub started_at: i64,
    #[serde(default)]
    pub answered_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCallSignal {
    pub sender_id: String,
    pub signal: serde_json::Value,
}

fn active_key(call_id: &str) -> String {
    format!("active_call:{call_id}")
}

fn user_index_key(user_id: &str) -> String {
    format!("active_call_by_user:{user_id}")
}

fn signal_key(call_id: &str) -> String {
    format!("call:signal_replay:{call_id}")
}

pub async fn get_active_call(
    client: &RedisClient,
    call_id: &str,
) -> Result<Option<ActiveCall>, RedisError> {
    let data: Option<String> = client.get(active_key(call_id)).await?;
    Ok(data.and_then(|raw| serde_json::from_str::<ActiveCall>(&raw).ok()))
}

pub async fn active_call_id_for_user(
    client: &RedisClient,
    user_id: &str,
) -> Result<Option<String>, RedisError> {
    client.get(user_index_key(user_id)).await
}

pub async fn put_active_call(
    client: &RedisClient,
    call: &ActiveCall,
    ttl_secs: i64,
) -> Result<(), RedisError> {
    let encoded = serde_json::to_string(call).unwrap_or_default();
    client
        .set::<(), _, _>(
            active_key(&call.call_id),
            encoded,
            Some(Expiration::EX(ttl_secs)),
            None,
            false,
        )
        .await?;
    Ok(())
}

pub async fn begin_active_call(
    client: &RedisClient,
    call: &ActiveCall,
    ttl_secs: i64,
    missed_deadline_ms: i64,
) -> Result<bool, RedisError> {
    let encoded = serde_json::to_string(call).unwrap_or_default();
    if encoded.is_empty() {
        return Ok(false);
    }
    let created: i64 = client
        .eval(
            BEGIN_ACTIVE_CALL_LUA,
            vec![
                active_key(&call.call_id),
                user_index_key(&call.caller_id),
                user_index_key(&call.recipient_id),
                MISSED_DEADLINES_KEY.to_string(),
            ],
            vec![
                encoded,
                call.call_id.clone(),
                ttl_secs.to_string(),
                missed_deadline_ms.to_string(),
            ],
        )
        .await?;
    Ok(created == 1)
}

pub async fn clear_active_call(client: &RedisClient, call: &ActiveCall) -> Result<(), RedisError> {
    client.del::<(), _>(active_key(&call.call_id)).await?;
    client.del::<(), _>(user_index_key(&call.caller_id)).await?;
    client
        .del::<(), _>(user_index_key(&call.recipient_id))
        .await?;
    let _ = client
        .zrem::<(), _, _>(MISSED_DEADLINES_KEY, vec![call.call_id.as_str()])
        .await;
    Ok(())
}

pub async fn remove_missed_deadline(client: &RedisClient, call_id: &str) -> Result<(), RedisError> {
    client
        .zrem::<(), _, _>(MISSED_DEADLINES_KEY, vec![call_id])
        .await
}

pub async fn due_missed_call_ids(
    client: &RedisClient,
    now_ms: i64,
    limit: usize,
) -> Result<Vec<String>, RedisError> {
    let call_ids: Vec<String> = client
        .zrangebyscore(
            MISSED_DEADLINES_KEY,
            f64::NEG_INFINITY,
            now_ms as f64,
            false,
            None,
        )
        .await?;
    let due = call_ids.into_iter().take(limit).collect::<Vec<_>>();
    if !due.is_empty() {
        let refs = due.iter().map(String::as_str).collect::<Vec<_>>();
        let _ = client.zrem::<(), _, _>(MISSED_DEADLINES_KEY, refs).await;
    }
    Ok(due)
}

pub async fn store_call_signal(
    client: &RedisClient,
    call_id: &str,
    signal: &StoredCallSignal,
) -> Result<(), RedisError> {
    let key = signal_key(call_id);
    let encoded = serde_json::to_string(signal).unwrap_or_default();
    if encoded.is_empty() {
        return Ok(());
    }
    client.lpush::<(), _, _>(&key, encoded).await?;
    client
        .ltrim::<(), _>(&key, 0, SIGNAL_REPLAY_MAX - 1)
        .await?;
    client.expire::<(), _>(&key, SIGNAL_REPLAY_TTL_SECS).await?;
    Ok(())
}

pub async fn replay_call_signals(
    client: &RedisClient,
    call_id: &str,
) -> Result<Vec<StoredCallSignal>, RedisError> {
    let mut items: Vec<String> = client.lrange(signal_key(call_id), 0, -1).await?;
    items.reverse();
    Ok(items
        .into_iter()
        .filter_map(|raw| serde_json::from_str::<StoredCallSignal>(&raw).ok())
        .collect())
}
