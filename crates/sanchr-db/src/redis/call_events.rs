use fred::prelude::*;
use serde::{Deserialize, Serialize};

const CALL_EVENT_INBOX_MAX: i64 = 128;
const CALL_EVENT_INBOX_TTL_SECS: i64 = 600; // bounded replay window

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallInboxEvent {
    Offer {
        call_id: String,
        caller_id: String,
        call_type: String,
        #[serde(default)]
        sdp_offer: String,
        #[serde(default)]
        srtp_key_params: String,
        #[serde(default)]
        encrypted_sdp_payload: String,
    },
    Lifecycle {
        call_id: String,
        peer_id: String,
        event_type: String,
        actor_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCallInboxEvent {
    expires_at_ms: i64,
    event: CallInboxEvent,
}

fn inbox_key(user_id: &str) -> String {
    format!("call:inbox:{user_id}")
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn event_kind(event: &CallInboxEvent) -> &'static str {
    match event {
        CallInboxEvent::Offer { .. } => "offer",
        CallInboxEvent::Lifecycle { .. } => "lifecycle",
    }
}

fn event_call_id(event: &CallInboxEvent) -> &str {
    match event {
        CallInboxEvent::Offer { call_id, .. } | CallInboxEvent::Lifecycle { call_id, .. } => {
            call_id
        }
    }
}

fn decode_stored(raw: &str) -> Option<StoredCallInboxEvent> {
    if let Ok(stored) = serde_json::from_str::<StoredCallInboxEvent>(raw) {
        return Some(stored);
    }

    // Backward compatibility for entries written by older core pods.
    serde_json::from_str::<CallInboxEvent>(raw)
        .ok()
        .map(|event| StoredCallInboxEvent {
            expires_at_ms: now_ms() + CALL_EVENT_INBOX_TTL_SECS * 1_000,
            event,
        })
}

pub async fn push_call_event(
    client: &Client,
    user_id: &str,
    payload: &CallInboxEvent,
    event_ttl_secs: i64,
) -> Result<(), Error> {
    let key = inbox_key(user_id);
    let ttl = event_ttl_secs.clamp(1, CALL_EVENT_INBOX_TTL_SECS);
    let stored = StoredCallInboxEvent {
        expires_at_ms: now_ms() + ttl * 1_000,
        event: payload.clone(),
    };
    let encoded = serde_json::to_string(&stored).unwrap_or_default();
    if encoded.is_empty() {
        return Ok(());
    }
    client.lpush::<(), _, _>(&key, encoded).await?;
    // Keep bounded history to avoid unbounded growth.
    client
        .ltrim::<(), _>(&key, 0, CALL_EVENT_INBOX_MAX - 1)
        .await?;
    client
        .expire::<(), _>(&key, CALL_EVENT_INBOX_TTL_SECS, None)
        .await?;
    Ok(())
}

/// Remove any queued `Offer` events for `call_id` from `user_id`'s inbox.
///
/// Called when a "ended" lifecycle event is stored so that the recipient is
/// not woken by a VoIP push only to immediately have the call killed by a
/// replayed "ended" event.  The "ended" lifecycle itself is kept — the
/// recipient should still transition away from any `.incoming` state that
/// was set up by an already-delivered VoIP push.
pub async fn evict_offer_for_call(
    client: &Client,
    user_id: &str,
    call_id: &str,
) -> Result<(), Error> {
    let key = inbox_key(user_id);
    let items: Vec<String> = client.lrange(&key, 0, -1).await?;
    for raw in items {
        if let Some(StoredCallInboxEvent {
            event: CallInboxEvent::Offer { call_id: cid, .. },
            ..
        }) = decode_stored(&raw)
        {
            if cid == call_id {
                // LREM count=0 removes all matching elements.
                let _ = client.lrem::<(), _, _>(&key, 0, raw).await;
            }
        }
    }
    Ok(())
}

pub async fn ack_call_event(
    client: &Client,
    user_id: &str,
    call_id: &str,
    kind: &str,
) -> Result<(), Error> {
    let key = inbox_key(user_id);
    let items: Vec<String> = client.lrange(&key, 0, -1).await?;
    for raw in items {
        if let Some(stored) = decode_stored(&raw) {
            if event_call_id(&stored.event) == call_id && event_kind(&stored.event) == kind {
                let _ = client.lrem::<(), _, _>(&key, 0, raw).await;
            }
        }
    }
    Ok(())
}

pub async fn has_call_event(
    client: &Client,
    user_id: &str,
    call_id: &str,
    kind: &str,
) -> Result<bool, Error> {
    let key = inbox_key(user_id);
    let items: Vec<String> = client.lrange(&key, 0, -1).await?;
    let now = now_ms();
    Ok(items.into_iter().any(|raw| {
        decode_stored(&raw)
            .map(|stored| {
                stored.expires_at_ms > now
                    && event_call_id(&stored.event) == call_id
                    && event_kind(&stored.event) == kind
            })
            .unwrap_or(false)
    }))
}

pub async fn peek_call_events(
    client: &Client,
    user_id: &str,
) -> Result<Vec<CallInboxEvent>, Error> {
    let key = inbox_key(user_id);
    let events: Vec<String> = client.lrange(&key, 0, -1).await?;

    // lpush stores newest first; replay oldest -> newest for client order.
    let mut ordered = events;
    ordered.reverse();
    let now = now_ms();

    let parsed = ordered
        .into_iter()
        .filter_map(|raw| decode_stored(&raw))
        .filter_map(|stored| {
            if stored.expires_at_ms > now {
                Some(stored.event)
            } else {
                None
            }
        })
        .collect();

    Ok(parsed)
}
