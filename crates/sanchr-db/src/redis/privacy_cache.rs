use fred::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::postgres::contacts as pg_contacts;
use crate::postgres::settings as pg_settings;

/// Cached privacy flags per user. Stored in Redis with 5-minute TTL.
/// Format: "privacy:{user_id}" → JSON-encoded `PrivacyFlags`.
///
/// On cache miss, falls back to Postgres and populates the cache. Legacy
/// comma-separated entries written by earlier versions of this module are
/// still accepted on read (and transparently upgraded on the next refresh).
///
/// Settings or block-list changes should call `invalidate()` to force a
/// re-fetch.
const CACHE_TTL_SECS: i64 = 300; // 5 minutes

fn default_true() -> bool {
    true
}

fn default_visibility() -> String {
    "everyone".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyFlags {
    #[serde(default = "default_true")]
    pub read_receipts: bool,
    #[serde(default = "default_true")]
    pub typing_indicator: bool,
    #[serde(default = "default_true")]
    pub online_status_visible: bool,
    #[serde(default)]
    pub sanchr_mode_enabled: bool,
    #[serde(default = "default_visibility")]
    pub profile_photo_visibility: String,
    #[serde(default)]
    pub blocked_user_ids: Vec<String>,
}

impl Default for PrivacyFlags {
    fn default() -> Self {
        Self {
            read_receipts: true,
            typing_indicator: true,
            online_status_visible: true,
            sanchr_mode_enabled: false,
            profile_photo_visibility: default_visibility(),
            blocked_user_ids: Vec::new(),
        }
    }
}

impl PrivacyFlags {
    /// Returns true if read receipts should be forwarded for this user.
    pub fn can_forward_read_receipts(&self) -> bool {
        self.read_receipts && !self.sanchr_mode_enabled
    }

    /// Returns true if typing indicators should be broadcast for this user.
    pub fn can_forward_typing(&self) -> bool {
        self.typing_indicator && !self.sanchr_mode_enabled
    }

    /// Returns true if this user has blocked the given sender. Exact (case
    /// sensitive) match against the canonical UUID strings stored in the
    /// contacts table.
    pub fn is_blocking(&self, sender_id: &str) -> bool {
        self.blocked_user_ids.iter().any(|id| id == sender_id)
    }

    fn to_cache_string(&self) -> String {
        // serde_json is infallible for this pure data struct; fall back to
        // an empty JSON object on the unreachable error path so the cache
        // write doesn't panic.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    fn from_cache_string(s: &str) -> Option<Self> {
        // Preferred: JSON (new format, supports all 6 fields).
        if let Ok(flags) = serde_json::from_str::<Self>(s) {
            return Some(flags);
        }

        // Legacy: comma-separated 4-field format written by earlier
        // versions. Accepted on read so the Phase 2 rollout doesn't require
        // a cache flush; the next refresh re-writes as JSON.
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() == 4 {
            return Some(PrivacyFlags {
                read_receipts: parts[0] == "1",
                typing_indicator: parts[1] == "1",
                online_status_visible: parts[2] == "1",
                sanchr_mode_enabled: parts[3] == "1",
                profile_photo_visibility: default_visibility(),
                blocked_user_ids: Vec::new(),
            });
        }

        None
    }
}

fn cache_key(user_id: &Uuid) -> String {
    format!("privacy:{}", user_id)
}

/// Get privacy flags for a user. Tries Redis first, falls back to Postgres.
/// On Postgres fetch, caches the result in Redis with 5-minute TTL.
pub async fn get_privacy_flags(
    redis: &RedisClient,
    pg_pool: &PgPool,
    user_id: Uuid,
) -> Result<PrivacyFlags, String> {
    let key = cache_key(&user_id);

    // Try Redis cache first
    match redis.get::<Option<String>, _>(&key).await {
        Ok(Some(cached)) => {
            if let Some(flags) = PrivacyFlags::from_cache_string(&cached) {
                return Ok(flags);
            }
            // Cache corrupted, fall through to Postgres
        }
        Ok(None) => {} // Cache miss, fall through
        Err(e) => {
            tracing::warn!(%user_id, error = %e, "Redis privacy cache read failed, falling back to Postgres");
        }
    }

    // Fetch from Postgres
    let settings = match pg_settings::get_settings(pg_pool, user_id).await {
        Ok(s) => s,
        Err(sqlx::Error::RowNotFound) => {
            // No settings row yet — return permissive defaults. This can happen
            // when a registration completed the `users` insert but the settings
            // insert was rolled back or not yet committed (e.g. a partial
            // failure during OTP verify). Rather than surfacing an INTERNAL
            // error to every caller that tries to look up this user's privacy
            // flags, we return the same defaults that `ensure_user_settings_row`
            // would have inserted anyway.
            tracing::debug!(%user_id, "no user_settings row found, returning defaults");
            return Ok(PrivacyFlags::default());
        }
        Err(e) => return Err(format!("failed to fetch settings: {e}")),
    };

    let blocked_uuids = pg_contacts::get_blocked_list(pg_pool, user_id)
        .await
        .map_err(|e| format!("failed to fetch blocked list: {e}"))?;

    let flags = PrivacyFlags {
        read_receipts: settings.read_receipts.unwrap_or(true),
        typing_indicator: settings.typing_indicator.unwrap_or(true),
        online_status_visible: settings.online_status_visible.unwrap_or(true),
        sanchr_mode_enabled: settings.sanchr_mode_enabled.unwrap_or(false),
        profile_photo_visibility: settings
            .profile_photo_visibility
            .unwrap_or_else(default_visibility),
        blocked_user_ids: blocked_uuids.into_iter().map(|id| id.to_string()).collect(),
    };

    // Cache in Redis (best-effort, don't fail if Redis is down)
    let _ = redis
        .set::<(), _, _>(
            &key,
            flags.to_cache_string(),
            Some(Expiration::EX(CACHE_TTL_SECS)),
            None,
            false,
        )
        .await;

    Ok(flags)
}

/// Invalidate the cached privacy flags for a user.
/// Call this when settings are updated.
pub async fn invalidate(redis: &RedisClient, user_id: &Uuid) {
    let key = cache_key(user_id);
    let _ = redis.del::<(), _>(&key).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_blocking_empty_list() {
        let flags = PrivacyFlags {
            read_receipts: true,
            typing_indicator: true,
            online_status_visible: true,
            sanchr_mode_enabled: false,
            profile_photo_visibility: "everyone".to_string(),
            blocked_user_ids: vec![],
        };
        assert!(!flags.is_blocking("any_user"));
    }

    #[test]
    fn test_is_blocking_positive_match() {
        let flags = PrivacyFlags {
            read_receipts: true,
            typing_indicator: true,
            online_status_visible: true,
            sanchr_mode_enabled: false,
            profile_photo_visibility: "everyone".to_string(),
            blocked_user_ids: vec!["alice".to_string(), "bob".to_string()],
        };
        assert!(flags.is_blocking("alice"));
        assert!(flags.is_blocking("bob"));
        assert!(!flags.is_blocking("charlie"));
    }

    #[test]
    fn test_is_blocking_case_sensitive() {
        let flags = PrivacyFlags {
            read_receipts: true,
            typing_indicator: true,
            online_status_visible: true,
            sanchr_mode_enabled: false,
            profile_photo_visibility: "everyone".to_string(),
            blocked_user_ids: vec!["Alice".to_string()],
        };
        assert!(!flags.is_blocking("alice"));
        assert!(flags.is_blocking("Alice"));
    }

    #[test]
    fn test_default_flags_are_permissive() {
        let flags = PrivacyFlags::default();
        assert!(flags.read_receipts);
        assert!(flags.typing_indicator);
        assert!(flags.online_status_visible);
        assert!(!flags.sanchr_mode_enabled);
        assert_eq!(flags.profile_photo_visibility, "everyone");
        assert!(flags.blocked_user_ids.is_empty());
    }
}
