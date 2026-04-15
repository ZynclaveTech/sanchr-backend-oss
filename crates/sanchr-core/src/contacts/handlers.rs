use std::collections::HashMap;
use std::sync::Arc;

use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::contacts as pg_contacts;
use sanchr_db::redis::privacy_cache::{self, PrivacyFlags};
use sanchr_db::redis::rate_limit;
use sanchr_proto::contacts::{Contact, MatchedContact};

use crate::privacy;
use crate::server::AppState;

pub const MAX_CONTACT_HASHES_PER_SYNC: usize = 10_000;

/// Hash-match phone contacts against registered users and persist as contacts.
pub async fn handle_sync_contacts(
    state: &Arc<AppState>,
    user_id: Uuid,
    phone_hashes: Vec<Vec<u8>>,
) -> Result<Vec<MatchedContact>, Status> {
    if phone_hashes.len() > MAX_CONTACT_HASHES_PER_SYNC {
        return Err(Status::invalid_argument(format!(
            "phone_hashes exceeds maximum of {MAX_CONTACT_HASHES_PER_SYNC}"
        )));
    }

    // Rate limit: max 10 sync requests per hour
    let rate_key = format!("rate:sync_contacts:{}", user_id);
    rate_limit::check_rate_limit(&state.redis, &rate_key, 10, 3600)
        .await
        .map_err(|e| match e {
            sanchr_common::errors::AppError::RateLimited => {
                Status::resource_exhausted("contact sync rate limited")
            }
            other => internal_status("rate limit check failed", other),
        })?;

    let matched = pg_contacts::sync_contacts(&state.pg_pool, user_id, &phone_hashes)
        .await
        .map_err(|e| internal_status("sync_contacts failed", e))?;

    // Phase 2 avatar visibility enforcement: cache PrivacyFlags lookups across
    // the whole response so the same owner appearing multiple times only
    // triggers one Redis/Postgres round trip per call. The cache is per-request
    // — long-lived caching lives in privacy_cache itself.
    let mut flags_cache: HashMap<Uuid, PrivacyFlags> = HashMap::new();

    let mut results = Vec::with_capacity(matched.len());
    for m in matched {
        let owner_id = m.id;
        let avatar_url = if owner_id == user_id {
            // Caller sees their own avatar untouched. In a contact-sync result
            // this is unusual (you wouldn't sync your own number), but we
            // skip the privacy_cache hit defensively.
            m.avatar_url.unwrap_or_default()
        } else {
            let flags = match flags_cache.get(&owner_id) {
                Some(f) => f.clone(),
                None => {
                    let f =
                        privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, owner_id)
                            .await
                            .map_err(|e| internal_status("privacy cache", e))?;
                    flags_cache.insert(owner_id, f.clone());
                    f
                }
            };
            privacy::avatar::filter_avatar_url(
                &state.pg_pool,
                &flags.profile_photo_visibility,
                owner_id,
                user_id,
                m.avatar_url,
            )
            .await
        };
        results.push(MatchedContact {
            user_id: owner_id.to_string(),
            display_name: m.display_name,
            avatar_url,
            status_text: m.status_text.unwrap_or_default(),
            phone_number: m.phone_number,
            profile_key: m.profile_key.unwrap_or_default(),
            encrypted_display_name: m.encrypted_display_name.unwrap_or_default(),
            encrypted_bio: m.encrypted_bio.unwrap_or_default(),
            encrypted_avatar_url: m.encrypted_avatar_url.unwrap_or_default(),
        });
    }

    Ok(results)
}

/// Return the full contact list for the authenticated user.
pub async fn handle_get_contacts(
    state: &Arc<AppState>,
    user_id: Uuid,
) -> Result<Vec<Contact>, Status> {
    let contacts = pg_contacts::get_contacts(&state.pg_pool, user_id)
        .await
        .map_err(|e| internal_status("get_contacts failed", e))?;

    // Phase 2 avatar visibility enforcement: per-request HashMap cache so we
    // hit privacy_cache at most once per contact. The PRIMARY KEY on
    // (user_id, contact_user_id) means each owner appears at most once in
    // this list, but we keep the cache for symmetry with the messaging
    // handlers and to insulate from any future schema change.
    let mut flags_cache: HashMap<Uuid, PrivacyFlags> = HashMap::new();

    let mut results = Vec::with_capacity(contacts.len());
    for c in contacts {
        let owner_id = c.contact_user_id;
        let avatar_url = if owner_id == user_id {
            c.avatar_url.unwrap_or_default()
        } else {
            let flags = match flags_cache.get(&owner_id) {
                Some(f) => f.clone(),
                None => {
                    let f =
                        privacy_cache::get_privacy_flags(&state.redis, &state.pg_pool, owner_id)
                            .await
                            .map_err(|e| internal_status("privacy cache", e))?;
                    flags_cache.insert(owner_id, f.clone());
                    f
                }
            };
            privacy::avatar::filter_avatar_url(
                &state.pg_pool,
                &flags.profile_photo_visibility,
                owner_id,
                user_id,
                c.avatar_url,
            )
            .await
        };
        results.push(Contact {
            user_id: owner_id.to_string(),
            display_name: c.display_name,
            avatar_url,
            status_text: c.status_text.unwrap_or_default(),
            is_blocked: c.is_blocked.unwrap_or(false),
            is_favorite: c.is_favorite.unwrap_or(false),
            phone_number: c.phone_number,
            profile_key: c.profile_key.unwrap_or_default(),
            encrypted_display_name: c.encrypted_display_name.unwrap_or_default(),
            encrypted_bio: c.encrypted_bio.unwrap_or_default(),
            encrypted_avatar_url: c.encrypted_avatar_url.unwrap_or_default(),
        });
    }

    Ok(results)
}

/// Block a contact.
pub async fn handle_block_contact(
    state: &Arc<AppState>,
    user_id: Uuid,
    contact_user_id: Uuid,
) -> Result<(), Status> {
    pg_contacts::block_contact(&state.pg_pool, user_id, contact_user_id)
        .await
        .map_err(|e| internal_status("block_contact failed", e))?;

    // Phase 2: invalidate privacy cache so the new block takes effect
    // immediately instead of waiting for the 5-minute TTL. Fire-and-forget —
    // if Redis is unavailable, the Postgres write still succeeds and the
    // cache self-heals on TTL expiry.
    privacy_cache::invalidate(&state.redis, &user_id).await;
    Ok(())
}

/// Unblock a contact.
pub async fn handle_unblock_contact(
    state: &Arc<AppState>,
    user_id: Uuid,
    contact_user_id: Uuid,
) -> Result<(), Status> {
    pg_contacts::unblock_contact(&state.pg_pool, user_id, contact_user_id)
        .await
        .map_err(|e| internal_status("unblock_contact failed", e))?;

    // Phase 2: invalidate privacy cache so the unblock takes effect
    // immediately instead of waiting for the 5-minute TTL. Fire-and-forget —
    // if Redis is unavailable, the Postgres write still succeeds and the
    // cache self-heals on TTL expiry.
    privacy_cache::invalidate(&state.redis, &user_id).await;
    Ok(())
}

/// Return all blocked user IDs.
pub async fn handle_get_blocked_list(
    state: &Arc<AppState>,
    user_id: Uuid,
) -> Result<Vec<String>, Status> {
    let blocked = pg_contacts::get_blocked_list(&state.pg_pool, user_id)
        .await
        .map_err(|e| internal_status("get_blocked_list failed", e))?;

    Ok(blocked.into_iter().map(|id| id.to_string()).collect())
}
