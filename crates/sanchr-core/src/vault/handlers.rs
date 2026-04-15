//! Handlers for the forward-secure VaultService.
//!
//! Contract: the server never sees a plaintext AES key, metadata is an opaque
//! AES-GCM blob, `vault_item_id` is client-generated UUIDv4 for crash-recovery
//! idempotency, and pagination uses Scylla's native paging state via the
//! opaque `paging_token` cursor.

use std::sync::Arc;

use metrics::counter;
use tonic::Status;
use uuid::Uuid;

use sanchr_common::errors::internal_status;
use sanchr_db::postgres::media as pg_media;
use sanchr_db::scylla::vault as scylla_vault;
use sanchr_db::scylla::vault::VaultItemRow;

use sanchr_proto::vault::{
    CreateVaultItemRequest, DeleteVaultItemResponse, GetVaultItemsRequest, GetVaultItemsResponse,
    VaultItem,
};

use crate::server::AppState;

/// Maximum size of the opaque `encrypted_metadata` blob. Enforced here as a
/// hard server-side validation; exceeding returns `INVALID_ARGUMENT`.
const MAX_ENCRYPTED_METADATA_BYTES: usize = 64 * 1024;

/// Create a new vault item. Idempotent on `(user_id, vault_item_id)`: a retry
/// with the same ID returns the existing row instead of creating a duplicate.
pub async fn handle_create_vault_item(
    state: &Arc<AppState>,
    user_id: Uuid,
    req: &CreateVaultItemRequest,
) -> Result<VaultItem, Status> {
    // Parse the two UUIDs from the wire.
    let vault_item_id = Uuid::parse_str(&req.vault_item_id)
        .map_err(|_| Status::invalid_argument("vault_item_id must be a valid UUID"))?;
    let media_id = Uuid::parse_str(&req.media_id)
        .map_err(|_| Status::invalid_argument("media_id must be a valid UUID"))?;

    // Validate encrypted_metadata size. The server never inspects the
    // contents — it only caps the length.
    if req.encrypted_metadata.is_empty() {
        return Err(Status::invalid_argument(
            "encrypted_metadata must not be empty",
        ));
    }
    if req.encrypted_metadata.len() > MAX_ENCRYPTED_METADATA_BYTES {
        return Err(Status::invalid_argument(format!(
            "encrypted_metadata exceeds {} bytes",
            MAX_ENCRYPTED_METADATA_BYTES
        )));
    }

    // Media ownership check. The caller MUST own the referenced media_id.
    // Anything else — not found, or owned by someone else — returns
    // PermissionDenied to prevent cross-user enumeration.
    let owned = pg_media::is_owned_by(&state.pg_pool, user_id, media_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "is_owned_by failed on create_vault_item");
            Status::unavailable("media metadata temporarily unavailable")
        })?;
    if !owned {
        // Structured log so an incident responder can attribute the denial
        // to a specific (user_id, media_id) pair. The metric counts events;
        // this log names them.
        tracing::warn!(
            target: "security",
            %user_id,
            %media_id,
            "media ownership denied on create_vault_item"
        );
        counter!("media_ownership_denied_total").increment(1);
        return Err(Status::permission_denied("media_id not owned by caller"));
    }

    // Idempotent dual-table insert via the scylla helper. `chrono::Utc`
    // matches the timestamp convention used across the rest of sanchr-core
    // (presence, auth, discovery) and is fail-safe against pre-epoch
    // clocks — the prior SystemTime::now().duration_since(UNIX_EPOCH)
    // pattern would silently substitute 0 on a skewed clock, stamping
    // rows with a 1970 timestamp and sorting them to the end of the
    // by_time listing forever.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let inserted = scylla_vault::insert_vault_item(
        &state.scylla,
        user_id,
        vault_item_id,
        media_id,
        &req.encrypted_metadata,
        now_ms,
        req.expires_at,
    )
    .await
    .map_err(|e| internal_status("insert_vault_item failed", e))?;

    if !inserted {
        // Idempotent hit: the row already exists from a prior call with the
        // same vault_item_id. Load the existing row and return it unchanged.
        counter!("vault_create_idempotent_hit_total").increment(1);
        return match scylla_vault::get_vault_item(&state.scylla, user_id, vault_item_id)
            .await
            .map_err(|e| internal_status("get_vault_item failed after idempotent hit", e))?
        {
            Some(row) => Ok(row_to_proto(row)),
            None => Err(internal_status(
                "idempotent hit reported but row missing on re-read",
                "missing row",
            )),
        };
    }

    counter!("vault_create_total").increment(1);
    Ok(VaultItem {
        vault_item_id: req.vault_item_id.clone(),
        media_id: req.media_id.clone(),
        encrypted_metadata: req.encrypted_metadata.clone(),
        created_at: now_ms,
        expires_at: req.expires_at,
    })
}

/// List a user's vault items, newest first, with Scylla-native pagination.
pub async fn handle_get_vault_items(
    state: &Arc<AppState>,
    user_id: Uuid,
    req: &GetVaultItemsRequest,
) -> Result<GetVaultItemsResponse, Status> {
    // Wire contract: limit is 1..=100, with 0/negative defaulting to 20.
    // The helper also clamps to [1, 100] as defense-in-depth, but enforcing
    // the wire contract HERE — at the handler, closest to the proto — keeps
    // the invariant visible to any reader of the handler and matches the
    // comment on `GetVaultItemsRequest.limit` in vault.proto.
    let limit = if req.limit <= 0 {
        20
    } else {
        req.limit.min(100)
    };

    let paging_token = if req.paging_token.is_empty() {
        None
    } else {
        Some(req.paging_token.as_str())
    };

    let (rows, next_cursor) =
        scylla_vault::list_vault_items(&state.scylla, user_id, limit, paging_token)
            .await
            .map_err(|e| internal_status("list_vault_items failed", e))?;

    counter!("vault_get_total").increment(1);

    Ok(GetVaultItemsResponse {
        items: rows.into_iter().map(row_to_proto).collect(),
        next_cursor,
    })
}

/// Point read for a single vault item. Returns PermissionDenied — NOT
/// NotFound — on miss, so a caller cannot enumerate other users'
/// vault_item_ids by guessing UUIDs.
pub async fn handle_get_vault_item(
    state: &Arc<AppState>,
    user_id: Uuid,
    vault_item_id_str: &str,
) -> Result<VaultItem, Status> {
    let vault_item_id = Uuid::parse_str(vault_item_id_str)
        .map_err(|_| Status::invalid_argument("vault_item_id must be a valid UUID"))?;

    let row = scylla_vault::get_vault_item(&state.scylla, user_id, vault_item_id)
        .await
        .map_err(|e| internal_status("get_vault_item failed", e))?;

    counter!("vault_get_item_total").increment(1);

    match row {
        Some(row) => Ok(row_to_proto(row)),
        None => Err(Status::permission_denied("vault item not accessible")),
    }
}

/// Delete a vault item. Idempotent: deleting a missing row is a no-op
/// returning success.
pub async fn handle_delete_vault_item(
    state: &Arc<AppState>,
    user_id: Uuid,
    vault_item_id_str: &str,
) -> Result<DeleteVaultItemResponse, Status> {
    let vault_item_id = Uuid::parse_str(vault_item_id_str)
        .map_err(|_| Status::invalid_argument("vault_item_id must be a valid UUID"))?;

    scylla_vault::delete_vault_item(&state.scylla, user_id, vault_item_id)
        .await
        .map_err(|e| internal_status("delete_vault_item failed", e))?;

    counter!("vault_delete_total").increment(1);
    Ok(DeleteVaultItemResponse {})
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn row_to_proto(row: VaultItemRow) -> VaultItem {
    VaultItem {
        vault_item_id: row.vault_item_id.to_string(),
        media_id: row.media_id.to_string(),
        encrypted_metadata: row.encrypted_metadata,
        created_at: row.created_at.0,
        expires_at: row.expires_at.0,
    }
}
