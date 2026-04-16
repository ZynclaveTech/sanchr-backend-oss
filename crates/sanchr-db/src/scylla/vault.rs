//! Scylla query helpers for the forward-secure vault.
//!
//! ## Schema
//!
//! Two tables, both partitioned by `user_id`, both carrying the same column set:
//! * `vault_items`          — point-lookup, `PRIMARY KEY ((user_id), vault_item_id)`
//! * `vault_items_by_time`  — time-ordered listing,
//!   `PRIMARY KEY ((user_id), created_at, vault_item_id)`
//!   with `CLUSTERING ORDER BY (created_at DESC, vault_item_id DESC)`
//!
//! Point lookups (`get_vault_item`) query only `vault_items`.
//! List queries (`list_vault_items`) query only `vault_items_by_time`.
//!
//! ## Atomic dual-table writes AND deletes
//!
//! Both tables must stay in sync: every row in `vault_items_by_time` must have
//! a matching row in `vault_items`, otherwise the listing query can return
//! rows that `get_vault_item` cannot resolve (and the reverse orphan is
//! equally bad — a row in `vault_items` that the listing query never sees).
//!
//! We therefore wrap BOTH inserts AND both deletes in single-partition
//! `BEGIN BATCH` statements so a crash between the two statements cannot
//! orphan a row. The partition key `user_id` is the same on both tables, so
//! every batch stays on a single shard and Scylla applies it atomically.
//! Insert atomicity closes the write-path orphan class; delete atomicity
//! closes the delete-path orphan class. There is no remaining path by which
//! the two tables can diverge under the normal CRUD flow.
//!
//! **Why not `IF NOT EXISTS` inside the BATCH?**  Scylla rejects LWT
//! conditions that span multiple tables with:
//! `"BATCH with conditions cannot span multiple tables"`.  Confirmed at
//! runtime on Scylla 5.4 against the sanchr keyspace during this rewrite.
//! We substitute a pre-flight point-read on `vault_items` to get the
//! "idempotent-hit" return value: if the row already exists we short-circuit
//! and return `Ok(false)`; otherwise we run the plain (non-LWT) batch and
//! return `Ok(true)`.  The check-then-act pattern is safe under the expected
//! single-writer-per-`vault_item_id` model, because the `vault_item_id` is a
//! fresh v4 UUID minted by the calling client on each new upload.
//!
//! ## Stale-replica retry window
//!
//! The pre-read → BATCH gap is NOT a consistency boundary. A retry that
//! arrives inside the replication window of its own first write can see
//! "no row" on the pre-read and re-run the BATCH. This is safe because
//! the retried payload is bytewise identical (same `media_id`, same
//! `encrypted_metadata`, same caller-computed `expires_at`), so the
//! second BATCH is a last-write-wins no-op overwrite. The only observable
//! effect is that `vault_create_idempotent_hit_total` under-counts fast
//! retries and `vault_create_total` over-counts by the same amount. The
//! row identity, row content, and list ordering are all unchanged.
//!
//! If stronger retry semantics are ever needed (e.g. if retries may
//! carry DIFFERENT payloads), upgrade the pre-read to `CL=SERIAL` or
//! move the primary-row insert out of the BATCH into an explicit LWT on
//! `vault_items` followed by a sequential `INSERT INTO vault_items_by_time`
//! that tolerates the write-path reconciliation window.
//!
//! ## Pagination
//!
//! Uses the native Scylla prepared-statement + `PagingState` API (available
//! in scylla-rs 0.14). List queries are served by a `PreparedStatement` so
//! the driver does not re-parse and re-plan the CQL on every page. The
//! opaque `paging_token` returned to callers is a URL-safe base64 encoding
//! of a one-byte version tag (`CURSOR_VERSION`) followed by the raw
//! driver-side `PagingState` bytes. An empty string on return means
//! "partition exhausted" (`NoMorePages`). The version tag exists to bound
//! the blast radius of a future scylla-rs upgrade that changes the paging
//! state encoding: decoding a stale cursor errors for one user instead of
//! crashing every in-flight page walk. See the encode/decode helpers
//! below for the exact format.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use scylla::client::session::Session;
use scylla::response::{PagingState, PagingStateResponse};
use scylla::statement::batch::{Batch, BatchType};
use scylla::value::CqlTimestamp;
use scylla::DeserializeRow;
use uuid::Uuid;

/// Version tag prepended to the raw `PagingState` bytes before base64
/// encoding when we hand a cursor back to callers, and checked on the
/// way back in. scylla-rs is pre-1.0 and does not guarantee wire stability
/// for `PagingState::as_bytes_slice()`, so a future driver upgrade could
/// silently change the byte layout. A 1-byte version tag bounds the blast
/// radius of that change to "one `paging_token version mismatch` error per
/// user, restart paging from empty" instead of "every live cursor crashes
/// on decode and every list call panics". Bump this constant whenever the
/// encoding changes in a way that old cursors cannot be decoded against
/// the new format.
const CURSOR_VERSION: u8 = 0x01;

/// Row returned from either the `vault_items` or `vault_items_by_time` table.
///
/// Field order MUST match the column order of the `SELECT` statements below
/// for `FromRow` to decode correctly.
#[derive(Debug, Clone, DeserializeRow)]
pub struct VaultItemRow {
    pub user_id: Uuid,
    pub vault_item_id: Uuid,
    pub media_id: Uuid,
    pub encrypted_metadata: Vec<u8>,
    pub created_at: CqlTimestamp,
    pub expires_at: CqlTimestamp,
}

const SELECT_COLS: &str =
    "user_id, vault_item_id, media_id, encrypted_metadata, created_at, expires_at";

/// Insert a vault item into BOTH tables atomically.
///
/// Returns:
/// * `Ok(true)`  — a new row was written
/// * `Ok(false)` — idempotent hit: `vault_items` already contained this
///   `(user_id, vault_item_id)`, no write was performed
///
/// See the module-level docs for why we use a plain BATCH with a pre-read
/// instead of `IF NOT EXISTS` inside the BATCH.
#[allow(clippy::too_many_arguments)]
pub async fn insert_vault_item(
    session: &Session,
    user_id: Uuid,
    vault_item_id: Uuid,
    media_id: Uuid,
    encrypted_metadata: &[u8],
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // SECURITY NOTE: this function trusts the caller's `vault_item_id`
    // to be a cryptographically random UUIDv4. A second caller who picks
    // the same UUID will silently overwrite the first — the pre-read
    // catches only the idempotent-retry case, not the collision case.
    // UUIDv4 gives ~122 bits of entropy, so the birthday-bound collision
    // probability inside a single `user_id` partition is negligible for
    // any realistic vault size.
    //
    // Step 1: pre-flight point-read on `vault_items` to detect idempotent
    // retries. We can't use `IF NOT EXISTS` inside the dual-table BATCH
    // because Scylla rejects LWT conditions that span multiple tables.
    let existing = session
        .query_unpaged(
            "SELECT vault_item_id FROM vault_items WHERE user_id = ? AND vault_item_id = ?",
            (user_id, vault_item_id),
        )
        .await?
        .into_rows_result()?;
    if existing.maybe_first_row::<(Uuid,)>()?.is_some() {
        return Ok(false);
    }

    // Step 2: single-partition BATCH writing to both tables.
    // Both tables are partitioned by `user_id`, so this is a single-shard
    // atomic write.  We explicitly use an UNLOGGED batch — single-partition
    // unlogged batches are atomic in Scylla and avoid the extra round-trip
    // the default LOGGED batch would pay.
    let created_at = CqlTimestamp(created_at_ms);
    let expires_at = CqlTimestamp(expires_at_ms);

    let mut batch = Batch::new(BatchType::Unlogged);
    batch.append_statement(
        "INSERT INTO vault_items \
         (user_id, vault_item_id, media_id, encrypted_metadata, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    );
    batch.append_statement(
        "INSERT INTO vault_items_by_time \
         (user_id, created_at, vault_item_id, media_id, encrypted_metadata, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    );

    // Each tuple is the parameter set for the corresponding statement above.
    // Note that the row order differs (vault_items_by_time has created_at
    // between user_id and vault_item_id because created_at is a clustering
    // key), so the value tuples must mirror the column order in each INSERT.
    session
        .batch(
            &batch,
            (
                (
                    user_id,
                    vault_item_id,
                    media_id,
                    encrypted_metadata.to_vec(),
                    created_at,
                    expires_at,
                ),
                (
                    user_id,
                    created_at,
                    vault_item_id,
                    media_id,
                    encrypted_metadata.to_vec(),
                    expires_at,
                ),
            ),
        )
        .await?;

    Ok(true)
}

/// Fetch a single vault item by its primary key.
///
/// Always targets `vault_items` — the point-lookup table. `None` is returned
/// if the row does not exist (either never inserted or already deleted).
pub async fn get_vault_item(
    session: &Session,
    user_id: Uuid,
    vault_item_id: Uuid,
) -> Result<Option<VaultItemRow>, Box<dyn std::error::Error>> {
    let result = session
        .query_unpaged(
            format!(
                "SELECT {SELECT_COLS} FROM vault_items \
                 WHERE user_id = ? AND vault_item_id = ?"
            ),
            (user_id, vault_item_id),
        )
        .await?
        .into_rows_result()?;

    let row = result.maybe_first_row::<VaultItemRow>()?;
    Ok(row)
}

/// List vault items for a user, newest first, using an opaque cursor.
///
/// Always targets `vault_items_by_time` — the clustering-order table.
///
/// * `limit` bounds the size of a single page
/// * `paging_token`:
///   - `None` or `Some("")` starts from the newest row
///   - `Some(cursor)` resumes from where the previous call ended
///
/// The returned tuple is `(rows, next_cursor)`. An empty `next_cursor`
/// string signals "no more pages" (partition exhausted).
pub async fn list_vault_items(
    session: &Session,
    user_id: Uuid,
    limit: i32,
    paging_token: Option<&str>,
) -> Result<(Vec<VaultItemRow>, String), Box<dyn std::error::Error>> {
    // Guard against callers passing `0`, negative values, or `i32::MAX`:
    // set_page_size would otherwise either trip a driver-side assertion at
    // runtime or ask Scylla to materialize an entire partition in a single
    // page. The clamp window (1..=100) matches the spec's page-size ceiling.
    let limit = limit.clamp(1, 100);

    // Decode the incoming cursor, if any.  An empty-string cursor is
    // treated the same as `None` — "start from the newest row". A non-empty
    // cursor must carry our `CURSOR_VERSION` tag; anything else is rejected
    // up-front with a descriptive error so the caller can restart paging
    // instead of triggering an opaque driver-side decode failure.
    let paging_state = match paging_token {
        None | Some("") => PagingState::start(),
        Some(cursor) => {
            let raw = URL_SAFE_NO_PAD.decode(cursor)?;
            let Some((&version, rest)) = raw.split_first() else {
                return Err("paging_token is empty after base64 decode".into());
            };
            if version != CURSOR_VERSION {
                return Err(format!(
                    "paging_token version mismatch: got 0x{version:02x}, \
                     expected 0x{CURSOR_VERSION:02x} — cursor was issued by \
                     an incompatible driver version, restart paging from empty"
                )
                .into());
            }
            PagingState::new_from_raw_bytes(rest.to_vec())
        }
    };

    // Use a prepared statement so the driver does not re-parse and re-plan
    // the CQL on every paging call. scylla-rs caches prepared statements
    // per-session internally, so a subsequent `prepare` of the same CQL
    // string is effectively free once the session has seen the statement.
    let mut prepared = session
        .prepare(format!(
            "SELECT {SELECT_COLS} FROM vault_items_by_time WHERE user_id = ?"
        ))
        .await?;
    prepared.set_page_size(limit);

    let (result, paging_state_response) = session
        .execute_single_page(&prepared, (user_id,), paging_state)
        .await?;

    let result = result.into_rows_result()?;
    let rows = result
        .rows::<VaultItemRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    let next_cursor = match paging_state_response {
        PagingStateResponse::HasMorePages { state } => state
            .as_bytes_slice()
            .map(|bytes| {
                // Prepend CURSOR_VERSION to the raw driver bytes before
                // base64-encoding. Decode path above checks the same tag.
                let raw: &[u8] = bytes.as_ref();
                let mut tagged = Vec::with_capacity(1 + raw.len());
                tagged.push(CURSOR_VERSION);
                tagged.extend_from_slice(raw);
                URL_SAFE_NO_PAD.encode(&tagged)
            })
            .unwrap_or_default(),
        PagingStateResponse::NoMorePages => String::new(),
    };

    Ok((rows, next_cursor))
}

/// Idempotently delete a vault item from BOTH tables atomically.
///
/// Missing rows are not an error: if the point-read on `vault_items` returns
/// nothing we return `Ok(())` without touching the secondary table. This
/// mirrors the Defense-2 design: deletion is a user intent, not a guarantee
/// that the row existed.
///
/// We cannot delete from `vault_items_by_time` using only `(user_id,
/// vault_item_id)` because `created_at` is part of its clustering key, so a
/// point read on `vault_items` is required to learn the timestamp first.
///
/// The two DELETEs are wrapped in a single-partition UNLOGGED BATCH so that
/// a crash between them cannot leave an orphan row in `vault_items_by_time`.
/// Both tables partition by `user_id` so the batch stays on a single shard
/// and is atomic at the commit-log layer. This closes the orphan class that
/// a sequential-delete implementation would otherwise leave for a future
/// reconciliation sweep to clean up.
pub async fn delete_vault_item(
    session: &Session,
    user_id: Uuid,
    vault_item_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    // Point-read `vault_items` to learn the `created_at` clustering key
    // required by the `vault_items_by_time` delete.
    let Some(row) = get_vault_item(session, user_id, vault_item_id).await? else {
        // Missing row is a success for an idempotent delete.
        return Ok(());
    };

    // Atomic dual-table delete via a single-partition UNLOGGED BATCH.
    // Both statements target the same `user_id` partition, so Scylla
    // applies them to the same shard in the same commit-log entry.
    let mut batch = Batch::new(BatchType::Unlogged);
    batch.append_statement("DELETE FROM vault_items WHERE user_id = ? AND vault_item_id = ?");
    batch.append_statement(
        "DELETE FROM vault_items_by_time \
         WHERE user_id = ? AND created_at = ? AND vault_item_id = ?",
    );

    session
        .batch(
            &batch,
            (
                (user_id, vault_item_id),
                (user_id, row.created_at, vault_item_id),
            ),
        )
        .await?;

    Ok(())
}
