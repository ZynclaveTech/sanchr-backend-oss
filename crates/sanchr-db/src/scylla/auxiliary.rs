// ScyllaDB data-access layer for the Ephemeral Key Framework (EKF).
//
// Table layout:
//   auxiliary_state
//     PRIMARY KEY ((user_id, class), entry_id)
//
// A secondary index on `class` enables the lifecycle manager to scan for
// expired entries across all users for a given key class without a full-table
// scan.

use scylla::client::session::Session;
use scylla::value::CqlTimestamp;
use scylla::DeserializeRow;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

/// A row returned by [`fetch_expired_entries`].
#[derive(Debug, Clone, DeserializeRow)]
pub struct ExpiredEntryRow {
    pub user_id: Uuid,
    pub entry_id: Uuid,
    pub class: String,
    pub policy: String,
    pub material: Vec<u8>,
    /// Milliseconds since the Unix epoch — matches the ScyllaDB TIMESTAMP wire
    /// encoding.
    pub created_at_ms: i64,
    pub ttl_secs: i64,
}

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

/// Create the `auxiliary_state` table and its secondary index if they do not
/// already exist, then apply table properties for efficient delete-heavy
/// workloads.
///
/// ## Table property rationale
/// - `gc_grace_seconds = 0`: The EKF lifecycle manager deletes expired rows
///   frequently. With the default 10-day grace period, tombstones would
///   accumulate for 10 days before compaction could reclaim them. Setting it
///   to 0 lets ScyllaDB compact tombstones away immediately after the next
///   compaction cycle, keeping the table lean.
/// - `SizeTieredCompactionStrategy`: Well-suited for write-heavy tables with
///   infrequent reads; triggers compaction when similarly-sized SSTables
///   accumulate, which is the typical pattern for EKF entries.
///
/// The `ALTER TABLE` runs on every startup and is idempotent — it applies the
/// same properties to existing tables on upgrade, not just fresh installations.
pub async fn create_auxiliary_table(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS auxiliary_state (
                user_id    UUID,
                class      TEXT,
                entry_id   UUID,
                policy     TEXT,
                material   BLOB,
                created_at TIMESTAMP,
                ttl_secs   BIGINT,
                PRIMARY KEY ((user_id, class), entry_id)
            ) WITH gc_grace_seconds = 0
              AND compaction = {'class': 'SizeTieredCompactionStrategy'}",
            &[],
        )
        .await?;

    // Best-effort: apply gc_grace_seconds = 0 to tables created before this
    // DDL was in place. ScyllaDB forbids setting gc_grace_seconds to 0 once a
    // secondary index (internal materialized view) exists on the table, so we
    // treat a failure here as a warning rather than a fatal error. The table
    // already has the correct setting from its CREATE TABLE statement for any
    // installation where the index was added after the table was first created.
    if let Err(e) = session
        .query_unpaged(
            "ALTER TABLE auxiliary_state \
             WITH gc_grace_seconds = 0 \
             AND compaction = {'class': 'SizeTieredCompactionStrategy'}",
            &[],
        )
        .await
    {
        tracing::warn!(
            error = %e,
            "ALTER TABLE auxiliary_state gc_grace_seconds skipped \
             (expected when a secondary index exists on the table)"
        );
    }

    session
        .query_unpaged(
            "CREATE INDEX IF NOT EXISTS auxiliary_state_class_idx \
             ON auxiliary_state (class)",
            &[],
        )
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Insert a new entry into `auxiliary_state`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_entry(
    session: &Session,
    user_id: Uuid,
    entry_id: Uuid,
    class: &str,
    policy: &str,
    material: &[u8],
    created_at_ms: i64,
    ttl_secs: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "INSERT INTO auxiliary_state \
             (user_id, class, entry_id, policy, material, created_at, ttl_secs) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                class.to_owned(),
                entry_id,
                policy.to_owned(),
                material.to_vec(),
                CqlTimestamp(created_at_ms),
                ttl_secs,
            ),
        )
        .await?;

    Ok(())
}

/// Delete a single entry by its full primary key.
pub async fn delete_entry(
    session: &Session,
    user_id: Uuid,
    class: &str,
    entry_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "DELETE FROM auxiliary_state \
             WHERE user_id = ? AND class = ? AND entry_id = ?",
            (user_id, class.to_owned(), entry_id),
        )
        .await?;

    Ok(())
}

/// Zero-fill the `material` column of an entry and reset `created_at`.
///
/// Used by the `Overwrite` expiry policy: the row is retained for audit
/// purposes but the key material is replaced with a 32-byte zero sentinel.
pub async fn overwrite_entry(
    session: &Session,
    user_id: Uuid,
    class: &str,
    entry_id: Uuid,
    null_sentinel: &[u8],
    new_created_at_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "UPDATE auxiliary_state \
             SET material = ?, created_at = ? \
             WHERE user_id = ? AND class = ? AND entry_id = ?",
            (
                null_sentinel.to_vec(),
                CqlTimestamp(new_created_at_ms),
                user_id,
                class.to_owned(),
                entry_id,
            ),
        )
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Fetch all entries for a given key `class` and return those whose age
/// exceeds their `ttl_secs`.
///
/// The filtering of stale rows is done in application code after a full-class
/// scan, which is acceptable because the secondary index on `class` keeps
/// the scan partition-local on small-to-medium deployments.  A `ALLOW
/// FILTERING` hint is required because the secondary index is on a
/// non-primary-key column.
pub async fn fetch_expired_entries(
    session: &Session,
    class: &str,
    now_millis: i64,
) -> Result<Vec<ExpiredEntryRow>, Box<dyn std::error::Error>> {
    // Row layout returned by the SELECT must match `ExpiredEntryRow` field order.
    let result = session
        .query_unpaged(
            "SELECT user_id, entry_id, class, policy, material, created_at, ttl_secs \
             FROM auxiliary_state \
             WHERE class = ? \
             ALLOW FILTERING",
            (class.to_owned(),),
        )
        .await?
        .into_rows_result()?;

    // `created_at` is a ScyllaDB TIMESTAMP which arrives as CqlTimestamp(i64).
    // We need to unpack the inner i64 manually since CqlTimestamp does not
    // implement the same FromCqlVal path as a plain i64.  We therefore read it
    // as a typed tuple and convert.
    type RawRow = (Uuid, Uuid, String, String, Vec<u8>, CqlTimestamp, i64);

    let all_rows: Vec<ExpiredEntryRow> = result
        .rows::<RawRow>()?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(
            |(user_id, entry_id, class, policy, material, created_at, ttl_secs)| ExpiredEntryRow {
                user_id,
                entry_id,
                class,
                policy,
                material,
                created_at_ms: created_at.0,
                ttl_secs,
            },
        )
        .collect();

    // Application-level age filter: age = now - created_at > ttl_secs.
    let expired = all_rows
        .into_iter()
        .filter(|row| {
            let age_ms = now_millis.saturating_sub(row.created_at_ms);
            let age_secs = age_ms / 1_000;
            age_secs > row.ttl_secs
        })
        .collect();

    Ok(expired)
}
