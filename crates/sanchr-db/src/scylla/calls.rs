use scylla::frame::value::CqlTimestamp;
use scylla::FromRow;
use scylla::Session;
use uuid::Uuid;

/// Row returned from the `call_logs` table.
#[derive(Debug, Clone, FromRow)]
pub struct CallLogRow {
    pub call_id: Uuid,
    pub peer_id: Uuid,
    pub call_type: String,
    pub direction: String,
    pub status: String,
    pub started_at: CqlTimestamp,
    pub ended_at: Option<CqlTimestamp>,
    pub duration_secs: Option<i32>,
}

/// Parameters for inserting a call log entry.
pub struct InsertCallLogParams<'a> {
    pub user_id: &'a Uuid,
    pub call_id: &'a Uuid,
    pub peer_id: &'a Uuid,
    pub call_type: &'a str,
    pub direction: &'a str,
    pub status: &'a str,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub duration_secs: Option<i32>,
}

/// Insert a new call log entry for a user.
pub async fn insert_call_log(
    session: &Session,
    params: &InsertCallLogParams<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    session
        .query_unpaged(
            "INSERT INTO call_logs (user_id, call_id, peer_id, call_type, direction, status, started_at, ended_at, duration_secs) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                params.user_id,
                params.call_id,
                params.peer_id,
                params.call_type,
                params.direction,
                params.status,
                CqlTimestamp(params.started_at_ms),
                params.ended_at_ms.map(CqlTimestamp),
                params.duration_secs,
            ),
        )
        .await?;
    Ok(())
}

/// Retrieve call history for a user, ordered by most recent first.
pub async fn get_call_history(
    session: &Session,
    user_id: &Uuid,
    limit: i32,
) -> Result<Vec<CallLogRow>, Box<dyn std::error::Error + Send + Sync>> {
    let result = session
        .query_unpaged(
            "SELECT call_id, peer_id, call_type, direction, status, started_at, ended_at, duration_secs \
             FROM call_logs WHERE user_id = ? LIMIT ?",
            (user_id, limit),
        )
        .await?;

    let rows = result
        .rows_typed::<CallLogRow>()?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Update a call's status, ended_at, and duration_secs.
pub async fn update_call_status(
    session: &Session,
    user_id: &Uuid,
    call_id: &Uuid,
    status: &str,
    ended_at_ms: i64,
    duration_secs: i32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    session
        .query_unpaged(
            "UPDATE call_logs SET status = ?, ended_at = ?, duration_secs = ? \
             WHERE user_id = ? AND call_id = ?",
            (
                status,
                CqlTimestamp(ended_at_ms),
                duration_secs,
                user_id,
                call_id,
            ),
        )
        .await?;
    Ok(())
}
