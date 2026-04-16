pub mod auxiliary;
pub mod calls;
pub mod messages;
pub mod outbox;
pub mod pending;
pub mod reactions;
pub mod receipts;
pub mod vault;

use sanchr_common::config::ScyllaConfig;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;

pub const SYNC_PAGE_SIZE: i32 = 100;
const DEVICE_OUTBOX_DEFAULT_TTL_SECS: i32 = 30 * 24 * 3600;

pub async fn create_session(config: &ScyllaConfig) -> Result<Session, Box<dyn std::error::Error>> {
    let session = SessionBuilder::new()
        .known_nodes(&config.nodes)
        .build()
        .await?;

    // Create keyspace
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': {}}}",
                config.keyspace, config.replication_factor
            ),
            &[],
        )
        .await?;

    session.use_keyspace(&config.keyspace, false).await?;

    // Create all tables
    create_tables(&session).await?;

    tracing::info!(keyspace = %config.keyspace, "ScyllaDB session created");
    Ok(session)
}

async fn create_tables(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS messages (
                conversation_id UUID,
                message_id TIMEUUID,
                sender_id UUID,
                sender_device INT,
                ciphertext BLOB,
                content_type TEXT,
                server_ts TIMESTAMP,
                expires_at TIMESTAMP,
                is_deleted BOOLEAN,
                edited_at TIMESTAMP,
                PRIMARY KEY (conversation_id, message_id)
            ) WITH CLUSTERING ORDER BY (message_id DESC)",
            &[],
        )
        .await?;

    // Idempotent migration: add edited_at to tables created before this
    // column existed.  ScyllaDB silently ignores the ALTER if the column is
    // already present (it returns an error for duplicate-column ADD, which we
    // suppress).
    let _ = session
        .query_unpaged("ALTER TABLE messages ADD edited_at TIMESTAMP", &[])
        .await;

    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS message_receipts (
                conversation_id UUID,
                message_id TIMEUUID,
                recipient_id UUID,
                status TEXT,
                status_at TIMESTAMP,
                PRIMARY KEY ((conversation_id, message_id), recipient_id)
            )",
            &[],
        )
        .await?;

    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS pending_messages (
                recipient_id UUID,
                recipient_device INT,
                message_id TIMEUUID,
                conversation_id UUID,
                sender_id UUID,
                ciphertext BLOB,
                content_type TEXT,
                server_ts TIMESTAMP,
                PRIMARY KEY ((recipient_id, recipient_device), message_id)
            ) WITH CLUSTERING ORDER BY (message_id ASC)
              AND default_time_to_live = 2592000",
            &[],
        )
        .await?;

    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS device_outbox (
                recipient_id UUID,
                recipient_device INT,
                message_id TIMEUUID,
                conversation_id UUID,
                sender_id UUID,
                sender_device INT,
                ciphertext BLOB,
                content_type TEXT,
                server_ts TIMESTAMP,
                expires_at TIMESTAMP,
                PRIMARY KEY ((recipient_id, recipient_device), message_id)
            ) WITH CLUSTERING ORDER BY (message_id ASC)
              AND default_time_to_live = 2592000",
            &[],
        )
        .await?;

    session
        .query_unpaged(
            format!(
                "ALTER TABLE device_outbox WITH default_time_to_live = {DEVICE_OUTBOX_DEFAULT_TTL_SECS}"
            ),
            &[],
        )
        .await?;

    // Forward-secure vault, Defense 2 compliant.
    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS vault_items (
                user_id UUID,
                vault_item_id UUID,
                media_id UUID,
                encrypted_metadata BLOB,
                created_at TIMESTAMP,
                expires_at TIMESTAMP,
                PRIMARY KEY ((user_id), vault_item_id)
            )",
            &[],
        )
        .await?;

    // Clustering order is `(DESC, DESC)` so that both columns traverse in
    // the same "newest first" direction. This matters for the fallback
    // pagination path: a `(created_at, vault_item_id) < (?, ?)` cursor
    // gets a deterministic tie-break when two rows share a `created_at`,
    // which avoids duplicate rows on page boundaries after LWT retries.
    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS vault_items_by_time (
                user_id UUID,
                created_at TIMESTAMP,
                vault_item_id UUID,
                media_id UUID,
                encrypted_metadata BLOB,
                expires_at TIMESTAMP,
                PRIMARY KEY ((user_id), created_at, vault_item_id)
            ) WITH CLUSTERING ORDER BY (created_at DESC, vault_item_id DESC)",
            &[],
        )
        .await?;

    // call_id is a regular UUID v4 (generated by Uuid::new_v4() in signaling.rs).
    // TIMEUUID was incorrect here — ScyllaDB rejects UUID v4 in a TIMEUUID column
    // ("Unsupported UUID version (4)"), causing every InitiateCall RPC to fail.
    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS call_logs (
                user_id UUID,
                call_id UUID,
                peer_id UUID,
                call_type TEXT,
                direction TEXT,
                status TEXT,
                started_at TIMESTAMP,
                ended_at TIMESTAMP,
                duration_secs INT,
                PRIMARY KEY (user_id, call_id)
            ) WITH CLUSTERING ORDER BY (call_id DESC)",
            &[],
        )
        .await?;

    auxiliary::create_auxiliary_table(session).await?;

    session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS reactions (
                conversation_id UUID,
                message_id TIMEUUID,
                user_id UUID,
                emoji TEXT,
                created_at TIMESTAMP,
                PRIMARY KEY ((conversation_id, message_id), user_id, emoji)
            )",
            &[],
        )
        .await?;

    Ok(())
}
