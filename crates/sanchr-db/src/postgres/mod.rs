pub mod backups;
pub mod contacts;
pub mod conversations;
pub mod devices;
pub mod keys;
pub mod media;
pub mod pending_registrations;
pub mod refresh_tokens;
pub mod settings;
pub mod users;

use sanchr_common::config::PostgresConfig;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn create_pool(config: &PostgresConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .connect(&config.url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(hashtext('sanchr_db_migrations')::bigint)")
        .execute(&mut *conn)
        .await?;

    let result = async {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            "#,
        )
        .execute(&mut *conn)
        .await?;

        let migrations = [
            (
                "001_initial_schema.sql",
                include_str!("../migrations/001_initial_schema.sql"),
            ),
            ("002_keys.sql", include_str!("../migrations/002_keys.sql")),
            (
                "003_conversations.sql",
                include_str!("../migrations/003_conversations.sql"),
            ),
            (
                "004_contacts.sql",
                include_str!("../migrations/004_contacts.sql"),
            ),
            (
                "005_backend_remediation.sql",
                include_str!("../migrations/005_backend_remediation.sql"),
            ),
            (
                "006_device_delivery_outbox.sql",
                include_str!("../migrations/006_device_delivery_outbox.sql"),
            ),
            (
                "007_backup_metadata.sql",
                include_str!("../migrations/007_backup_metadata.sql"),
            ),
            (
                "008_full_key_bundles.sql",
                include_str!("../migrations/008_full_key_bundles.sql"),
            ),
            (
                "009_presence_device_state.sql",
                include_str!("../migrations/009_presence_device_state.sql"),
            ),
            (
                "010_direct_conversations_unique_pairs.sql",
                include_str!("../migrations/010_direct_conversations_unique_pairs.sql"),
            ),
            (
                "011_refresh_tokens.sql",
                include_str!("../migrations/011_refresh_tokens.sql"),
            ),
            (
                "012_rename_sanchr_mode.sql",
                include_str!("../migrations/012_rename_sanchr_mode.sql"),
            ),
            (
                "013_performance_indexes.sql",
                include_str!("../migrations/013_performance_indexes.sql"),
            ),
            (
                "014_encrypted_profile.sql",
                include_str!("../migrations/014_encrypted_profile.sql"),
            ),
            (
                "015_drop_direct_conversations.sql",
                include_str!("../migrations/015_drop_direct_conversations.sql"),
            ),
            (
                "016_push_token_rotation.sql",
                include_str!("../migrations/016_push_token_rotation.sql"),
            ),
            (
                "017_registration_lock.sql",
                include_str!("../migrations/017_registration_lock.sql"),
            ),
            (
                "018_voip_push_token.sql",
                include_str!("../migrations/018_voip_push_token.sql"),
            ),
            (
                "019_conversation_device_notification_prefs.sql",
                include_str!("../migrations/019_conversation_device_notification_prefs.sql"),
            ),
        ];

        for (name, sql) in migrations {
            let already_applied: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM schema_migrations
                    WHERE name = $1
                )
                "#,
            )
            .bind(name)
            .fetch_one(&mut *conn)
            .await?;

            if already_applied {
                continue;
            }

            sqlx::raw_sql(sql).execute(&mut *conn).await?;
            sqlx::query(
                r#"
                INSERT INTO schema_migrations (name)
                VALUES ($1)
                ON CONFLICT (name) DO NOTHING
                "#,
            )
            .bind(name)
            .execute(&mut *conn)
            .await?;
        }

        Ok::<(), sqlx::Error>(())
    }
    .await;

    let unlock_result =
        sqlx::query("SELECT pg_advisory_unlock(hashtext('sanchr_db_migrations')::bigint)")
            .execute(&mut *conn)
            .await;

    result?;
    unlock_result?;
    tracing::info!("database migrations applied");
    Ok(())
}
