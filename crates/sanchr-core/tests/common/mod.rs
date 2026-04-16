use std::sync::Arc;

use uuid::Uuid;

use sanchr_common::config::AppConfig;
use sanchr_db::postgres;
use sanchr_db::redis;
use sanchr_server_crypto::jwt::JwtManager;

/// Setup shared state for integration tests.
/// Requires docker-compose services running (Postgres, Redis, ScyllaDB, NATS, MinIO).
pub async fn setup_test_state() -> Arc<sanchr_core::server::AppState> {
    // Cargo sets CARGO_MANIFEST_DIR to the crate root during tests. Change to
    // the workspace root so AppConfig::load() can pick up optional config/*
    // files or SANCHR__ env overrides from the repository root.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent() // -> crates/
        .and_then(|p| p.parent()) // -> backend/
        .expect("could not determine workspace root");
    std::env::set_current_dir(workspace_root).expect("failed to set cwd to workspace root");

    // Load config from optional config files and environment variables.
    let config = AppConfig::load().expect("failed to load test config");

    let pg_pool = postgres::create_pool(&config.database.postgres)
        .await
        .expect("failed to create pg pool");

    postgres::run_migrations(&pg_pool)
        .await
        .expect("failed to run migrations");

    let redis_client = redis::create_client(&config.database.redis)
        .await
        .expect("failed to create redis client");

    let scylla_session = sanchr_db::scylla::create_session(&config.database.scylla)
        .await
        .expect("failed to create scylla session");

    let nats_client = async_nats::connect(&config.database.nats.url)
        .await
        .expect("failed to connect to NATS");

    // S3 client (MinIO)
    let s3_creds = aws_credential_types::Credentials::new(
        &config.storage.access_key,
        &config.storage.secret_key,
        None,
        None,
        "test",
    );
    let s3_config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(
            config.storage.region.clone(),
        ))
        .endpoint_url(&config.storage.endpoint)
        .credentials_provider(s3_creds)
        .force_path_style(true)
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(s3_config);
    if s3_client
        .head_bucket()
        .bucket(&config.storage.bucket)
        .send()
        .await
        .is_err()
    {
        if let Err(error) = s3_client
            .create_bucket()
            .bucket(&config.storage.bucket)
            .send()
            .await
        {
            let message = error.to_string();
            if !message.contains("BucketAlreadyOwnedByYou")
                && !message.contains("BucketAlreadyExists")
            {
                panic!("failed to create test bucket: {error:?}");
            }
        }
    }

    let jwt = JwtManager::new(config.auth.jwt_secret.as_bytes());
    let stream_mgr = Arc::new(sanchr_core::messaging::stream::StreamManager::new());

    let metrics_handle = sanchr_core::observability::metrics::init_metrics()
        .expect("failed to initialize test metrics recorder");

    let sealed_sender_signer =
        Arc::new(sanchr_server_crypto::sealed_sender::SealedSenderSigner::generate(1));

    let crypto_provider: Arc<dyn sanchr_server_crypto::provider::CryptoProvider> = Arc::new(
        sanchr_server_crypto::local_provider::LocalCryptoProvider::new(
            JwtManager::new(config.auth.jwt_secret.as_bytes()),
            config.auth.otp_secret.clone(),
            config.auth.otp_ttl,
            Arc::clone(&sealed_sender_signer),
            config.calling.turn_secret.clone(),
        ),
    );

    Arc::new(sanchr_core::server::AppState {
        config,
        pg_pool,
        redis: redis_client,
        jwt,
        scylla: scylla_session,
        nats: nats_client,
        stream_mgr,
        s3: s3_client,
        metrics_handle,
        oprf_secret: None,
        discovery_daily_salt: None,
        discovery_snapshot_cache: Arc::new(
            sanchr_core::discovery::cache::DiscoverySnapshotCache::new(),
        ),
        sealed_sender_signer,
        push_sender: None,
        challenge_provider: None,
        crypto_provider,
    })
}

/// Generate a unique phone number for test isolation.
pub fn unique_phone() -> String {
    let suffix: u32 = rand::random::<u32>() % 10_000_000;
    format!("+1555{:07}", suffix)
}

/// Generate a unique test name.
pub fn unique_name() -> String {
    format!("TestUser-{}", &Uuid::new_v4().to_string()[..8])
}

#[allow(unused)]
pub async fn register_and_verify_user(
    state: &Arc<sanchr_core::server::AppState>,
    password: &str,
    device_name: &str,
    platform: &str,
    installation_id: Option<&str>,
) -> (sanchr_core::auth::handlers::AuthResult, String) {
    register_and_verify_user_with_delivery_ack(
        state,
        password,
        device_name,
        platform,
        installation_id,
        false,
    )
    .await
}

pub async fn register_and_verify_user_with_delivery_ack(
    state: &Arc<sanchr_core::server::AppState>,
    password: &str,
    device_name: &str,
    platform: &str,
    installation_id: Option<&str>,
    supports_delivery_ack: bool,
) -> (sanchr_core::auth::handlers::AuthResult, String) {
    let phone = unique_phone();
    let name = unique_name();

    sanchr_core::auth::handlers::handle_register(state, &phone, &name, password, None, None)
        .await
        .expect("registration failed");

    let now = chrono::Utc::now().timestamp();
    let otp = sanchr_server_crypto::otp::generate_otp(
        &state.config.auth.otp_secret,
        &phone,
        now,
        state.config.auth.otp_ttl,
    )
    .expect("otp generation failed");

    let auth = sanchr_core::auth::handlers::handle_verify_otp(
        state,
        &phone,
        &otp,
        Some(device_name),
        platform,
        installation_id,
        supports_delivery_ack,
        "",
    )
    .await
    .expect("otp verification failed");

    (auth, phone)
}
