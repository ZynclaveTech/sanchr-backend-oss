use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::task::JoinHandle;
use tonic::transport::Server as TonicServer;
use tower::ServiceBuilder;
use uuid::Uuid;

use sanchr_common::config::AppConfig;
use sanchr_core::auth;
use sanchr_core::auth::challenge::PowChallengeProvider;
use sanchr_core::backup;
use sanchr_core::contacts;
use sanchr_core::discovery;
use sanchr_core::ekf;
use sanchr_core::keys;
use sanchr_core::media;
use sanchr_core::messaging;
use sanchr_core::notifications;
use sanchr_core::observability;
use sanchr_core::push::ApnsSender;
use sanchr_core::server;
use sanchr_core::settings;
use sanchr_core::vault;
use sanchr_db::postgres;
use sanchr_db::redis;
use sanchr_proto::auth::auth_service_server::AuthServiceServer;
use sanchr_proto::backup::backup_service_server::BackupServiceServer;
use sanchr_proto::contacts::contact_service_server::ContactServiceServer;
use sanchr_proto::discovery::discovery_service_server::DiscoveryServiceServer;
use sanchr_proto::keys::key_service_server::KeyServiceServer;
use sanchr_proto::media::media_service_server::MediaServiceServer;
use sanchr_proto::messaging::messaging_service_server::MessagingServiceServer;
use sanchr_proto::notifications::notification_service_server::NotificationServiceServer;
use sanchr_proto::settings::settings_service_server::SettingsServiceServer;
use sanchr_proto::vault::vault_service_server::VaultServiceServer;
use sanchr_psi::bloom::generate_daily_salt;
use sanchr_psi::oprf::OprfServerSecret;
use sanchr_server_crypto::jwt::JwtManager;
use sanchr_server_crypto::local_provider::LocalCryptoProvider;
use sanchr_server_crypto::sealed_sender::SealedSenderSigner;

use auth::service::AuthServiceImpl;
use backup::service::BackupServiceImpl;
use contacts::service::ContactServiceImpl;
use discovery::service::DiscoveryService;
use keys::service::KeyServiceImpl;
use media::service::MediaServiceImpl;
use messaging::service::MessagingServiceImpl;
use messaging::stream::StreamManager;
use notifications::service::NotificationServiceImpl;
use observability::grpc_metrics::GrpcMetricsLayer;
use sanchr_core::middleware::request_size::RequestSizeLayer;
use server::{http_router, AppState};
use settings::service::SettingsServiceImpl;
use vault::service::VaultServiceImpl;

const PLACEHOLDER_JWT_SECRET: &str = "replace-me-with-a-unique-jwt-secret";
const PLACEHOLDER_OTP_SECRET: &str = "replace-me-with-a-unique-otp-secret";
const PLACEHOLDER_TURN_SECRET: &str = "replace-me-with-a-unique-turn-secret";
pub(crate) const DISCOVERY_STATE_USER_ID: Uuid = Uuid::from_u128(0);
pub(crate) const DISCOVERY_OPRF_ENTRY_ID: Uuid = Uuid::from_u128(1);
pub(crate) const DISCOVERY_SALT_ENTRY_ID: Uuid = Uuid::from_u128(2);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_rustls_provider()?;

    // Keep the guard alive for the process lifetime so in-flight spans flush.
    let _otel_guard = observability::tracing_setup::init_tracing("sanchr-core");
    let metrics_handle = observability::metrics::init_metrics()?;

    tracing::info!("starting sanchr-core server");

    let config = load_and_validate_config()?;
    let http_port = config.server.http_port;
    let grpc_port = config.server.grpc_port;
    let state = build_app_state(config, metrics_handle).await?;
    let _background_tasks = spawn_background_tasks(Arc::clone(&state));

    serve(state, http_port, grpc_port).await
}

fn install_rustls_provider() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;
    Ok(())
}

fn load_and_validate_config() -> anyhow::Result<AppConfig> {
    let config = AppConfig::load().context("failed to load configuration")?;
    validate_runtime_config(&config)?;
    Ok(config)
}

fn validate_runtime_config(config: &AppConfig) -> anyhow::Result<()> {
    if config.auth.dev_mode {
        return Ok(());
    }

    if config.auth.jwt_secret == PLACEHOLDER_JWT_SECRET {
        bail!("auth.jwt_secret must be overridden before running with auth.dev_mode=false");
    }

    if config.auth.otp_secret == PLACEHOLDER_OTP_SECRET {
        bail!("auth.otp_secret must be overridden before running with auth.dev_mode=false");
    }

    if config.calling.turn_secret == PLACEHOLDER_TURN_SECRET {
        bail!("calling.turn_secret must be overridden before running with auth.dev_mode=false");
    }

    if config
        .discovery
        .as_ref()
        .is_some_and(|discovery| discovery.oprf_enabled && discovery.oprf_secret_hex.is_empty())
    {
        bail!(
            "discovery.oprf_secret_hex is required when OPRF discovery is enabled outside dev mode"
        );
    }

    bail!(
        "sealed-sender production signer config is not available in this public repository; \
         use isolated local development with auth.dev_mode=true or add your own signer integration"
    );
}

async fn build_app_state(
    config: AppConfig,
    metrics_handle: PrometheusHandle,
) -> anyhow::Result<Arc<AppState>> {
    let pg_pool = postgres::create_pool(&config.database.postgres).await?;
    tracing::info!("postgres pool created");

    postgres::run_migrations(&pg_pool).await?;
    tracing::info!("database migrations applied");

    let redis_client = redis::create_client(&config.database.redis).await?;
    tracing::info!("redis client connected");

    let scylla_session = sanchr_db::scylla::create_session(&config.database.scylla)
        .await
        .map_err(|e| anyhow::anyhow!("failed to create ScyllaDB session: {e}"))?;
    tracing::info!("ScyllaDB session created");

    let nats_cfg = &config.database.nats;
    let nats_client = match (&nats_cfg.username, &nats_cfg.password) {
        (Some(user), Some(pass)) => {
            async_nats::ConnectOptions::with_user_and_password(user.clone(), pass.clone())
                .connect(&nats_cfg.url)
                .await?
        }
        _ => {
            if !config.auth.dev_mode {
                tracing::warn!(
                    "NATS credentials not configured; connecting without authentication. \
                     Set database.nats.username and database.nats.password for production."
                );
            }
            async_nats::ConnectOptions::new()
                .connect(&nats_cfg.url)
                .await?
        }
    };
    tracing::info!("NATS client connected");

    let s3_client = build_s3_client(&config);
    tracing::info!("S3 client configured");
    configure_s3_lifecycle(&s3_client, &config).await;

    let jwt = JwtManager::new(config.auth.jwt_secret.as_bytes());
    let stream_mgr = Arc::new(StreamManager::new());
    let oprf_secret = build_oprf_secret(&config)?;
    let discovery_daily_salt = build_discovery_daily_salt(&oprf_secret);
    register_discovery_lifecycle_entries(
        &scylla_session,
        &config,
        &oprf_secret,
        &discovery_daily_salt,
    )
    .await?;
    let discovery_snapshot_cache = Arc::new(discovery::cache::DiscoverySnapshotCache::new());
    let sealed_sender_signer = build_sealed_sender_signer(&config)?;
    let push_sender = ApnsSender::from_config(&config.push)
        .context("failed to initialise APNs push sender")?
        .map(Arc::new);

    let crypto_provider: Arc<dyn sanchr_server_crypto::provider::CryptoProvider> =
        Arc::new(LocalCryptoProvider::new(
            JwtManager::new(config.auth.jwt_secret.as_bytes()),
            config.auth.otp_secret.clone(),
            config.auth.otp_ttl,
            Arc::clone(&sealed_sender_signer),
            config.calling.turn_secret.clone(),
        ));

    let challenge_provider: Option<Arc<dyn sanchr_core::auth::challenge::ChallengeProvider>> =
        if config.challenge.enabled {
            let provider = PowChallengeProvider::new(
                config.challenge.pow_difficulty,
                config.challenge.challenge_ttl_secs,
                redis_client.clone(),
            );
            tracing::info!(
                difficulty = config.challenge.pow_difficulty,
                ttl = config.challenge.challenge_ttl_secs,
                "PoW challenge provider enabled"
            );
            Some(Arc::new(provider))
        } else {
            tracing::info!("challenge system disabled");
            None
        };

    Ok(Arc::new(AppState {
        config,
        pg_pool,
        redis: redis_client,
        jwt,
        scylla: scylla_session,
        nats: nats_client,
        stream_mgr,
        s3: s3_client,
        metrics_handle,
        oprf_secret,
        discovery_daily_salt,
        discovery_snapshot_cache,
        sealed_sender_signer,
        push_sender,
        challenge_provider,
        crypto_provider,
    }))
}

fn build_s3_client(config: &AppConfig) -> aws_sdk_s3::Client {
    let s3_creds = aws_credential_types::Credentials::new(
        &config.storage.access_key,
        &config.storage.secret_key,
        None,
        None,
        "sanchr",
    );
    let s3_config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(
            config.storage.region.clone(),
        ))
        .endpoint_url(&config.storage.endpoint)
        .credentials_provider(s3_creds)
        .force_path_style(true) // For MinIO/DO Spaces compatibility
        .build();
    aws_sdk_s3::Client::from_conf(s3_config)
}

/// Applies a lifecycle rule to the S3 bucket that expires encrypted media
/// ciphertext under the `media/` prefix after `config.storage.media_lifecycle_days` days.
///
/// This is best-effort: failures are logged as warnings and do not abort startup.
/// MinIO supports the S3 lifecycle API; AWS S3 and most compatible stores also
/// support it. Avatars (`avatars/` prefix) are excluded — they are user-controlled
/// and have no automatic expiry.
async fn configure_s3_lifecycle(client: &aws_sdk_s3::Client, config: &AppConfig) {
    use aws_sdk_s3::types::{
        BucketLifecycleConfiguration, ExpirationStatus, LifecycleExpiration, LifecycleRule,
        LifecycleRuleFilter,
    };

    let days = config.storage.media_lifecycle_days;
    if days == 0 {
        tracing::info!("S3 media lifecycle disabled (media_lifecycle_days = 0)");
        return;
    }

    let expiration = LifecycleExpiration::builder().days(days as i32).build();

    let rule = match LifecycleRule::builder()
        .id("sanchr-media-30d-expiry")
        .filter(LifecycleRuleFilter::builder().prefix("media/").build())
        .expiration(expiration)
        .status(ExpirationStatus::Enabled)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("S3 lifecycle rule build failed: {e}");
            return;
        }
    };

    let lifecycle_config = match BucketLifecycleConfiguration::builder().rules(rule).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("S3 lifecycle config build failed: {e}");
            return;
        }
    };

    match client
        .put_bucket_lifecycle_configuration()
        .bucket(&config.storage.bucket)
        .lifecycle_configuration(lifecycle_config)
        .send()
        .await
    {
        Ok(_) => tracing::info!(
            days,
            bucket = %config.storage.bucket,
            "S3 lifecycle rule applied: media/ expires after {days} days"
        ),
        Err(e) => tracing::warn!("S3 lifecycle configuration failed (non-fatal): {e}"),
    }
}

fn build_oprf_secret(config: &AppConfig) -> anyhow::Result<Option<Arc<ArcSwap<OprfServerSecret>>>> {
    let oprf_secret = match &config.discovery {
        Some(disc) if disc.oprf_enabled => {
            if disc.oprf_secret_hex.is_empty() {
                if !config.auth.dev_mode {
                    bail!("discovery.oprf_secret_hex is required when OPRF discovery is enabled outside dev mode");
                }
                tracing::warn!(
                    "discovery.oprf_enabled is true but oprf_secret_hex is empty; \
                     auto-generating an ephemeral OPRF secret because auth.dev_mode=true; \
                     set oprf_secret_hex for production)"
                );
                Some(Arc::new(
                    ArcSwap::from_pointee(OprfServerSecret::generate()),
                ))
            } else {
                let bytes = hex::decode(&disc.oprf_secret_hex)
                    .context("discovery.oprf_secret_hex is not valid hex")?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    anyhow::anyhow!(
                        "discovery.oprf_secret_hex must be exactly 32 bytes (64 hex chars), got {} bytes",
                        v.len()
                    )
                })?;
                let secret = OprfServerSecret::from_bytes(&bytes).ok_or_else(|| {
                    anyhow::anyhow!(
                        "discovery.oprf_secret_hex does not encode a valid non-zero canonical scalar"
                    )
                })?;
                tracing::info!("OPRF server secret loaded from config");
                Some(Arc::new(ArcSwap::from_pointee(secret)))
            }
        }
        _ => {
            tracing::info!("OPRF contact discovery is disabled");
            None
        }
    };

    Ok(oprf_secret)
}

fn build_discovery_daily_salt(
    oprf_secret: &Option<Arc<ArcSwap<OprfServerSecret>>>,
) -> Option<ArcSwap<Vec<u8>>> {
    if oprf_secret.is_some() {
        let salt = generate_daily_salt();
        tracing::info!("generated daily discovery salt ({} bytes)", salt.len());
        Some(ArcSwap::from_pointee(salt))
    } else {
        None
    }
}

async fn register_discovery_lifecycle_entries(
    scylla: &scylla::Session,
    config: &AppConfig,
    oprf_secret: &Option<Arc<ArcSwap<OprfServerSecret>>>,
    discovery_daily_salt: &Option<ArcSwap<Vec<u8>>>,
) -> anyhow::Result<()> {
    use sanchr_db::scylla::auxiliary;

    let now_ms = chrono::Utc::now().timestamp_millis();

    if let Some(secret) = oprf_secret {
        let ttl_secs = config
            .discovery
            .as_ref()
            .map(|d| d.oprf_rotation_interval_secs as i64)
            .unwrap_or(7 * 24 * 60 * 60)
            .max(1);

        auxiliary::insert_entry(
            scylla,
            DISCOVERY_STATE_USER_ID,
            DISCOVERY_OPRF_ENTRY_ID,
            "discovery",
            "rotate",
            &secret.load().to_bytes(),
            now_ms,
            ttl_secs,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to register OPRF lifecycle entry: {error}"))?;
    }

    if let Some(salt) = discovery_daily_salt {
        auxiliary::insert_entry(
            scylla,
            DISCOVERY_STATE_USER_ID,
            DISCOVERY_SALT_ENTRY_ID,
            "discovery",
            "rotate",
            &salt.load().to_vec(),
            now_ms,
            24 * 60 * 60,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!("failed to register discovery salt lifecycle entry: {error}")
        })?;
    }

    Ok(())
}

fn build_sealed_sender_signer(config: &AppConfig) -> anyhow::Result<Arc<SealedSenderSigner>> {
    if !config.auth.dev_mode {
        bail!("sealed-sender signer requires configured production key material");
    }

    tracing::warn!(
        "sealed-sender signer initialized with ephemeral dev key because auth.dev_mode=true"
    );
    Ok(Arc::new(SealedSenderSigner::generate(1)))
}

fn spawn_background_tasks(state: Arc<AppState>) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();

    tasks.extend(messaging::call_bridge::spawn_call_event_bridges(
        Arc::clone(&state),
    ));
    tasks.push(messaging::relay_bridge::spawn_message_relay_bridge(
        Arc::clone(&state),
    ));
    tasks.push(messaging::relay_bridge::spawn_sealed_relay_bridge(
        Arc::clone(&state),
    ));

    if state.config.ekf.enabled {
        let ekf_state = state.clone();
        let tick_interval = std::time::Duration::from_secs(state.config.ekf.tick_interval_secs);
        let handle = tokio::spawn(async move {
            ekf::manager::run_lifecycle_loop(ekf_state, tick_interval).await;
        });
        tasks.push(handle);
        tracing::info!("EKF lifecycle manager spawned");
    } else if !state.config.auth.dev_mode {
        tracing::warn!(
            "EKF is disabled — paper security guarantees D1 (24h discovery bound) \
             and D2 (30d media bound) are not enforced"
        );
    }

    // Spawn daily salt rotation if OPRF discovery is enabled.
    if state.discovery_daily_salt.is_some() {
        let salt_state = state.clone();
        let handle = tokio::spawn(async move {
            discovery::salt_rotation::run_salt_rotation_loop(salt_state).await;
        });
        tasks.push(handle);
        tracing::info!("daily salt rotation task spawned");
    }

    // Spawn weekly OPRF secret rotation if OPRF discovery is enabled.
    if state.oprf_secret.is_some() {
        let rotation_interval = state
            .config
            .discovery
            .as_ref()
            .map(|d| std::time::Duration::from_secs(d.oprf_rotation_interval_secs))
            .unwrap_or(std::time::Duration::from_secs(7 * 24 * 60 * 60));

        if !rotation_interval.is_zero() {
            let oprf_state = state.clone();
            let handle = tokio::spawn(async move {
                discovery::secret_rotation::run_oprf_secret_rotation_loop(
                    oprf_state,
                    rotation_interval,
                )
                .await;
            });
            tasks.push(handle);
            tracing::info!(
                interval_secs = rotation_interval.as_secs(),
                "OPRF secret rotation task spawned"
            );
        }
    }

    // ── Media cleanup sweeper (every 6 hours) ──────────────────────────
    {
        let pg_pool = state.pg_pool.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // discard immediate first tick

            loop {
                interval.tick().await;

                match sanchr_db::postgres::media::delete_stale_media_objects(&pg_pool, 30).await {
                    Ok(n) if n > 0 => {
                        tracing::info!("media sweeper: deleted {n} stale attachments (>30d)");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("media sweeper: stale cleanup failed: {e}"),
                }

                match sanchr_db::postgres::media::delete_unconfirmed_uploads(&pg_pool, 24).await {
                    Ok(n) if n > 0 => {
                        tracing::info!("media sweeper: deleted {n} unconfirmed uploads (>24h)");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("media sweeper: unconfirmed cleanup failed: {e}"),
                }
            }
        });
        tasks.push(handle);
        tracing::info!("media cleanup sweeper spawned (6h interval)");
    }

    // ── Pre-key cleanup sweeper (every 6 hours) ────────────────────────
    {
        let pg_pool = state.pg_pool.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                interval.tick().await;

                match sanchr_db::postgres::keys::delete_stale_one_time_pre_keys(&pg_pool, 7).await {
                    Ok(n) if n > 0 => {
                        tracing::info!("prekey sweeper: deleted {n} stale one-time pre-keys (>7d)");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("prekey sweeper: stale cleanup failed: {e}"),
                }
            }
        });
        tasks.push(handle);
        tracing::info!("prekey cleanup sweeper spawned (6h interval)");
    }

    tasks
}

async fn serve(state: Arc<AppState>, http_port: u16, grpc_port: u16) -> anyhow::Result<()> {
    let auth_service = AuthServiceImpl {
        state: Arc::clone(&state),
    };
    let keys_service = KeyServiceImpl {
        state: Arc::clone(&state),
    };
    let backup_service = BackupServiceImpl {
        state: Arc::clone(&state),
    };
    let messaging_service = MessagingServiceImpl {
        state: Arc::clone(&state),
        stream_mgr: Arc::clone(&state.stream_mgr),
    };
    let contacts_service = ContactServiceImpl {
        state: Arc::clone(&state),
    };
    let settings_service = SettingsServiceImpl {
        state: Arc::clone(&state),
    };
    let vault_service = VaultServiceImpl {
        state: Arc::clone(&state),
    };
    let media_service = MediaServiceImpl {
        state: Arc::clone(&state),
    };
    let notification_service = NotificationServiceImpl {
        state: Arc::clone(&state),
    };
    let discovery_service = DiscoveryService {
        state: Arc::clone(&state),
    };

    let http_addr: SocketAddr = ([0, 0, 0, 0], http_port).into();
    let http_router = http_router(Arc::clone(&state));
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    tracing::info!(%http_addr, "HTTP server listening");

    let http_server = axum::serve(http_listener, http_router.into_make_service());

    let grpc_addr: SocketAddr = ([0, 0, 0, 0], grpc_port).into();
    tracing::info!(%grpc_addr, "gRPC server listening");

    let request_size_layer = RequestSizeLayer::from_config(&state.config.server.request_size);

    let grpc_server = TonicServer::builder()
        .layer(
            ServiceBuilder::new()
                .layer(request_size_layer)
                .layer(GrpcMetricsLayer),
        )
        .add_service(AuthServiceServer::new(auth_service))
        .add_service(BackupServiceServer::new(backup_service))
        .add_service(KeyServiceServer::new(keys_service))
        .add_service(MessagingServiceServer::new(messaging_service))
        .add_service(ContactServiceServer::new(contacts_service))
        .add_service(SettingsServiceServer::new(settings_service))
        .add_service(VaultServiceServer::new(vault_service))
        .add_service(MediaServiceServer::new(media_service))
        .add_service(NotificationServiceServer::new(notification_service))
        .add_service(DiscoveryServiceServer::new(discovery_service))
        .serve(grpc_addr);

    tokio::select! {
        res = http_server => {
            if let Err(e) = res {
                tracing::error!(error = %e, "HTTP server error");
            }
        }
        res = grpc_server => {
            if let Err(e) = res {
                tracing::error!(error = %e, "gRPC server error");
            }
        }
    }

    Ok(())
}
