mod signaling;
mod turn;

use std::sync::Arc;

use anyhow::{bail, Context};
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use sanchr_common::config::AppConfig;
use sanchr_proto::calling::call_signaling_service_server::CallSignalingServiceServer;

const PLACEHOLDER_JWT_SECRET: &str = "replace-me-with-a-unique-jwt-secret";
const PLACEHOLDER_OTP_SECRET: &str = "replace-me-with-a-unique-otp-secret";
const PLACEHOLDER_TURN_SECRET: &str = "replace-me-with-a-unique-turn-secret";

pub struct CallAppState {
    pub config: AppConfig,
    pub redis: fred::clients::RedisClient,
    pub scylla: scylla::Session,
    pub nats: async_nats::Client,
    pub jwt: sanchr_server_crypto::jwt::JwtManager,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider before any TLS connections (required by rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sanchr_call=debug,sanchr_db=debug")),
        )
        .init();

    tracing::info!("starting sanchr-call server");

    let config = load_and_validate_config()?;

    // ---- config audit (never log secrets in full, just enough to diagnose) ----
    tracing::info!(
        turn_servers_count = config.calling.turn_servers.len(),
        turn_servers = ?config.calling.turn_servers,
        turn_secret_len = config.calling.turn_secret.len(),
        turn_credential_ttl = config.calling.turn_credential_ttl,
        "calling config loaded"
    );

    let redis = sanchr_db::redis::create_client(&config.database.redis).await?;
    tracing::info!("redis client connected");

    let scylla = sanchr_db::scylla::create_session(&config.database.scylla)
        .await
        .map_err(|error| anyhow::anyhow!("failed to initialize ScyllaDB session: {error}"))?;
    tracing::info!("scylla session created");

    let nats = {
        let nats_cfg = &config.database.nats;
        match (&nats_cfg.username, &nats_cfg.password) {
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
        }
    };
    tracing::info!("nats client connected");

    let jwt = sanchr_server_crypto::jwt::JwtManager::new(config.auth.jwt_secret.as_bytes());

    let state = Arc::new(CallAppState {
        config: config.clone(),
        redis,
        scylla,
        nats,
        jwt,
    });

    let call_service = signaling::CallSignalingServiceImpl {
        state: state.clone(),
    };
    let _missed_call_sweeper = signaling::spawn_missed_call_sweeper(state.clone());

    let grpc_addr = "0.0.0.0:9091".parse()?;
    tracing::info!(%grpc_addr, "gRPC call server listening");

    Server::builder()
        .add_service(
            CallSignalingServiceServer::new(call_service).max_decoding_message_size(65_536), // 64 KB — call signaling messages are small
        )
        .serve(grpc_addr)
        .await?;

    Ok(())
}

fn load_and_validate_config() -> anyhow::Result<AppConfig> {
    let config = AppConfig::load().context("failed to load config")?;
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

    Ok(())
}
