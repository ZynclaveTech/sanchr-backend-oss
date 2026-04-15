use config::{Config, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub storage: S3Config,
    pub push: PushConfig,
    pub calling: CallingConfig,
    #[serde(default)]
    pub ekf: Option<EkfConfig>,
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub grpc_port: u16,
    pub http_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub postgres: PostgresConfig,
    pub redis: RedisConfig,
    pub scylla: ScyllaConfig,
    pub nats: NatsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScyllaConfig {
    pub nodes: Vec<String>,
    pub keyspace: String,
    pub replication_factor: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NatsConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub otp_secret: String,
    /// Seconds until access token expires (default: 900 = 15 min)
    pub access_token_ttl: u64,
    /// Seconds until refresh token expires (default: 7_776_000 = 90 days)
    pub refresh_token_ttl: u64,
    /// Seconds until OTP expires (default: 300 = 5 min)
    pub otp_ttl: u64,
    /// Argon2 memory cost in KiB
    pub argon2_memory: u32,
    /// Argon2 iteration count
    pub argon2_iterations: u32,
    /// Argon2 parallelism degree
    pub argon2_parallelism: u32,
    /// When true, logs OTP codes at INFO level for local development.
    #[serde(default)]
    pub dev_mode: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Seconds until a presigned URL expires.
    pub presigned_url_ttl: u64,
    /// CDN base URL for public media (e.g. https://cdn.example.com/sanchr-media)
    #[serde(default)]
    pub cdn_base_url: Option<String>,
    /// Days after which encrypted media ciphertext under the `media/` prefix
    /// is automatically expired by the S3 lifecycle policy. Defaults to 30.
    /// Set to 0 to disable the lifecycle rule.
    #[serde(default = "default_media_lifecycle_days")]
    pub media_lifecycle_days: u32,
}

fn default_media_lifecycle_days() -> u32 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct PushConfig {
    pub fcm_key: String,
    /// Filesystem path to the APNs .p8 private key file.
    pub apns_key_path: String,
    pub apns_team_id: String,
    pub apns_key_id: String,
    /// APNs topic (= app bundle ID, e.g. "com.sanchr.app").
    pub apns_bundle_id: String,
    /// When true, targets the APNs sandbox (development) endpoint.
    #[serde(default)]
    pub apns_sandbox: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CallingConfig {
    pub turn_secret: String,
    pub turn_servers: Vec<String>,
    pub turn_credential_ttl: u64,
    pub max_call_duration: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EkfConfig {
    #[serde(default = "default_ekf_tick_interval")]
    pub tick_interval_secs: u64,
    #[serde(default = "default_ekf_grace_period")]
    pub rotation_grace_secs: u64,
    #[serde(default)]
    pub enabled: bool,
}

fn default_ekf_tick_interval() -> u64 {
    60
}

fn default_ekf_grace_period() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub oprf_enabled: bool,
    #[serde(default)]
    pub oprf_secret_hex: String,
    /// How often (seconds) to rotate the OPRF server secret.
    /// Defaults to 7 days. Set to 0 to disable background rotation.
    #[serde(default = "default_oprf_rotation_interval")]
    pub oprf_rotation_interval_secs: u64,
}

fn default_oprf_rotation_interval() -> u64 {
    7 * 24 * 60 * 60 // 7 days
}

impl AppConfig {
    /// Load configuration from files and environment variables.
    ///
    /// Sources (later sources override earlier ones):
    ///   1. `config/default.yaml`  – optional operator-provided baseline
    ///   2. `config/local-dev.yaml` – optional local-only developer overrides
    ///   3. `config/production.yaml` – optional operator-specific overrides
    ///   4. `SANCHR__`-prefixed env vars (double underscore separator)
    pub fn load() -> Result<Self, config::ConfigError> {
        let cfg = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/local-dev").required(false))
            .add_source(File::with_name("config/production").required(false))
            .add_source(
                Environment::with_prefix("SANCHR")
                    .prefix_separator("__")
                    .separator("__"),
            )
            .build()?;

        cfg.try_deserialize()
    }
}
