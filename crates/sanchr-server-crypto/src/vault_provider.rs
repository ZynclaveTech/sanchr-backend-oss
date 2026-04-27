//! HashiCorp Vault-backed [`CryptoProvider`] implementation.
//!
//! Uses the Vault Transit secrets engine for:
//! - Asymmetric signing (sealed sender certificates)
//! - HMAC operations (OTP, TURN credentials)
//!
//! JWT operations remain local (HS256 with secret retrieved from Vault KV
//! at startup). This avoids a network round-trip per token validation.
//!
//! # Configuration
//!
//! Requires:
//! - `vault_addr`: Vault server address (e.g. `https://vault.example.com:8200`)
//! - `vault_token`: Authentication token (or use Vault agent auto-auth)
//! - `transit_mount`: Mount path for the Transit engine (default `transit`)
//! - `signing_key_name`: Named key in Transit for asymmetric signing
//!   (must be `ecdsa-p256` or `ed25519` type)
//! - `hmac_key_name`: Named key in Transit for HMAC operations
//! - `jwt_secret_path`: KV v2 path where the JWT signing secret is stored
//!
//! # Feature gate
//!
//! This module is only compiled when the `kms-vault` feature is enabled.
//!
//! ```toml
//! sanchr-server-crypto = { path = "...", features = ["kms-vault"] }
//! ```
//!
//! # Required Vault policies
//!
//! ```hcl
//! # Transit signing
//! path "transit/sign/<signing_key_name>" {
//!   capabilities = ["update"]
//! }
//! path "transit/verify/<signing_key_name>" {
//!   capabilities = ["update"]
//! }
//! path "transit/keys/<signing_key_name>" {
//!   capabilities = ["read"]
//! }
//!
//! # Transit HMAC
//! path "transit/hmac/<hmac_key_name>" {
//!   capabilities = ["update"]
//! }
//! path "transit/verify/<hmac_key_name>" {
//!   capabilities = ["update"]
//! }
//!
//! # JWT secret from KV v2
//! path "secret/data/<jwt_secret_path>" {
//!   capabilities = ["read"]
//! }
//! ```
//!
//! See `docs/kms-integration.md` for full setup instructions.

use async_trait::async_trait;

use crate::jwt::JwtManager;
use crate::provider::{CryptoProvider, CryptoProviderError, TokenClaims, TurnCredential};

/// HashiCorp Vault-backed implementation of [`CryptoProvider`].
///
/// Communicates with the Vault HTTP API via `reqwest`. All cryptographic
/// operations (signing, HMAC) are delegated to the Transit secrets engine,
/// ensuring key material never leaves Vault.
///
/// The JWT signing secret is the sole exception: it is fetched from Vault
/// KV once at startup and held in-process for the lifetime of the provider
/// to avoid a network round-trip on every token validation.
pub struct VaultCryptoProvider {
    /// Base URL of the Vault server (e.g. `https://vault.example.com:8200`).
    #[allow(dead_code)]
    vault_addr: String,

    /// HTTP client for Vault API calls. Pre-configured with connection
    /// pooling and timeouts.
    #[allow(dead_code)]
    http_client: reqwest::Client,

    /// Vault authentication token. In production, prefer Vault Agent
    /// auto-auth or Kubernetes auth instead of a static token.
    #[allow(dead_code)]
    vault_token: String,

    /// Mount path of the Transit secrets engine (e.g. `transit`).
    #[allow(dead_code)]
    transit_mount: String,

    /// Name of the Transit key used for asymmetric signing of sealed
    /// sender certificates. Must be an `ecdsa-p256` or `ed25519` key.
    #[allow(dead_code)]
    signing_key_name: String,

    /// Name of the Transit key used for HMAC operations (OTP and TURN
    /// credential generation).
    #[allow(dead_code)]
    hmac_key_name: String,

    /// Local JWT manager initialized with a secret from Vault KV.
    #[allow(dead_code)]
    jwt_manager: JwtManager,
}

impl VaultCryptoProvider {
    /// Create a new Vault-backed crypto provider.
    ///
    /// # Startup sequence
    ///
    /// 1. Read the JWT signing secret from `jwt_secret_path` in Vault KV v2.
    /// 2. Initialize a local [`JwtManager`] with that secret.
    /// 3. Verify that `signing_key_name` exists in Transit and has the
    ///    correct key type.
    /// 4. Verify that `hmac_key_name` exists in Transit.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoProviderError::Internal`] if Vault is unreachable,
    /// authentication fails, or any key is missing.
    pub async fn new(
        vault_addr: String,
        vault_token: String,
        transit_mount: String,
        signing_key_name: String,
        hmac_key_name: String,
        _jwt_secret_path: String,
    ) -> Result<Self, CryptoProviderError> {
        // In a real implementation:
        // 1. Build a reqwest::Client with appropriate timeouts and TLS config.
        // 2. GET /v1/secret/data/<jwt_secret_path> with X-Vault-Token header
        //    to retrieve the JWT signing secret.
        // 3. Construct a JwtManager with that secret.
        // 4. GET /v1/<transit_mount>/keys/<signing_key_name> to verify the
        //    signing key exists and is the correct type.
        // 5. GET /v1/<transit_mount>/keys/<hmac_key_name> to verify the HMAC
        //    key exists.
        let _ = (
            &vault_addr,
            &vault_token,
            &transit_mount,
            &signing_key_name,
            &hmac_key_name,
        );
        Err(CryptoProviderError::Internal(
            "Vault provider not yet implemented: cannot fetch JWT secret at startup".into(),
        ))
    }
}

#[async_trait]
impl CryptoProvider for VaultCryptoProvider {
    // ── JWT (local, using secret fetched from Vault KV at init) ─────────

    async fn create_access_token(
        &self,
        _user_id: &uuid::Uuid,
        _device_id: i32,
        _ttl_secs: i64,
    ) -> Result<(String, String), CryptoProviderError> {
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: create_access_token".into(),
        ))
    }

    async fn validate_token(&self, _token: &str) -> Result<TokenClaims, CryptoProviderError> {
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: validate_token".into(),
        ))
    }

    // ── OTP (Vault Transit HMAC) ────────────────────────────────────────

    async fn generate_otp(
        &self,
        _phone: &str,
        _timestamp: i64,
    ) -> Result<String, CryptoProviderError> {
        // Real implementation:
        // POST /v1/<transit_mount>/hmac/<hmac_key_name>
        // Body: { "input": base64(phone||timestamp), "algorithm": "hmac-sha256" }
        // Then truncate the returned HMAC to a 6-digit OTP per RFC 4226.
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: generate_otp".into(),
        ))
    }

    async fn verify_otp(
        &self,
        _phone: &str,
        _otp: &str,
        _timestamp: i64,
    ) -> Result<(), CryptoProviderError> {
        // Real implementation:
        // POST /v1/<transit_mount>/verify/<hmac_key_name>
        // with the same message construction, then compare the OTP.
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: verify_otp".into(),
        ))
    }

    // ── Sealed sender (Vault Transit signing) ───────────────────────────

    async fn issue_sender_certificate(
        &self,
        _sender_uuid: &str,
        _device_id: u32,
        _identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), CryptoProviderError> {
        // Real implementation:
        // POST /v1/<transit_mount>/sign/<signing_key_name>
        // Body: { "input": base64(certificate_bytes), "hash_algorithm": "sha2-256" }
        // Embed the returned signature in the certificate protobuf.
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: issue_sender_certificate".into(),
        ))
    }

    async fn sealed_sender_public_key(&self) -> Result<Vec<u8>, CryptoProviderError> {
        // Real implementation:
        // GET /v1/<transit_mount>/keys/<signing_key_name>
        // Extract the public key from the latest key version and convert
        // from PEM/DER to the 33-byte type-prefixed Curve25519 format
        // clients expect.
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: sealed_sender_public_key".into(),
        ))
    }

    // ── TURN (Vault Transit HMAC) ───────────────────────────────────────

    async fn generate_turn_credentials(
        &self,
        _user_id: &str,
        _ttl_secs: u64,
    ) -> Result<TurnCredential, CryptoProviderError> {
        // Real implementation:
        // POST /v1/<transit_mount>/hmac/<hmac_key_name>
        // with the coturn shared-secret TURN credential message format.
        Err(CryptoProviderError::Internal(
            "Vault not yet implemented: generate_turn_credentials".into(),
        ))
    }

    // ── Key rotation ────────────────────────────────────────────────────

    async fn active_key_id(&self) -> String {
        // Real implementation: query Transit for the latest key version
        // of the signing key and return it as an identifier string.
        format!("vault:{}:{}", self.transit_mount, self.signing_key_name)
    }
}
