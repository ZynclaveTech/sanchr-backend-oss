use async_trait::async_trait;

/// Unified error type for all cryptographic provider operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoProviderError {
    #[error("jwt error: {0}")]
    Jwt(String),
    #[error("otp error: {0}")]
    Otp(String),
    #[error("sealed sender error: {0}")]
    SealedSender(String),
    #[error("turn error: {0}")]
    Turn(String),
    #[error("provider error: {0}")]
    Internal(String),
}

/// Validated JWT claims returned by [`CryptoProvider::validate_token`].
pub struct TokenClaims {
    /// Subject: user UUID string.
    pub sub: String,
    /// Device ID.
    pub did: i32,
    /// Unique token identifier (JWT ID).
    pub jti: String,
    /// Expiration timestamp (Unix epoch seconds).
    pub exp: i64,
}

/// TURN relay credentials returned by [`CryptoProvider::generate_turn_credentials`].
pub struct TurnCredential {
    pub username: String,
    pub credential: String,
    pub ttl: u64,
}

/// Abstracts all server-side cryptographic operations.
///
/// The local implementation wraps the existing standalone crypto modules
/// (`JwtManager`, OTP helpers, `SealedSenderSigner`, TURN credential
/// generation). Future backends (e.g. cloud KMS, HSM) can implement
/// this trait to delegate key management externally while keeping call
/// sites unchanged.
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    // ── JWT ──────────────────────────────────────────────────────────────

    /// Create an access token for `user_id` / `device_id`.
    ///
    /// Returns `(token_string, jti)`.
    async fn create_access_token(
        &self,
        user_id: &uuid::Uuid,
        device_id: i32,
        ttl_secs: i64,
    ) -> Result<(String, String), CryptoProviderError>;

    /// Validate `token` and return its claims.
    async fn validate_token(&self, token: &str) -> Result<TokenClaims, CryptoProviderError>;

    // ── OTP ──────────────────────────────────────────────────────────────

    /// Generate a 6-digit OTP for `phone` at the given `timestamp`.
    async fn generate_otp(
        &self,
        phone: &str,
        timestamp: i64,
    ) -> Result<String, CryptoProviderError>;

    /// Verify that `otp` is valid for `phone` at the given `timestamp`.
    async fn verify_otp(
        &self,
        phone: &str,
        otp: &str,
        timestamp: i64,
    ) -> Result<(), CryptoProviderError>;

    // ── Sealed sender ────────────────────────────────────────────────────

    /// Issue a sealed-sender certificate.
    ///
    /// Returns `(serialized_sender_certificate, expiration_unix_ts)`.
    async fn issue_sender_certificate(
        &self,
        sender_uuid: &str,
        device_id: u32,
        identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), CryptoProviderError>;

    /// Return the 32-byte Ed25519 public key used for sealed-sender
    /// certificate verification.
    async fn sealed_sender_public_key(&self) -> Result<[u8; 32], CryptoProviderError>;

    // ── TURN ─────────────────────────────────────────────────────────────

    /// Generate time-limited TURN relay credentials.
    async fn generate_turn_credentials(
        &self,
        user_id: &str,
        ttl_secs: u64,
    ) -> Result<TurnCredential, CryptoProviderError>;

    // ── Key rotation (future KMS backends) ───────────────────────────────

    /// Return an identifier for the currently active signing / encryption
    /// key. For the local provider this is a static string; KMS backends
    /// would return the active key version.
    async fn active_key_id(&self) -> String;
}
