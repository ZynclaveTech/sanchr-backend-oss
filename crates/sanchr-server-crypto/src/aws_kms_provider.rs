//! AWS KMS-backed [`CryptoProvider`] implementation.
//!
//! Uses AWS KMS for:
//! - Asymmetric signing (sealed sender certificates)
//! - HMAC operations (OTP, TURN credentials)
//! - Envelope encryption (protecting OPRF server secret at rest)
//!
//! JWT operations remain local (HS256 with KMS-managed secret retrieved at
//! startup). This avoids a round-trip to KMS on every token validation while
//! still allowing the JWT secret to be rotated centrally.
//!
//! # Configuration
//!
//! Requires these KMS key ARNs:
//! - `signing_key_arn`: Asymmetric ECC_NIST_P256 or RSA key for sealed sender
//!   signing
//! - `hmac_key_arn`: Symmetric HMAC key for OTP and TURN credential generation
//! - `jwt_secret_arn`: Secrets Manager ARN or KMS data key for JWT secret
//!
//! # Feature gate
//!
//! This module is only compiled when the `kms-aws` feature is enabled.
//!
//! ```toml
//! sanchr-server-crypto = { path = "...", features = ["kms-aws"] }
//! ```
//!
//! # Key provisioning
//!
//! Operators must pre-create the KMS keys and grant the server's IAM role
//! the following permissions:
//!
//! - `kms:Sign` / `kms:GetPublicKey` on the signing key
//! - `kms:GenerateMac` / `kms:VerifyMac` on the HMAC key
//! - `kms:Decrypt` (or `secretsmanager:GetSecretValue`) on the JWT secret
//!
//! See `docs/kms-integration.md` for full IAM policy examples.

use async_trait::async_trait;

use crate::jwt::JwtManager;
use crate::provider::{CryptoProvider, CryptoProviderError, TokenClaims, TurnCredential};

/// AWS KMS-backed implementation of [`CryptoProvider`].
///
/// All cryptographic key material lives in AWS KMS. The only secret held
/// in-process is the JWT signing key, which is fetched from KMS (or Secrets
/// Manager) once at startup and cached for the lifetime of the provider.
pub struct AwsKmsCryptoProvider {
    /// AWS KMS SDK client, pre-configured with region and credentials.
    #[allow(dead_code)]
    kms_client: aws_sdk_kms::Client,

    /// ARN of the asymmetric signing key used for sealed sender certificates.
    /// Must be an ECC_NIST_P256 key with SIGN_VERIFY usage.
    #[allow(dead_code)]
    signing_key_arn: String,

    /// ARN of the symmetric HMAC key used for OTP generation/verification
    /// and TURN credential derivation.
    #[allow(dead_code)]
    hmac_key_arn: String,

    /// Local JWT manager initialized with a secret retrieved from KMS.
    /// JWT operations stay in-process for performance (no KMS round-trip
    /// per token validation).
    #[allow(dead_code)]
    jwt_manager: JwtManager,
}

impl AwsKmsCryptoProvider {
    /// Create a new AWS KMS-backed crypto provider.
    ///
    /// # Startup sequence
    ///
    /// 1. Fetch the JWT signing secret from `jwt_secret_arn` (either a Secrets
    ///    Manager secret or a KMS-encrypted data key).
    /// 2. Initialize a local [`JwtManager`] with that secret.
    /// 3. Verify that `signing_key_arn` exists and is an asymmetric signing key.
    /// 4. Verify that `hmac_key_arn` exists and supports `GenerateMac`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoProviderError::Internal`] if any key is inaccessible or
    /// has the wrong key spec.
    pub async fn new(
        kms_client: aws_sdk_kms::Client,
        signing_key_arn: String,
        hmac_key_arn: String,
        _jwt_secret_arn: String,
    ) -> Result<Self, CryptoProviderError> {
        // In a real implementation:
        // 1. Call kms:Decrypt or secretsmanager:GetSecretValue to retrieve
        //    the raw JWT signing secret from `jwt_secret_arn`.
        // 2. Construct a JwtManager with that secret.
        // 3. Call kms:DescribeKey on `signing_key_arn` to verify it is an
        //    asymmetric ECC_NIST_P256 key with SIGN_VERIFY usage.
        // 4. Call kms:DescribeKey on `hmac_key_arn` to verify it is a
        //    symmetric HMAC_SHA_256 key.
        let _ = (&kms_client, &signing_key_arn, &hmac_key_arn);
        Err(CryptoProviderError::Internal(
            "AWS KMS provider not yet implemented: cannot fetch JWT secret at startup".into(),
        ))
    }
}

#[async_trait]
impl CryptoProvider for AwsKmsCryptoProvider {
    // ── JWT (local, using secret fetched from KMS at init) ───────────────

    async fn create_access_token(
        &self,
        _user_id: &uuid::Uuid,
        _device_id: i32,
        _ttl_secs: i64,
    ) -> Result<(String, String), CryptoProviderError> {
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: create_access_token".into(),
        ))
    }

    async fn validate_token(&self, _token: &str) -> Result<TokenClaims, CryptoProviderError> {
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: validate_token".into(),
        ))
    }

    // ── OTP (KMS HMAC) ─────────────────────────────────────────────────

    async fn generate_otp(
        &self,
        _phone: &str,
        _timestamp: i64,
    ) -> Result<String, CryptoProviderError> {
        // Real implementation: call kms:GenerateMac with HMAC_SHA_256
        // using `hmac_key_arn`, passing phone||timestamp as the message.
        // Truncate the MAC to a 6-digit OTP using RFC 4226 dynamic
        // truncation.
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: generate_otp".into(),
        ))
    }

    async fn verify_otp(
        &self,
        _phone: &str,
        _otp: &str,
        _timestamp: i64,
    ) -> Result<(), CryptoProviderError> {
        // Real implementation: call kms:VerifyMac with the same message
        // construction, then compare the truncated OTP.
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: verify_otp".into(),
        ))
    }

    // ── Sealed sender (KMS asymmetric signing) ──────────────────────────

    async fn issue_sender_certificate(
        &self,
        _sender_uuid: &str,
        _device_id: u32,
        _identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), CryptoProviderError> {
        // Real implementation: serialize the certificate protobuf, then
        // call kms:Sign with ECDSA_SHA_256 using `signing_key_arn`.
        // The certificate embeds the KMS-generated signature instead of
        // a local Ed25519 signature.
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: issue_sender_certificate".into(),
        ))
    }

    async fn sealed_sender_public_key(&self) -> Result<[u8; 32], CryptoProviderError> {
        // Real implementation: call kms:GetPublicKey on `signing_key_arn`
        // and cache the result. Note: KMS ECC keys return a DER-encoded
        // public key, which must be converted to the 32-byte format
        // expected by clients.
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: sealed_sender_public_key".into(),
        ))
    }

    // ── TURN (KMS HMAC) ─────────────────────────────────────────────────

    async fn generate_turn_credentials(
        &self,
        _user_id: &str,
        _ttl_secs: u64,
    ) -> Result<TurnCredential, CryptoProviderError> {
        // Real implementation: call kms:GenerateMac with HMAC_SHA_1
        // (or HMAC_SHA_256 with local truncation) using `hmac_key_arn`,
        // following the coturn shared-secret TURN credential scheme.
        Err(CryptoProviderError::Internal(
            "AWS KMS not yet implemented: generate_turn_credentials".into(),
        ))
    }

    // ── Key rotation ────────────────────────────────────────────────────

    async fn active_key_id(&self) -> String {
        // Real implementation: return the signing key ARN with its current
        // key version suffix, enabling clients to detect key rotation.
        format!("aws-kms:{}", self.signing_key_arn)
    }
}
