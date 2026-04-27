use std::sync::Arc;

use async_trait::async_trait;

use crate::jwt::JwtManager;
use crate::otp;
use crate::provider::{CryptoProvider, CryptoProviderError, TokenClaims, TurnCredential};
use crate::sealed_sender::SealedSenderSigner;
use crate::turn_creds;

/// Local (in-process) implementation of [`CryptoProvider`].
///
/// Delegates every operation to the existing standalone crypto modules.
/// All methods are trivially async — they wrap synchronous calls — so
/// there is no actual `.await` overhead.
pub struct LocalCryptoProvider {
    jwt: JwtManager,
    otp_secret: String,
    otp_ttl: u64,
    sealed_sender: Arc<SealedSenderSigner>,
    turn_secret: String,
}

impl LocalCryptoProvider {
    pub fn new(
        jwt: JwtManager,
        otp_secret: String,
        otp_ttl: u64,
        sealed_sender: Arc<SealedSenderSigner>,
        turn_secret: String,
    ) -> Self {
        Self {
            jwt,
            otp_secret,
            otp_ttl,
            sealed_sender,
            turn_secret,
        }
    }
}

#[async_trait]
impl CryptoProvider for LocalCryptoProvider {
    // ── JWT ──────────────────────────────────────────────────────────────

    async fn create_access_token(
        &self,
        user_id: &uuid::Uuid,
        device_id: i32,
        ttl_secs: i64,
    ) -> Result<(String, String), CryptoProviderError> {
        self.jwt
            .create_access_token(user_id, device_id, ttl_secs)
            .map_err(|e| CryptoProviderError::Jwt(e.to_string()))
    }

    async fn validate_token(&self, token: &str) -> Result<TokenClaims, CryptoProviderError> {
        let claims = self
            .jwt
            .validate_token(token)
            .map_err(|e| CryptoProviderError::Jwt(e.to_string()))?;

        Ok(TokenClaims {
            sub: claims.sub,
            did: claims.did,
            jti: claims.jti,
            exp: claims.exp,
        })
    }

    // ── OTP ──────────────────────────────────────────────────────────────

    async fn generate_otp(
        &self,
        phone: &str,
        timestamp: i64,
    ) -> Result<String, CryptoProviderError> {
        otp::generate_otp(&self.otp_secret, phone, timestamp, self.otp_ttl)
            .map_err(|e| CryptoProviderError::Otp(e.to_string()))
    }

    async fn verify_otp(
        &self,
        phone: &str,
        otp: &str,
        timestamp: i64,
    ) -> Result<(), CryptoProviderError> {
        otp::verify_otp(&self.otp_secret, phone, otp, timestamp, self.otp_ttl)
            .map_err(|e| CryptoProviderError::Otp(e.to_string()))
    }

    // ── Sealed sender ────────────────────────────────────────────────────

    async fn issue_sender_certificate(
        &self,
        sender_uuid: &str,
        device_id: u32,
        identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), CryptoProviderError> {
        self.sealed_sender
            .issue_certificate(sender_uuid, device_id, identity_key)
            .map_err(|e| CryptoProviderError::SealedSender(e.to_string()))
    }

    async fn sealed_sender_public_key(&self) -> Result<Vec<u8>, CryptoProviderError> {
        Ok(self.sealed_sender.trust_root_public_key_bytes())
    }

    // ── TURN ─────────────────────────────────────────────────────────────

    async fn generate_turn_credentials(
        &self,
        user_id: &str,
        ttl_secs: u64,
    ) -> Result<TurnCredential, CryptoProviderError> {
        let (username, credential, ttl) =
            turn_creds::generate_turn_credentials(&self.turn_secret, user_id, ttl_secs);

        Ok(TurnCredential {
            username,
            credential,
            ttl,
        })
    }

    // ── Key rotation ─────────────────────────────────────────────────────

    async fn active_key_id(&self) -> String {
        "local-static".to_string()
    }
}
