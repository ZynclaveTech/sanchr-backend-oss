use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: user ID
    pub sub: String,
    /// Device ID
    pub did: i32,
    /// JWT ID: unique token identifier
    pub jti: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("failed to create JWT: {0}")]
    CreationError(String),
    #[error("JWT validation failed: {0}")]
    ValidationError(String),
    #[error("JWT has expired")]
    Expired,
}

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtManager {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    /// Returns (token, jti)
    pub fn create_access_token(
        &self,
        user_id: &Uuid,
        device_id: i32,
        ttl_seconds: i64,
    ) -> Result<(String, String), JwtError> {
        let now = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: user_id.to_string(),
            did: device_id,
            jti: jti.clone(),
            iat: now,
            exp: now + ttl_seconds,
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| JwtError::CreationError(e.to_string()))?;

        Ok((token, jti))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0;

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::ValidationError(e.to_string()),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> JwtManager {
        JwtManager::new(b"test_secret_key_for_unit_tests_only")
    }

    fn test_user_id() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn create_and_validate_roundtrip() {
        let mgr = make_manager();
        let user_id = test_user_id();
        let (token, jti) = mgr
            .create_access_token(&user_id, 42, 3600)
            .expect("token creation should succeed");

        let claims = mgr
            .validate_token(&token)
            .expect("validation should succeed");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.did, 42);
        assert_eq!(claims.jti, jti);
    }

    #[test]
    fn expired_token_returns_expired_error() {
        let mgr = make_manager();
        let user_id = test_user_id();
        // Create a token that expired 10 seconds ago
        let (token, _) = mgr
            .create_access_token(&user_id, 1, -10)
            .expect("token creation should succeed");

        let result = mgr.validate_token(&token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::Expired));
    }

    #[test]
    fn invalid_token_string_fails() {
        let mgr = make_manager();
        let result = mgr.validate_token("this.is.not.a.valid.jwt");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::ValidationError(_)));
    }

    #[test]
    fn wrong_secret_fails_validation() {
        let signer = make_manager();
        let verifier = JwtManager::new(b"completely_different_secret");

        let user_id = test_user_id();
        let (token, _) = signer
            .create_access_token(&user_id, 1, 3600)
            .expect("token creation should succeed");

        let result = verifier.validate_token(&token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::ValidationError(_)));
    }
}
