use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PasswordHasherConfig {
    pub memory_cost: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for PasswordHasherConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("failed to hash password: {0}")]
    HashError(String),
    #[error("password verification failed")]
    VerifyError,
}

pub fn hash_password(
    password: &str,
    config: &PasswordHasherConfig,
) -> Result<String, PasswordError> {
    let params = Params::new(
        config.memory_cost,
        config.iterations,
        config.parallelism,
        None,
    )
    .map_err(|e| PasswordError::HashError(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::HashError(e.to_string()))?;

    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<(), PasswordError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| PasswordError::HashError(e.to_string()))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| PasswordError::VerifyError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PasswordHasherConfig {
        PasswordHasherConfig {
            memory_cost: 4096,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn hash_and_verify_succeeds() {
        let config = test_config();
        let password = "super_secret_password_123";
        let hash = hash_password(password, &config).expect("hashing should succeed");
        verify_password(password, &hash).expect("verification should succeed");
    }

    #[test]
    fn wrong_password_fails() {
        let config = test_config();
        let hash = hash_password("correct_password", &config).expect("hashing should succeed");
        let result = verify_password("wrong_password", &hash);
        assert!(result.is_err(), "wrong password should fail verification");
        assert!(matches!(result.unwrap_err(), PasswordError::VerifyError));
    }

    #[test]
    fn different_hashes_for_same_password() {
        let config = test_config();
        let password = "same_password";
        let hash1 = hash_password(password, &config).expect("first hash should succeed");
        let hash2 = hash_password(password, &config).expect("second hash should succeed");
        assert_ne!(
            hash1, hash2,
            "same password should produce different hashes due to random salt"
        );
    }
}
