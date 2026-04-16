use fred::clients::RedisClient;
use fred::interfaces::KeysInterface;
use fred::types::Expiration;
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use sanchr_common::errors::AppError;

// ---------------------------------------------------------------------------
// ChallengeProvider trait
// ---------------------------------------------------------------------------

pub struct Challenge {
    pub challenge_id: String,
    pub challenge_type: String,
    pub challenge_data: String,
    pub expires_at: i64,
}

#[tonic::async_trait]
pub trait ChallengeProvider: Send + Sync {
    async fn issue(&self, phone_number: &str) -> Result<Challenge, AppError>;
    async fn verify(&self, challenge_id: &str, solution: &str) -> Result<(), AppError>;
}

// ---------------------------------------------------------------------------
// Proof-of-Work implementation
// ---------------------------------------------------------------------------

pub struct PowChallengeProvider {
    difficulty: u32,
    ttl_secs: u64,
    redis: RedisClient,
}

impl PowChallengeProvider {
    pub fn new(difficulty: u32, ttl_secs: u64, redis: RedisClient) -> Self {
        Self {
            difficulty,
            ttl_secs,
            redis,
        }
    }
}

/// Check whether the SHA-256 digest has at least `difficulty` leading zero bits.
fn has_leading_zero_bits(hash: &[u8], difficulty: u32) -> bool {
    let mut remaining = difficulty;
    for &byte in hash {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if byte != 0 {
                return false;
            }
            remaining -= 8;
        } else {
            // Check the top `remaining` bits of this byte.
            let mask = 0xFF_u8 << (8 - remaining);
            return byte & mask == 0;
        }
    }
    remaining == 0
}

#[tonic::async_trait]
impl ChallengeProvider for PowChallengeProvider {
    async fn issue(&self, _phone_number: &str) -> Result<Challenge, AppError> {
        let challenge_id = Uuid::new_v4().to_string();

        // Generate a random 16-byte hex prefix.
        let mut prefix_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut prefix_bytes);
        let prefix = hex::encode(prefix_bytes);

        let redis_key = format!("challenge:{}", challenge_id);
        let redis_value = format!("{}:{}", prefix, self.difficulty);

        self.redis
            .set::<(), _, _>(
                &redis_key,
                redis_value,
                Some(Expiration::EX(self.ttl_secs as i64)),
                None,
                false,
            )
            .await
            .map_err(|e| AppError::Internal(format!("redis set challenge: {e}")))?;

        let expires_at = chrono::Utc::now().timestamp() + self.ttl_secs as i64;
        let challenge_data = serde_json::json!({
            "difficulty": self.difficulty,
            "prefix": prefix,
        })
        .to_string();

        Ok(Challenge {
            challenge_id,
            challenge_type: "pow".to_string(),
            challenge_data,
            expires_at,
        })
    }

    async fn verify(&self, challenge_id: &str, solution: &str) -> Result<(), AppError> {
        let redis_key = format!("challenge:{}", challenge_id);

        let stored: Option<String> = self
            .redis
            .get(&redis_key)
            .await
            .map_err(|e| AppError::Internal(format!("redis get challenge: {e}")))?;

        let stored = stored
            .ok_or_else(|| AppError::InvalidInput("challenge not found or expired".into()))?;

        // Delete immediately to enforce one-shot usage.
        self.redis
            .del::<(), _>(&redis_key)
            .await
            .map_err(|e| AppError::Internal(format!("redis del challenge: {e}")))?;

        // Parse stored value: "prefix:difficulty"
        let (prefix, difficulty_str) = stored
            .rsplit_once(':')
            .ok_or_else(|| AppError::Internal("malformed challenge data in redis".into()))?;

        let difficulty: u32 = difficulty_str
            .parse()
            .map_err(|_| AppError::Internal("malformed difficulty in challenge data".into()))?;

        // Compute SHA-256(prefix || solution)
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(solution.as_bytes());
        let hash = hasher.finalize();

        if !has_leading_zero_bits(&hash, difficulty) {
            return Err(AppError::InvalidInput(
                "challenge proof does not satisfy difficulty requirement".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_all_zero() {
        let hash = [0u8; 32];
        assert!(has_leading_zero_bits(&hash, 256));
    }

    #[test]
    fn leading_zero_bits_none() {
        let mut hash = [0u8; 32];
        hash[0] = 0x80;
        assert!(has_leading_zero_bits(&hash, 0));
        assert!(!has_leading_zero_bits(&hash, 1));
    }

    #[test]
    fn leading_zero_bits_partial_byte() {
        // 0x0F = 0000_1111 → 4 leading zero bits
        let mut hash = [0u8; 32];
        hash[0] = 0x0F;
        assert!(has_leading_zero_bits(&hash, 4));
        assert!(!has_leading_zero_bits(&hash, 5));
    }

    #[test]
    fn leading_zero_bits_across_bytes() {
        // First byte = 0x00 (8 zeros), second byte = 0x01 (7 zeros) = 15 total
        let mut hash = [0u8; 32];
        hash[1] = 0x01;
        assert!(has_leading_zero_bits(&hash, 15));
        assert!(!has_leading_zero_bits(&hash, 16));
    }
}
