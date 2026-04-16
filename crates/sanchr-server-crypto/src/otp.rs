use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("OTP generation failed: {0}")]
    GenerationError(String),
    #[error("OTP verification failed")]
    VerificationError,
    #[error("OTP has expired")]
    Expired,
}

/// Compute the time window index for a given timestamp and TTL.
///
/// Returns 0 if `ttl_seconds` is 0 to avoid division by zero.
fn time_window(timestamp: i64, ttl_seconds: u64) -> i64 {
    if ttl_seconds == 0 {
        return 0;
    }
    timestamp / ttl_seconds as i64
}

/// Generate the HMAC-SHA256 based 6-digit OTP for a specific time window.
fn compute_otp(secret: &str, phone: &str, window: i64) -> Result<String, OtpError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| OtpError::GenerationError(e.to_string()))?;

    // Message = phone + ":" + window (big-endian i64 bytes)
    mac.update(phone.as_bytes());
    mac.update(b":");
    mac.update(&window.to_be_bytes());

    let result = mac.finalize().into_bytes();

    // Dynamic truncation: use last nibble of result as offset
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    Ok(format!("{:06}", code % 1_000_000))
}

/// Generate a 6-digit OTP that is deterministic within the current time window.
pub fn generate_otp(
    secret: &str,
    phone: &str,
    timestamp: i64,
    ttl_seconds: u64,
) -> Result<String, OtpError> {
    let window = time_window(timestamp, ttl_seconds);
    compute_otp(secret, phone, window)
}

/// Verify an OTP against the current window and the previous window (grace period).
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_otp(
    secret: &str,
    phone: &str,
    otp: &str,
    current_timestamp: i64,
    ttl_seconds: u64,
) -> Result<(), OtpError> {
    let current_window = time_window(current_timestamp, ttl_seconds);
    let mut found = 0u8;

    for window in [current_window, current_window - 1] {
        let expected =
            compute_otp(secret, phone, window).map_err(|_| OtpError::VerificationError)?;
        found |= expected.as_bytes().ct_eq(otp.as_bytes()).unwrap_u8();
    }

    if found == 1 {
        Ok(())
    } else {
        Err(OtpError::VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test_otp_secret";
    const PHONE: &str = "+15550001234";
    const TTL: u64 = 300; // 5 minutes

    #[test]
    fn output_is_six_digits() {
        let otp = generate_otp(SECRET, PHONE, 1_000_000, TTL).expect("should generate OTP");
        assert_eq!(otp.len(), 6, "OTP must be exactly 6 characters");
        assert!(
            otp.chars().all(|c| c.is_ascii_digit()),
            "OTP must be all digits"
        );
    }

    #[test]
    fn same_window_produces_same_otp() {
        // Both timestamps fall in the same 300-second window
        let ts1 = 1_000_000i64;
        let ts2 = ts1 + 100; // still same window
        let otp1 = generate_otp(SECRET, PHONE, ts1, TTL).expect("otp1 should succeed");
        let otp2 = generate_otp(SECRET, PHONE, ts2, TTL).expect("otp2 should succeed");
        assert_eq!(otp1, otp2, "same window should produce same OTP");
    }

    #[test]
    fn different_phone_produces_different_otp() {
        let ts = 1_000_000i64;
        let otp1 = generate_otp(SECRET, "+15550001234", ts, TTL).expect("otp1 should succeed");
        let otp2 = generate_otp(SECRET, "+15559998765", ts, TTL).expect("otp2 should succeed");
        assert_ne!(otp1, otp2, "different phones should produce different OTPs");
    }

    #[test]
    fn verify_current_window_works() {
        let ts = 1_000_000i64;
        let otp = generate_otp(SECRET, PHONE, ts, TTL).expect("generation should succeed");
        verify_otp(SECRET, PHONE, &otp, ts, TTL).expect("verification should succeed");
    }

    #[test]
    fn verify_previous_window_grace_works() {
        let window_start = 1_000_000i64 / TTL as i64 * TTL as i64;
        // Generate OTP for the previous window
        let prev_ts = window_start - 1;
        let otp = generate_otp(SECRET, PHONE, prev_ts, TTL).expect("generation should succeed");

        // Verify at the very start of the current window (grace period)
        let current_ts = window_start;
        verify_otp(SECRET, PHONE, &otp, current_ts, TTL)
            .expect("previous window OTP should pass grace period check");
    }

    #[test]
    fn wrong_otp_fails() {
        let ts = 1_000_000i64;
        let result = verify_otp(SECRET, PHONE, "000000", ts, TTL);
        // "000000" is extremely unlikely to be valid
        let otp = generate_otp(SECRET, PHONE, ts, TTL).expect("generation should succeed");
        if otp != "000000" {
            assert!(result.is_err(), "wrong OTP should fail");
            assert!(matches!(result.unwrap_err(), OtpError::VerificationError));
        }
    }
}
