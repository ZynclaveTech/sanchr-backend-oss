use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Generate time-limited TURN credentials per RFC 5389.
///
/// Username = `"{expiry_timestamp}:{user_id}"`
/// Credential = `Base64(HMAC-SHA1(shared_secret, username))`
///
/// Returns `(username, credential, ttl_seconds)`.
pub fn generate_turn_credentials(
    secret: &str,
    user_id: &str,
    ttl_seconds: u64,
) -> (String, String, u64) {
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl_seconds;

    let username = format!("{}:{}", expiry, user_id);

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let result = mac.finalize().into_bytes();

    use base64::Engine;
    let credential = base64::engine::general_purpose::STANDARD.encode(result);

    (username, credential, ttl_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_turn_credentials() {
        let (username, credential, ttl) = generate_turn_credentials("secret", "user123", 86400);
        assert!(username.contains("user123"));
        assert!(!credential.is_empty());
        assert_eq!(ttl, 86400);
    }
}
