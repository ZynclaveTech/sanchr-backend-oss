use hkdf::Hkdf;
use sha2::Sha256;

pub mod labels {
    pub const MEDIA_KEY: &[u8] = b"sanchr-media-v1";
    pub const ACCESS_KEY: &[u8] = b"sanchr-access-v1";
    pub const DISCOVERY_CACHED: &[u8] = b"sanchr-discovery-v1";
    pub const ROTATION_KEY: &[u8] = b"sanchr-rotate-v1";
    pub const MEDIA_CHAIN_ADVANCE: &[u8] = b"sanchr-media-chain-advance-v1";
    pub const MEDIA_CHAIN_INIT: &[u8] = b"sanchr-media-chain-init-v1";
}

/// Generic HKDF-SHA256 key derivation.
///
/// Derives a 32-byte key from input keying material `ikm`, an optional `salt`,
/// and a domain-separation `info` label.
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand failed: output length is valid for SHA-256");
    okm
}

/// Derives a per-file media encryption key from the current chain key and the
/// file's content hash.
pub fn derive_media_key(chain_key: &[u8; 32], file_hash: &[u8; 32]) -> [u8; 32] {
    // ikm = chain_key || file_hash, salt = empty, info = MEDIA_KEY label
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(chain_key);
    ikm[32..].copy_from_slice(file_hash);
    derive_key(&ikm, &[], labels::MEDIA_KEY)
}

/// Derives a per-device, per-media access key from a media key, the device's
/// secret, and the media identifier.
/// Paper: AccessK_i = HKDF(MediaK_n, dls, "access-v1-<id>")
pub fn derive_access_key(
    media_key: &[u8; 32],
    device_secret: &[u8; 32],
    media_id: &str,
) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(media_key);
    ikm[32..].copy_from_slice(device_secret);
    let info = format!("sanchr-access-v1-{}", media_id);
    derive_key(&ikm, &[], info.as_bytes())
}

/// Derives a privacy-preserving discovery hash from a phone number's SHA-256
/// digest and a daily rotating salt.
pub fn derive_discovery_hash(phone_sha256: &[u8; 32], daily_salt: &[u8]) -> [u8; 32] {
    derive_key(phone_sha256, daily_salt, labels::DISCOVERY_CACHED)
}

/// Advances the media chain key, providing forward secrecy — the previous chain
/// key cannot be recovered from the new one.
pub fn advance_media_chain(current: &[u8; 32]) -> [u8; 32] {
    derive_key(current, &[], labels::MEDIA_CHAIN_ADVANCE)
}

/// Initialises a media chain key for a new conversation from the device secret
/// and a conversation identifier.
pub fn init_media_chain(device_secret: &[u8; 32], conversation_id: &[u8]) -> [u8; 32] {
    derive_key(device_secret, conversation_id, labels::MEDIA_CHAIN_INIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_key_derivation_deterministic() {
        let chain_key = [1u8; 32];
        let file_hash = [2u8; 32];

        let key1 = derive_media_key(&chain_key, &file_hash);
        let key2 = derive_media_key(&chain_key, &file_hash);

        assert_eq!(key1, key2, "same inputs must produce the same media key");
    }

    #[test]
    fn test_media_key_different_files_different_keys() {
        let chain_key = [1u8; 32];
        let file_hash_a = [2u8; 32];
        let file_hash_b = [3u8; 32];

        let key_a = derive_media_key(&chain_key, &file_hash_a);
        let key_b = derive_media_key(&chain_key, &file_hash_b);

        assert_ne!(
            key_a, key_b,
            "different file hashes must yield different keys"
        );
    }

    #[test]
    fn test_domain_separation_produces_different_keys() {
        let ikm = [0xABu8; 32];
        let salt = [0xCDu8; 16];

        let k_media = derive_key(&ikm, &salt, labels::MEDIA_KEY);
        let k_access = derive_key(&ikm, &salt, labels::ACCESS_KEY);
        let k_discovery = derive_key(&ikm, &salt, labels::DISCOVERY_CACHED);

        assert_ne!(
            k_media, k_access,
            "MEDIA_KEY and ACCESS_KEY labels must diverge"
        );
        assert_ne!(
            k_media, k_discovery,
            "MEDIA_KEY and DISCOVERY_CACHED labels must diverge"
        );
        assert_ne!(
            k_access, k_discovery,
            "ACCESS_KEY and DISCOVERY_CACHED labels must diverge"
        );
    }

    #[test]
    fn test_access_key_device_isolation() {
        let media_key = [0x42u8; 32];
        let device_a = [1u8; 32];
        let device_b = [2u8; 32];

        let access_a = derive_access_key(&media_key, &device_a, "same-media");
        let access_b = derive_access_key(&media_key, &device_b, "same-media");

        assert_ne!(
            access_a, access_b,
            "different device secrets must produce different access keys"
        );
    }

    #[test]
    fn test_access_key_per_media_uniqueness() {
        let media_key = [0x42u8; 32];
        let device_secret = [0x01u8; 32];

        let key_a = derive_access_key(&media_key, &device_secret, "media-aaa");
        let key_b = derive_access_key(&media_key, &device_secret, "media-bbb");

        assert_ne!(
            key_a, key_b,
            "different media IDs must produce different access keys"
        );
    }

    #[test]
    fn test_media_chain_forward_secrecy() {
        let initial = [0xFFu8; 32];

        let step1 = advance_media_chain(&initial);
        let step2 = advance_media_chain(&step1);
        let step3 = advance_media_chain(&step2);

        assert_ne!(initial, step1, "chain step 0 → 1 must differ");
        assert_ne!(step1, step2, "chain step 1 → 2 must differ");
        assert_ne!(step2, step3, "chain step 2 → 3 must differ");
        assert_ne!(initial, step3, "non-adjacent chain keys must differ");
    }
}
