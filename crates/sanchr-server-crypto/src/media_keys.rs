use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

const MEDIA_KEY_INFO: &[u8] = b"sanchr-media-v1";

/// Verifies that `claimed_media_key` is the correct HKDF-SHA256 derivation
/// of `chain_key` and `file_hash` under the `sanchr-media-v1` domain label.
///
/// The comparison is performed in constant time to prevent timing-based
/// oracle attacks.
pub fn verify_media_key_derivation(
    chain_key: &[u8; 32],
    file_hash: &[u8; 32],
    claimed_media_key: &[u8; 32],
) -> bool {
    let derived = derive_media_key_internal(chain_key, file_hash);
    // subtle::ConstantTimeEq returns Choice (1 = equal, 0 = not equal)
    derived.ct_eq(claimed_media_key).into()
}

fn derive_media_key_internal(chain_key: &[u8; 32], file_hash: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(chain_key);
    ikm[32..].copy_from_slice(file_hash);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(MEDIA_KEY_INFO, &mut okm)
        .expect("HKDF expand failed: output length is valid for SHA-256");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct_derivation() {
        let chain_key = [0x11u8; 32];
        let file_hash = [0x22u8; 32];

        let correct_key = derive_media_key_internal(&chain_key, &file_hash);
        assert!(
            verify_media_key_derivation(&chain_key, &file_hash, &correct_key),
            "correctly derived key must pass verification"
        );
    }

    #[test]
    fn test_reject_wrong_derivation() {
        let chain_key = [0x11u8; 32];
        let file_hash = [0x22u8; 32];
        let wrong_key = [0xFFu8; 32];

        assert!(
            !verify_media_key_derivation(&chain_key, &file_hash, &wrong_key),
            "wrong key must be rejected"
        );
    }
}
