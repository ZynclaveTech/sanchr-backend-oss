//! Sealed-sender certificate signer compatible with libsignal-protocol.
//!
//! Issued certificates use libsignal-canonical key encoding:
//!   * public keys are 33 bytes: `[0x05 (DJB type tag), curve25519_pub (32B)]`
//!   * signatures are 64-byte XEdDSA signatures over the inner certificate bytes
//!     (per <https://signal.org/docs/specifications/xeddsa/#curve25519>).
//!
//! This module reuses the existing 32-byte server seed (previously fed to
//! ed25519-dalek's `SigningKey::from_bytes`) as a Curve25519 private key. The
//! same secret material continues to work; only the derived public key (and
//! therefore the client trust root) changes.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::{self, Scalar};
use prost::Message;
// In the OSS workspace `rand` is at 0.10 (no `OsRng` re-export) but the
// `rand_core` 0.6 dep — pulled in by `argon2` and `curve25519-dalek` — still
// exposes the classic `OsRng` + `CryptoRng + RngCore` traits. Pin to those
// so we don't have to track `rand`'s churn.
use rand_core::{CryptoRng, OsRng, RngCore};
use sanchr_proto::sealed_sender::{
    sender_certificate, server_certificate, SenderCertificate, ServerCertificate,
};
// `Scalar::from_hash` requires a `digest::Digest` impl, but `sha2 0.11` (the
// workspace pin) and `curve25519-dalek 4.x` use incompatible `digest` major
// versions. We sidestep that by hashing into a 64-byte buffer with sha2's
// API and feeding it to `Scalar::from_bytes_mod_order_wide` — same semantics,
// no trait-bound coupling.
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// Type byte prefix for DJB (Curve25519) public keys in libsignal's wire format.
const DJB_TYPE: u8 = 0x05;
const CURVE25519_KEY_LEN: usize = 32;
const TYPED_PUBLIC_KEY_LEN: usize = 1 + CURVE25519_KEY_LEN; // 33
const XEDDSA_SIGNATURE_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum SealedSenderError {
    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),
    #[error("identity_key must be 33 bytes (1-byte type tag + 32-byte key), got {0}")]
    InvalidIdentityKeyLength(usize),
    #[error("identity_key has invalid type byte 0x{0:02x}; expected 0x05 (Curve25519/DJB)")]
    InvalidIdentityKeyType(u8),
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] prost::EncodeError),
    #[error("system clock error")]
    Clock,
}

/// Signs `SenderCertificate` protos using a Curve25519 (XEdDSA) server key.
///
/// The issued certificates follow libsignal's canonical wire format so they
/// can be decoded by `org.signal.libsignal.protocol.SenderCertificate(bytes)`
/// on Android / iOS without modification.
pub struct SealedSenderSigner {
    /// Raw Curve25519 private scalar (clamped on construction).
    secret: StaticSecret,
    /// Cached 33-byte type-prefixed public key (`[0x05, ...]`).
    public_key_typed: [u8; TYPED_PUBLIC_KEY_LEN],
    key_id: u32,
}

impl SealedSenderSigner {
    /// Load from a deterministic 32-byte seed (production: read from config / HSM).
    ///
    /// The seed is interpreted as a Curve25519 private key with standard
    /// X25519 clamping (matches `libsignal_core::curve::curve25519::PrivateKey::from`).
    pub fn from_seed(seed: &[u8; 32], key_id: u32) -> Self {
        let clamped = scalar::clamp_integer(*seed);
        let secret = StaticSecret::from(clamped);
        Self::from_secret(secret, key_id)
    }

    /// Generate a random signing key. Use only in dev/test environments.
    pub fn generate(key_id: u32) -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes = scalar::clamp_integer(bytes);
        Self::from_secret(StaticSecret::from(bytes), key_id)
    }

    fn from_secret(secret: StaticSecret, key_id: u32) -> Self {
        let pubkey = *XPublicKey::from(&secret).as_bytes();
        let mut public_key_typed = [0u8; TYPED_PUBLIC_KEY_LEN];
        public_key_typed[0] = DJB_TYPE;
        public_key_typed[1..].copy_from_slice(&pubkey);
        Self {
            secret,
            public_key_typed,
            key_id,
        }
    }

    /// Returns the 33-byte type-prefixed Curve25519 public key suitable for
    /// embedding as the client trust root (`[0x05, ...32B...]`).
    pub fn trust_root_public_key_bytes(&self) -> Vec<u8> {
        self.public_key_typed.to_vec()
    }

    /// Issue a `SenderCertificate` for the given sender.
    ///
    /// `identity_key` must be the 33-byte libsignal-serialized identity public
    /// key as emitted by `IdentityKeyPair.publicKey.serialize()` on Android
    /// (1-byte DJB tag + 32-byte raw key). It is passed through unchanged into
    /// the inner certificate.
    ///
    /// Returns `(serialized_sender_certificate, expiration_unix_ts_seconds)`.
    /// The certificate is valid for 24 hours from the current time.
    pub fn issue_certificate(
        &self,
        sender_uuid: &str,
        sender_device_id: u32,
        identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), SealedSenderError> {
        if identity_key.len() != TYPED_PUBLIC_KEY_LEN {
            return Err(SealedSenderError::InvalidIdentityKeyLength(
                identity_key.len(),
            ));
        }
        if identity_key[0] != DJB_TYPE {
            return Err(SealedSenderError::InvalidIdentityKeyType(identity_key[0]));
        }

        let expires = now_unix()? + 86_400;

        // --- 1. ServerCertificate ---
        let server_cert_inner = server_certificate::Certificate {
            id: self.key_id,
            key: self.public_key_typed.to_vec(),
        };
        let server_cert_bytes = server_cert_inner.encode_to_vec();
        let server_sig = self.xeddsa_sign(&server_cert_bytes, &mut OsRng);

        let server_certificate = ServerCertificate {
            certificate: server_cert_bytes,
            signature: server_sig.to_vec(),
        };

        // --- 2. SenderCertificate ---
        // Field numbers match libsignal's canonical SenderCertificate.Certificate
        // (sender_device=2, expires=3, identity_key=4, signer=5, sender_uuid=6).
        let sender_cert_inner = sender_certificate::Certificate {
            sender_uuid: sender_uuid.to_string(),
            sender_device: sender_device_id,
            expires,
            identity_key: identity_key.to_vec(),
            signer: Some(server_certificate),
        };
        let sender_cert_bytes = sender_cert_inner.encode_to_vec();
        let sender_sig = self.xeddsa_sign(&sender_cert_bytes, &mut OsRng);

        let sender_certificate = SenderCertificate {
            certificate: sender_cert_bytes,
            signature: sender_sig.to_vec(),
        };

        Ok((sender_certificate.encode_to_vec(), expires))
    }

    /// XEdDSA signature using the X25519 private key directly.
    ///
    /// Mirrors `libsignal_core::curve::curve25519::PrivateKey::calculate_signature`
    /// (AGPL-3.0, Signal Messenger LLC) — see
    /// <https://signal.org/docs/specifications/xeddsa/#curve25519>.
    fn xeddsa_sign<R: CryptoRng + RngCore>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> [u8; XEDDSA_SIGNATURE_LEN] {
        let mut random_bytes = [0u8; 64];
        csprng.fill_bytes(&mut random_bytes);

        let key_data = self.secret.to_bytes();
        let a = Scalar::from_bytes_mod_order(key_data);
        let ed_public_key_point = &a * ED25519_BASEPOINT_TABLE;
        let ed_public_key = ed_public_key_point.compress();
        let sign_bit = ed_public_key.as_bytes()[31] & 0b1000_0000_u8;

        // Domain-separation prefix: 0xFE followed by 31 0xFF bytes.
        const HASH_PREFIX: [u8; 32] = [
            0xFEu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ];

        let mut hash1 = Sha512::new();
        hash1.update(HASH_PREFIX.as_slice());
        hash1.update(key_data.as_slice());
        hash1.update(message);
        hash1.update(random_bytes.as_slice());
        let r = scalar_from_sha512(hash1);
        let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress();

        let mut hash = Sha512::new();
        hash.update(cap_r.as_bytes());
        hash.update(ed_public_key.as_bytes());
        hash.update(message);
        let h = scalar_from_sha512(hash);

        let s = (h * a) + r;

        let mut result = [0u8; XEDDSA_SIGNATURE_LEN];
        result[..32].copy_from_slice(cap_r.as_bytes());
        result[32..].copy_from_slice(s.as_bytes());
        // Stash the Edwards-point sign bit into the high bit of s (libsignal-java
        // compatibility — diverges slightly from the XEdDSA paper which fixes it
        // to 0).
        result[XEDDSA_SIGNATURE_LEN - 1] &= 0b0111_1111_u8;
        result[XEDDSA_SIGNATURE_LEN - 1] |= sign_bit;
        result
    }
}

/// Bridge between `sha2 0.11` (workspace) and `curve25519-dalek 4.x` (which
/// expects `digest 0.10`'s `Digest` trait). Finalises to a `[u8; 64]` and
/// reduces mod ℓ — exactly what `Scalar::from_hash::<Sha512>` would do.
fn scalar_from_sha512(hash: Sha512) -> Scalar {
    let bytes: [u8; 64] = hash.finalize().into();
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn now_unix() -> Result<u64, SealedSenderError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SealedSenderError::Clock)
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use subtle::ConstantTimeEq;

    /// XEdDSA verification — matches libsignal_core's `PrivateKey::verify_signature`.
    /// Used only in tests; production verification happens on the client.
    fn xeddsa_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let mont_point = MontgomeryPoint(*public_key);
        let ed_pub_key_point = match mont_point.to_edwards((signature[63] & 0b1000_0000_u8) >> 7) {
            Some(x) => x,
            None => return false,
        };
        let cap_a = ed_pub_key_point.compress();
        let mut cap_r = [0u8; 32];
        cap_r.copy_from_slice(&signature[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);
        s[31] &= 0b0111_1111_u8;
        if (s[31] & 0b1110_0000_u8) != 0 {
            return false;
        }
        let minus_cap_a = -ed_pub_key_point;

        let mut hash = Sha512::new();
        hash.update(cap_r.as_slice());
        hash.update(cap_a.as_bytes());
        hash.update(message);
        let h = scalar_from_sha512(hash);

        let cap_r_check_point = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &h,
            &minus_cap_a,
            &Scalar::from_bytes_mod_order(s),
        );
        let cap_r_check = cap_r_check_point.compress();
        bool::from(cap_r_check.as_bytes().ct_eq(&cap_r))
    }

    fn dummy_identity_key() -> Vec<u8> {
        let mut k = vec![0u8; TYPED_PUBLIC_KEY_LEN];
        k[0] = 0x05;
        for (i, b) in k.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn trust_root_pubkey_is_typed_curve25519() {
        let signer = SealedSenderSigner::generate(1);
        let trust_root = signer.trust_root_public_key_bytes();
        assert_eq!(trust_root.len(), 33);
        assert_eq!(trust_root[0], 0x05);
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0xA5u8; 32];
        let a = SealedSenderSigner::from_seed(&seed, 1);
        let b = SealedSenderSigner::from_seed(&seed, 1);
        assert_eq!(
            a.trust_root_public_key_bytes(),
            b.trust_root_public_key_bytes()
        );
    }

    /// Fixture emitter for the Android oracle test in
    /// `core/crypto/src/test/java/.../SealedSenderInteropFixtureTest.kt`.
    ///
    /// Prints a deterministic `(trust_root_b64, cert_b64)` pair for a fixed
    /// seed + sender identity. The Android side embeds these bytes verbatim
    /// and proves that libsignal-android's `SenderCertificate(bytes)` decoder
    /// + `CertificateValidator` accept what this Rust signer produces.
    ///
    /// To regenerate fixtures after a wire-format change, run:
    ///   cargo test -p sanchr-server-crypto sealed_sender::tests::emit_kotlin_oracle_fixture -- --nocapture
    /// and paste the printed values into the Kotlin test.
    #[test]
    fn emit_kotlin_oracle_fixture() {
        let seed = [0x11u8; 32];
        let signer = SealedSenderSigner::from_seed(&seed, 7);
        // Deterministic 33-byte type-prefixed identity key.
        let mut identity_key = [0u8; 33];
        identity_key[0] = 0x05;
        for (i, b) in identity_key.iter_mut().enumerate().skip(1) {
            *b = (i as u8).wrapping_mul(0x37);
        }
        let (cert_bytes, expires) = signer
            .issue_certificate("11111111-2222-3333-4444-555555555555", 1, &identity_key)
            .expect("issue_certificate succeeds");
        let trust_root_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signer.trust_root_public_key_bytes(),
        );
        let cert_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_bytes);
        let identity_key_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, identity_key);
        println!("KOTLIN_FIXTURE_TRUST_ROOT_B64={trust_root_b64}");
        println!("KOTLIN_FIXTURE_CERT_B64={cert_b64}");
        println!("KOTLIN_FIXTURE_IDENTITY_KEY_B64={identity_key_b64}");
        println!("KOTLIN_FIXTURE_EXPIRES_UNIX={expires}");
    }

    #[test]
    fn from_seed_logs_trust_root_pubkey_for_operators() {
        // Stable seed so this test prints the same pubkey every CI run; useful
        // when grepping `cargo test -- --nocapture`.
        let seed = [0u8; 32];
        let signer = SealedSenderSigner::from_seed(&seed, 1);
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signer.trust_root_public_key_bytes(),
        );
        println!("SEALED_SENDER_TRUST_ROOT_FROM_ZERO_SEED={b64}");
    }

    #[test]
    fn issued_cert_has_libsignal_canonical_shape() {
        let signer = SealedSenderSigner::generate(42);
        let identity_key = dummy_identity_key();

        let (cert_bytes, expires) = signer
            .issue_certificate("user-uuid-123", 7, &identity_key)
            .expect("issue_certificate succeeds");

        let sender_cert =
            SenderCertificate::decode(cert_bytes.as_slice()).expect("valid SenderCertificate");
        assert_eq!(
            sender_cert.signature.len(),
            XEDDSA_SIGNATURE_LEN,
            "XEdDSA outer signature must be 64 bytes"
        );

        let inner = sender_certificate::Certificate::decode(sender_cert.certificate.as_slice())
            .expect("valid inner Certificate");
        assert_eq!(inner.sender_uuid, "user-uuid-123");
        assert_eq!(inner.sender_device, 7);
        assert_eq!(inner.expires, expires);
        assert_eq!(
            inner.identity_key.len(),
            TYPED_PUBLIC_KEY_LEN,
            "identity_key must be 33 bytes (type-prefixed)"
        );
        assert_eq!(inner.identity_key[0], 0x05);
        assert_eq!(inner.identity_key, identity_key);

        let server_cert = inner.signer.expect("signer present");
        assert_eq!(server_cert.signature.len(), XEDDSA_SIGNATURE_LEN);

        let server_inner =
            server_certificate::Certificate::decode(server_cert.certificate.as_slice())
                .expect("valid ServerCertificate inner");
        assert_eq!(server_inner.id, 42);
        assert_eq!(
            server_inner.key.len(),
            TYPED_PUBLIC_KEY_LEN,
            "ServerCertificate.key must be 33 bytes (type-prefixed)"
        );
        assert_eq!(server_inner.key[0], 0x05);
        assert_eq!(server_inner.key, signer.trust_root_public_key_bytes());
    }

    #[test]
    fn issued_cert_signatures_verify_with_xeddsa() {
        let signer = SealedSenderSigner::generate(99);
        let identity_key = dummy_identity_key();

        let (cert_bytes, _) = signer
            .issue_certificate("verify-me", 3, &identity_key)
            .expect("issue_certificate succeeds");

        let sender_cert =
            SenderCertificate::decode(cert_bytes.as_slice()).expect("valid SenderCertificate");

        // Strip the 0x05 type byte before passing to raw XEdDSA verifier.
        let raw_pub: [u8; 32] = signer.public_key_typed[1..].try_into().unwrap();
        let outer_sig: [u8; 64] = sender_cert.signature.as_slice().try_into().unwrap();
        assert!(
            xeddsa_verify(&raw_pub, &sender_cert.certificate, &outer_sig),
            "outer SenderCertificate XEdDSA signature must verify"
        );

        let inner = sender_certificate::Certificate::decode(sender_cert.certificate.as_slice())
            .expect("valid inner");
        let server_cert = inner.signer.expect("signer present");
        let server_sig: [u8; 64] = server_cert.signature.as_slice().try_into().unwrap();
        assert!(
            xeddsa_verify(&raw_pub, &server_cert.certificate, &server_sig),
            "inner ServerCertificate XEdDSA signature must verify"
        );
    }

    #[test]
    fn rejects_identity_key_with_wrong_length() {
        let signer = SealedSenderSigner::generate(1);
        let err = signer
            .issue_certificate("u", 1, &[0x05u8; 32])
            .expect_err("32-byte identity key must be rejected");
        assert!(matches!(
            err,
            SealedSenderError::InvalidIdentityKeyLength(32)
        ));
    }

    #[test]
    fn rejects_identity_key_with_wrong_type_byte() {
        let signer = SealedSenderSigner::generate(1);
        let mut bad = [0u8; 33];
        bad[0] = 0x3c;
        let err = signer
            .issue_certificate("u", 1, &bad)
            .expect_err("non-0x05 type byte must be rejected");
        assert!(matches!(
            err,
            SealedSenderError::InvalidIdentityKeyType(0x3c)
        ));
    }

    #[test]
    fn certificate_expires_24h_from_now() {
        let signer = SealedSenderSigner::generate(1);
        let (_cert, expires) = signer
            .issue_certificate("user-abc", 1, &dummy_identity_key())
            .expect("issue_certificate succeeds");
        let expected = now_unix().expect("clock") + 86_400;
        let diff = expires.abs_diff(expected);
        assert!(diff <= 1, "expiration should be within 1s of now+86400");
    }
}
