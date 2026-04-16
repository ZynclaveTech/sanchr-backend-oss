use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use sanchr_proto::sealed_sender::{
    sender_certificate, server_certificate, SenderCertificate, ServerCertificate,
};

#[derive(Debug, thiserror::Error)]
pub enum SealedSenderError {
    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),
    #[error("protobuf encode error: {0}")]
    EncodeError(#[from] prost::EncodeError),
    #[error("system clock error")]
    Clock,
}

/// Signs `SenderCertificate` protos using an Ed25519 server key.
///
/// The issued certificates follow the libsignal `SenderCertificate`
/// protobuf format so clients can verify them with the standard
/// sealed-sender verification path.
pub struct SealedSenderSigner {
    signing_key: SigningKey,
    key_id: u32,
}

impl SealedSenderSigner {
    /// Load from a deterministic 32-byte seed (production: read from config / HSM).
    pub fn from_seed(seed: &[u8; 32], key_id: u32) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
            key_id,
        }
    }

    /// Generate a random signing key. Use only in dev/test environments.
    pub fn generate(key_id: u32) -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            signing_key: SigningKey::generate(&mut rng),
            key_id,
        }
    }

    /// Return the raw 32-byte public key for embedding in client trust stores.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        let vk: VerifyingKey = (&self.signing_key).into();
        vk.to_bytes()
    }

    /// Issue a `SenderCertificate` for the given sender.
    ///
    /// Returns `(serialized_sender_certificate, expiration_unix_ts)`.
    /// The certificate is valid for 24 hours from the current time.
    pub fn issue_certificate(
        &self,
        sender_uuid: &str,
        sender_device_id: u32,
        identity_key: &[u8],
    ) -> Result<(Vec<u8>, u64), SealedSenderError> {
        let expires = now_unix()? + 86400;

        // --- 1. Build ServerCertificate ---
        let server_cert_inner = server_certificate::Certificate {
            id: self.key_id,
            key: self.public_key_bytes().to_vec(),
        };
        let server_cert_bytes = server_cert_inner.encode_to_vec();
        let server_sig = self.signing_key.sign(&server_cert_bytes);

        let server_certificate = ServerCertificate {
            certificate: server_cert_bytes,
            signature: server_sig.to_bytes().to_vec(),
        };

        // --- 2. Build SenderCertificate ---
        let sender_cert_inner = sender_certificate::Certificate {
            sender_uuid: sender_uuid.to_string(),
            sender_device_id,
            expires,
            identity_key: identity_key.to_vec(),
            signer: Some(server_certificate),
        };
        let sender_cert_bytes = sender_cert_inner.encode_to_vec();
        let sender_sig = self.signing_key.sign(&sender_cert_bytes);

        let sender_certificate = SenderCertificate {
            certificate: sender_cert_bytes,
            signature: sender_sig.to_bytes().to_vec(),
        };

        Ok((sender_certificate.encode_to_vec(), expires))
    }
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
    use ed25519_dalek::Verifier;

    #[test]
    fn test_issue_certificate_returns_valid_protobuf() {
        let signer = SealedSenderSigner::generate(42);
        let identity_key = [0xABu8; 33]; // fake identity key

        let (cert_bytes, _expires) = signer
            .issue_certificate("user-uuid-123", 7, &identity_key)
            .expect("issue_certificate should succeed");

        // Decode outer SenderCertificate
        let sender_cert =
            SenderCertificate::decode(cert_bytes.as_slice()).expect("valid SenderCertificate");
        assert_eq!(sender_cert.signature.len(), 64, "Ed25519 sig is 64 bytes");

        // Decode inner Certificate
        let inner = sender_certificate::Certificate::decode(sender_cert.certificate.as_slice())
            .expect("valid inner Certificate");
        assert_eq!(inner.sender_uuid, "user-uuid-123");
        assert_eq!(inner.sender_device_id, 7);
        assert_eq!(inner.identity_key, identity_key.to_vec());

        // Verify embedded ServerCertificate
        let server_cert = inner.signer.expect("signer must be present");
        assert_eq!(server_cert.signature.len(), 64);

        let server_inner =
            server_certificate::Certificate::decode(server_cert.certificate.as_slice())
                .expect("valid ServerCertificate inner");
        assert_eq!(server_inner.id, 42);
        assert_eq!(server_inner.key, signer.public_key_bytes().to_vec());
    }

    #[test]
    fn test_certificate_expiration_is_24h_from_now() {
        let signer = SealedSenderSigner::generate(1);
        let (_cert_bytes, expires) = signer
            .issue_certificate("user-abc", 1, &[0u8; 33])
            .expect("issue_certificate should succeed");

        let expected = now_unix().expect("clock error") + 86400;
        let diff = expires.abs_diff(expected);
        assert!(diff <= 1, "expiration should be within 1s of now + 86400");
    }

    #[test]
    fn test_certificate_signature_is_verifiable() {
        let signer = SealedSenderSigner::generate(99);
        let identity_key = [0xCDu8; 33];

        let (cert_bytes, _) = signer
            .issue_certificate("verify-me", 3, &identity_key)
            .expect("issue_certificate should succeed");

        let sender_cert =
            SenderCertificate::decode(cert_bytes.as_slice()).expect("valid SenderCertificate");

        // Verify the SenderCertificate signature
        let vk = VerifyingKey::from_bytes(&signer.public_key_bytes()).expect("valid verifying key");
        let sig_bytes: [u8; 64] = sender_cert
            .signature
            .as_slice()
            .try_into()
            .expect("64-byte signature");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(&sender_cert.certificate, &sig)
            .expect("SenderCertificate signature must verify");

        // Also verify the embedded ServerCertificate signature
        let inner = sender_certificate::Certificate::decode(sender_cert.certificate.as_slice())
            .expect("valid inner");
        let server_cert = inner.signer.expect("signer present");
        let server_sig_bytes: [u8; 64] = server_cert
            .signature
            .as_slice()
            .try_into()
            .expect("64-byte server signature");
        let server_sig = ed25519_dalek::Signature::from_bytes(&server_sig_bytes);
        vk.verify(&server_cert.certificate, &server_sig)
            .expect("ServerCertificate signature must verify");
    }
}
