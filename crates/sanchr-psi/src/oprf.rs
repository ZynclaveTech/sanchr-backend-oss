//! OPRF (Oblivious Pseudo-Random Function) core implementation.
//!
//! Uses Ristretto255 (a prime-order group built on Curve25519) for a
//! 2-HashDH-OPRF:
//!   - Server holds secret scalar `k`.
//!   - Client blinds input:  B = r * H(phone),  sends B.
//!   - Server evaluates:     R = k * B,          sends R.
//!   - Client unblinds:      r⁻¹ * R = k * H(phone).
//!
//! The final value `k * H(phone)` is stable and can be compared against
//! the server's pre-computed set without revealing `phone` to the server
//! or `k` to the client.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OprfError {
    /// The compressed point could not be decompressed into a valid group element.
    #[error("decompression failed: bytes do not encode a valid Ristretto point")]
    DecompressionFailed,

    /// A supplied compressed point is the identity / not on the curve.
    #[error("invalid point: expected a non-identity Ristretto point")]
    InvalidPoint,

    /// The scalar is zero, which would produce an insecure result.
    #[error("zero scalar: blinding/server scalar must be non-zero")]
    ZeroScalar,
}

// ── Server secret ─────────────────────────────────────────────────────────────

/// The server-side OPRF secret.  Wraps a non-zero `Scalar`.
///
/// Must be kept confidential; exposing it breaks the obliviousness guarantee.
#[derive(Clone)]
pub struct OprfServerSecret {
    scalar: Scalar,
}

impl OprfServerSecret {
    /// Generate a fresh random server secret using the OS CSPRNG.
    ///
    /// The generated scalar is guaranteed to be non-zero (probability of
    /// hitting zero is 1/|group order| ≈ 2⁻²⁵²).
    pub fn generate() -> Self {
        loop {
            let scalar = Scalar::random(&mut OsRng);
            if scalar != Scalar::ZERO {
                return Self { scalar };
            }
        }
    }

    /// Reconstruct a server secret from a previously serialised 32-byte array.
    ///
    /// Returns `None` if the bytes do not represent a canonical, non-zero scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let scalar: Option<Scalar> = Scalar::from_canonical_bytes(*bytes).into();
        let scalar = scalar?;
        if scalar == Scalar::ZERO {
            return None;
        }
        Some(Self { scalar })
    }

    /// Serialise the secret to a 32-byte canonical encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Server-side evaluation: R = k * B.
    ///
    /// `blinded_point` is the compressed point sent by the client.
    /// Returns the compressed evaluated point, or an error if the input is
    /// not a valid Ristretto point.
    pub fn evaluate(
        &self,
        blinded_point: &CompressedRistretto,
    ) -> Result<CompressedRistretto, OprfError> {
        let point = blinded_point
            .decompress()
            .ok_or(OprfError::DecompressionFailed)?;

        // Reject the identity element — evaluating on it leaks nothing useful
        // and indicates a misbehaving or buggy client.
        if point == RistrettoPoint::default() {
            return Err(OprfError::InvalidPoint);
        }

        Ok((self.scalar * point).compress())
    }

    /// Batch variant of [`evaluate`](Self::evaluate).
    ///
    /// Fails fast: returns an error as soon as the first invalid point is
    /// encountered.
    pub fn evaluate_batch(
        &self,
        points: &[CompressedRistretto],
    ) -> Result<Vec<CompressedRistretto>, OprfError> {
        points.iter().map(|p| self.evaluate(p)).collect()
    }

    /// Compute the canonical set element for a phone number without going
    /// through the client blinding protocol.
    ///
    /// Used server-side to pre-compute the registered-user lookup set:
    ///   element = k * H(phone_e164)
    pub fn compute_set_element(&self, phone_e164: &str) -> CompressedRistretto {
        let h = hash_to_point(phone_e164);
        (self.scalar * h).compress()
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Hash an arbitrary string to a `RistrettoPoint` using the standard
/// hash-to-group construction (Elligator2 with SHA-512).
pub fn hash_to_point(input: &str) -> RistrettoPoint {
    let digest: [u8; 64] = Sha512::digest(input.as_bytes()).into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

/// Client-side blinding.
///
/// Returns `(r, r * H(phone))` where `r` is a fresh random scalar.
/// The caller must keep `r` secret until unblinding.
///
/// # Panics
///
/// In the astronomically unlikely event that the generated scalar is zero
/// this function loops until a non-zero scalar is drawn.
pub fn blind(phone_e164: &str) -> (Scalar, CompressedRistretto) {
    let h = hash_to_point(phone_e164);
    loop {
        let r = Scalar::random(&mut OsRng);
        if r != Scalar::ZERO {
            let blinded = (r * h).compress();
            return (r, blinded);
        }
    }
}

/// Client-side unblinding.
///
/// Given the blinding scalar `r` and the server's response `R = k * r * H(phone)`,
/// returns `r⁻¹ * R = k * H(phone)`.
///
/// Returns an error if `blinding_scalar` is zero or if `server_response`
/// cannot be decompressed.
pub fn unblind(
    blinding_scalar: &Scalar,
    server_response: &CompressedRistretto,
) -> Result<CompressedRistretto, OprfError> {
    if *blinding_scalar == Scalar::ZERO {
        return Err(OprfError::ZeroScalar);
    }

    let point = server_response
        .decompress()
        .ok_or(OprfError::DecompressionFailed)?;

    let r_inv = blinding_scalar.invert();
    Ok((r_inv * point).compress())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Full OPRF round-trip: blind → server evaluate → client unblind must
    /// equal the direct server computation `k * H(phone)`.
    #[test]
    fn test_oprf_roundtrip() {
        let secret = OprfServerSecret::generate();
        let phone = "+14155552671";

        let (r, blinded) = blind(phone);
        let server_resp = secret.evaluate(&blinded).expect("evaluate should succeed");
        let unblinded = unblind(&r, &server_resp).expect("unblind should succeed");

        let expected = secret.compute_set_element(phone);
        assert_eq!(unblinded, expected, "unblinded value must equal k·H(phone)");
    }

    /// Batch variant: three different phone numbers all round-trip correctly.
    #[test]
    fn test_oprf_batch_roundtrip() {
        let secret = OprfServerSecret::generate();
        let phones = ["+14155552671", "+447911123456", "+819012345678"];

        let (scalars, blinded_points): (Vec<_>, Vec<_>) = phones.iter().map(|p| blind(p)).unzip();

        let server_responses = secret
            .evaluate_batch(&blinded_points)
            .expect("batch evaluate should succeed");

        for ((phone, r), resp) in phones
            .iter()
            .zip(scalars.iter())
            .zip(server_responses.iter())
        {
            let unblinded = unblind(r, resp).expect("unblind should succeed");
            let expected = secret.compute_set_element(phone);
            assert_eq!(unblinded, expected, "mismatch for {}", phone);
        }
    }

    /// Two independent blindings of the same phone number must unblind to the
    /// same value — proving that the blinding scalar cancels correctly.
    #[test]
    fn test_different_blindings_same_result() {
        let secret = OprfServerSecret::generate();
        let phone = "+14155552671";

        let (r1, blinded1) = blind(phone);
        let (r2, blinded2) = blind(phone);

        // The two blinded points should (with overwhelming probability) differ.
        assert_ne!(
            blinded1, blinded2,
            "different blindings should produce different points"
        );

        let resp1 = secret.evaluate(&blinded1).expect("evaluate 1");
        let resp2 = secret.evaluate(&blinded2).expect("evaluate 2");

        let result1 = unblind(&r1, &resp1).expect("unblind 1");
        let result2 = unblind(&r2, &resp2).expect("unblind 2");

        assert_eq!(result1, result2, "both unblinded results must be equal");
    }

    /// Round-trip serialisation: serialize → deserialize → same OPRF output.
    #[test]
    fn test_server_secret_serialization() {
        let secret = OprfServerSecret::generate();
        let bytes = secret.to_bytes();

        let restored = OprfServerSecret::from_bytes(&bytes)
            .expect("from_bytes must succeed for a valid secret");

        let phone = "+14155552671";
        assert_eq!(
            secret.compute_set_element(phone),
            restored.compute_set_element(phone),
            "restored secret must produce the same OPRF output"
        );
    }

    /// Garbage bytes must be rejected by `evaluate` with `DecompressionFailed`.
    #[test]
    fn test_invalid_point_rejected() {
        let secret = OprfServerSecret::generate();

        // All-ones bytes do not encode a valid Ristretto point.
        let garbage = CompressedRistretto([0xFF; 32]);

        let err = secret
            .evaluate(&garbage)
            .expect_err("evaluate should reject garbage bytes");

        assert_eq!(err, OprfError::DecompressionFailed);
    }
}
