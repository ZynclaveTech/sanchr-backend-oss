//! Salted Bloom filter — Layer 1 (fast-path) of the hybrid contact discovery system.
//!
//! A phone number that is **absent** from the filter is definitely not a registered
//! user; the client can skip the expensive OPRF-PSI round-trip for that contact.
//! The daily salt is rotated every 24 hours via the EKF, limiting rainbow-table
//! exposure for the hash values stored in the bit-array.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a cryptographically random 32-byte salt for daily Bloom filter rotation.
///
/// Uses the OS CSPRNG via `rand::rngs::OsRng`.
pub fn generate_daily_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// A space-efficient probabilistic membership structure with a rotating daily salt.
///
/// Sizing follows the standard optimal formulas:
/// - `m = -n * ln(p) / (ln 2)^2`  (number of bits)
/// - `k = (m / n) * ln 2`          (number of hash functions)
///
/// Double-hashing is used to derive `k` independent bit indices from a single
/// 32-byte SHA-256 digest, avoiding the cost of `k` separate hash computations.
#[derive(Debug, Clone)]
pub struct SaltedBloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: u8,
    salt: Vec<u8>,
}

impl SaltedBloomFilter {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new filter sized for `expected_items` entries at `fp_rate` false-positive
    /// probability, keyed with `daily_salt`.
    ///
    /// Panics if `fp_rate` is not in the open interval `(0.0, 1.0)`.
    pub fn new(expected_items: usize, fp_rate: f64, daily_salt: &[u8]) -> Self {
        assert!(
            fp_rate > 0.0 && fp_rate < 1.0,
            "fp_rate must be in (0.0, 1.0), got {fp_rate}"
        );
        let n = expected_items.max(1);
        let m = Self::optimal_num_bits(n, fp_rate);
        let k = Self::optimal_num_hashes(n, m);

        // Round up to the nearest byte boundary.
        let byte_len = m.div_ceil(8);

        Self {
            bits: vec![0u8; byte_len],
            num_bits: m,
            num_hashes: k,
            salt: daily_salt.to_vec(),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Add `phone_e164` to the filter.
    pub fn insert(&mut self, phone_e164: &str) {
        let hash = self.hash_phone(phone_e164);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(&hash, i);
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Returns `true` if `phone_e164` *might* be in the set.
    /// Returns `false` if it is *definitely not* in the set.
    pub fn might_contain(&self, phone_e164: &str) -> bool {
        let hash = self.hash_phone(phone_e164);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(&hash, i);
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Compute `SHA-256(phone_bytes || salt_bytes)`.
    ///
    /// This is the *public* salted commitment used by the EKF rotation layer.
    /// Exposed as a `pub` associated function so callers can derive the same
    /// hash without constructing a full filter.
    pub fn salted_hash(phone_e164: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(phone_e164.as_bytes());
        hasher.update(salt);
        hasher.finalize().into()
    }

    /// Return a slice over the raw bit-array bytes, suitable for transmission
    /// to clients (e.g. serialised into a protobuf `bytes` field).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Number of hash functions (`k`).
    pub fn num_hashes(&self) -> u8 {
        self.num_hashes
    }

    /// Number of bits in the filter (`m`).
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Hash `phone_e164` against the filter's current salt.
    fn hash_phone(&self, phone_e164: &str) -> [u8; 32] {
        Self::salted_hash(phone_e164, &self.salt)
    }

    /// Derive the `i`-th bit index using double-hashing:
    ///
    /// ```text
    /// h1 = first  8 bytes of digest (little-endian u64)
    /// h2 = second 8 bytes of digest (little-endian u64)
    /// idx = (h1 + i * h2) mod num_bits
    /// ```
    ///
    /// This gives `k` approximately independent uniform bit positions from a
    /// single hash evaluation, which is standard practice (Kirsch & Mitzenmacher,
    /// "Less Hashing, Same Performance", ESA 2006).
    fn bit_index(&self, hash: &[u8; 32], i: u8) -> usize {
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        // Use wrapping arithmetic to avoid overflow panics.
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (combined % self.num_bits as u64) as usize
    }

    /// `m = ceil(-n * ln(p) / (ln 2)^2)`
    fn optimal_num_bits(n: usize, fp_rate: f64) -> usize {
        let ln2_sq = core::f64::consts::LN_2 * core::f64::consts::LN_2;
        let m = -(n as f64) * fp_rate.ln() / ln2_sq;
        // Ensure at least 8 bits (1 byte) so the byte slice is never empty.
        (m.ceil() as usize).max(8)
    }

    /// `k = round((m / n) * ln 2)`, clamped to [1, 255].
    fn optimal_num_hashes(n: usize, m: usize) -> u8 {
        let k = ((m as f64 / n as f64) * core::f64::consts::LN_2).round();
        (k as usize).clamp(1, 255) as u8
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Insert two phones; confirm both are found and a third (never inserted) is not.
    #[test]
    fn test_bloom_insert_and_check() {
        let salt = b"test-salt-2024";
        let mut bf = SaltedBloomFilter::new(100, 0.01, salt);

        let phone_a = "+14155550100";
        let phone_b = "+14155550101";
        let phone_c = "+14155550199"; // never inserted

        bf.insert(phone_a);
        bf.insert(phone_b);

        assert!(
            bf.might_contain(phone_a),
            "phone_a must be found after insert"
        );
        assert!(
            bf.might_contain(phone_b),
            "phone_b must be found after insert"
        );
        assert!(
            !bf.might_contain(phone_c),
            "phone_c was never inserted; expect false"
        );
    }

    /// The same phone number hashed with two different salts must produce different
    /// SHA-256 digests.
    #[test]
    fn test_bloom_different_salt_different_results() {
        let phone = "+14155550100";
        let salt_a = b"salt-day-1";
        let salt_b = b"salt-day-2";

        let hash_a = SaltedBloomFilter::salted_hash(phone, salt_a);
        let hash_b = SaltedBloomFilter::salted_hash(phone, salt_b);

        assert_ne!(
            hash_a, hash_b,
            "different salts must yield different digests"
        );

        // Additionally confirm that a filter built with salt_a does not report
        // membership when queried using salt_b — the internal hash_phone call
        // uses the filter's own salt, so inserting under salt_a and checking
        // under a filter keyed with salt_b must not find the entry.
        let mut bf_a = SaltedBloomFilter::new(100, 0.01, salt_a);
        bf_a.insert(phone);

        let bf_b = SaltedBloomFilter::new(100, 0.01, salt_b);
        // bf_b has no entries; regardless of salt collision probability this
        // should be false for a freshly constructed (all-zero) filter.
        assert!(
            !bf_b.might_contain(phone),
            "empty filter must not report membership"
        );
    }

    /// Insert 10 000 items, then probe 10 000 *different* items.  The empirical
    /// false-positive rate must stay below 2 % (the target is 1 %).
    #[test]
    fn test_bloom_false_positive_rate() {
        const N: usize = 10_000;
        const FP_TARGET: f64 = 0.01; // 1 % design rate
        const FP_LIMIT: f64 = 0.02; // 2 % hard ceiling in the test

        let salt = b"fp-rate-test-salt";
        let mut bf = SaltedBloomFilter::new(N, FP_TARGET, salt);

        // Insert phones "+1415555XXXX" for X in 0..N.
        for i in 0..N {
            let phone = format!("+1415{:07}", i);
            bf.insert(&phone);
        }

        // Probe phones in a disjoint range "+1416555XXXX".
        let mut false_positives = 0usize;
        for i in 0..N {
            let phone = format!("+1416{:07}", i);
            if bf.might_contain(&phone) {
                false_positives += 1;
            }
        }

        let fp_rate = false_positives as f64 / N as f64;
        assert!(
            fp_rate < FP_LIMIT,
            "false positive rate {:.4} exceeds hard ceiling {FP_LIMIT}",
            fp_rate
        );
    }
}
