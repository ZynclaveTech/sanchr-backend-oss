//! Tests for OPRF secret initialization from config and daily salt generation.

use sanchr_psi::bloom::generate_daily_salt;
use sanchr_psi::oprf::OprfServerSecret;

/// Generate a secret, serialize to hex, deserialize back, and verify both
/// produce identical OPRF evaluations on the same blinded point.
#[test]
fn test_oprf_secret_from_hex_config() {
    let original = OprfServerSecret::generate();
    let bytes = original.to_bytes();
    let hex_str = hex::encode(bytes);

    // Simulate what main.rs does: decode hex, then from_bytes.
    let decoded = hex::decode(&hex_str).expect("hex decode must succeed");
    let decoded_arr: [u8; 32] = decoded
        .try_into()
        .expect("decoded bytes must be exactly 32");
    let restored =
        OprfServerSecret::from_bytes(&decoded_arr).expect("from_bytes must succeed for valid key");

    // Both secrets must produce identical OPRF evaluations.
    let phone = "+14155552671";
    let (r, blinded) = sanchr_psi::oprf::blind(phone);

    let eval_original = original
        .evaluate(&blinded)
        .expect("evaluate with original secret");
    let eval_restored = restored
        .evaluate(&blinded)
        .expect("evaluate with restored secret");

    assert_eq!(
        eval_original, eval_restored,
        "original and restored secrets must produce identical evaluations"
    );

    // Also verify full round-trip unblinding matches direct set element.
    let unblinded = sanchr_psi::oprf::unblind(&r, &eval_original).expect("unblind must succeed");
    let expected = original.compute_set_element(phone);
    assert_eq!(
        unblinded, expected,
        "unblinded result must equal direct set element"
    );
}

/// Verify that `generate_daily_salt` returns 32 bytes and two successive
/// calls produce different salts (with overwhelming probability).
#[test]
fn test_daily_salt_generation() {
    let salt1 = generate_daily_salt();
    let salt2 = generate_daily_salt();

    assert_eq!(salt1.len(), 32, "salt must be exactly 32 bytes");
    assert_eq!(salt2.len(), 32, "salt must be exactly 32 bytes");
    assert_ne!(
        salt1, salt2,
        "two independently generated salts must differ (with overwhelming probability)"
    );
}
