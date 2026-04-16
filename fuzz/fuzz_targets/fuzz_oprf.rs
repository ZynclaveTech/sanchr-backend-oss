#![no_main]
use libfuzzer_sys::fuzz_target;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Test Ristretto255 point deserialization with arbitrary bytes.
    let compressed = CompressedRistretto::from_slice(&data[..32]);
    if let Ok(point) = compressed {
        let _ = point.decompress();
    }

    // Test scalar deserialization if we have enough bytes.
    if data.len() >= 64 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[32..64]);
        let _ = Scalar::from_bytes_mod_order(bytes);
    }
});
