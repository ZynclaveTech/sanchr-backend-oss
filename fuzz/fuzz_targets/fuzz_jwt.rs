#![no_main]
use libfuzzer_sys::fuzz_target;
use sanchr_server_crypto::jwt::JwtManager;

fuzz_target!(|data: &[u8]| {
    // Need at least a few bytes for a meaningful token string.
    if data.is_empty() {
        return;
    }

    // Use a fixed secret for the manager so we test parsing, not key derivation.
    let manager = JwtManager::new(b"fuzz_test_secret_key_32_bytes_ok");

    // Interpret the fuzz input as a token string and try to validate it.
    // This exercises the full JWT parsing/validation path with arbitrary input.
    if let Ok(token_str) = std::str::from_utf8(data) {
        let _ = manager.validate_token(token_str);
    }

    // Also try the raw bytes as a lossy UTF-8 string to cover more paths.
    let lossy = String::from_utf8_lossy(data);
    let _ = manager.validate_token(&lossy);
});
