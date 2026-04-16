#![no_main]
use libfuzzer_sys::fuzz_target;
use sanchr_server_crypto::otp;

fuzz_target!(|data: &[u8]| {
    // Need at least: 1 byte secret + 1 byte phone + 8 bytes timestamp + 8 bytes ttl
    if data.len() < 18 {
        return;
    }

    // Split the input into components.
    // Use the first byte as a split point for secret/phone boundary.
    let split = (data[0] as usize) % (data.len() - 17) + 1;
    let secret = std::str::from_utf8(&data[1..split]).unwrap_or("fuzz_secret");
    let phone_end = split + (data.len() - split - 16).min(32);
    let phone = std::str::from_utf8(&data[split..phone_end]).unwrap_or("+15550000000");

    let ts_start = data.len() - 16;
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&data[ts_start..ts_start + 8]);
    let timestamp = i64::from_be_bytes(ts_bytes);

    let mut ttl_bytes = [0u8; 8];
    ttl_bytes.copy_from_slice(&data[ts_start + 8..ts_start + 16]);
    let ttl_seconds = u64::from_be_bytes(ttl_bytes);

    // Avoid division by zero in time_window calculation.
    if ttl_seconds == 0 {
        return;
    }

    // Fuzz generate_otp: should never panic.
    if let Ok(otp_code) = otp::generate_otp(secret, phone, timestamp, ttl_seconds) {
        // Fuzz verify_otp with the generated code: should never panic.
        let _ = otp::verify_otp(secret, phone, &otp_code, timestamp, ttl_seconds);
    }

    // Also try verifying with arbitrary OTP strings derived from input.
    let fake_otp = &format!("{:06}", u32::from_be_bytes([data[0], data[1], data[2], data[3]]) % 1_000_000);
    let _ = otp::verify_otp(secret, phone, fake_otp, timestamp, ttl_seconds);
});
