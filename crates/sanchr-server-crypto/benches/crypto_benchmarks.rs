use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sanchr_server_crypto::jwt::JwtManager;
use sanchr_server_crypto::otp;
use sanchr_server_crypto::password::{hash_password, PasswordHasherConfig};
use sanchr_server_crypto::sealed_sender::SealedSenderSigner;
use sanchr_server_crypto::turn_creds::generate_turn_credentials;
use uuid::Uuid;

// ── JWT ──────────────────────────────────────────────────────────────────────

fn bench_jwt(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt");

    let mgr = JwtManager::new(b"bench_secret_key_32bytes_long_ok!");
    let user_id = Uuid::new_v4();

    group.bench_function("create_access_token", |b| {
        b.iter(|| {
            mgr.create_access_token(black_box(&user_id), black_box(1), black_box(3600))
                .unwrap()
        })
    });

    // Pre-create a token for validation benchmarks
    let (token, _) = mgr.create_access_token(&user_id, 1, 3600).unwrap();

    group.bench_function("validate_token", |b| {
        b.iter(|| mgr.validate_token(black_box(&token)).unwrap())
    });

    group.finish();
}

// ── OTP ──────────────────────────────────────────────────────────────────────

fn bench_otp(c: &mut Criterion) {
    let mut group = c.benchmark_group("otp");

    let secret = "bench_otp_secret_key";
    let phone = "+14155551234";
    let timestamp = 1_700_000_000i64;
    let ttl = 300u64;

    group.bench_function("generate", |b| {
        b.iter(|| {
            otp::generate_otp(
                black_box(secret),
                black_box(phone),
                black_box(timestamp),
                black_box(ttl),
            )
            .unwrap()
        })
    });

    let code = otp::generate_otp(secret, phone, timestamp, ttl).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            otp::verify_otp(
                black_box(secret),
                black_box(phone),
                black_box(&code),
                black_box(timestamp),
                black_box(ttl),
            )
            .unwrap()
        })
    });

    group.finish();
}

// ── Sealed Sender ────────────────────────────────────────────────────────────

fn bench_sealed_sender(c: &mut Criterion) {
    let mut group = c.benchmark_group("sealed_sender");

    let signer = SealedSenderSigner::generate(1);
    let identity_key = [0xABu8; 33];

    group.bench_function("issue_certificate", |b| {
        b.iter(|| {
            signer
                .issue_certificate(
                    black_box("user-uuid-bench"),
                    black_box(7),
                    black_box(&identity_key),
                )
                .unwrap()
        })
    });

    group.finish();
}

// ── Password hashing ─────────────────────────────────────────────────────────

fn bench_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("password");
    // Use minimal params so benchmarks complete in reasonable time.
    // Production config (64 MiB / 3 iterations / p=4) is intentionally slow.
    let config = PasswordHasherConfig {
        memory_cost: 1024, // 1 MiB — fast enough for CI
        iterations: 1,
        parallelism: 1,
    };

    group.sample_size(10); // argon2 is slow even with minimal params
    group.bench_function("hash_password_minimal_params", |b| {
        b.iter(|| {
            hash_password(
                black_box("correct-horse-battery-staple"),
                black_box(&config),
            )
            .unwrap()
        })
    });

    group.finish();
}

// ── TURN credentials ─────────────────────────────────────────────────────────

fn bench_turn(c: &mut Criterion) {
    let mut group = c.benchmark_group("turn");

    group.bench_function("generate_credentials", |b| {
        b.iter(|| {
            generate_turn_credentials(
                black_box("turn_shared_secret"),
                black_box("user-uuid-bench"),
                black_box(86400),
            )
        })
    });

    group.finish();
}

// ── Criterion harness ────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_jwt,
    bench_otp,
    bench_sealed_sender,
    bench_password,
    bench_turn,
);
criterion_main!(benches);
