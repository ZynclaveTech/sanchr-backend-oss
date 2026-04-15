use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sanchr_psi::bloom::SaltedBloomFilter;
use sanchr_psi::hkdf_utils;
use sanchr_psi::oprf::{self, OprfServerSecret};

fn bench_oprf_single_eval(c: &mut Criterion) {
    let server = OprfServerSecret::generate();
    let (_, blinded) = oprf::blind("+14155551234");

    c.bench_function("oprf_single_eval", |b| {
        b.iter(|| server.evaluate(black_box(&blinded)).unwrap())
    });
}

fn bench_oprf_batch(c: &mut Criterion) {
    let server = OprfServerSecret::generate();

    let mut group = c.benchmark_group("oprf_batch");
    for size in [10, 100, 500, 1000] {
        let phones: Vec<String> = (0..size).map(|i| format!("+1415555{:04}", i)).collect();
        let (_, blindeds): (Vec<_>, Vec<_>) = phones.iter().map(|p| oprf::blind(p)).unzip();

        group.bench_with_input(BenchmarkId::from_parameter(size), &blindeds, |b, pts| {
            b.iter(|| server.evaluate_batch(black_box(pts)).unwrap())
        });
    }
    group.finish();
}

fn bench_bloom_filter(c: &mut Criterion) {
    let salt = b"bench-salt";
    let phones: Vec<String> = (0..10_000).map(|i| format!("+1415{:07}", i)).collect();

    let mut bloom = SaltedBloomFilter::new(10_000, 0.01, salt);
    for phone in &phones {
        bloom.insert(phone);
    }

    c.bench_function("bloom_lookup", |b| {
        b.iter(|| bloom.might_contain(black_box("+14150000001")))
    });
}

fn bench_hkdf_media_key(c: &mut Criterion) {
    let chain_key = [0xAA; 32];
    let file_hash = [0xBB; 32];

    c.bench_function("hkdf_media_key", |b| {
        b.iter(|| hkdf_utils::derive_media_key(black_box(&chain_key), black_box(&file_hash)))
    });
}

fn bench_hkdf_access_key(c: &mut Criterion) {
    let media_key = [0xCC; 32];
    let device_secret = [0xDD; 32];

    c.bench_function("hkdf_access_key", |b| {
        b.iter(|| {
            hkdf_utils::derive_access_key(
                black_box(&media_key),
                black_box(&device_secret),
                "bench-media",
            )
        })
    });
}

fn bench_media_chain_advance(c: &mut Criterion) {
    let ck = [0xEE; 32];

    c.bench_function("media_chain_advance", |b| {
        b.iter(|| hkdf_utils::advance_media_chain(black_box(&ck)))
    });
}

criterion_group!(
    benches,
    bench_oprf_single_eval,
    bench_oprf_batch,
    bench_bloom_filter,
    bench_hkdf_media_key,
    bench_hkdf_access_key,
    bench_media_chain_advance,
);
criterion_main!(benches);
