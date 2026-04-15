use sanchr_psi::bloom::SaltedBloomFilter;
use sanchr_psi::oprf::{self, OprfServerSecret};

#[tokio::test]
async fn test_oprf_discovery_full_flow() {
    // Simulate registered users
    let registered_phones = ["+14155551234", "+14155555678", "+442071234567"];

    // Server setup
    let server_secret = OprfServerSecret::generate();

    // Build server's registered set
    let registered_set: Vec<_> = registered_phones
        .iter()
        .map(|p| server_secret.compute_set_element(p))
        .collect();

    // Client wants to discover which of their contacts are on the platform
    let client_contacts = [
        "+14155551234",  // registered
        "+14155559999",  // NOT registered
        "+442071234567", // registered
        "+81312345678",  // NOT registered
    ];

    // Client blinds contacts
    let (scalars, blinded_points): (Vec<_>, Vec<_>) =
        client_contacts.iter().map(|p| oprf::blind(p)).unzip();

    // Server evaluates OPRF
    let evaluated = server_secret.evaluate_batch(&blinded_points).unwrap();

    // Client unblinds
    let unblinded: Vec<_> = scalars
        .iter()
        .zip(evaluated.iter())
        .map(|(r, e)| oprf::unblind(r, e).unwrap())
        .collect();

    // Client finds matches against registered set
    let mut matches = Vec::new();
    for (i, result) in unblinded.iter().enumerate() {
        if registered_set.contains(result) {
            matches.push(client_contacts[i]);
        }
    }

    assert_eq!(matches, vec!["+14155551234", "+442071234567"]);
}

#[tokio::test]
async fn test_bloom_filter_fast_path() {
    let salt = b"2026-04-07-daily-salt";
    let registered = ["+14155551234", "+442071234567"];

    let mut bloom = SaltedBloomFilter::new(1000, 0.01, salt);
    for phone in &registered {
        bloom.insert(phone);
    }

    // Registered phones should pass
    assert!(bloom.might_contain("+14155551234"));
    assert!(bloom.might_contain("+442071234567"));

    // Unregistered should fail (with high probability)
    assert!(!bloom.might_contain("+14155559999"));
    assert!(!bloom.might_contain("+81312345678"));
}

#[tokio::test]
async fn test_hkdf_domain_separation() {
    use sanchr_psi::hkdf_utils;

    let chain_key = [0xAA; 32];
    let file_hash = [0xBB; 32];
    let device_secret = [0xCC; 32];

    let media_key = hkdf_utils::derive_media_key(&chain_key, &file_hash);
    let access_key = hkdf_utils::derive_access_key(&media_key, &device_secret, "test-media");

    // Media key and access key must be different
    assert_ne!(media_key, access_key);

    // Media chain advancement must be one-way
    let ck0 = [0xDD; 32];
    let ck1 = hkdf_utils::advance_media_chain(&ck0);
    let ck2 = hkdf_utils::advance_media_chain(&ck1);
    assert_ne!(ck0, ck1);
    assert_ne!(ck1, ck2);
}
