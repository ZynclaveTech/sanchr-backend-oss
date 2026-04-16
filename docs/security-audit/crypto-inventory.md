# Cryptographic Primitive Inventory

**Project:** Sanchr Backend (OSS)
**Date:** 2026-04-16

All cryptographic primitives used by the backend, verified against source.

---

## Primitive Table

| Primitive | Purpose | Library | Parameters | Location |
|-----------|---------|---------|------------|----------|
| Argon2id (v0x13) | Password hashing | `argon2` crate | 65536 KiB (64 MiB) memory, 3 iterations, parallelism=4; random salt via `OsRng` | `crates/sanchr-server-crypto/src/password.rs` |
| HMAC-SHA256 | OTP generation and verification | `hmac` + `sha2` crates | 6-digit output via dynamic truncation; 5-minute window (300s default `otp_ttl`); message = `phone || ":" || window_be_bytes`; constant-time comparison via `subtle::ConstantTimeEq`; verifies current + previous window (grace period) | `crates/sanchr-server-crypto/src/otp.rs` |
| HMAC-SHA256 (HS256) | JWT access token signing | `jsonwebtoken` crate | Algorithm: `HS256`; default TTL: 900s (15 min); zero leeway on expiration; claims: `sub` (user UUID), `did` (device ID), `jti` (UUID v4), `iat`, `exp` | `crates/sanchr-server-crypto/src/jwt.rs` |
| Ed25519 | Sealed sender certificate signing | `ed25519-dalek` crate | 32-byte seed or random key generation; 24h certificate TTL (`now + 86400`); signs both `ServerCertificate` and `SenderCertificate` protobuf payloads; server cert embeds public key + key_id | `crates/sanchr-server-crypto/src/sealed_sender.rs` |
| HMAC-SHA1 | TURN credential generation | `hmac` + `sha1` crates | Username format: `"{expiry_timestamp}:{user_id}"`; credential: `Base64(HMAC-SHA1(secret, username))`; RFC 5389 compliant; TTL is operator-configurable via `calling.turn_credential_ttl` | `crates/sanchr-server-crypto/src/turn_creds.rs` |
| HKDF-SHA256 | Media key derivation | `hkdf` + `sha2` crates | IKM = `chain_key (32B) || file_hash (32B)`; salt = none; info = `b"sanchr-media-v1"`; output = 32 bytes; constant-time verification via `subtle::ConstantTimeEq` | `crates/sanchr-server-crypto/src/media_keys.rs` |
| HKDF-SHA256 | Key derivation (media, access, discovery, rotation, chain) | `hkdf` + `sha2` crates | 6 domain labels: `sanchr-media-v1`, `sanchr-access-v1`, `sanchr-discovery-v1`, `sanchr-rotate-v1`, `sanchr-media-chain-advance-v1`, `sanchr-media-chain-init-v1`; output = 32 bytes each | `crates/sanchr-psi/src/hkdf_utils.rs` |
| Ristretto255 | OPRF blinding and evaluation | `curve25519-dalek` crate | 2-HashDH-OPRF protocol; hash-to-point via SHA-512 + Elligator2 (`RistrettoPoint::from_uniform_bytes`); server scalar must be non-zero; identity point rejected on evaluation; batch evaluation supported | `crates/sanchr-psi/src/oprf.rs` |
| SHA-256 | Bloom filter salted hashing | `sha2` crate | Input: `phone_bytes || salt_bytes`; double-hashing for k bit indices (Kirsch-Mitzenmacher construction); h1 = first 8 bytes LE u64, h2 = second 8 bytes LE u64; `idx = (h1 + i*h2) mod m` | `crates/sanchr-psi/src/bloom.rs` |
| SHA-256 | Proof-of-Work challenge verification | `sha2` crate | Input: `prefix_bytes || solution_bytes`; difficulty: configurable leading zero bits (default: 20); challenge stored in Redis with TTL; one-shot usage (deleted after verification) | `crates/sanchr-core/src/auth/challenge.rs` |
| SHA-512 | OPRF hash-to-point | `sha2` crate | Used internally by `hash_to_point()` to produce 64-byte digest for `RistrettoPoint::from_uniform_bytes` (Elligator2 map) | `crates/sanchr-psi/src/oprf.rs` |

---

## Key Material Lifecycle

| Key | Storage | Rotation | Dev Mode Behavior |
|-----|---------|----------|-------------------|
| JWT signing secret | Config (`auth.jwt_secret`) | Manual operator rotation | Placeholder `replace-me-with-a-unique-jwt-secret` accepted only when `auth.dev_mode=true`; startup rejects placeholder otherwise |
| OTP HMAC secret | Config (`auth.otp_secret`) | Manual operator rotation | Placeholder `replace-me-with-a-unique-otp-secret` accepted only in dev mode |
| TURN shared secret | Config (`calling.turn_secret`) | Manual operator rotation | Placeholder `replace-me-with-a-unique-turn-secret` accepted only in dev mode |
| OPRF server scalar | Config (`discovery.oprf_secret_hex`) or ephemeral | Automatic weekly rotation (default: 7 days); persisted to ScyllaDB auxiliary table | Ephemeral random scalar generated at startup with warning if config absent |
| Sealed sender Ed25519 key | Ephemeral at startup (dev) or config/HSM (prod) | Not automatically rotated in current code | Random key generated at startup in dev; production signer integration is not in the public repo |
| Discovery daily salt | ArcSwap in memory; persisted to ScyllaDB | Automatic daily rotation by background task | Generated from `OsRng` at startup |
| PoW challenge prefix | Redis (per-challenge, ephemeral) | Per-challenge; TTL default 300s | N/A |

---

## Constant-Time Operations

The following operations use constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing attacks:

1. OTP verification (`otp.rs:73`) -- compares expected vs. provided OTP bytes
2. Media key verification (`media_keys.rs:19`) -- compares derived vs. claimed media key

---

## Notes for Auditors

1. **Argon2id parameters** are configurable via `auth.argon2_memory`, `auth.argon2_iterations`, `auth.argon2_parallelism` in the app config. The defaults (64 MiB / 3 / 4) are set in `PasswordHasherConfig::default()`.

2. **OTP time windows** are derived from `timestamp / ttl_seconds`. The verification checks both the current and previous window, providing a grace period of up to one full TTL window.

3. **OPRF server secret** must be non-zero scalar. `OprfServerSecret::generate()` loops until a non-zero scalar is drawn (probability of zero is ~2^-252). `from_bytes()` rejects both non-canonical and zero scalars.

4. **Bloom filter** uses optimal sizing formulas: `m = -n * ln(p) / (ln2)^2` bits, `k = (m/n) * ln2` hash functions. Empirical FP rate is validated in tests to stay under 2% for a 1% design target.

5. **CryptoProvider trait abstraction** (`crates/sanchr-server-crypto/src/provider.rs`) defines an `async_trait` interface covering JWT, OTP, sealed sender, and TURN operations. Three implementations exist:
   - `LocalCryptoProvider` (`local_provider.rs`): in-process implementation wrapping the standalone crypto modules. Used by default.
   - `AwsKmsCryptoProvider` (`aws_kms_provider.rs`): AWS KMS-backed implementation (feature-gated behind `kms-aws`). Uses KMS asymmetric signing for sealed sender, KMS HMAC for OTP/TURN, and retrieves JWT secret from KMS/Secrets Manager at startup.
   - `VaultCryptoProvider` (`vault_provider.rs`): HashiCorp Vault Transit-backed implementation (feature-gated behind `kms-vault`). Uses Vault Transit engine for signing and HMAC operations.
   
   The trait's `active_key_id()` method supports key rotation tracking across backends. OPRF server secret rotation is handled separately (weekly rotation via EKF, persisted to ScyllaDB).
