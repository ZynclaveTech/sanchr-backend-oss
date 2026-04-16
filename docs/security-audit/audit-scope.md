# Security Audit Scope

**Project:** Sanchr Backend (OSS)
**Date:** 2026-04-16
**Repository:** `backend-oss/`

---

## In Scope

### Rust Crates (7 crates)

| Crate | Path | Description |
|-------|------|-------------|
| `sanchr-common` | `crates/sanchr-common/` | Shared configuration, error types, and utilities |
| `sanchr-proto` | `crates/sanchr-proto/` | Protobuf definitions and generated gRPC service stubs |
| `sanchr-server-crypto` | `crates/sanchr-server-crypto/` | All server-side cryptographic primitives (JWT, OTP, password hashing, sealed sender, TURN, media keys) |
| `sanchr-db` | `crates/sanchr-db/` | Database abstractions for Postgres, Redis, and ScyllaDB |
| `sanchr-core` | `crates/sanchr-core/` | Primary gRPC + HTTP server: auth, messaging, keys, contacts, discovery, vault, media, backup, notifications, settings, EKF lifecycle, middleware |
| `sanchr-call` | `crates/sanchr-call/` | Call signaling service (WebRTC, TURN credential minting, call history) |
| `sanchr-psi` | `crates/sanchr-psi/` | Private Set Intersection: OPRF protocol, Bloom filter, HKDF key derivation utilities |

### Protocol Buffer Definitions

14 `.proto` files under `crates/sanchr-proto/proto/`:
`auth.proto`, `messaging.proto`, `keys.proto`, `contacts.proto`, `discovery.proto`, `vault.proto`, `media.proto`, `backup.proto`, `notifications.proto`, `settings.proto`, `calling.proto`, `sealed_sender.proto`, `ekf.proto`, `backup_payload.proto`

### Docker Compose Configuration

- `docker-compose.yml` -- local development infrastructure (Postgres 16, Redis 7, ScyllaDB 5.4, NATS 2.10, MinIO, Jaeger)
- `config/nats-server.conf` -- NATS broker configuration with auth and JetStream

### All Cryptographic Implementations

- Password hashing (Argon2id)
- OTP generation and verification (HMAC-SHA256)
- JWT signing and validation (HS256)
- Sealed sender certificate signing (Ed25519)
- TURN credential generation (HMAC-SHA1)
- Media key derivation and verification (HKDF-SHA256)
- OPRF blinding/evaluation (Ristretto255)
- Bloom filter hashing (SHA-256)
- Proof-of-work challenge verification (SHA-256)
- HKDF domain-separated key derivation (6 domain labels)

### Authentication and Session Management

- Phone-based OTP registration and login flows
- Dev-mode OTP bypass guard (`auth.dev_mode` config flag)
- JWT access token issuance and validation
- Refresh token lifecycle (hashed storage, rotation)
- Redis-backed session management
- Registration lock support
- PoW challenge-response system for abuse mitigation

### Rate Limiting and Abuse Detection

- Per-phone rate limits on register, login, verify OTP (5 requests / 15 minutes)
- Per-user rate limits on message send (60 / 60s)
- Per-user rate limits on contact sync (10 / 1 hour)
- Per-user rate limits on OPRF discovery, Bloom filter retrieval, registered set retrieval
- Per-user rate limits on KeyService RPCs (UploadPreKeys: 10/hr, GetPreKeyBundle: 60/hr, UploadSignedPreKey: 10/hr)
- Per-user rate limits on reactions
- Request-size middleware on `sanchr-core` with global default (1 MiB) and per-RPC overrides
- Request-size limit on `sanchr-call` (64 KB `max_decoding_message_size`)

### EKF Lifecycle Enforcement

- Background lifecycle tick loop (default: 60s interval)
- Expiry policies per key class: Presence, Discovery, PreKey, Media
- Rotation grace period (default: 3600s)
- OPRF secret weekly rotation (default: 7 days)
- Discovery daily salt rotation
- EKF enabled by default (`ekf.enabled = true`)
- S3 media lifecycle policy (default: 30 days)

---

## Out of Scope

| Item | Rationale |
|------|-----------|
| iOS/Android client applications | Separate codebase; client-side crypto is not in this repository |
| Operator infrastructure (cloud accounts, networking, IAM) | Operator-managed; not represented in source |
| Third-party dependencies | Audited separately via `cargo audit` / `cargo deny`; see dependency manifest in `Cargo.lock` |
| Deployment manifests (Helm chart, Kubernetes configs) | Operator-configured in private ops repository |
| Production CI/CD workflows | Kept in private operations repository; public CI is secretless |
| Dynamic penetration testing | Requires running deployment; this audit covers source review |

---

## Priority Areas for Review

Listed in order of criticality:

### 1. `sanchr-server-crypto` -- All Crypto Primitives
**Files:** `crates/sanchr-server-crypto/src/`
- Argon2id parameter validation and usage
- OTP HMAC construction, time-window logic, constant-time comparison
- JWT signing algorithm, expiration enforcement, zero leeway
- Ed25519 sealed sender certificate chain (server cert -> sender cert)
- TURN credential HMAC-SHA1 (RFC 5389 compliance)
- Media key HKDF derivation and constant-time verification
- CryptoProvider trait abstraction and LocalCryptoProvider implementation

### 2. `sanchr-psi` -- OPRF Protocol and Bloom Filter
**Files:** `crates/sanchr-psi/src/`
- OPRF server secret generation, serialization, zero-scalar rejection
- Ristretto255 point validation (identity rejection, decompression checks)
- Batch evaluation security
- Bloom filter sizing, double-hashing construction, daily salt rotation
- HKDF domain-separated key derivation (6 labels: media, access, discovery, rotation, chain-advance, chain-init)

### 3. Auth Flows -- OTP, JWT, Session Management, Registration Lock
**Files:** `crates/sanchr-core/src/auth/`, `crates/sanchr-db/src/postgres/refresh_tokens.rs`, `crates/sanchr-db/src/redis/sessions.rs`
- OTP generation tied to phone + time window
- Refresh token hashing and rotation
- Registration lock PIN verification
- PoW challenge issuance and one-shot verification
- Rate limiting on auth endpoints

### 4. Sealed Sender -- Certificate Issuance, Relay
**Files:** `crates/sanchr-server-crypto/src/sealed_sender.rs`, `crates/sanchr-core/src/messaging/sealed_handler.rs`, `crates/sanchr-db/src/redis/delivery_tokens.rs`
- Ed25519 certificate chain integrity
- 24-hour certificate TTL enforcement
- Delivery token lifecycle (one-time use, Redis-backed)
- Anonymous relay routing without exposing sender identity
- Ephemeral signing key in dev vs. production signer requirements

### 5. EKF Lifecycle -- Temporal Enforcement
**Files:** `crates/sanchr-core/src/ekf/`, `crates/sanchr-db/src/scylla/auxiliary.rs`
- Key class expiry policies (Rotate, Delete, Overwrite)
- Grace period enforcement for stale rotations
- NULL_SENTINEL overwrite for forward secrecy
- Integration with discovery salt and OPRF secret rotation
- Scylla auxiliary state table management

### 6. NATS Relay -- Message Routing, Access Control
**Files:** `crates/sanchr-core/src/messaging/relay_bridge.rs`, `crates/sanchr-call/src/signaling.rs`, `config/nats-server.conf`
- Subject namespace design (`msg.relay.*`, `msg.sealed.*`, `call.*`)
- Relay bridge event forwarding to connected clients
- NATS auth configuration (username/password in docker-compose)
- Call signaling stream validation
- Risk of event injection from compromised internal workloads
