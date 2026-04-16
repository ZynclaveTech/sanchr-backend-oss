# Sanchr Backend Architecture

## Crate Dependency Graph

```
sanchr-common (config, errors, shared types)
    |
    +-- sanchr-proto (gRPC service definitions, generated from .proto files)
    |
    +-- sanchr-server-crypto (JWT, OTP, sealed sender, password hashing, TURN creds)
    |       +-- local_provider   (LocalCryptoProvider -- default, in-process keys)
    |       +-- aws_kms_provider (feature: kms-aws -- delegates to AWS KMS)
    |       +-- vault_provider   (feature: kms-vault -- delegates to HashiCorp Vault)
    |
    +-- sanchr-psi (OPRF, Bloom filter, HKDF utilities for private contact discovery)
    |
    +-- sanchr-db (Postgres, Redis, ScyllaDB, NATS adapter modules)
    |
    +-- sanchr-core (main service binary)
    |       +-- auth/           register, OTP verification, login, challenge
    |       +-- messaging/      send, stream, relay, sealed sender, reactions
    |       +-- ekf/            Ephemeral Key Framework lifecycle manager, tick loop
    |       +-- keys/           pre-key bundles, identity keys
    |       +-- contacts/       contact sync, blocklist
    |       +-- discovery/      OPRF-PSI flow, Bloom filter intersection
    |       +-- media/          presigned upload/download URLs, lifecycle
    |       +-- vault/          encrypted vault items (CRUD)
    |       +-- backup/         backup metadata, blob management
    |       +-- calling/        WebRTC signaling bridge (via sanchr-call)
    |       +-- notifications/  APNs + FCM push delivery
    |       +-- settings/       user preferences
    |       +-- presence/       online/typing indicators
    |       +-- privacy/        privacy enforcement layer
    |       +-- middleware/     auth extraction, request size limits
    |       +-- observability/  Prometheus metrics, OpenTelemetry tracing
    |
    +-- sanchr-call (standalone call signaling binary)
```

## Data Flow Diagrams

### Message Send (Standard)

```
Client A                        sanchr-core                  ScyllaDB       NATS        Client B
   |                                |                            |            |              |
   |-- SendMessageRequest -------->|                            |            |              |
   |                                |-- validate auth + device ->|            |              |
   |                                |-- insert into outbox ----->|            |              |
   |                                |-- publish relay event -----|----------->|              |
   |                                |                            |            |-- push ----->|
   |<-- SendMessageResponse -------|                            |            |              |
   |                                |                            |            |              |
   |                                |<--- delivery ack ---------|------------|--- ack ------|
   |                                |-- mark delivered --------->|            |              |
```

### Message Send (Sealed Sender)

```
Client A                        sanchr-core                 ScyllaDB       NATS       Client B
   |                                |                           |            |             |
   |-- SealedSenderEnvelope ------>|                           |            |             |
   |   (no auth header;            |                           |            |             |
   |    sender identity is         |-- unseal envelope,        |            |             |
   |    inside the encrypted       |   verify sender cert ---->|            |             |
   |    payload)                   |-- insert outbox --------->|            |             |
   |                               |-- relay via NATS ---------|----------->|             |
   |                               |                           |            |-- push ---->|
   |<-- 200 OK -------------------|                           |            |             |
```

### Contact Discovery (OPRF Flow)

```
Client                          sanchr-core                   sanchr-psi
   |                                |                              |
   |-- blinded contact hashes ---->|                              |
   |                                |-- OPRF evaluate ----------->|
   |                                |<-- blinded results ---------|
   |<-- OPRF response ------------|                              |
   |                                |                              |
   |   (client unblinds locally,    |                              |
   |    compares against Bloom      |                              |
   |    filter of registered users) |                              |
```

### Media Upload / Download

```
Client                          sanchr-core                 MinIO/S3       Postgres
   |                                |                          |              |
   |-- RequestUploadURL ---------->|                          |              |
   |                                |-- create media record ---|------------->|
   |                                |-- generate presigned PUT-|->           |
   |<-- presigned URL + media_id --|                          |              |
   |                                |                          |              |
   |-- PUT blob to presigned URL --|------------------------->|              |
   |                                |                          |              |
   |-- ConfirmUpload ------------>|                          |              |
   |                                |-- mark media ready ------|------------->|
   |<-- OK -----------------------|                          |              |
   |                                |                          |              |
   |  (Recipient)                   |                          |              |
   |-- RequestDownloadURL -------->|                          |              |
   |                                |-- generate presigned GET-|->           |
   |<-- presigned URL ------------|                          |              |
   |-- GET blob ------------------|------------------------->|              |
```

### Registration + OTP Verification

```
Client                          sanchr-core            Redis            Postgres
   |                                |                     |                 |
   |-- Register(phone, password) ->|                     |                 |
   |                                |-- hash password --->|                 |
   |                                |-- store OTP ------->|  (TTL 5 min)   |
   |                                |-- send SMS -------->|  (via provider) |
   |<-- registration_id -----------|                     |                 |
   |                                |                     |                 |
   |-- VerifyOTP(code) ----------->|                     |                 |
   |                                |-- check OTP ------->|                 |
   |                                |-- create user ------|---------------->|
   |                                |-- create device ----|---------------->|
   |                                |-- issue JWT ------->|                 |
   |<-- AuthResult (token, user) --|                     |                 |
```

## Database Schema Overview

### Postgres -- Relational / Transactional Data

- **users**: account records (id, phone hash, password hash, created_at, status)
- **devices**: per-user device registrations (device_id, user_id, push_token, platform)
- **identity_keys**: long-term identity public keys per device
- **pre_keys / signed_pre_keys**: X3DH pre-key bundles
- **conversations**: conversation metadata (direct and group)
- **conversation_members**: membership join table
- **contacts**: server-side contact graph (owner, contact_user_id)
- **blocked_users**: blocklist entries
- **media_metadata**: upload records (media_id, owner, bucket, key, status)
- **backups**: backup metadata (user_id, version, s3_key, created_at)

### ScyllaDB -- High-Throughput / Append-Heavy Data

- **message_outbox**: per-recipient message queue (recipient_id, timestamp, payload)
- **delivery_receipts**: read/delivered receipts keyed by message_id
- **vault_items**: end-to-end encrypted vault entries
- **reactions**: message reactions
- **ekf_state**: Ephemeral Key Framework auxiliary rotation state

### Redis -- Ephemeral / Real-Time State

- **sessions**: JWT session tracking and revocation
- **rate_limits**: sliding-window counters per endpoint per user
- **otp_codes**: time-limited OTP storage (TTL-based expiry)
- **presence**: online/offline status per device
- **typing_indicators**: short-lived typing events
- **idempotency_keys**: request dedup tokens (TTL ~24h)

### NATS -- Event Streaming / Pub-Sub

- **message relay**: fan-out of encrypted message payloads to recipient devices
- **call events**: WebRTC signaling events (offer, answer, ICE candidates, hangup)
- **EKF rotation notifications**: broadcast key rotation triggers to connected devices

### S3 (MinIO in dev) -- Blob Storage

- **Encrypted media**: images, video, voice notes (client-side encrypted)
- **Backup blobs**: encrypted backup archives
- **Avatars**: profile pictures

## Key Architectural Decisions

1. **End-to-end encryption is non-negotiable.** The server never sees plaintext message content. Media is client-side encrypted before upload. Vault items are opaque blobs.

2. **Sealed sender minimizes metadata.** The sealed sender path strips the sender identity from the transport layer; only the recipient can unseal the envelope and learn who sent it.

3. **ScyllaDB for the hot path.** Message outbox and delivery receipts need single-digit-ms p99 latency at high write throughput. Postgres handles the relational data that benefits from joins and transactions.

4. **NATS for real-time fan-out.** Message relay, call signaling, and EKF rotation events use NATS pub/sub so connected clients receive updates with minimal latency and the server stays stateless.

5. **OPRF-based contact discovery.** Contacts are never uploaded in cleartext. The OPRF protocol lets clients discover mutual contacts without revealing their full address book to the server.

6. **Pluggable crypto provider.** `sanchr-server-crypto` defines a `CryptoProvider` trait with three implementations (local, AWS KMS, Vault). Production deployments can use hardware-backed key management without code changes.

7. **Ephemeral Key Framework (EKF).** A background tick loop rotates short-lived keys on a configurable cadence, limiting the blast radius of any single key compromise.
