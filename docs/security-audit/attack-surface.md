# Attack Surface Enumeration

**Project:** Sanchr Backend (OSS)
**Date:** 2026-04-16

All external-facing interfaces, authentication requirements, and rate limiting status.

---

## gRPC Services -- `sanchr-core` (port 9090)

| Interface | Service | Auth | Rate Limit | Request-Size Middleware | Notes |
|-----------|---------|------|------------|------------------------|-------|
| Register | AuthService | None | 5 req / 15 min per phone | Yes (global 1 MiB default + per-RPC overrides) | PoW challenge required if `challenge.enabled=true` |
| RequestOtp | AuthService | None | 5 req / 15 min per phone | Yes | Generates OTP; dev mode logs OTP at INFO level |
| VerifyOtp | AuthService | None | 5 req / 15 min per phone | Yes | Returns access + refresh tokens |
| RefreshToken | AuthService | Refresh token | None explicit | Yes | Issues new access token; rotates refresh token |
| RequestChallenge | AuthService | None | None explicit | Yes | Issues PoW challenge if challenge system enabled |
| VerifyChallenge | AuthService | None | None explicit | Yes | One-shot challenge verification |
| SendMessage | MessagingService | Bearer JWT + Redis session | 60 req / 60s per user | Yes | Per-device message arrays in request |
| SendSealedMessage | MessagingService | Delivery token (anonymous) | None explicit | Yes | One-time delivery token consumed on use |
| MessageStream | MessagingService | Bearer JWT + Redis session | None explicit | Yes | Bidirectional streaming; long-lived connection |
| EditMessage | MessagingService | Bearer JWT + Redis session | 60 req / 60s per user | Yes | Shares rate limit with SendMessage |
| SendReaction | MessagingService | Bearer JWT + Redis session | Per-user limit (via rate_limit) | Yes | Reaction-specific rate limit |
| GetPreKeyBundle | KeyService | Bearer JWT + Redis session | 60 req / 1 hour per user | Yes | Retrieves recipient's pre-key bundle |
| UploadPreKeys | KeyService | Bearer JWT + Redis session | 10 req / 1 hour per user | Yes | Uploads one-time pre-keys |
| UploadSignedPreKey | KeyService | Bearer JWT + Redis session | 10 req / 1 hour per user | Yes | Updates signed pre-key |
| SyncContacts | ContactService | Bearer JWT + Redis session | 10 req / 1 hour per user | Yes | Hash-based contact matching; phone_number field redacted in response |
| OprfDiscover | DiscoveryService | Bearer JWT + Redis session | 20 req / 1 hour per user | Yes | Batch of 500 max blinded points per request |
| GetBloomFilter | DiscoveryService | Bearer JWT + Redis session | 6 req / 1 hour per user | Yes | Returns daily-salted Bloom filter bits |
| GetRegisteredSet | DiscoveryService | Bearer JWT + Redis session | 6 req / 1 hour per user | Yes | Returns pre-computed OPRF set elements |
| StoreVaultItem | VaultService | Bearer JWT + Redis session | None explicit | Yes | Vault metadata capped at 64 KiB |
| GetVaultItems | VaultService | Bearer JWT + Redis session | None explicit | Yes | |
| DeleteVaultItem | VaultService | Bearer JWT + Redis session | None explicit | Yes | Ownership check enforced |
| GetPresignedUploadUrl | MediaService | Bearer JWT + Redis session | None explicit | Yes | Issues S3 presigned URL; media capped at 100 MiB |
| GetPresignedDownloadUrl | MediaService | Bearer JWT + Redis session | None explicit | Yes | Ownership check on media metadata |
| CreateBackup | BackupService | Bearer JWT + Redis session | None explicit | Yes | Backup body capped at 512 MiB |
| GetBackups | BackupService | Bearer JWT + Redis session | None explicit | Yes | No pagination cap documented |
| DeleteBackup | BackupService | Bearer JWT + Redis session | None explicit | Yes | Ownership check enforced |
| RegisterPushToken | NotificationService | Bearer JWT + Redis session | None explicit | Yes | |
| UnregisterPushToken | NotificationService | Bearer JWT + Redis session | None explicit | Yes | |
| GetSettings | SettingsService | Bearer JWT + Redis session | None explicit | Yes | |
| UpdateSettings | SettingsService | Bearer JWT + Redis session | None explicit | Yes | |

## gRPC Services -- `sanchr-call` (port 9091)

| Interface | Service | Auth | Rate Limit | Request-Size Limit | Notes |
|-----------|---------|------|------------|---------------------|-------|
| InitiateCall | CallSignalingService | Bearer JWT | None explicit | 64 KB (`max_decoding_message_size`) | Publishes to NATS call subjects |
| CallStream | CallSignalingService | Bearer JWT | None explicit | 64 KB | Bidirectional streaming for signaling |
| EndCall | CallSignalingService | Bearer JWT | None explicit | 64 KB | Updates Redis active-call state |
| GetCallHistory | CallSignalingService | Bearer JWT | None explicit | 64 KB | ScyllaDB query; no page-size cap documented |
| GetTurnCredentials | CallSignalingService | Bearer JWT | None explicit | 64 KB | Mints time-limited TURN credentials |

## HTTP Endpoints -- `sanchr-core` (port 8080)

| Endpoint | Method | Auth | Rate Limit | Notes |
|----------|--------|------|------------|-------|
| `/health` | GET | None | None | Returns `"ok"` string |
| `/ready` | GET | None | None | Tests Postgres, Redis, ScyllaDB connectivity with 2s timeouts; returns 200 or 503 |
| `/metrics` | GET | Optional Bearer token (`metrics_token` config) | None | Prometheus text format; when `metrics_token` is configured, requests must include `Authorization: Bearer <token>` |

---

## Internal Service Interfaces

| Interface | Protocol | Auth | Notes |
|-----------|----------|------|-------|
| NATS JetStream | TCP:4222 | Username/password (`sanchr` / `$NATS_PASSWORD`) | Config in `config/nats-server.conf`; TLS commented out; subject ACLs not configured; `docker-compose.yml` sets default password `changeme-dev-only` |
| NATS HTTP Monitor | HTTP:8222 | None | Exposes broker stats; should not be reachable from internet |
| Postgres | TCP:5432 | Password auth | `sanchr / sanchr_dev` in docker-compose |
| Redis | TCP:6379 | None (docker-compose default) | `appendonly yes`; no password configured in docker-compose |
| ScyllaDB CQL | TCP:9042 | None (docker-compose default) | No auth in docker-compose config |
| MinIO (S3) | HTTP:9000, Console:9001 | `minioadmin / minioadmin` | Dev-only credentials |

---

## Request-Size Enforcement

### `sanchr-core` (Tower Middleware)

The `RequestSizeLayer` (`crates/sanchr-core/src/middleware/request_size.rs`) applies to all `sanchr-core` gRPC traffic:

- **Global default:** 1 MiB (`1_048_576` bytes) when no per-RPC override matches
- **Enforcement:** Checks `Content-Length` header; rejects with `tonic::Code::ResourceExhausted`
- **Per-RPC overrides:** Configured via `server.request_size.per_rpc` map in app config
- **Lookup strategy:** Tries full path, then trimmed path, then `ServiceName/MethodName` short form
- **Limitation:** Only checks `Content-Length` header; streaming RPCs without `Content-Length` may bypass this check

### `sanchr-call` (Tonic Config)

The call signaling server applies a 64 KB `max_decoding_message_size` at the Tonic server level. This limits the maximum size of any single decoded gRPC message.

---

## Gaps Identified

1. **No rate limiting on VaultService, MediaService, BackupService, NotificationService, SettingsService** -- authenticated users can call these without throttling.
2. **No rate limiting on any CallSignalingService RPCs** -- call initiation, signaling stream, and history have no per-user limits.
3. **Streaming RPCs may bypass content-length check** -- `MessageStream` and `CallStream` use bidirectional streaming where individual frames may not carry `Content-Length`.
4. **NATS monitoring port (8222) exposed** -- docker-compose exposes the monitoring HTTP port without auth.
5. **Redis and ScyllaDB have no auth in docker-compose** -- acceptable for dev but must be secured in production.
