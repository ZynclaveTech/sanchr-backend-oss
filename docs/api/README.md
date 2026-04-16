# API Documentation

The proto files in `crates/sanchr-proto/proto/` are the source of truth for the Sanchr gRPC API.

## Quick reference

Generate a basic API reference from the proto service definitions:

```bash
make docs
```

This produces `docs/api/API.md` with service and RPC listings extracted from the proto files. No additional tooling is required.

## Full documentation with protoc-gen-doc

For richer output (field tables, cross-references, nested message expansion), install [protoc-gen-doc](https://github.com/pseudomuto/protoc-gen-doc) and run:

```bash
protoc \
  --doc_out=docs/api \
  --doc_opt=markdown,API.md \
  crates/sanchr-proto/proto/*.proto
```

HTML output is also supported:

```bash
protoc \
  --doc_out=docs/api \
  --doc_opt=html,index.html \
  crates/sanchr-proto/proto/*.proto
```

## Proto file overview

| File | Service | Description |
|------|---------|-------------|
| `auth.proto` | AuthService | Registration, OTP, login, token refresh, account deletion |
| `messaging.proto` | MessagingService | E2EE messaging, streaming, sealed sender, conversations |
| `keys.proto` | KeyService | Signal Protocol key bundles, pre-keys, device management |
| `contacts.proto` | ContactService | Contact sync, blocking |
| `discovery.proto` | DiscoveryService | OPRF-based privacy-preserving contact discovery |
| `vault.proto` | VaultService | Forward-secure encrypted file storage |
| `media.proto` | MediaService | Presigned upload/download URLs for encrypted media |
| `backup.proto` | BackupService | Encrypted backup lifecycle |
| `notifications.proto` | NotificationService | Push tokens and notification preferences |
| `settings.proto` | SettingsService | User preferences, profile, registration lock |
| `calling.proto` | CallSignalingService | Voice/video call signaling, TURN credentials |
| `sealed_sender.proto` | *(data only)* | Sealed-sender certificate wire format |
| `ekf.proto` | *(data only)* | Ephemeral key framework rotation events |
| `backup_payload.proto` | *(data only)* | Backup archive frame definitions |
