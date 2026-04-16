# KMS Backend Integration

Sanchr supports pluggable cryptographic backends via the `CryptoProvider` trait.
By default the server uses the **local provider**, which holds all key material
in-process. For production deployments that require external key management, two
additional backends are available behind Cargo feature gates.

> **Status**: Both KMS backends are currently **stubs** -- the trait interface is
> wired up but every operation returns an error. This document describes the
> target architecture so operators can begin provisioning keys and policies ahead
> of the full implementation.

---

## Enabling a KMS Backend

### AWS KMS

```toml
# In the server crate's Cargo.toml (or via CLI)
sanchr-server-crypto = { path = "crates/sanchr-server-crypto", features = ["kms-aws"] }
```

```sh
cargo build --features kms-aws
```

### HashiCorp Vault

```toml
sanchr-server-crypto = { path = "crates/sanchr-server-crypto", features = ["kms-vault"] }
```

```sh
cargo build --features kms-vault
```

Both features are additive and can be enabled simultaneously, though only one
backend is active at runtime.

---

## AWS KMS Backend

### Required Keys

| Key | KMS Key Spec | Usage | Purpose |
|-----|-------------|-------|---------|
| Signing key | `ECC_NIST_P256` | `SIGN_VERIFY` | Sealed sender certificate signing |
| HMAC key | `HMAC_256` | `GENERATE_VERIFY_MAC` | OTP generation, TURN credentials |
| JWT secret | Secrets Manager secret or KMS data key | -- | JWT HS256 signing (fetched at startup) |

### IAM Policy

The server's IAM role (EC2 instance profile, ECS task role, or EKS IRSA) needs
the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SealedSenderSigning",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:<region>:<account>:key/<signing-key-id>"
    },
    {
      "Sid": "HmacOperations",
      "Effect": "Allow",
      "Action": [
        "kms:GenerateMac",
        "kms:VerifyMac",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:<region>:<account>:key/<hmac-key-id>"
    },
    {
      "Sid": "JwtSecretAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:<jwt-secret-name>-*"
    }
  ]
}
```

### Key Provisioning

```sh
# 1. Create the signing key
aws kms create-key \
  --key-spec ECC_NIST_P256 \
  --key-usage SIGN_VERIFY \
  --description "Sanchr sealed sender signing key" \
  --tags TagKey=Service,TagValue=sanchr

# 2. Create the HMAC key
aws kms create-key \
  --key-spec HMAC_256 \
  --key-usage GENERATE_VERIFY_MAC \
  --description "Sanchr OTP/TURN HMAC key" \
  --tags TagKey=Service,TagValue=sanchr

# 3. Store the JWT secret in Secrets Manager
aws secretsmanager create-secret \
  --name sanchr/jwt-signing-key \
  --secret-string "$(openssl rand -base64 64)" \
  --description "Sanchr JWT HS256 signing secret"
```

### Key Rotation

- **Signing key**: Enable automatic key rotation in KMS. The provider tracks the
  active key version via `active_key_id()`. Clients receiving certificates signed
  with the previous version will re-fetch on next session.
- **HMAC key**: KMS does not support automatic rotation for HMAC keys. Rotate
  manually by creating a new key and updating the server configuration. During
  the transition window, the server should accept OTPs generated with either key.
- **JWT secret**: Rotate in Secrets Manager using staging labels
  (`AWSCURRENT` / `AWSPREVIOUS`). The server fetches the secret at startup, so
  a rolling restart across instances completes the rotation.

---

## HashiCorp Vault Backend

### Required Transit Keys

| Key | Transit Key Type | Purpose |
|-----|-----------------|---------|
| Signing key | `ecdsa-p256` or `ed25519` | Sealed sender certificate signing |
| HMAC key | `aes256-gcm96` (supports HMAC) | OTP generation, TURN credentials |

The JWT signing secret is stored in **KV v2** (not Transit).

### Vault Policies

```hcl
# Transit signing operations
path "transit/sign/sanchr-signing" {
  capabilities = ["update"]
}

path "transit/verify/sanchr-signing" {
  capabilities = ["update"]
}

path "transit/keys/sanchr-signing" {
  capabilities = ["read"]
}

# Transit HMAC operations
path "transit/hmac/sanchr-hmac" {
  capabilities = ["update"]
}

path "transit/verify/sanchr-hmac" {
  capabilities = ["update"]
}

path "transit/keys/sanchr-hmac" {
  capabilities = ["read"]
}

# JWT secret from KV v2
path "secret/data/sanchr/jwt-signing-key" {
  capabilities = ["read"]
}
```

### Key Provisioning

```sh
# 1. Enable Transit if not already enabled
vault secrets enable transit

# 2. Create the signing key
vault write transit/keys/sanchr-signing type=ecdsa-p256

# 3. Create the HMAC key
vault write transit/keys/sanchr-hmac type=aes256-gcm96

# 4. Store the JWT secret in KV v2
vault kv put secret/sanchr/jwt-signing-key \
  value="$(openssl rand -base64 64)"

# 5. Create the policy
vault policy write sanchr-crypto - <<EOF
# (paste the policy from above)
EOF

# 6. Create an AppRole or Kubernetes auth role bound to the policy
vault write auth/approle/role/sanchr-server \
  token_policies="sanchr-crypto" \
  token_ttl=1h \
  token_max_ttl=4h
```

### Key Rotation

- **Signing key**: `vault write -f transit/keys/sanchr-signing/rotate`. Transit
  supports automatic rotation via `auto_rotate_period`. The provider returns the
  latest version via `active_key_id()`.
- **HMAC key**: `vault write -f transit/keys/sanchr-hmac/rotate`. Same rotation
  mechanism as signing keys.
- **JWT secret**: Update the KV v2 secret and perform a rolling restart. KV v2
  version history allows rollback if needed.

---

## Architecture Notes

### Why JWT Stays Local

Both KMS backends fetch the JWT signing secret from the external key manager at
startup and then perform all JWT signing/validation locally. This is a deliberate
tradeoff:

- **Performance**: JWT validation happens on every authenticated API request.
  A KMS round-trip (2-10ms for AWS, variable for Vault) would add unacceptable
  latency.
- **Availability**: Local JWT validation means the server continues to function
  even if KMS is temporarily unreachable after startup.
- **Security**: The JWT secret is still centrally managed and rotatable. The
  in-process copy is protected by OS memory isolation.

### Sealed Sender Key Format

The local provider uses Ed25519 for sealed sender signing, producing a 32-byte
public key. KMS backends may use ECDSA P-256 instead (the only asymmetric
algorithm universally supported by cloud KMS services). Clients must handle both
key types -- the `active_key_id()` return value indicates which backend is active.

### Error Handling

All stub methods return `CryptoProviderError::Internal` with a descriptive
message. When implementing, each method should map KMS/Vault errors to the
appropriate `CryptoProviderError` variant (`Jwt`, `Otp`, `SealedSender`, `Turn`,
or `Internal`) so call sites can handle failures granularly.
