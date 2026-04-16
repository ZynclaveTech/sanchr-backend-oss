# Roadmap

## Completed

### Phase 1: Security Hardening

- Request-size limit middleware with per-RPC configuration
- NATS authentication support in Docker Compose
- EKF lifecycle enforcement enabled by default
- Fuzz testing targets for security-critical input paths (proto decode, OTP, OPRF, JWT)

### Phase 2: Production Readiness

- ChallengeProvider trait with proof-of-work implementation
- CryptoProvider abstraction layer with LocalCryptoProvider
- AWS KMS and HashiCorp Vault provider stubs (feature-gated)
- Helm chart for Kubernetes deployment
- API documentation with proto doc comments

### Phase 3: Formal Verification

- Tamarin formal verification models (OPRF, EKF, MediaK)
- Composition proof document
- Criterion.rs microbenchmarks for crypto operations
- KMS backend abstraction with pluggable providers

### Phase 4: Ecosystem Maturity

- Community infrastructure (issue templates, CODEOWNERS, governance)
- Contributor tooling (dev container, architecture docs, testing guide)
- Security audit preparation documents (scope, crypto inventory, threat model, attack surface, known issues)

## In Progress

### Phase 5: External Validation

- Security audit engagement with external firm
- Scale and chaos testing infrastructure
- Release process and changelog automation
- RFC process for protocol changes
- Community growth and adoption

## Future

- Android client
- Federation protocol exploration
- Multi-device sync improvements
- Additional KMS backend implementations (GCP KMS, Azure Key Vault)
