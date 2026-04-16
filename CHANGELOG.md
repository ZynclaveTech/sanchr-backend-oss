# Changelog

All notable changes to the Sanchr backend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.0.1] - 2026-04-16

Initial public release.

### Added

- Request-size limit middleware with per-RPC configuration
- NATS authentication support in Docker Compose
- ChallengeProvider trait with proof-of-work implementation
- CryptoProvider abstraction layer with LocalCryptoProvider
- AWS KMS and HashiCorp Vault provider stubs (feature-gated)
- Helm chart for Kubernetes deployment
- API documentation with proto doc comments
- Tamarin formal verification models (OPRF, EKF, MediaK)
- Composition proof document
- Criterion.rs microbenchmarks for crypto operations
- Fuzz testing targets (proto decode, OTP, OPRF, JWT)
- Dev container configuration
- Architecture and testing documentation
- Security audit preparation documents
- Community infrastructure (issue templates, CODEOWNERS, governance)
- RFC process for protocol changes
- Release process documentation
- Public roadmap

### Changed

- EKF lifecycle enforcement enabled by default
- NATS connection supports authenticated mode

### Security

- Request body size limits prevent payload amplification
- NATS broker requires authentication
- Fuzz testing covers security-critical input paths
