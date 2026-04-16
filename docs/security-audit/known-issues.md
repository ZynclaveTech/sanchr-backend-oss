# Known Issues Register

**Project:** Sanchr Backend (OSS)
**Date:** 2026-04-16
**Source:** `backend-threat-model.md` (2026-04-11) cross-referenced with source code

---

## Priority Definitions

- **P0:** Blocks production or public launch. Exploitable for account takeover, persistent compromise, or serious infrastructure abuse.
- **P1:** Should be fixed before open source or any non-local shared deployment. Exploitable by authenticated users or internal footholds, or materially affects public security claims.
- **P2:** Important hardening and open source readiness. Not immediately exploitable in dev, but creates avoidable release risk.

---

## Issue Register

| ID | Severity | Finding | Status | Mitigation | Source Reference |
|----|----------|---------|--------|------------|-----------------|
| TM-003 | P1 | **NATS event injection:** Relay bridges forward NATS events to users; compromised internal producer can inject forged message/call events | Partially Fixed | NATS auth (username/password) added to `docker-compose.yml` and `config/nats-server.conf`. TLS is documented but commented out. Subject-level ACLs and per-service credentials are not configured. Application-layer relay envelope signing is not implemented. | `config/nats-server.conf`, `docker-compose.yml:45-56` |
| TM-005 | P1 | **Paper-claim mismatch:** OPRF, EKF, and sealed sender use ephemeral/dev keys by default; research paper claims production-grade time-bounded privacy | Partially Fixed | EKF enabled by default (`ekf.enabled = true`); startup rejects OPRF without secret in non-dev mode; OPRF weekly rotation implemented; discovery daily salt rotation implemented. Remaining gaps: sealed sender signer is ephemeral in dev (production signer config not in public repo); HSM/KMS integration incomplete; no integration tests proving TTL/rotation properties. | `crates/sanchr-common/src/config.rs:164-166`, `crates/sanchr-core/src/main.rs:117-131` |
| TM-007 | P1 | **Media/backup/vault lifecycle drift:** Encrypted blobs or metadata may outlive expected lifetimes; dev/staging code path drops Scylla vault tables at startup | Partially Fixed | S3 media lifecycle policy configurable (default: 30 days via `media_lifecycle_days`); EKF lifecycle tick runs by default. Remaining gaps: no integration tests proving retention; Scylla startup table drops must be gated to dev-only; backup/vault retention not enforced by cleanup workers. | `crates/sanchr-db/src/scylla/mod.rs:110`, `crates/sanchr-common/src/config.rs:124-130` |
| TM-008 | P1 | **Public repo exposes operational assumptions:** Production registry names, cluster names, or deploy workflows could leak into public source | Mitigated | Public CI is secretless; production CD kept in private ops repo; deploy workflow not present in public repo. Requires ongoing review gate to prevent regression. | `.github/workflows/` |
| TM-009 | P2 | **Naming drift (sanchr vs Sanchr):** Crate names, proto packages, Docker images, Kubernetes names still use legacy `sanchr` naming | Open | Rename planned but not executed. Proto package rename is breaking for generated clients. Decision needed before public launch. | Workspace `Cargo.toml`, all `crates/sanchr-*/` |
| TM-010 | P2 | **Open source policy process:** Security mailbox and maintainer response process must be confirmed; dependency license/advisory policy pending | Partially Fixed | `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` present. Remaining: verify security contact monitoring is operational; add `cargo audit`/`cargo deny`; add SBOM/release checklist. | Root repo files |

---

## Additional Findings from Source Review

| ID | Severity | Finding | Status | Notes |
|----|----------|---------|--------|-------|
| SR-003 | P2 | **Redis has no auth in docker-compose:** Dev Redis instance has no password; any local process can connect | Open | Acceptable for dev; must be secured for any shared environment |
| SR-004 | P2 | **NATS monitoring port exposed:** Docker-compose exposes port 8222 (HTTP monitoring) without auth | Open | Provides broker internals; should be restricted to operator access only |

---

## Remediation Priority

### Before Open Source Release
1. Document which research-paper defenses are implemented vs. pending (TM-005)
2. Confirm security contact monitoring is operational (TM-010)
3. Complete or plan naming cleanup (TM-009)

### Before Production Deployment
1. Add NATS TLS, subject ACLs, and per-service credentials (TM-003)
2. Gate Scylla table drops to dev-only; add retention integration tests (TM-007)
3. Secure Redis and ScyllaDB auth for shared environments (SR-003)
4. Restrict NATS monitoring port to internal networks (SR-004)
