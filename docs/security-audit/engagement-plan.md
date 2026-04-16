# Security Audit Engagement Plan

## Objective

Source code review and protocol analysis of Sanchr's cryptographic and privacy-critical code paths. The audit should validate that the implementation correctly realizes the formal properties proven in our Tamarin models and that no exploitable gaps exist between specification and code.

## Scope

The five audit preparation documents in `docs/security-audit/` define the detailed scope:

| Document | Purpose |
|----------|---------|
| [audit-scope.md](audit-scope.md) | Boundaries, in-scope crates, and exclusions |
| [crypto-inventory.md](crypto-inventory.md) | Every cryptographic primitive, parameter, and usage site |
| [threat-model-consolidated.md](threat-model-consolidated.md) | Consolidated threat model with adversary capabilities |
| [attack-surface.md](attack-surface.md) | Entry points, trust boundaries, and data flows |
| [known-issues.md](known-issues.md) | Pre-existing issues the auditor should be aware of |

## Recommended Firms

| Firm | Rationale |
|------|-----------|
| **NCC Group** | Published cryptographic protocol audits (Signal, WireGuard). Rust codebase experience. Large team allows flexible scheduling. |
| **Trail of Bits** | Deep Rust tooling expertise (cargo-fuzz, Semgrep rules). Published audits of crypto libraries (ring, rustls). Strong formal methods team. |
| **Cure53** | Published audits for messaging protocols (Matrix, Briar). Browser and mobile crypto experience. Competitive pricing for focused engagements. |

## Selection Criteria

1. **Published cryptographic protocol audit reports** -- the firm must have at least two public reports covering protocol-level (not just implementation-level) cryptographic review.
2. **Rust codebase experience** -- prior audits of Rust projects, demonstrating familiarity with Rust-specific patterns (unsafe blocks, FFI boundaries, memory model).
3. **Availability within timeline** -- ability to begin within 4 weeks of engagement and complete within the estimated effort window.

## Engagement Type

**Time-boxed source code review** (not penetration testing).

The auditors will receive read-only access to the repository and review the source code, protocol design, and formal verification artifacts. This is not a black-box or gray-box penetration test -- the goal is deep understanding of cryptographic correctness, not network-level vulnerability scanning.

## Estimated Effort

- **Team:** 2 engineers
- **Duration:** 2-4 weeks
- **Codebase size:** ~15K LOC of crypto-focused Rust
- **Focus areas:** OPRF protocol, EKF lifecycle, sealed sender construction, key derivation, media encryption

## Budget Range

$50K-$150K depending on firm, depth of review, and whether formal verification artifacts are independently checked.

| Depth | Estimated Cost | Coverage |
|-------|---------------|----------|
| Focused (2 weeks, 2 engineers) | $50K-$75K | Core crypto paths only |
| Standard (3 weeks, 2 engineers) | $75K-$110K | Crypto paths + protocol state machines |
| Comprehensive (4 weeks, 2 engineers) | $110K-$150K | Full scope including Tamarin model review |

## Timeline

Engage **after Tamarin models are finalized** so auditors can reference formal properties as a correctness oracle.

```
Week 0     : Tamarin models complete and passing
Week 1-2   : Firm selection, NDA, SOW negotiation
Week 3     : Repository access granted, kick-off call
Week 4-7   : Active audit period
Week 8     : Draft findings report delivered
Week 9     : Remediation period (Sanchr team)
Week 10    : Final report delivered
Week 11-12 : Coordinated public disclosure
```

## Deliverables from Auditor

1. **Findings report** with severity ratings (Critical / High / Medium / Low / Informational)
2. **Recommendations** for each finding, including suggested code changes where applicable
3. **Proof-of-concept** for critical and high findings demonstrating exploitability
4. **Executive summary** suitable for public disclosure

## Publication

The findings report will be **published publicly after remediation**. A coordinated disclosure timeline will be agreed with the auditor before engagement begins:

- Critical findings: 90-day remediation window before public disclosure
- High findings: 60-day remediation window
- Medium and below: published with the final report
- The auditor retains the right to publish their report on their own site after the agreed timeline

## Pre-Engagement Checklist

- [ ] Audit scope document reviewed and finalized
- [ ] Crypto inventory verified against current code
- [ ] Known issues register updated
- [ ] Attack surface map current
- [ ] Tamarin models complete and passing
- [ ] NDA executed with selected firm
- [ ] Repository access granted (read-only)
- [ ] Point of contact designated for auditor questions
