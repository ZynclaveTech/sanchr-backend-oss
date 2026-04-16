# Governance

This document describes the governance model for the Sanchr backend project.

## Roles

### Core Team

The core team is responsible for the security-critical subsystems of Sanchr: cryptographic primitives, protocol logic, authentication, and sealed-sender messaging. Core team members have write access to the repository and final approval authority over changes to protected paths (see `CODEOWNERS`).

Responsibilities:

- Review and approve all changes to crypto, protocol, and auth code
- Triage security reports per `SECURITY.md`
- Maintain the threat model and ensure changes do not introduce regressions
- Participate in RFC review for protocol extensions

### Community Reviewers

Community reviewers help maintain non-security-critical areas such as Helm charts, documentation, configuration, and issue templates. They can approve PRs in community-reviewable paths but cannot merge changes to core-team-owned paths.

### Contributors

Anyone who submits a pull request or files an issue is a contributor. All contributions must follow `CONTRIBUTING.md` and the project's code of conduct.

## Decision-Making

### Minor Changes

Minor changes (documentation fixes, non-functional config updates, CI improvements) use **lazy consensus**: if no core team member objects within 72 hours of a PR being opened, the change may be merged by any reviewer with write access.

### Significant Changes

Changes that affect public APIs, database schemas, deployment topology, or observable behavior require **explicit approval** from at least one core team member before merging.

### Crypto and Protocol Changes

Any change to cryptographic code, protocol wire formats, key management, or authentication logic requires **explicit approval from at least two core team members**. These changes must include:

- A description of the threat model impact
- Updated or new tests covering the security-relevant behavior
- A reference to the relevant section of the threat model document if applicable

## RFC Process

Protocol extensions, new cryptographic constructions, and changes to the sealed-sender design follow a lightweight RFC process:

1. Open a GitHub Discussion in the "RFCs" category with the proposal
2. The proposal must include: motivation, detailed design, security considerations, and alternatives considered
3. A minimum **7-day comment period** is required before any decision
4. Core team members vote to accept, reject, or request revisions
5. Accepted RFCs are tracked as GitHub issues and referenced in the implementing PRs

## Joining the Core Team

To be nominated for the core team, a contributor should demonstrate:

- Sustained, high-quality contributions over at least 3 months
- Familiarity with the project's threat model and security posture
- Constructive participation in code review and design discussions

Nominations are made by existing core team members and require unanimous approval from the current core team.

## Code of Conduct

All participants in the Sanchr project are expected to follow the project's [Code of Conduct](CODE_OF_CONDUCT.md). Violations may be reported to the core team and will be handled per the enforcement guidelines in that document.
