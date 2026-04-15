# Security Policy

## Supported Versions

The backend is in active development. Security fixes are made on the main
development branch until a public release process defines supported release
lines.

## Reporting a Vulnerability

Do not open a public GitHub issue for vulnerabilities.

Report suspected vulnerabilities privately by emailing `security@sanchr.com`.
If GitHub private vulnerability reporting is enabled for the repository, that
route is also acceptable.

Include:

- Affected commit, branch, or version.
- Impact and affected component.
- Reproduction steps or proof of concept.
- Any logs, stack traces, or request samples with secrets redacted.

Expected handling:

- Initial acknowledgement target: 3 business days.
- Triage target: 7 business days.
- Coordinated disclosure timing will be agreed with the reporter based on
  severity and remediation complexity.

Before public launch, Zynclave Tech Private Limited must confirm that the
security contact mailbox is monitored.

## Security-Sensitive Areas

Changes in these areas require extra review:

- Authentication, OTP, JWT, refresh tokens, and sessions.
- Contact discovery, OPRF, EKF, key rotation, and retention lifecycle logic.
- Message, sealed sender, call signaling, and NATS relay paths.
- Media, backup, vault, and object-storage access control.
- CI/CD, deployment, Helm values, and secret handling.
