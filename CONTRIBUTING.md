# Contributing

Thank you for contributing to Sanchr.

## Development Workflow

1. Fork or branch from the current development branch.
2. Keep changes focused and include tests for behavior changes.
3. Run the standard checks before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --tests
```

For local dependencies:

```sh
docker compose up -d
```

## Security Rules

- Do not commit real secrets, production values, kubeconfigs, access tokens, or
  cloud resource identifiers.
- Do not add public production deployment workflows to this repository.
- Do not add hard-coded OTP/SMS/email provider credentials or a production
  delivery workflow to the public repo; document operator integration points
  instead.
- Do not report vulnerabilities in public issues. Use the process in
  [SECURITY.md](SECURITY.md).
- Treat auth, session, cryptography, discovery, retention, and relay changes as
  security-sensitive.

## Naming

The public project name is Sanchr. Some internal crates, protobuf packages,
binaries, and environment variables still use legacy `sanchr` names. Do not
rename those interfaces opportunistically; compatibility-sensitive renames
should happen in a dedicated change.

## Commit Sign-Off

This project uses the Developer Certificate of Origin instead of a separate
CLA. Sign off commits with:

```sh
git commit -s
```

The sign-off certifies that you have the right to submit the contribution under
the project's license.

## Pull Requests

Pull requests should include:

- What changed.
- Why it changed.
- Tests run.
- Security or privacy impact, if any.
