# Sanchr Backend

Sanchr backend services provide authentication, key management, messaging,
calling, contact discovery, media, backups, vault metadata, and supporting
infrastructure adapters for the Sanchr app.

This repository is the public backend codebase. It intentionally omits
deployment manifests, production CI/CD, cloud credentials, and operational
runbooks. Operators are expected to wire infrastructure and runtime policy in
their own environment.

## Status

- Public source release of the backend codebase.
- Rust workspace with gRPC services and local Docker dependencies.
- Code license: MIT.
- Security model: see [backend-threat-model.md](backend-threat-model.md).
- Public project name: Sanchr.
- Legacy internal identifiers: several crates, protobuf packages, binaries, and
  environment variables still use `sanchr`. Those names are intentionally left in
  place until a separate compatibility-aware rename.
- No committed deploy or observability config is required. Operators can use
  environment variables or bring their own config files if they prefer.

## Local Development

Prerequisites:

- Rust toolchain from `rust-toolchain.toml`.
- Docker and Docker Compose.
- `protoc`.

Start dependencies:

```sh
docker compose up -d
```

Provide configuration through `SANCHR__...` environment variables, or mount your
own optional config files under `config/` if that matches your environment.

Run the core service:

```sh
cargo run -p sanchr-core
```

Run the call service in a second terminal when needed:

```sh
cargo run -p sanchr-call
```

The public repo does not ship production-ready secrets, deploy manifests,
Prometheus/Grafana config, or an OTP delivery provider. `Register` generates an
OTP, but sending that code to the user is the operator's responsibility. Use
your own SMS, voice, email, or trusted out-of-band workflow if you deploy this
code.

Do not run with `auth.dev_mode=true` outside an isolated local development
environment.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --tests
```

The public CI workflow is intentionally limited to secretless build, lint, and
test jobs.

## Operator Notes

This repository intentionally does not prescribe a deployment shape. Bring your
own:

- secrets management
- database and object storage endpoints
- TURN infrastructure
- OTP delivery integration
- signer and key-management integrations for hardened environments

## Security

Do not report vulnerabilities in public issues. Follow
[SECURITY.md](SECURITY.md) for private reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
