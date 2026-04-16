# Release Process

## Versioning

Sanchr follows [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

| Increment | When |
|-----------|------|
| **MAJOR** | Breaking protobuf changes, breaking configuration changes, incompatible API changes |
| **MINOR** | New features, new RPCs, new configuration options (backward-compatible) |
| **PATCH** | Bug fixes, security fixes, documentation updates |

## Release Checklist

Before tagging a release, complete every item:

- [ ] All tests pass (`make test && make reliability-guards`)
- [ ] Clippy clean (`make lint`)
- [ ] Benchmarks show no regression (Criterion comparison against previous release)
- [ ] `CHANGELOG.md` updated with all changes since last release
- [ ] Version bumped in workspace `Cargo.toml`
- [ ] Git tag created and signed (`git tag -s vX.Y.Z -m "vX.Y.Z"`)
- [ ] GitHub Release created with changelog excerpt
- [ ] Crates published (`sanchr-server-crypto`, `sanchr-psi`) if changed

## Changelog

Generated from [conventional commits](https://www.conventionalcommits.org/) using [git-cliff](https://git-cliff.org/) or equivalent.

- **Format:** [Keep a Changelog](https://keepachangelog.com/)
- **Categories:**
  - **Added** -- new features and capabilities
  - **Changed** -- changes to existing functionality
  - **Deprecated** -- features marked for removal
  - **Removed** -- features removed in this release
  - **Fixed** -- bug fixes
  - **Security** -- security-related fixes and improvements

## Crate Publishing

Two crates are published to [crates.io](https://crates.io/) as standalone libraries useful to other projects:

| Crate | Purpose |
|-------|---------|
| `sanchr-server-crypto` | Server-side cryptographic operations (OPRF, key derivation) |
| `sanchr-psi` | Private set intersection protocol implementation |

All other workspace crates are internal and not published.

### Publishing Steps

1. Ensure the crate version is bumped in its `Cargo.toml`
2. Run `cargo publish --dry-run -p <crate-name>` to verify
3. Run `cargo publish -p <crate-name>`
4. Verify the crate appears on crates.io

## Security Releases

Security releases follow the process defined in [SECURITY.md](../SECURITY.md):

1. Receive and acknowledge vulnerability report
2. Coordinate with reporter on disclosure timeline
3. Develop and test patch on a private branch
4. Tag patch release (increment PATCH version)
5. Create GitHub Release with security advisory
6. Publish advisory via GitHub Security Advisories
7. Notify downstream users if applicable

Security patches are backported to the latest MINOR release only.

## Release Workflow Summary

```
1. Finalize CHANGELOG.md
2. Bump version in workspace Cargo.toml
3. make test && make lint && make reliability-guards
4. git commit -m "chore: release vX.Y.Z"
5. git tag -s vX.Y.Z -m "vX.Y.Z"
6. git push origin main --tags
7. Create GitHub Release from tag
8. cargo publish (for public crates, if changed)
```
