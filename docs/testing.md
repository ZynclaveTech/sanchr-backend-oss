# Testing Guide

## Prerequisites

All integration tests require the Docker Compose services to be running:

```bash
docker compose up -d
```

Wait for all services to report healthy before running tests. You can verify with:

```bash
docker compose ps
```

The required services are: Postgres, Redis, ScyllaDB, NATS, and MinIO. ScyllaDB takes the longest to initialize (up to 60 seconds on first start).

## Running Tests

### Unit + Integration Tests

```bash
make test
# Equivalent to: cargo test --workspace
```

### Reliability Guards Only

```bash
make reliability-guards
# Equivalent to: cargo test -p sanchr-core --test reliability_guards
```

### Linting

```bash
make lint
# Runs: cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings
```

## Test Harness Overview

Integration tests live in `crates/sanchr-core/tests/`. Each test file uses a shared harness defined in `tests/common/mod.rs`.

### `common::setup_test_state()`

This is the entry point for every integration test. It:

1. Sets the working directory to the workspace root so config files resolve correctly.
2. Loads `AppConfig` from `config/` files and `SANCHR__` environment variable overrides.
3. Creates connection pools for Postgres, Redis, ScyllaDB, and NATS.
4. Runs Postgres migrations automatically.
5. Creates the S3 bucket in MinIO if it does not exist.
6. Builds and returns a shared `Arc<AppState>` ready for use.

### `common::register_and_verify_user*()`

Helper functions that register a new user with a random phone number, auto-verify the OTP (by reading it from Redis), and return an `AuthResult` with a valid JWT. Most tests call one of these to get authenticated test users.

## Writing a New Integration Test

1. Create a new file in `crates/sanchr-core/tests/`, e.g. `my_feature_flow.rs`.

2. Import the common harness:

```rust
mod common;

use std::sync::Arc;
use uuid::Uuid;
```

3. Write an async test function:

```rust
#[tokio::test]
async fn test_my_feature() {
    let state = common::setup_test_state().await;

    // Create test users
    let (auth, phone) = common::register_and_verify_user(
        &state,
        "Password123!",
        "test-device",
        "ios",
        Some(&format!("install-{}", Uuid::new_v4())),
    )
    .await;

    // Exercise the feature under test using state.pg_pool,
    // state.redis_client, the gRPC service traits, etc.
    // ...

    // Assert outcomes
    // ...
}
```

4. Run your new test:

```bash
cargo test -p sanchr-core --test my_feature_flow
```

### Pattern Notes

- Each test gets its own users with random phone numbers, so tests are isolated and can run in parallel.
- Use the gRPC service trait methods directly (e.g. `MessagingService::send_message()`) rather than going through a network socket. This keeps tests fast and deterministic.
- For tests that need a `tonic::Request`, build it manually and attach auth metadata via `request.metadata_mut()`.

## Reliability Guards

The `reliability_guards` test suite (`crates/sanchr-core/tests/reliability_guards.rs`) is a dedicated regression gate for message delivery invariants. It verifies:

- **Idempotency**: sending the same message twice (same idempotency key) produces exactly one outbox entry.
- **Deduplication**: duplicate relay events do not create duplicate deliveries.
- **Delivery tracking**: messages transition correctly through pending, delivered, and read states.
- **Sealed sender delivery**: sealed-sender messages follow the same reliability guarantees as standard messages.

Run these as a fast pre-merge gate:

```bash
make reliability-guards
```

## Load Tests

Load tests use [k6](https://k6.io/) with gRPC and live in `loadtests/`. Each scenario targets a specific subsystem.

### Prerequisites

- Install k6: `brew install k6` (macOS) or see [k6 installation docs](https://k6.io/docs/get-started/installation/).
- The backend must be running (`make dev`).

### Running Load Tests

```bash
# Run all scenarios sequentially
make loadtest

# Run a specific scenario
make loadtest-auth          # Registration + login flows
make loadtest-messaging     # Message send + delivery
make loadtest-keys          # Pre-key upload + fetch
make loadtest-contacts      # Contact sync + blocklist
make loadtest-lifecycle     # Full user lifecycle (register -> message -> delete)
make loadtest-smoke         # Quick sanity check (low VU count)
```

Load test scripts are in `loadtests/`:

| File                          | Scenario                              |
| ----------------------------- | ------------------------------------- |
| `auth.js`                     | Registration, OTP, login              |
| `messaging.js`                | Send + stream messages                |
| `keys.js`                     | Pre-key bundle upload + retrieval     |
| `contacts_settings_vault.js`  | Contacts, settings, vault CRUD        |
| `full_lifecycle.js`           | End-to-end user journey               |
| `lib/`                        | Shared helpers (gRPC client, auth)    |

The `run.sh` orchestrator accepts a scenario name (matching the Makefile targets above) or `all` to run every scenario in sequence.
