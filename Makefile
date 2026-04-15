.PHONY: dev test reliability-guards lint build clean \
       loadtest loadtest-auth loadtest-messaging loadtest-keys \
       loadtest-contacts loadtest-lifecycle loadtest-smoke

dev:
	docker compose up -d
	cargo run -p sanchr-core

test:
	cargo test --workspace

# Fail-fast reliability regression gate.
reliability-guards:
	cargo test -p sanchr-core --test reliability_guards

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace -- -D warnings

build:
	cargo build --workspace --release

clean:
	cargo clean
	docker compose down -v

# ── Load tests (k6 gRPC) ────────────────────────────────────────────────────

loadtest:
	./loadtests/run.sh all

loadtest-auth:
	./loadtests/run.sh auth

loadtest-messaging:
	./loadtests/run.sh messaging

loadtest-keys:
	./loadtests/run.sh keys

loadtest-contacts:
	./loadtests/run.sh contacts

loadtest-lifecycle:
	./loadtests/run.sh lifecycle

loadtest-smoke:
	./loadtests/run.sh smoke
