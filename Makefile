.PHONY: setup dev test reliability-guards lint build clean \
       loadtest loadtest-auth loadtest-messaging loadtest-keys \
       loadtest-contacts loadtest-lifecycle loadtest-smoke \
       bench fuzz docs

# ── Contributor setup ────────────────────────────────────────────────────────

setup:
	@echo "==> Checking prerequisites..."
	@rustc --version || { echo "ERROR: rustc not found. Install via https://rustup.rs"; exit 1; }
	@protoc --version || { echo "ERROR: protoc not found. Install protobuf compiler."; exit 1; }
	@docker --version || { echo "ERROR: docker not found. Install Docker Desktop."; exit 1; }
	@echo ""
	@echo "==> Starting Docker Compose services..."
	docker compose up -d
	@echo ""
	@echo "==> Waiting for services to become healthy (10s)..."
	@sleep 10
	docker compose ps
	@echo ""
	@echo "==> Running cargo check..."
	cargo check --workspace
	@echo ""
	@echo "==> Setup complete. Run 'make dev' to start the server."

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

# ── Benchmarks ──────────────────────────────────────────────────────────────

bench:
	cargo bench --workspace

# ── Fuzz testing ─────────────────────────────────────────────────────────────

fuzz:
	cargo +nightly fuzz run fuzz_proto_decode -- -max_total_time=60
	cargo +nightly fuzz run fuzz_otp -- -max_total_time=60
	cargo +nightly fuzz run fuzz_oprf -- -max_total_time=60
	cargo +nightly fuzz run fuzz_jwt -- -max_total_time=60

# ── API documentation ───────────────────────────────────────────────────────

docs:
	@echo "Generating API docs from proto files..."
	@mkdir -p docs/api
	@echo "# Sanchr gRPC API Reference" > docs/api/API.md
	@echo "" >> docs/api/API.md
	@echo "Auto-generated from proto files. Run \`make docs\` to regenerate." >> docs/api/API.md
	@echo "" >> docs/api/API.md
	@echo "## Services" >> docs/api/API.md
	@echo "" >> docs/api/API.md
	@for f in crates/sanchr-proto/proto/*.proto; do \
		echo "### $$(basename $$f .proto)" >> docs/api/API.md; \
		echo '```protobuf' >> docs/api/API.md; \
		grep -A 100 "^service " "$$f" | head -50 >> docs/api/API.md; \
		echo '```' >> docs/api/API.md; \
		echo "" >> docs/api/API.md; \
	done
	@echo "Docs generated at docs/api/API.md"
