#!/usr/bin/env bash
# Sanchr gRPC load test runner
#
# Usage:
#   ./loadtests/run.sh              # run all tests sequentially
#   ./loadtests/run.sh auth         # run only auth tests
#   ./loadtests/run.sh smoke        # quick smoke (5 VUs, 15s)
#   ./loadtests/run.sh spike        # full lifecycle spike test
#
# Environment:
#   GRPC_ADDR   gRPC server address (default: localhost:9090)
#   K6_OUT      k6 output (e.g., "influxdb=http://localhost:8086/k6")

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRPC_ADDR="${GRPC_ADDR:-localhost:9090}"

# Proto path relative to where k6 runs (from backend/)
export PROTO_DIR="${SCRIPT_DIR}/../crates/sanchr-proto/proto"
export GRPC_ADDR

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[LOAD]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[FAIL]${NC} $*"; }

# Check prerequisites
if ! command -v k6 &>/dev/null; then
  err "k6 not found. Install: brew install grafana/k6/k6"
  exit 1
fi

# Verify server is reachable
if ! grpcurl -plaintext "$GRPC_ADDR" list &>/dev/null 2>&1; then
  warn "gRPC server at $GRPC_ADDR not reachable. Tests may fail."
  warn "Start the server: cargo run --bin sanchr-core"
fi

K6_EXTRA_ARGS="${K6_OUT:+--out $K6_OUT}"

run_test() {
  local name="$1"
  local script="$2"
  shift 2
  local extra_args=("$@")

  log "Running: $name"
  log "Script:  $script"
  log "Target:  $GRPC_ADDR"
  echo ""

  if k6 run "$script" ${K6_EXTRA_ARGS:-} "${extra_args[@]}" 2>&1; then
    log "$name completed successfully"
  else
    err "$name failed (exit code: $?)"
  fi
  echo ""
  echo "────────────────────────────────────────────────────────────"
  echo ""
}

case "${1:-all}" in
  auth)
    run_test "Auth Load Test" "$SCRIPT_DIR/auth.js"
    ;;
  messaging|msg)
    run_test "Messaging Load Test" "$SCRIPT_DIR/messaging.js"
    ;;
  contacts|csv)
    run_test "Contacts/Settings/Vault Load Test" "$SCRIPT_DIR/contacts_settings_vault.js"
    ;;
  keys)
    run_test "Keys Load Test" "$SCRIPT_DIR/keys.js"
    ;;
  lifecycle|full)
    run_test "Full Lifecycle Load Test" "$SCRIPT_DIR/full_lifecycle.js"
    ;;
  smoke)
    log "Running smoke tests (5 VUs, 15s) across all services..."
    echo ""
    run_test "Auth Smoke" "$SCRIPT_DIR/auth.js" \
      --vus 5 --duration 15s --no-thresholds
    run_test "Messaging Smoke" "$SCRIPT_DIR/messaging.js" \
      --vus 3 --duration 15s --no-thresholds
    run_test "Keys Smoke" "$SCRIPT_DIR/keys.js" \
      --vus 3 --duration 15s --no-thresholds
    run_test "Contacts/Settings/Vault Smoke" "$SCRIPT_DIR/contacts_settings_vault.js" \
      --vus 3 --duration 15s --no-thresholds
    ;;
  spike)
    run_test "Spike Test (Full Lifecycle)" "$SCRIPT_DIR/full_lifecycle.js"
    ;;
  all)
    log "Running complete load test suite..."
    echo ""
    run_test "Auth Load Test" "$SCRIPT_DIR/auth.js"
    run_test "Keys Load Test" "$SCRIPT_DIR/keys.js"
    run_test "Messaging Load Test" "$SCRIPT_DIR/messaging.js"
    run_test "Contacts/Settings/Vault Load Test" "$SCRIPT_DIR/contacts_settings_vault.js"
    run_test "Full Lifecycle Load Test" "$SCRIPT_DIR/full_lifecycle.js"
    log "All load tests complete!"
    ;;
  *)
    echo "Usage: $0 {auth|messaging|contacts|keys|lifecycle|smoke|spike|all}"
    exit 1
    ;;
esac
