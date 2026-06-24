#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

ARTIFACT_ROOT=""
REQUIRE_BASE_SEPOLIA=0

usage() {
  cat <<'EOF'
Usage:
  ./scenario/01-web3-service-order.sh [--artifact-dir PATH] [--require-base-sepolia-smoke]

Starts the local web3 internet-of-agents topology, runs the service-order flow,
and verifies the generated bundle.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    --require-base-sepolia-smoke)
      REQUIRE_BASE_SEPOLIA=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -f "${ROOT}/target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json" ]]; then
  REQUIRE_BASE_SEPOLIA=1
fi

if [[ -z "${ARTIFACT_ROOT}" ]]; then
  ARTIFACT_ROOT="$(prepare_scenario_dir "web3-service-order")"
fi

rm -rf "${ARTIFACT_ROOT}"
mkdir -p "${ARTIFACT_ROOT}"
trap stop_live_topology EXIT

start_live_topology "${ARTIFACT_ROOT}"
run_live_scenario "${ARTIFACT_ROOT}" "${REQUIRE_BASE_SEPOLIA}"
assert_review_ok "${ARTIFACT_ROOT}"
verify_transaction_passport "${ARTIFACT_ROOT}"

printf 'scenario 01-web3-service-order passed\n'
printf 'artifacts: %s\n' "${ARTIFACT_ROOT}"
