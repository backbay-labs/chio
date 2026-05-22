#!/usr/bin/env bash
set -euo pipefail

MODE="all"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    shift
    ;;
  "--negative-only")
    MODE="negative-only"
    shift
    ;;
  *)
    echo "usage: check-chio-runtime-policy.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-runtime-policy.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"

CHIO_RUNTIME_SCHEMA_DIR="$repo_root/spec/schemas/chio-runtime/v1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat >"$tmpdir/runtime-peer-weights.json" <<'JSON'
{
  "body": {
    "schema": "chio.runtime.peer-weights.v1",
    "verifierId": "did:chio:buyer-verifier",
    "keyId": "verifier-key-1",
    "reputationEpoch": 7,
    "issuedAtUnixMs": 1800000000000,
    "expiresAtUnixMs": 1800003600000,
    "weights": [
      {
        "peerKernelId": "kernel.vendor-b",
        "weight": 1.0
      }
    ]
  },
  "signerKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "signature": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
JSON

cat >"$tmpdir/runtime-policy.json" <<'JSON'
{
  "body": {
    "schema": "chio.runtime.pheromone-policy.v1",
    "policyId": "policy-runtime-risk",
    "verifierId": "did:chio:buyer-verifier",
    "keyId": "verifier-key-1",
    "policyVersion": 1,
    "mode": "enforce",
    "issuedAtUnixMs": 1800000000000,
    "expiresAtUnixMs": 1800003600000,
    "allowedReputationEpochs": [7],
    "maxQueryReportAgeMs": 60000,
    "minDistinctOriginPairs": 1,
    "runtimeTrustBundleSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "peerWeightsSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "rules": [
      {
        "ruleId": "deny-high-runtime-risk",
        "subjectClass": "workflow.destructive_step",
        "subjectClassNamespace": "chio.runtime",
        "actionClassId": "*",
        "direction": "deny_if_at_or_above",
        "thresholdTotalStrength": 0.75,
        "effect": "deny"
      }
    ]
  },
  "signerKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "signature": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
JSON

cat >"$tmpdir/runtime-policy-decision.json" <<'JSON'
{
  "schema": "chio.runtime.pheromone-policy-decision.v1",
  "enforced": true,
  "decision": "deny",
  "policyId": "policy-runtime-risk",
  "policySha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "queryReportSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "peerWeightsSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "reputationEpoch": 7,
  "matchedRuleId": "deny-high-runtime-risk",
  "reasonCode": "runtime_pheromone_policy_deny"
}
JSON

cat >"$tmpdir/runtime-trust-floor-state.json" <<'JSON'
{
  "schema": "chio.runtime.trust-floor-state.v1",
  "entries": [
    {
      "verifierId": "did:chio:buyer-verifier",
      "keyId": "verifier-key-1",
      "highestVersion": 2,
      "latestBundleSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "latestRevocationCheckpointSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ]
}
JSON

run_spec_validate() {
  if [[ -n "${CHIO_SPEC_VALIDATE_BIN:-}" ]]; then
    "$CHIO_SPEC_VALIDATE_BIN" "$@"
  else
    cargo run -p chio-spec-validate -- "$@"
  fi
}

validate_schema() {
  run_spec_validate "$1" "$2" >/dev/null
}

run_cargo_test_filter() {
  local package="$1"
  local filter="$2"
  shift 2
  local output
  if ! output="$(cargo test -p "$package" "$filter" "$@" 2>&1)"; then
    printf '%s\n' "$output"
    return 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed;' <<<"$output"; then
    echo "cargo test filter '$filter' in $package matched zero tests" >&2
    return 1
  fi
}

run_schema_checks() {
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/peer-weights.schema.json" \
    "$tmpdir/runtime-peer-weights.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/pheromone-policy.schema.json" \
    "$tmpdir/runtime-policy.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/pheromone-policy-decision.schema.json" \
    "$tmpdir/runtime-policy-decision.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/trust-floor-state.schema.json" \
    "$tmpdir/runtime-trust-floor-state.json"
}

run_runtime_tests() {
  run_cargo_test_filter chio-runtime-core \
    chio_native_runtime_policy_material_emits_chio_decision \
    --test runtime_pheromone_policy
  run_cargo_test_filter chio-runtime-core \
    runtime_trust_floor \
    --test runtime_trust
  run_cargo_test_filter chio-cli \
    chio_runtime \
    --bin chio
}

case "$MODE" in
  "schema-only")
    run_schema_checks
    ;;
  "negative-only")
    run_runtime_tests
    ;;
  "all")
    run_schema_checks
    run_runtime_tests
    bash "$repo_root/scripts/check-chio-runtime-spine.sh"
    ;;
esac
