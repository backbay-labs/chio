#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
    echo "usage: check-chiodos-runtime-policy.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-runtime-policy.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chiodos/v1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat >"$tmpdir/runtime-peer-weights.json" <<'JSON'
{
  "body": {
    "schema": "chio.chiodos.runtime-peer-weights.v1",
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
    "schema": "chio.chiodos.runtime-pheromone-policy.v1",
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
        "subjectClassNamespace": "chiodos.runtime",
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
  "schema": "chio.chiodos.runtime-pheromone-policy-decision.v1",
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
  "schema": "chio.chiodos.runtime-trust-floor-state.v1",
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

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

run_schema_checks() {
  validate_schema "$SCHEMA_DIR/runtime-peer-weights.schema.json" "$tmpdir/runtime-peer-weights.json"
  validate_schema "$SCHEMA_DIR/runtime-pheromone-policy.schema.json" "$tmpdir/runtime-policy.json"
  validate_schema "$SCHEMA_DIR/runtime-pheromone-policy-decision.schema.json" \
    "$tmpdir/runtime-policy-decision.json"
  validate_schema "$SCHEMA_DIR/runtime-trust-floor-state.schema.json" \
    "$tmpdir/runtime-trust-floor-state.json"
}

run_runtime_tests() {
  cargo test -p chio-chiodos-runtime signed_runtime_pheromone_policy
  cargo test -p chio-chiodos-runtime runtime_trust_floor
  cargo test -p chio-cli --bin chio chiodos_runtime
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
    bash "$ROOT/scripts/check-chiodos-runtime-spine.sh"
    ;;
esac
