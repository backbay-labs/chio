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
    echo "usage: check-chio-runtime-spine.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-runtime-spine.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"

CHIO_RUNTIME_SCHEMA_DIR="$repo_root/spec/schemas/chio-runtime/v1"
CHIO_ATTEST_SCHEMA_DIR="$repo_root/spec/schemas/chio-attest/v1"
LEGACY_SCHEMA_DIR="$repo_root/spec/schemas/chiodos/v1"
RUNTIME_SPINE_FIXTURE_DIR="$repo_root/examples/chio-3vendor/fixtures/runtime-spine"

tmpdir="$(mktemp -d)"
trap 'if [[ "${CHIO_KEEP_TMP:-0}" == "1" ]]; then echo "kept tmpdir: $tmpdir" >&2; else rm -rf "$tmpdir"; fi' EXIT

run_chio() {
  if [[ -n "${CHIO_BIN:-}" ]]; then
    "$CHIO_BIN" "$@"
  else
    cargo run -p chio-cli --bin chio -- "$@"
  fi
}

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

copy_runtime_spine_fixture() {
  local name="$1"
  cp "$RUNTIME_SPINE_FIXTURE_DIR/$name" "$tmpdir/$name"
}

prepare_runtime_spine_inputs() {
  copy_runtime_spine_fixture "profile.json"
  copy_runtime_spine_fixture "request.json"
  copy_runtime_spine_fixture "bundle.json"
  copy_runtime_spine_fixture "verifier.seed"
  copy_runtime_spine_fixture "runtime-trust-body.json"
  copy_runtime_spine_fixture "pheromone-query-report.json"
  copy_runtime_spine_fixture "runtime-peer-weights-body.json"
  copy_runtime_spine_fixture "runtime-policy-body.json"
}

run_schema_checks() {
  bash "$repo_root/scripts/check-chio-runtime-spine-fixtures.sh"
  validate_schema "$LEGACY_SCHEMA_DIR/proof-package.schema.json" \
    "$repo_root/examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
  validate_schema "$LEGACY_SCHEMA_DIR/verifier-report.schema.json" \
    "$repo_root/examples/chio-3vendor/fixtures/verifier-report.json"
}

run_positive_checks() {
  prepare_runtime_spine_inputs
  run_chio runtime sign-trust-input \
    --body "$tmpdir/runtime-trust-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-trust-input.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/verifier-trust-bundle.schema.json" \
    "$tmpdir/runtime-trust-input.json"
  python3 - "$tmpdir/runtime-trust-input.json" "$tmpdir/trusted-verifiers.json" <<'PY'
import json
import sys

signed = json.load(open(sys.argv[1], "r", encoding="utf-8"))
trusted = {
    "schema": "chio.runtime.trusted-verifiers.v1",
    "verifierKeys": [
        {
            "verifierId": signed["body"]["verifierId"],
            "keyId": signed["body"]["keyId"],
            "publicKey": signed["signerKey"],
            "validFromUnixMs": 1800000000000,
            "validUntilUnixMs": 1800003600000,
            "status": "active",
        }
    ],
}
json.dump(trusted, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/trusted-verifiers.schema.json" \
    "$tmpdir/trusted-verifiers.json"
  run_chio runtime peer-weights hash \
    --body "$tmpdir/runtime-peer-weights-body.json" \
    --out "$tmpdir/runtime-peer-weights.sha256"
  python3 - "$tmpdir/runtime-policy-body.json" "$tmpdir/runtime-peer-weights.sha256" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
peer_hash = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
body = path.read_text(encoding="utf-8").replace("PEER_WEIGHTS_SHA256", peer_hash)
path.write_text(body, encoding="utf-8")
PY
  run_chio runtime peer-weights sign \
    --body "$tmpdir/runtime-peer-weights-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-peer-weights.json"
  run_chio runtime policy sign \
    --body "$tmpdir/runtime-policy-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-policy.json"
  run_chio runtime pheromone sign-query-report \
    --body "$tmpdir/pheromone-query-report.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/pheromone-query-report.signed.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/peer-weights.schema.json" \
    "$tmpdir/runtime-peer-weights.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/pheromone-policy.schema.json" \
    "$tmpdir/runtime-policy.json"
  run_chio runtime admit \
    --request "$tmpdir/request.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/admission-store.json" \
    --trust-floor-state "$tmpdir/runtime-trust-floor-live.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/admission-report.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/admission-report.schema.json" \
    "$tmpdir/admission-report.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/admission-store.schema.json" \
    "$tmpdir/admission-store.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/trust-floor-state.schema.json" \
    "$tmpdir/runtime-trust-floor-live.json"
  python3 - "$tmpdir/admission-report.json" \
    "$tmpdir/admission-store.json" \
    "$tmpdir/runtime-trust-floor-live.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
admission_store = json.load(open(sys.argv[2], "r", encoding="utf-8"))
trust_floor_state = json.load(open(sys.argv[3], "r", encoding="utf-8"))

if report.get("schema") != "chio.runtime.admission-report.v1":
    raise SystemExit("runtime admission report schema mismatch")
if not report.get("accepted"):
    raise SystemExit("runtime admission report was not accepted")
if admission_store.get("schema") != "chio.runtime.admission-store.v1":
    raise SystemExit("runtime admission store schema mismatch")
if len(admission_store.get("bundles", [])) != 1:
    raise SystemExit("runtime admission store did not retain admission bundle")
if len(admission_store.get("consumedLeaseIds", [])) != 1:
    raise SystemExit("runtime admission store did not retain lease replay fence")
if admission_store.get("trustFloors"):
    raise SystemExit("runtime admission store leaked separate trust-floor state")
if trust_floor_state.get("schema") != "chio.runtime.trust-floor-state.v1":
    raise SystemExit("runtime trust-floor state schema mismatch")
if len(trust_floor_state.get("entries", [])) != 1:
    raise SystemExit("runtime trust-floor state did not persist verifier floor")
metadata = report.get("receiptMetadata", {}).get("chio_runtime", {})
if report.get("receiptMetadata", {}).get("chiodos_runtime") is not None:
    raise SystemExit("Chio admission report used legacy runtime metadata key")
if metadata.get("admission_id") != "adm-live-1":
    raise SystemExit("runtime admission metadata did not bind admission id")
if not metadata.get("destructive"):
    raise SystemExit("runtime admission metadata did not record destructive step")
advisory = report.get("pheromoneAdvisory")
if not advisory or not advisory.get("observeOnly"):
    raise SystemExit("runtime admission report did not record observe-only pheromone advisory")
if metadata.get("pheromone_advisory", {}).get("observeOnly") is not True:
    raise SystemExit("runtime admission metadata did not preserve observe-only pheromone advisory")
PY
  bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
}

run_negative_checks() {
  if run_chio runtime admit \
    --request "$tmpdir/request.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/admission-store.json" \
    --trust-floor-state "$tmpdir/runtime-trust-floor-live.json" \
    --now-unix-ms 1800000002000 \
    --report "$tmpdir/replay-report.json"; then
    echo "expected destructive lease replay to fail" >&2
    exit 1
  fi
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/admission-report.schema.json" \
    "$tmpdir/replay-report.json"
  python3 - "$tmpdir/replay-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
if report.get("accepted"):
    raise SystemExit("replay report unexpectedly accepted")
if report.get("failureCode") != "destructive_lease_replay":
    raise SystemExit(f"wrong replay failure code: {report.get('failureCode')}")
if report.get("receiptMetadata", {}).get("chiodos_runtime") is not None:
    raise SystemExit("Chio replay report used legacy runtime metadata key")
PY

  python3 - "$tmpdir/request.json" "$tmpdir/request-mismatch.json" <<'PY'
import json
import sys

request = json.load(open(sys.argv[1], "r", encoding="utf-8"))
request["toolArgsSha256"] = "d" * 64
json.dump(request, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
  if run_chio runtime admit \
    --request "$tmpdir/request-mismatch.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/mismatch-store.json" \
    --trust-floor-state "$tmpdir/mismatch-trust-floor-live.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/mismatch-report.json"; then
    echo "expected request binding mismatch to fail" >&2
    exit 1
  fi
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/admission-report.schema.json" \
    "$tmpdir/mismatch-report.json"
  python3 - "$tmpdir/mismatch-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
if report.get("failureCode") != "request_binding_mismatch":
    raise SystemExit(f"wrong mismatch failure code: {report.get('failureCode')}")
if report.get("receiptMetadata", {}).get("chiodos_runtime") is not None:
    raise SystemExit("Chio mismatch report used legacy runtime metadata key")
PY
}

case "$MODE" in
  "schema-only")
    run_schema_checks
    ;;
  "negative-only")
    run_positive_checks
    run_negative_checks
    ;;
  "all")
    run_schema_checks
    cargo test -p chio-chiodos-runtime
    run_cargo_test_filter chio-kernel chiodos_runtime
    run_positive_checks
    run_negative_checks
    ;;
esac
