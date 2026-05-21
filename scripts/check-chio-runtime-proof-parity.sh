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
  "--regenerate-only")
    MODE="regenerate-only"
    shift
    ;;
  "--parity-only")
    MODE="parity-only"
    shift
    ;;
  "--fixtures-only")
    MODE="fixtures-only"
    shift
    ;;
  *)
    echo "usage: check-chio-runtime-proof-parity.sh [--schema-only|--negative-only|--regenerate-only|--parity-only|--fixtures-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-runtime-proof-parity.sh [--schema-only|--negative-only|--regenerate-only|--parity-only|--fixtures-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
LEGACY_SCHEMA_DIR="$repo_root/spec/schemas/chiodos/v1"
CHIO_FEDERATION_SCHEMA_DIR="$repo_root/spec/schemas/chio-federation/v1"

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

run_historical_fixture_tests() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  if ! cargo run -p chiodos-three-vendor-example --bin generate-chio-three-vendor-fixtures -- \
    --out-dir "$tmpdir/fixtures"; then
    rm -rf "$tmpdir"
    return 1
  fi
  validate_schema "$LEGACY_SCHEMA_DIR/proof-package.schema.json" \
    "$tmpdir/fixtures/buyer-auditor-proof-package.json"
  validate_schema "$LEGACY_SCHEMA_DIR/selective-disclosure-proof.schema.json" \
    "$tmpdir/fixtures/selective-disclosure-proof.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/verifier-trust-bundle.schema.json" \
    "$tmpdir/fixtures/verifier-trust-bundle.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/verification-context.schema.json" \
    "$tmpdir/fixtures/verification-context.json"
  cargo run -p chio-cli --bin chio -- attest legacy chiodos-v1 verify \
    --package "$tmpdir/fixtures/buyer-auditor-proof-package.json" \
    --trust-bundle "$tmpdir/fixtures/verifier-trust-bundle.json" \
    --context "$tmpdir/fixtures/verification-context.json" \
    --report "$tmpdir/fixtures/verifier-report-rerun.json"
  validate_schema "$LEGACY_SCHEMA_DIR/verifier-report.schema.json" \
    "$tmpdir/fixtures/verifier-report-rerun.json"
  rm -rf "$tmpdir"
}

case "$MODE" in
  "schema-only")
    bash "$repo_root/scripts/check-chio-runtime-spine.sh" --schema-only
    ;;
  "negative-only")
    bash "$repo_root/scripts/check-chio-runtime-spine.sh" --negative-only
    ;;
  "regenerate-only")
    bash "$repo_root/scripts/check-chio-runtime-spine.sh"
    ;;
  "parity-only")
    run_cargo_test_filter chio-chiodos-runtime runtime_proof_regeneration
    bash "$repo_root/scripts/check-chio-runtime-spine.sh" --schema-only
    ;;
  "fixtures-only")
    run_historical_fixture_tests
    ;;
  "all")
    run_cargo_test_filter chio-chiodos-runtime runtime_workflow_report
    run_cargo_test_filter chio-chiodos-runtime proof_regeneration_report
    run_cargo_test_filter chio-chiodos-runtime runtime_proof_regeneration
    run_historical_fixture_tests
    run_cargo_test_filter chio-cli chio_runtime --bin chio
    bash "$repo_root/scripts/check-chio-runtime-spine.sh"
    ;;
esac
