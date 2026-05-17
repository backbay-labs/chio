#!/usr/bin/env bash
set -euo pipefail

MODE="full"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    ;;
  "--negative-only")
    MODE="negative-only"
    ;;
  "--runtime-only")
    MODE="runtime-only"
    ;;
  "--packet-only")
    MODE="packet-only"
    ;;
  "--explain-only")
    MODE="explain-only"
    ;;
  *)
    echo "usage: check-chiodos-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chiodos-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
schema_dir="$repo_root/spec/schemas/chiodos/v1"
fixture_dir="$repo_root/examples/chiodos-3vendor/fixtures"
tmpdir="$(mktemp -d)"
trap 'if [[ "${CHIODOS_KEEP_TMP:-0}" == "1" ]]; then echo "kept tmpdir: $tmpdir" >&2; else rm -rf "$tmpdir"; fi' EXIT

run_chio() {
  if [[ -n "${CHIO_BIN:-}" ]]; then
    "$CHIO_BIN" "$@"
  else
    cargo run -p chio-cli -- "$@"
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

run_strict_dsse_negative_tests() {
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_missing_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_non_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available --test runtime_buyer_review
  cargo test -p chio-federation strict_chiodos_treaty_review_binds_live_material --lib
}

runtime_spine_tmpdir=""

run_runtime_spine_with_artifacts() {
  local mode_arg="${1:-}"
  local log_file="$tmpdir/runtime-spine.log"
  local keep_tmp="${CHIODOS_KEEP_TMP:-0}"
  if [[ -n "$mode_arg" ]]; then
    CHIODOS_KEEP_TMP=1 bash "$repo_root/scripts/check-chiodos-runtime-spine.sh" "$mode_arg" >"$log_file" 2>&1
  else
    CHIODOS_KEEP_TMP=1 bash "$repo_root/scripts/check-chiodos-runtime-spine.sh" >"$log_file" 2>&1
  fi
  cat "$log_file"
  runtime_spine_tmpdir="$(sed -n 's/^kept tmpdir: //p' "$log_file" | tail -n 1)"
  if [[ -z "$runtime_spine_tmpdir" || ! -d "$runtime_spine_tmpdir" ]]; then
    echo "runtime spine did not expose kept artifacts" >&2
    exit 1
  fi
  if [[ "$keep_tmp" != "1" ]]; then
    trap 'rm -rf "$tmpdir" "$runtime_spine_tmpdir"' EXIT
  fi
}

if [[ "$MODE" == "packet-only" ]]; then
  run_runtime_spine_with_artifacts
  exit 0
fi

if [[ "$MODE" == "explain-only" ]]; then
  run_runtime_spine_with_artifacts
  run_chio chiodos buyer explain \
    --report "$runtime_spine_tmpdir/loopback-out/buyer-review-report.json" \
    --format text \
    --out "$tmpdir/review.txt"
  grep -q "Accepted: true" "$tmpdir/review.txt"
  grep -q "Verification state: strict_verified" "$tmpdir/review.txt"
  exit 0
fi

if [[ "$MODE" == "negative-only" ]]; then
  run_runtime_spine_with_artifacts --negative-only
  run_strict_dsse_negative_tests
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_buyer_review
  exit 0
fi

if [[ "$MODE" == "full" ]]; then
  bash "$0" --schema-only
  bash "$0" --packet-only
  bash "$0" --explain-only
  bash "$0" --negative-only
  exit 0
fi

if [[ "$MODE" == "runtime-only" ]]; then
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime receipt_lineage_bundle --test runtime_buyer_review
  exit 0
fi

if [[ "$MODE" == "schema-only" ]]; then
  run_runtime_spine_with_artifacts
  validate_schema "$schema_dir/receipt-lineage-bundle.schema.json" \
    "$runtime_spine_tmpdir/loopback-out/receipt-lineage-bundle.json"
  validate_schema "$schema_dir/proof-package.schema.json" \
    "$runtime_spine_tmpdir/loopback-out/proof-package.json"
  validate_schema "$schema_dir/buyer-attestation-review-package.schema.json" \
    "$runtime_spine_tmpdir/loopback-out/buyer-review-package.json"
  validate_schema "$schema_dir/treaty-runtime-negative-fixture-corpus.schema.json" \
    "$fixture_dir/treaty-runtime-negative-corpus.json"
  exit 0
fi
