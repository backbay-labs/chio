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
  "--dsse-only")
    MODE="dsse-only"
    ;;
  "--lineage-only")
    MODE="lineage-only"
    ;;
  "--proof-only")
    MODE="proof-only"
    ;;
  "--buyer-only")
    MODE="buyer-only"
    ;;
  *)
    echo "usage: check-chio-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chio-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
  if grep -Eq 'test result: ok\. 0 passed;' <<<"$output"; then
    echo "cargo test filter '$filter' in $package matched zero tests" >&2
    return 1
  fi
}

run_schema() {
  bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --schema-only
}

run_runtime_admission_test() {
  run_cargo_test_filter chio-runtime-core "$1" --test runtime_admission
}

run_runtime_treaty_test() {
  run_cargo_test_filter chio-runtime-core "$1" --test runtime_treaty
}

run_runtime_buyer_review_test() {
  run_cargo_test_filter chio-runtime-core "$1" --test runtime_buyer_review
}

run_runtime_kernel_hook_test() {
  run_cargo_test_filter chio-runtime-core "$1" --test runtime_kernel_hook
}

run_runtime_store_test() {
  run_cargo_test_filter chio-runtime-core "$1" --test runtime_store
}

run_runtime_negative_matrix() {
  run_runtime_kernel_hook_test kernel_hook_denies_cross_boundary_request_when_treaty_store_evidence_missing
  run_runtime_admission_test treaty_runtime_hook_denies_missing_lineage_evidence_ref
  run_runtime_admission_test treaty_runtime_hook_denies_missing_bilateral_invocation_evidence_ref
  run_runtime_admission_test treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch
  run_runtime_admission_test treaty_runtime_hook_denies_stale_continuation_before_dispatch
  run_runtime_admission_test treaty_runtime_hook_denies_replayed_continuation
  run_runtime_admission_test treaty_runtime_hook_denies_request_smuggled_trust_root
  run_runtime_admission_test treaty_runtime_hook_denies_request_smuggled_dynamic_trust
  run_runtime_treaty_test treaty_cross_boundary_admission_rejects_unverified_or_forged_intersection
}

run_runtime() {
  run_runtime_store_test sqlite_runtime_orchestration_store_persists_treaty_evidence_idempotently
  run_runtime_negative_matrix
}

run_dsse() {
  run_cargo_test_filter chio-federation strict_chio_signer_binds_treaty_runtime_refs --lib
}

run_lineage() {
  run_cargo_test_filter chio-runtime-core receipt_lineage_bundle --test runtime_buyer_review
}

run_proof() {
  bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
  run_cargo_test_filter chio-runtime-core runtime_orchestration_evidence_binding_accepts_consistent_artifacts --test runtime_orchestration
  run_cargo_test_filter chio-runtime-core runtime_orchestration_evidence_load_rejects_manifest_artifact_hash_mismatch --test runtime_orchestration
}

run_buyer() {
  bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
  run_cargo_test_filter chio-runtime-core buyer_review --test runtime_buyer_review
  run_cargo_test_filter chio-cli chio_attest_buyer --bin chio
}

run_negative() {
  bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --negative-only
  run_runtime_negative_matrix
  run_runtime_buyer_review_test buyer_review_package_rejects_missing_strict_dsse_envelope
  run_runtime_buyer_review_test buyer_review_package_rejects_non_strict_dsse_envelope
}

case "$MODE" in
  "schema-only")
    run_schema
    ;;
  "negative-only")
    run_negative
    ;;
  "runtime-only")
    run_runtime
    ;;
  "dsse-only")
    run_dsse
    ;;
  "lineage-only")
    run_lineage
    ;;
  "proof-only")
    run_proof
    ;;
  "buyer-only")
    run_buyer
    ;;
  "full")
    run_schema
    run_runtime
    run_dsse
    run_lineage
    run_proof
    run_buyer
    run_negative
    ;;
esac
