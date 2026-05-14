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
    echo "usage: check-chiodos-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chiodos-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_schema() {
  bash "$repo_root/scripts/check-chiodos-treaty-buyer-hero-loop.sh" --schema-only
}

run_runtime_admission_test() {
  cargo test -p chio-chiodos-runtime "$1" --test runtime_admission
}

run_runtime_negative_matrix() {
  run_runtime_admission_test kernel_hook_denies_cross_boundary_request_when_treaty_store_evidence_missing
  run_runtime_admission_test treaty_runtime_hook_denies_missing_lineage_evidence_ref
  run_runtime_admission_test treaty_runtime_hook_denies_missing_bilateral_invocation_evidence_ref
  run_runtime_admission_test treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch
  run_runtime_admission_test treaty_runtime_hook_denies_stale_continuation_before_dispatch
  run_runtime_admission_test treaty_runtime_hook_denies_replayed_continuation
  run_runtime_admission_test treaty_runtime_hook_denies_request_smuggled_trust_root
  run_runtime_admission_test treaty_runtime_hook_denies_request_smuggled_dynamic_trust
  run_runtime_admission_test treaty_cross_boundary_admission_rejects_unverified_or_forged_intersection
}

run_runtime() {
  run_runtime_admission_test sqlite_runtime_orchestration_store_persists_treaty_evidence_idempotently
  run_runtime_negative_matrix
}

run_dsse() {
  cargo test -p chio-federation strict_chiodos_signer_binds_treaty_runtime_refs --lib
}

run_lineage() {
  cargo test -p chio-chiodos-runtime receipt_lineage_bundle --test runtime_admission
}

run_proof() {
  bash "$repo_root/scripts/check-chiodos-runtime-spine.sh"
  cargo test -p chio-chiodos-runtime runtime_workflow_report --test runtime_admission
  cargo test -p chio-chiodos-runtime runtime_proof_regeneration --test runtime_admission
}

run_buyer() {
  bash "$repo_root/scripts/check-chiodos-treaty-buyer-hero-loop.sh" --packet-only
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission
  cargo test -p chio-cli --bin chio chiodos_buyer
}

run_negative() {
  bash "$repo_root/scripts/check-chiodos-treaty-buyer-hero-loop.sh" --negative-only
  run_runtime_negative_matrix
  run_runtime_admission_test buyer_review_package_rejects_missing_strict_dsse_envelope
  run_runtime_admission_test buyer_review_package_rejects_non_strict_dsse_envelope
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
