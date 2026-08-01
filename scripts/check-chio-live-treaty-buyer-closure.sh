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
  "--matrix-only")
    MODE="matrix-only"
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
    echo "usage: check-chio-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--matrix-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chio-live-treaty-buyer-closure.sh [--schema-only|--negative-only|--matrix-only|--runtime-only|--dsse-only|--lineage-only|--proof-only|--buyer-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
negative_fixture="${CHIO_TREATY_NEGATIVE_FIXTURE:-$repo_root/examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json}"

run_cargo_test_filter() {
  local package="$1"
  local filter="$2"
  shift 2
  local release_profile=false
  case "${CHIO_TEST_PROFILE:-debug}" in
    "debug")
      ;;
    "release")
      release_profile=true
      ;;
    *)
      echo "CHIO_TEST_PROFILE must be 'debug' or 'release'" >&2
      return 2
      ;;
  esac
  local output
  if [[ "$release_profile" == true ]]; then
    output="$(cargo test --release -p "$package" "$filter" "$@" 2>&1)" || {
      printf '%s\n' "$output"
      return 1
    }
  elif ! output="$(cargo test -p "$package" "$filter" "$@" 2>&1)"; then
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

run_matrix_test_and_verify_code() {
  local package="$1"
  local target_kind="$2"
  local target_name="$3"
  local test_filter="$4"
  local expected_code="$5"
  local output

  case "$target_kind" in
    "lib")
      if ! output="$(
        CHIO_THREAT_MATRIX_EMIT_CODE=1 \
          run_cargo_test_filter "$package" "$test_filter" --lib -- --nocapture 2>&1
      )"; then
        printf '%s\n' "$output"
        return 1
      fi
      ;;
    "integration")
      if ! output="$(
        CHIO_THREAT_MATRIX_EMIT_CODE=1 \
          run_cargo_test_filter "$package" "$test_filter" --test "$target_name" -- --nocapture 2>&1
      )"; then
        printf '%s\n' "$output"
        return 1
      fi
      ;;
    *)
      echo "unsupported target kind '$target_kind'" >&2
      return 1
      ;;
  esac

  printf '%s\n' "$output"
  local observed_codes
  observed_codes="$({
    grep -oE 'CHIO_THREAT_MATRIX_CODE=[a-z0-9_.-]+' <<<"$output" \
      | cut -d= -f2
  } || true)"
  local observed_count
  observed_count="$(awk 'NF { count += 1 } END { print count + 0 }' <<<"$observed_codes")"
  if [[ "$observed_count" -ne 1 ]]; then
    printf 'expected exactly one machine-readable failure code from %s; observed %d\n' \
      "$test_filter" "$observed_count" >&2
    return 1
  fi
  if [[ "$observed_codes" != "$expected_code" ]]; then
    printf 'failure code mismatch for %s: expected %s, observed %s\n' \
      "$test_filter" "$expected_code" "$observed_codes" >&2
    return 1
  fi
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

run_declared_threat_matrix() {
  local rows
  rows="$(
    python - "$negative_fixture" <<'PY'
import json
import sys

fixture_path = sys.argv[1]
with open(fixture_path, encoding="utf-8") as fixture_file:
    fixture = json.load(fixture_file)

cases = fixture.get("cases", [])
assumptions = fixture.get("assumptions", [])
if len(cases) < 20:
    raise SystemExit(f"threat matrix has {len(cases)} executable cases; expected at least 20")
if not assumptions:
    raise SystemExit("threat matrix must state its non-testable assumptions")

threat_ids = [case.get("threatId") for case in cases]
case_ids = [case.get("caseId") for case in cases]
if len(set(threat_ids)) != len(threat_ids):
    raise SystemExit("threat matrix contains duplicate threatId values")
if len(set(case_ids)) != len(case_ids):
    raise SystemExit("threat matrix contains duplicate caseId values")

allowed_phases = {"pre_dispatch", "post_dispatch_review"}
allowed_target_kinds = {"lib", "integration"}
for case in cases:
    if case.get("phase") not in allowed_phases:
        raise SystemExit(f"{case.get('threatId')}: invalid phase")
    if case.get("targetKind") not in allowed_target_kinds:
        raise SystemExit(f"{case.get('threatId')}: invalid targetKind")
    if case.get("dispatchExpected") is not False:
        raise SystemExit(f"{case.get('threatId')}: negative case must deny dispatch")
    fields = (
        case["threatId"],
        case["package"],
        case["targetKind"],
        case["targetName"],
        case["testFilter"],
        case["expectedCode"],
        case["phase"],
    )
    if any("\t" in field or "\n" in field for field in fields):
        raise SystemExit(f"{case.get('threatId')}: matrix fields must be single-line")
    print("\t".join(fields))
PY
  )"

  local count=0
  local threat_id
  local package
  local target_kind
  local target_name
  local test_filter
  local expected_code
  local phase
  while IFS=$'\t' read -r threat_id package target_kind target_name test_filter expected_code phase; do
    [[ -n "$threat_id" ]] || continue
    printf 'running %s (%s, expected %s): %s\n' \
      "$threat_id" "$phase" "$expected_code" "$test_filter"
    if ! run_matrix_test_and_verify_code \
      "$package" "$target_kind" "$target_name" "$test_filter" "$expected_code"; then
      echo "$threat_id: threat-matrix diagnostic verification failed" >&2
      return 1
    fi
    count=$((count + 1))
  done <<<"$rows"

  local assumption_count
  assumption_count="$(
    python - "$negative_fixture" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fixture_file:
    print(len(json.load(fixture_file)["assumptions"]))
PY
  )"
  printf 'bilateral threat matrix passed: %d executable cases; %d explicit non-testable assumption(s)\n' \
    "$count" "$assumption_count"
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
  run_declared_threat_matrix
}

case "$MODE" in
  "schema-only")
    run_schema
    ;;
  "negative-only")
    run_negative
    ;;
  "matrix-only")
    run_declared_threat_matrix
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
