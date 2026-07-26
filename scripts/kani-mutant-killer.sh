#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

expected_version="0.67.0"
if [[ -n "${CHIO_KANI_VERSION:-}" && "${CHIO_KANI_VERSION}" != "${expected_version}" ]]; then
  echo "kani-mutant-killer: CHIO_KANI_VERSION must remain ${expected_version}" >&2
  exit 2
fi
version="$(cargo kani --version 2>&1)"
version_pattern="${expected_version//./\\.}"
if [[ ! "${version}" =~ (^|[^0-9.])${version_pattern}([^0-9.]|$) ]]; then
  echo "kani-mutant-killer: expected Kani ${expected_version}, found ${version}" >&2
  exit 2
fi

priority_harnesses=(
  "kani_harnesses::scalar_helpers_match_reference_predicates"
  "kani_harnesses::reservation_ledger_matches_one_step_oracle"
  "kani_public_harnesses::verify_inclusion_step_equivalence"
  "kani_harnesses::time_window_classifier_matches_valid_predicate"
  "kani_harnesses::optional_caps_never_widen_parent_cap"
  "kani_harnesses::monetary_caps_never_widen_parent_cap"
  "kani_harnesses::dpop_required_missing_or_invalid_fails_closed"
  "kani_harnesses::dpop_replayed_nonce_never_admits"
  "kani_harnesses::dpop_freshness_rejects_future_beyond_skew"
  "kani_harnesses::budget_commit_never_increases_remaining_counters"
  "kani_harnesses::two_sequential_budget_commits_cannot_overspend"
  "kani_harnesses::guard_deny_or_error_dominates_pipeline"
  "kani_harnesses::revocation_snapshot_denies_presented_token_or_ancestor"
  "kani_harnesses::receipt_coupling_requires_every_field_match"
  "kani_harnesses::subset_helpers_preserve_parent_requirements"
  "kani_public_harnesses::public_normalized_scope_subset_rejects_widened_child"
  "kani_public_harnesses::public_normalized_scope_subset_rejects_value_widened_child"
  "kani_public_harnesses::public_normalized_scope_subset_rejects_identity_mismatch"
  "kani_public_harnesses::public_resolve_matching_grants_rejects_out_of_scope_request"
  "kani_public_harnesses::public_resolve_matching_grants_preserves_wildcard_matching"
  "kani_public_harnesses::verify_scope_intersection_associative"
  "kani_public_harnesses::verify_revocation_admission_projection"
  "kani_public_harnesses::verify_delegation_chain_step"
  "kani_public_harnesses::verify_reservation_ledger_terminal_classification"
  "kani_public_harnesses::verify_reservation_ledger_conservation"
  "kani_public_harnesses::verify_budget_admission_projection"
  "kani_public_harnesses::verify_delegate_no_widen"
  "kani_public_harnesses::verify_oracle_inclusion_walk_parity"
)

# Kani sorts a multi-harness selection by source location. Run each priority
# harness separately so fail-fast follows the order above.
for harness in "${priority_harnesses[@]}"; do
  cargo kani -p chio-kernel-core --lib --default-unwind 8 \
    --no-unwinding-checks --exact --fail-fast --harness "${harness}"
done

exec bash scripts/check-kani-core.sh
