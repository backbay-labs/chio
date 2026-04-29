#!/usr/bin/env bash
# check-proptest-coverage.sh - Gate the eighteen named capability-algebra invariants.
#
# Confirms every named proptest function is still present in the corresponding
# test file. A missing or renamed function is a regression: the rename loses
# load-bearing property coverage even when the file still compiles and the
# remaining tests pass. The CI `verify` lane wires this gate as required.
#
# Usage:
#   scripts/check-proptest-coverage.sh
#   exit 0 -> all eighteen names found
#   exit 1 -> at least one name missing; offending names printed to stderr
#
# Requires: bash, grep

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

err() { printf '%s\n' "$*" >&2; }
declare -a missing=()

# Pairs of "<test file relative path>::<test fn name>".
INVARIANTS=(
    "crates/chio-core-types/tests/property_capability_algebra.rs::scope_subset_reflexive"
    "crates/chio-core-types/tests/property_capability_algebra.rs::scope_subset_transitive_normalized"
    "crates/chio-core-types/tests/property_capability_algebra.rs::tool_grant_subset_implies_scope_subset"
    "crates/chio-core-types/tests/property_capability_algebra.rs::validate_attenuation_monotonic_under_chain_extension"
    "crates/chio-core-types/tests/property_capability_algebra.rs::delegation_depth_bounded_by_root"
    "crates/chio-kernel-core/tests/property_evaluate.rs::evaluate_deny_when_capability_revoked"
    "crates/chio-kernel-core/tests/property_evaluate.rs::evaluate_allow_implies_grant_subset_of_request"
    "crates/chio-kernel-core/tests/property_evaluate.rs::resolve_matching_grants_order_independent"
    "crates/chio-kernel-core/tests/property_evaluate.rs::intersection_distributes_over_grant_union"
    "crates/chio-kernel-core/tests/property_evaluate.rs::wildcard_subsumes_specific_under_intersection"
    "crates/chio-credentials/tests/property_passport.rs::passport_verify_idempotent_on_well_formed"
    "crates/chio-credentials/tests/property_passport.rs::revoked_lifecycle_entry_never_verifies"
    "crates/chio-credentials/tests/property_passport.rs::lifecycle_state_transitions_monotone"
    "crates/chio-credentials/tests/property_passport.rs::passport_signature_breaks_under_any_subject_mutation"
    "crates/chio-policy/tests/property_evaluate.rs::merge_associative_for_extends"
    "crates/chio-policy/tests/property_evaluate.rs::deny_overrides_warn_and_allow"
    "crates/chio-policy/tests/property_evaluate.rs::decision_deterministic_for_fixed_input"
    "crates/chio-policy/tests/property_evaluate.rs::empty_extends_chain_is_identity_under_merge"
)

for entry in "${INVARIANTS[@]}"; do
    file="${entry%%::*}"
    name="${entry#*::}"
    if [[ ! -f "${file}" ]]; then
        missing+=("MISSING FILE: ${file} (expected to contain ${name})")
        continue
    fi
    # Match either `fn <name>` (free fn) or `name(...)` immediately inside
    # a `proptest!` block (where the function header is unconventional).
    if ! grep -qE "(\bfn[[:space:]]+${name}\b|^[[:space:]]*${name}\b)" "${file}"; then
        missing+=("MISSING NAME: ${file}::${name}")
    fi
done

expected=${#INVARIANTS[@]}
found=$(( expected - ${#missing[@]} ))
printf 'check-proptest-coverage: %d of %d named invariants present\n' "${found}" "${expected}"

if (( ${#missing[@]} > 0 )); then
    err ""
    err "FAIL: ${#missing[@]} invariant name(s) missing or renamed:"
    for m in "${missing[@]}"; do
        err "  ${m}"
    done
    err ""
    err "If a rename is genuinely needed, edit the truth list in this script in the"
    err "same PR; do not silently rename the test fn."
    exit 1
fi
exit 0
