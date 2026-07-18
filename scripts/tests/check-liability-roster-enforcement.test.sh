#!/usr/bin/env bash
# Self-test for scripts/check-liability-roster-enforcement.sh.
#
# Tests: positive (all constructions in the choke-point with sufficient roster
# calls), false-green guard (no matches found), violation (construction outside
# the choke-point), and missing-roster-calls (fewer than 3 roster calls).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LINT="${REPO_ROOT}/scripts/check-liability-roster-enforcement.sh"

if [[ ! -x "${LINT}" ]]; then
  echo "FAIL: ${LINT} not found or not executable" >&2
  exit 1
fi

work="$(mktemp -d -t chio-liability-roster-enforcement-test-XXXXXX)"
trap 'rm -rf "${work}"' EXIT

CHOKE_POINT_REL="crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs"

make_choke_point() {
  local root="$1"
  local body="$2"
  mkdir -p "$(dirname "${root}/${CHOKE_POINT_REL}")"
  printf '%s\n' "${body}" > "${root}/${CHOKE_POINT_REL}"
}

BODY_VALID=$(cat <<'RS'
pub fn adjudicate() {
    validate_against_roster(&roster);
    let _a = LiabilityClaimAdjudicationArtifact { id: 1 };
    validate_against_roster(&roster);
    let _b = LiabilityClaimPayoutInstructionArtifact { id: 2 };
    validate_against_roster(&roster);
    let _c = LiabilityClaimSettlementInstructionArtifact { id: 3 };
}
RS
)

# Positive: all constructions in the choke-point, three roster calls.
make_choke_point "${work}/positive" "${BODY_VALID}"
positive_out=$(CHIO_LIABILITY_ROOT="${work}/positive" \
               CHIO_LIABILITY_LIB="${work}/positive/${CHOKE_POINT_REL}" \
               bash "${LINT}" 2>&1) && positive_status=0 || positive_status=$?

echo "positive: status=${positive_status} output=${positive_out}"
if [[ ${positive_status} -ne 0 ]]; then
  echo "FAIL: positive case should pass" >&2
  exit 1
fi

# False-green guard: zero constructions found must trip the guard.
mkdir -p "${work}/zero/crates/some-crate/src"
printf '// nothing here\n' > "${work}/zero/crates/some-crate/src/lib.rs"
make_choke_point "${work}/zero" '// no constructions'
zero_out=$(CHIO_LIABILITY_ROOT="${work}/zero" \
           CHIO_LIABILITY_LIB="${work}/zero/${CHOKE_POINT_REL}" \
           bash "${LINT}" 2>&1) && zero_status=0 || zero_status=$?

echo "zero-match (false-green guard): status=${zero_status} output=${zero_out}"
if [[ ${zero_status} -eq 0 ]]; then
  echo "FAIL: zero-match case should fail (false-green guard)" >&2
  exit 1
fi
if ! printf '%s' "${zero_out}" | grep -qF "FALSE-GREEN GUARD"; then
  echo "FAIL: zero-match should emit FALSE-GREEN GUARD" >&2
  echo "  got: ${zero_out}" >&2
  exit 1
fi

# Violation: construction in a file outside the choke-point.
make_choke_point "${work}/violation" "${BODY_VALID}"
mkdir -p "${work}/violation/crates/other-crate/src"
cat > "${work}/violation/crates/other-crate/src/lib.rs" <<'RS'
pub fn bad() {
    let _x = LiabilityClaimAdjudicationArtifact { id: 99 };
}
RS
violation_out=$(CHIO_LIABILITY_ROOT="${work}/violation" \
                CHIO_LIABILITY_LIB="${work}/violation/${CHOKE_POINT_REL}" \
                bash "${LINT}" 2>&1) && violation_status=0 || violation_status=$?

echo "violation: status=${violation_status} output=${violation_out}"
if [[ ${violation_status} -eq 0 ]]; then
  echo "FAIL: violation case should fail" >&2
  exit 1
fi
if ! printf '%s' "${violation_out}" | grep -qF "VIOLATION: liability value-path artifact constructed outside liability.rs"; then
  echo "FAIL: violation should emit VIOLATION message" >&2
  echo "  got: ${violation_out}" >&2
  exit 1
fi

# Missing roster calls: constructions present but fewer than 3 roster calls.
make_choke_point "${work}/roster" "$(cat <<'RS'
pub fn adjudicate() {
    validate_against_roster(&roster);
    let _a = LiabilityClaimAdjudicationArtifact { id: 1 };
    validate_against_roster(&roster);
    let _b = LiabilityClaimPayoutInstructionArtifact { id: 2 };
    let _c = LiabilityClaimSettlementInstructionArtifact { id: 3 };
}
RS
)"
roster_out=$(CHIO_LIABILITY_ROOT="${work}/roster" \
             CHIO_LIABILITY_LIB="${work}/roster/${CHOKE_POINT_REL}" \
             bash "${LINT}" 2>&1) && roster_status=0 || roster_status=$?

echo "missing-roster-calls: status=${roster_status} output=${roster_out}"
if [[ ${roster_status} -eq 0 ]]; then
  echo "FAIL: missing-roster-calls case should fail" >&2
  exit 1
fi
if ! printf '%s' "${roster_out}" | grep -qF "validate_against_roster calls in liability.rs"; then
  echo "FAIL: missing-roster-calls should emit roster violation message" >&2
  echo "  got: ${roster_out}" >&2
  exit 1
fi

# Confirm the script passes on the real repo.
bash "${LINT}"

echo "check-liability-roster-enforcement.test.sh: all cases passed"
