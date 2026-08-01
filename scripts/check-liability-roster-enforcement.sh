#!/usr/bin/env bash
set -euo pipefail

ROOT="${CHIO_LIABILITY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
LIB="${CHIO_LIABILITY_LIB:-${ROOT}/crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs}"

# 1) Every construction of these artifacts anywhere under crates/ must live in
#    liability.rs (the known choke-point file). Any other site is a violation.
violations=0
found_total=0
while IFS= read -r hit; do
  found_total=$((found_total + 1))
  file="${hit%%:*}"
  if [[ "${file}" != "${LIB}" ]]; then
    echo "VIOLATION: liability value-path artifact constructed outside liability.rs: ${hit}"
    violations=$((violations + 1))
  fi
done < <(grep -rn --include='*.rs' -F \
  -e "LiabilityClaimAdjudicationArtifact {" \
  -e "LiabilityClaimPayoutInstructionArtifact {" \
  -e "LiabilityClaimSettlementInstructionArtifact {" \
  "${ROOT}/crates" \
  | grep -v "/tests.rs:" \
  | grep -v "/tests/" \
  | grep -v ":[[:space:]]*pub struct " \
  | grep -v ":[[:space:]]*impl " \
  || true)

# 2) No false green: we must have actually found the known constructions.
if [[ "${found_total}" -eq 0 ]]; then
  echo "FALSE-GREEN GUARD: found 0 liability value-path constructions; grep is broken"
  exit 1
fi

# 3) liability.rs must call validate_against_roster at least three times
#    (one per value-path choke point).
roster_calls="$(grep -c "validate_against_roster" "${LIB}" || true)"
if [[ "${roster_calls}" -lt 3 ]]; then
  echo "VIOLATION: expected >=3 validate_against_roster calls in liability.rs, found ${roster_calls}"
  violations=$((violations + 1))
fi

if [[ "${violations}" -ne 0 ]]; then
  echo "check-liability-roster-enforcement: FAILED (${violations} violations)"
  exit 1
fi
echo "check-liability-roster-enforcement: OK (${found_total} constructions checked, ${roster_calls} roster calls)"
