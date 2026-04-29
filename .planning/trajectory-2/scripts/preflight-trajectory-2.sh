#!/usr/bin/env bash
# preflight-trajectory-2.sh
#
# Wave 0 pre-flight checklist (EXECUTION-BOARD section 2). For each
# blocking artifact, verify existence and basic well-formedness; for
# each advisory artifact, warn but do not block.
#
# Usage:
#   bash .planning/trajectory-2/scripts/preflight-trajectory-2.sh
#
# Exit code:
#   0  all blocking checks pass (advisory items may have warned)
#   1  at least one blocking check failed

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TRAJ_DIR="${REPO_ROOT}/.planning/trajectory-2"

BLOCKING_FAILED=0
WARNINGS=0

ok()    { printf '  [ ok ]   %s\n' "$*"; }
warn()  { printf '  [warn]   %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail()  { printf '  [FAIL]   %s\n' "$*"; BLOCKING_FAILED=$((BLOCKING_FAILED + 1)); }

require_blocking_file() {
  local path="$1" label="$2"
  if [[ -f "${path}" ]]; then
    ok "${label}: ${path}"
  else
    fail "${label}: ${path} (missing)"
  fi
}

advisory_file() {
  local path="$1" label="$2"
  if [[ -e "${path}" ]]; then
    ok "${label}: ${path}"
  else
    warn "${label}: ${path} (missing; advisory)"
  fi
}

echo "trajectory-2 Wave 0 pre-flight"
echo

echo "Blocking artifacts (EXECUTION-BOARD section 2):"
require_blocking_file "${TRAJ_DIR}/OWNERS.toml"            "1. ownership manifest"
require_blocking_file "${TRAJ_DIR}/freezes.yml"            "2. freeze register"
require_blocking_file "${TRAJ_DIR}/decisions.yml"          "3. decisions register"
require_blocking_file "${REPO_ROOT}/CODEOWNERS"            "4. CODEOWNERS regen for trust-boundary paths"

# Item 4 freshness: if CODEOWNERS is older than either OWNERS.toml,
# invoke the dual-trajectory regenerator. The script is idempotent;
# a no-op call is cheap, but a stale generated file would mask drift.
T1_OWNERS_FILE="${REPO_ROOT}/.planning/trajectory/OWNERS.toml"
T2_OWNERS_FILE="${TRAJ_DIR}/OWNERS.toml"
CODEOWNERS_FILE="${REPO_ROOT}/CODEOWNERS"
REGEN_SCRIPT="${TRAJ_DIR}/scripts/regen-codeowners.sh"
if [[ -f "${CODEOWNERS_FILE}" && -x "${REGEN_SCRIPT}" ]]; then
  stale=0
  if [[ -f "${T1_OWNERS_FILE}" && "${T1_OWNERS_FILE}" -nt "${CODEOWNERS_FILE}" ]]; then
    stale=1
  fi
  if [[ -f "${T2_OWNERS_FILE}" && "${T2_OWNERS_FILE}" -nt "${CODEOWNERS_FILE}" ]]; then
    stale=1
  fi
  if [[ "${stale}" -eq 1 ]]; then
    if "${REGEN_SCRIPT}" >/dev/null 2>&1; then
      ok "4a. CODEOWNERS was stale; regenerated via ${REGEN_SCRIPT}"
    else
      fail "4a. CODEOWNERS stale and regen failed (run ${REGEN_SCRIPT} manually)"
    fi
  else
    ok "4a. CODEOWNERS fresh (newer than both OWNERS.toml inputs)"
  fi
elif [[ ! -x "${REGEN_SCRIPT}" ]]; then
  warn "4a. dual-trajectory regen script missing or non-executable: ${REGEN_SCRIPT}"
fi

require_blocking_file "${TRAJ_DIR}/tickets/manifest.yml"   "5. ticket manifest"

# Per-phase ticket files: at least one P*.yml under each M{nn}/.
echo "6. per-phase ticket files (one per milestone, P0..P5):"
for nn in 01 02 03 04 05 06 07 08 09 10; do
  phase_dir="${TRAJ_DIR}/tickets/M${nn}"
  shopt -s nullglob
  files=("${phase_dir}"/P*.yml)
  shopt -u nullglob
  if [[ "${#files[@]}" -ge 6 ]]; then
    ok "  M${nn}: ${#files[@]} phase files"
  else
    fail "  M${nn}: only ${#files[@]} phase files under ${phase_dir} (need >= 6)"
  fi
done

require_blocking_file "${TRAJ_DIR}/EXECUTION-STATE.json"   "7. execution-state seed"

echo
echo "Advisory artifacts:"
advisory_file "${TRAJ_DIR}/EXECUTION-LOG.ndjson"           "8. audit-log path (created on first append)"
advisory_file "${TRAJ_DIR}/scripts/install-orchestrator-tools.sh" "10. yq+jq install snippet"

# Item 9: branch ruleset is a GitHub-side artifact; verify locally that
# the m05-freeze-guard workflow exists and trajectory-2 freezes are
# declared in freezes.yml. Operator must confirm the GitHub ruleset.
if [[ -f "${REPO_ROOT}/.github/workflows/m05-freeze-guard.yml" ]]; then
  ok "9. m05-freeze-guard workflow present (ruleset must be rewritten on GitHub)"
else
  warn "9. m05-freeze-guard workflow missing (advisory; rebuild before M03/M04/M05/M10 P1 starts)"
fi

# Toolchain pins.
if command -v yq >/dev/null 2>&1; then
  ok "yq on PATH: $(yq --version 2>&1 | head -n1)"
else
  fail "yq missing (install via .planning/trajectory-2/scripts/install-orchestrator-tools.sh)"
fi
if command -v jq >/dev/null 2>&1; then
  ok "jq on PATH: $(jq --version 2>&1)"
else
  fail "jq missing"
fi

# Validate manifest if present.
if [[ -x "${TRAJ_DIR}/scripts/validate-manifest.sh" ]]; then
  if bash "${TRAJ_DIR}/scripts/validate-manifest.sh" >/dev/null 2>&1; then
    ok "manifest integrity check"
  else
    fail "manifest integrity check (run scripts/validate-manifest.sh for details)"
  fi
else
  warn "validate-manifest.sh missing or non-executable"
fi

echo
if [[ "${BLOCKING_FAILED}" -gt 0 ]]; then
  echo "preflight FAILED: ${BLOCKING_FAILED} blocking issue(s); ${WARNINGS} warning(s)" >&2
  exit 1
fi
echo "preflight OK: 0 blocking issues; ${WARNINGS} warning(s)"
