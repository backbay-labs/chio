#!/usr/bin/env bash
# validate-manifest.sh
#
# Run trajectory-2 manifest integrity checks:
#   1. yq parses every per-phase file and the generated manifest.
#   2. Ticket IDs are unique across all phase files.
#   3. depends_on references resolve to known ticket IDs.
#   4. Em-dash sweep (U+2014) over phase files and narrative docs.
#   5. ID-pattern check (M{NN}.P{n}.T{k}[.{a-z}]).
#
# Usage:
#   bash .planning/trajectory-2/scripts/validate-manifest.sh
#
# Exits non-zero on any failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TRAJ_DIR="${REPO_ROOT}/.planning/trajectory-2"
TICKETS_DIR="${TRAJ_DIR}/tickets"

fail() {
  echo "validate-manifest: FAIL: $*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

require_tool yq
require_tool jq

shopt -s nullglob
PHASE_FILES=("${TICKETS_DIR}"/M*/P*.yml)
[[ "${#PHASE_FILES[@]}" -gt 0 ]] || fail "no per-phase ticket files under ${TICKETS_DIR}"

# 1. Parse every phase file (and the manifest if it exists).
for f in "${PHASE_FILES[@]}" "${TICKETS_DIR}/manifest.yml"; do
  [[ -f "$f" ]] || continue
  yq -N e '.' "$f" >/dev/null || fail "yq parse failed on ${f}"
done

# 2. Unique ID check.
ALL_IDS_RAW="$(yq -N ea '[.[].id] | .[]' "${PHASE_FILES[@]}")"
DUPES="$(printf '%s\n' "${ALL_IDS_RAW}" | sort | uniq -d || true)"
if [[ -n "${DUPES}" ]]; then
  fail "duplicate ticket ids:"$'\n'"${DUPES}"
fi

# 3. Dangling depends_on references.
ALL_IDS_SORTED="$(printf '%s\n' "${ALL_IDS_RAW}" | sort -u)"
DEPS_RAW="$(yq -N ea '[.[] | .depends_on // [] | .[]] | .[]' "${PHASE_FILES[@]}" 2>/dev/null || true)"
if [[ -n "${DEPS_RAW}" ]]; then
  while IFS= read -r dep; do
    [[ -z "${dep}" ]] && continue
    if ! grep -Fxq "${dep}" <<<"${ALL_IDS_SORTED}"; then
      fail "dangling depends_on reference: ${dep}"
    fi
  done <<<"${DEPS_RAW}"
fi

# 4. Em-dash sweep.
EMDASH="$(printf '\342\200\224')"
SWEEP_PATHS=("${TICKETS_DIR}" "${TRAJ_DIR}"/*.md)
HITS="$(grep -rln "${EMDASH}" "${SWEEP_PATHS[@]}" 2>/dev/null || true)"
if [[ -n "${HITS}" ]]; then
  fail "em-dash (U+2014) found in:"$'\n'"${HITS}"
fi

# 5. ID-pattern check (M01.P0.T1, optional .a-.z suffix).
ID_RE='^M[0-9]{2}\.P[0-9]+\.T[0-9]+(\.[a-z])?$'
while IFS= read -r id; do
  [[ -z "${id}" ]] && continue
  if [[ ! "${id}" =~ ${ID_RE} ]]; then
    fail "ticket id violates schema pattern: ${id}"
  fi
done <<<"${ALL_IDS_RAW}"

echo "validate-manifest: OK (${#PHASE_FILES[@]} phase files; $(printf '%s\n' "${ALL_IDS_SORTED}" | wc -l | tr -d ' ') unique ticket ids)"
