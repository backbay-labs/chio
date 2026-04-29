#!/usr/bin/env bash
# Per-runtime gzipped wasm size budget gate for the Chio TypeScript SDK.
#
# Reads sdks/typescript/scripts/size-budget.json, gzips each declared wasm
# artifact, and asserts that the gzipped size is at or below the recorded
# ceiling. Prints a pass/fail table.
#
# Source-of-truth ceilings live in size-budget.json; the JSON schema is
# pinned via the top-level "schema" key (chio.size-budget/v1). Updates to
# the budget MUST land in the JSON, not here, so CI and humans see the
# same numbers.
#
# Usage:
#   size-budget.sh                       # gate every runtime in the JSON
#   size-budget.sh <runtime>             # gate a single runtime
#   size-budget.sh <runtime> <kb_cap>    # override ceiling for one runtime
#                                        # (advisory; intended for ticket
#                                        #  gate-checks, not for relaxing
#                                        #  the source-of-truth budget)
#
# Behavior:
#   - Soft-skip: if a wasm artifact does not exist (e.g. wasm-pack has not
#     run yet), print SKIP and continue. Never fail-on-missing because the
#     build pipeline runs this script before and after wasm-pack.
#   - Fail-closed: any entry whose gzipped size exceeds its ceiling exits
#     non-zero with a clear diagnostic.
#   - Schema-locked: refuses to run if the JSON schema string does not
#     match the version this script understands.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CONFIG="${SCRIPT_DIR}/size-budget.json"
EXPECTED_SCHEMA="chio.size-budget/v1"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required to read ${CONFIG}." >&2
  echo "  install with: brew install jq  (macOS) or apt-get install jq (Debian/Ubuntu)" >&2
  exit 2
fi

if ! command -v gzip >/dev/null 2>&1; then
  echo "ERROR: gzip is required for size measurement." >&2
  exit 2
fi

if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: budget config not found at ${CONFIG}" >&2
  exit 2
fi

ACTUAL_SCHEMA="$(jq -r '.schema' "${CONFIG}")"
if [[ "${ACTUAL_SCHEMA}" != "${EXPECTED_SCHEMA}" ]]; then
  echo "ERROR: budget schema mismatch:" >&2
  echo "  expected: ${EXPECTED_SCHEMA}" >&2
  echo "  found:    ${ACTUAL_SCHEMA}" >&2
  exit 2
fi

ONLY_RUNTIME="${1:-}"
OVERRIDE_KB="${2:-}"

if [[ -n "${OVERRIDE_KB}" ]]; then
  if ! [[ "${OVERRIDE_KB}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: override ceiling must be a positive integer (KB), got '${OVERRIDE_KB}'" >&2
    exit 2
  fi
fi

# Build the list of runtimes to gate.
if [[ -n "${ONLY_RUNTIME}" ]]; then
  if ! jq -e --arg r "${ONLY_RUNTIME}" '.budgets[$r]' "${CONFIG}" >/dev/null; then
    echo "ERROR: runtime '${ONLY_RUNTIME}' not declared in ${CONFIG}" >&2
    echo "  available: $(jq -r '.budgets | keys | join(", ")' "${CONFIG}")" >&2
    exit 2
  fi
  RUNTIMES=("${ONLY_RUNTIME}")
else
  # shellcheck disable=SC2207
  RUNTIMES=($(jq -r '.budgets | keys[]' "${CONFIG}"))
fi

# Header for the result table.
printf '%-10s  %-10s  %-10s  %s\n' "runtime" "gzipped" "ceiling" "status"
printf '%-10s  %-10s  %-10s  %s\n' "-------" "-------" "-------" "------"

failed=0
skipped=0
checked=0

for runtime in "${RUNTIMES[@]}"; do
  wasm_rel="$(jq -r --arg r "${runtime}" '.budgets[$r].wasm_path' "${CONFIG}")"
  ceiling_kb="$(jq -r --arg r "${runtime}" '.budgets[$r].gzipped_kb' "${CONFIG}")"

  if [[ -n "${OVERRIDE_KB}" && "${runtime}" == "${ONLY_RUNTIME}" ]]; then
    ceiling_kb="${OVERRIDE_KB}"
  fi

  wasm_abs="${REPO_ROOT}/${wasm_rel}"

  if [[ ! -f "${wasm_abs}" ]]; then
    printf '%-10s  %-10s  %-10s  %s\n' \
      "${runtime}" "-" "${ceiling_kb}KB" "SKIP (no artifact at ${wasm_rel})"
    skipped=$((skipped + 1))
    continue
  fi

  # gzip -c -9 -n: max compression, omit timestamp/name for reproducibility.
  gz_bytes="$(gzip -c -9 -n "${wasm_abs}" | wc -c | tr -d ' ')"
  # Round up to KB so 1024 bytes reads as 1 KB and 1025 bytes reads as 2 KB.
  gz_kb=$(( (gz_bytes + 1023) / 1024 ))
  ceiling_bytes=$(( ceiling_kb * 1024 ))

  if (( gz_bytes <= ceiling_bytes )); then
    printf '%-10s  %-10s  %-10s  %s\n' \
      "${runtime}" "${gz_kb}KB" "${ceiling_kb}KB" "PASS"
    checked=$((checked + 1))
  else
    printf '%-10s  %-10s  %-10s  %s\n' \
      "${runtime}" "${gz_kb}KB" "${ceiling_kb}KB" "FAIL"
    failed=$((failed + 1))
  fi
done

echo
echo "summary: checked=${checked} skipped=${skipped} failed=${failed}"

if (( failed > 0 )); then
  echo "ERROR: ${failed} runtime(s) exceed their gzipped wasm budget." >&2
  exit 1
fi

exit 0
