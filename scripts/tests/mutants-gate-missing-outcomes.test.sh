#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

status=0
env \
  MUTANTS_PACKAGE=chio-kernel-core \
  MUTANTS_OUTPUT_DIR="${TMP_DIR}/mutants-out" \
  MUTANTS_EXIT=0 \
  bash "${REPO_ROOT}/scripts/mutants-gate.sh" \
  >"${TMP_DIR}/stdout" 2>"${TMP_DIR}/stderr" || status=$?

if [[ "${status}" -eq 0 ]]; then
  echo "FAIL: blocking mutation gate passed with missing outcomes.json" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

if ! grep -q "outcomes_json=missing" "${TMP_DIR}/stderr"; then
  echo "FAIL: missing outcomes.json failure did not explain the fail-closed reason" >&2
  cat "${TMP_DIR}/stdout" >&2
  cat "${TMP_DIR}/stderr" >&2
  exit 1
fi

echo "PASS: blocking mutation gate fails closed when outcomes.json is missing"
