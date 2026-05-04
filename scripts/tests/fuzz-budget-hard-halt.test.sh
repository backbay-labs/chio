#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_WORKFLOW="${REPO_ROOT}/.github/workflows/cflite_pr.yml"
MUTANTS_WORKFLOW="${REPO_ROOT}/.github/workflows/mutants.yml"
DOCS="${REPO_ROOT}/docs/fuzzing/continuous.md"

if grep -q "GH_FUZZ_BUDGET_CAP_MODE: warn" "${PR_WORKFLOW}"; then
  echo "FAIL: cflite_pr budget gate must hard halt instead of warn-only" >&2
  exit 1
fi

python3 - <<'PY' "${MUTANTS_WORKFLOW}"
from pathlib import Path
import sys

workflow = Path(sys.argv[1])
text = workflow.read_text(encoding="utf-8")
start = text.index("name: Verify shared 30-day fuzz/mutants budget")
end = text.index("name: Capture PR diff for --in-diff scoping", start)
block = text[start:end]
if "GH_FUZZ_BUDGET_CAP_MODE: warn" in block:
    raise SystemExit("mutants-pr budget gate must hard halt instead of warn-only")
if "hard halt" not in block:
    raise SystemExit("mutants-pr budget gate must document hard halt behavior")
PY

if ! grep -q "PR-time fuzz and mutation gates hard halt" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe PR hard halt behavior" >&2
  exit 1
fi

echo "PASS: PR fuzz budget gates and docs agree on hard halt behavior"
