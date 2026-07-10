#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_WORKFLOW="${REPO_ROOT}/.github/workflows/cflite_pr.yml"
MUTANTS_WORKFLOW="${REPO_ROOT}/.github/workflows/mutants.yml"
DOCS="${REPO_ROOT}/docs/fuzzing/continuous.md"

python3 - <<'PY' "${PR_WORKFLOW}" "${MUTANTS_WORKFLOW}"
from pathlib import Path
import sys

pr_text = Path(sys.argv[1]).read_text(encoding="utf-8")
pr_start = pr_text.index("name: Verify 30-day fuzz budget")
pr_end = pr_text.index("changed-target-sampling:", pr_start)
if "GH_FUZZ_BUDGET_CAP_MODE: fail" not in pr_text[pr_start:pr_end]:
    raise SystemExit("cflite_pr budget gate must set cap mode to fail")

mutants_text = Path(sys.argv[2]).read_text(encoding="utf-8")
mutants_start = mutants_text.index("name: Verify shared 30-day fuzz/mutants budget")
mutants_end = mutants_text.index("name: Capture PR diff for --in-diff scoping", mutants_start)
mutants_block = mutants_text[mutants_start:mutants_end]
if "GH_FUZZ_BUDGET_CAP_MODE: fail" not in mutants_block:
    raise SystemExit("mutants-pr budget gate must set cap mode to fail")
if "hard halt" not in mutants_block:
    raise SystemExit("mutants-pr budget gate must document hard halt behavior")
PY

if ! grep -q "PR-time fuzz and mutation gates hard halt" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe PR hard halt behavior" >&2
  exit 1
fi

echo "PASS: PR fuzz budget gates and docs agree on hard halt behavior"
