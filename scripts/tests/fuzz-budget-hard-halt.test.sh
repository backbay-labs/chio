#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_WORKFLOW="${REPO_ROOT}/.github/workflows/cflite_pr.yml"
MUTANTS_WORKFLOW="${REPO_ROOT}/.github/workflows/mutants.yml"
DOCS="${REPO_ROOT}/docs/fuzzing/continuous.md"
BUDGET_SCRIPT="${REPO_ROOT}/scripts/check-fuzz-budget.sh"

if ! grep -q "GH_FUZZ_BUDGET_CAP_MODE: warn" "${PR_WORKFLOW}"; then
  echo "FAIL: cflite_pr budget gate must be advisory when shared fuzz spend is over cap" >&2
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

if ! grep -q "PR-time CFLite budget checks are advisory" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe PR CFLite advisory behavior" >&2
  exit 1
fi

if ! grep -q "PR-time mutation gates hard halt" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe PR mutation hard halt behavior" >&2
  exit 1
fi

python3 - <<'PY' "${BUDGET_SCRIPT}"
from pathlib import Path
import sys

script = Path(sys.argv[1]).read_text(encoding="utf-8")
if 'cap_mode="${GH_FUZZ_BUDGET_CAP_MODE:-fail}"' not in script:
    raise SystemExit("fuzz budget cap mode must default to fail")
if 'missing_workflow_mode="${GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE:-fail}"' not in script:
    raise SystemExit("missing workflow mode must default to fail")
if "workflow ${wf} is not registered yet; counting 0 minutes" in script:
    raise SystemExit("missing workflow must not be counted as zero minutes by default")
PY

echo "PASS: PR fuzz budget gates and docs agree on advisory and hard halt behavior"
