#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_WORKFLOW="${REPO_ROOT}/.github/workflows/cflite_pr.yml"
MUTANTS_WORKFLOW="${REPO_ROOT}/.github/workflows/mutants.yml"
DOCS="${REPO_ROOT}/docs/fuzzing/continuous.md"
BUDGET_SCRIPT="${REPO_ROOT}/scripts/check-fuzz-budget.sh"

python3 - <<'PY' "${PR_WORKFLOW}" "${MUTANTS_WORKFLOW}"
from pathlib import Path
import sys

pr_text = Path(sys.argv[1]).read_text(encoding="utf-8")
pr_start = pr_text.index("name: Verify 30-day fuzz budget")
pr_end = pr_text.index("changed-target-sampling:", pr_start)
if "GH_FUZZ_BUDGET_CAP_MODE: warn" not in pr_text[pr_start:pr_end]:
    raise SystemExit("cflite_pr budget gate must keep its advisory cap mode")

mutants_text = Path(sys.argv[2]).read_text(encoding="utf-8")
mutants_path = Path(sys.argv[2]).resolve()
repo_root = mutants_path.parents[2]
selection_start = mutants_text.index("name: Select changed package")
selection_end = mutants_text.index("name: Install Rust toolchain", selection_start)
selection_block = mutants_text[selection_start:selection_end]
crate_paths = {
    "chio-kernel-core": "crates/kernel/chio-kernel-core",
    "chio-policy": "crates/guards/chio-policy",
    "chio-guards": "crates/guards/chio-guards",
    "chio-credentials": "crates/trust/chio-credentials",
    "chio-attest-verify": "crates/trust/chio-attest-verify",
    "chio-anchor": "crates/economy/chio-anchor",
}
for package, crate_path in crate_paths.items():
    mapping = f'{package}) crate_path="{crate_path}" ;;'
    if mapping not in selection_block:
        raise SystemExit(f"mutants-pr selection is missing grouped path for {package}")
    if not (repo_root / crate_path / "mutants.toml").is_file():
        raise SystemExit(f"mutants-pr config does not exist for {package}")
if 'echo "crate_path=${crate_path}" >> "${GITHUB_OUTPUT}"' not in selection_block:
    raise SystemExit("mutants-pr selection must export its resolved crate path")

mutation_start = mutants_text.index("name: Run cargo-mutants --in-diff against PR base")
mutation_end = mutants_text.index("name: Read survivor issue budget", mutation_start)
mutation_block = mutants_text[mutation_start:mutation_end]
if '--config "${{ steps.select.outputs.crate_path }}/mutants.toml"' not in mutation_block:
    raise SystemExit("mutants-pr must load the selected grouped crate config")
if '--config "crates/${{ matrix.package }}/mutants.toml"' in mutants_text:
    raise SystemExit("mutants-pr still reconstructs a flat crate config path")

mutants_start = mutants_text.index("name: Verify shared 30-day fuzz/mutants budget")
mutants_end = mutants_text.index("name: Capture PR diff for --in-diff scoping", mutants_start)
mutants_block = mutants_text[mutants_start:mutants_end]
if "GH_FUZZ_BUDGET_CAP_MODE: fail" not in mutants_block:
    raise SystemExit("mutants-pr budget gate must set cap mode to fail")
if "hard halt" not in mutants_block:
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
if ! grep -q 'proof-mutants.yml' "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must include proof-mutants budget accounting" >&2
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
if '"proof-mutants.yml"' not in script:
    raise SystemExit("proof-mutants workflow must count against the shared budget")
PY

echo "PASS: PR fuzz budget gates and docs agree on advisory and hard halt behavior"
