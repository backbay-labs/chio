#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/tuf-rebake.yml"
SCRIPT="${REPO_ROOT}/scripts/tuf-rebake.sh"

python3 - <<'PY' "${WORKFLOW}" "${SCRIPT}"
from pathlib import Path
import re
import sys

workflow = Path(sys.argv[1])
script = Path(sys.argv[2])
text = workflow.read_text(encoding="utf-8")

if re.search(r"\bstub\b|awaiting|replace this step", text, flags=re.IGNORECASE):
    raise SystemExit("tuf-rebake workflow still contains stub wording")

required = [
    "scripts/tuf-rebake.sh --write",
    "scripts/tuf-rebake.sh --check",
    "cargo test -p chio-attest-verify --test integration constructor_loads_embedded_trust_root -- --exact",
    "git diff --exit-code -- crates/trust/chio-attest-verify/sigstore-root",
]
missing = [marker for marker in required if marker not in text]
if missing:
    raise SystemExit("tuf-rebake workflow missing required marker(s): " + ", ".join(missing))

run_blocks = re.findall(r"run: \|\n((?:          .*\n)+)", text)
echo_only_blocks = []
for block in run_blocks:
    commands = [
        line.strip()
        for line in block.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and not line.strip().startswith("set ")
    ]
    if commands and all(command.startswith("echo ") for command in commands):
        echo_only_blocks.append(block)

if echo_only_blocks:
    raise SystemExit("tuf-rebake workflow contains an echo-only run block")

script_text = script.read_text(encoding="utf-8")
script_markers = [
    "cargo run -p chio-attest-verify --bin tuf-rebake",
    'exec "$@"',
]
missing_script = [marker for marker in script_markers if marker not in script_text]
if missing_script:
    raise SystemExit("tuf-rebake script missing required marker(s): " + ", ".join(missing_script))

print("PASS: tuf-rebake workflow invokes real rebake tooling and is not a stub")
PY
