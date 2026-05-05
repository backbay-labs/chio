#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/release-qualification.yml"

python3 - <<'PY' "${WORKFLOW}"
from pathlib import Path
import sys

workflow = Path(sys.argv[1])
lines = workflow.read_text(encoding="utf-8").splitlines()

required_markers = {
    "CHIO_AENEAS_RELEASE_TAG": "Aeneas release pin",
    "CHIO_AENEAS_LINUX_X86_64_SHA256": "Aeneas archive checksum",
    "CHIO_CREUSOT_REV": "Creusot revision pin",
    "CHIO_KANI_VERSION": "Kani version pin",
    "Install Aeneas and Charon": "Aeneas and Charon install step",
    "sha256sum -c -": "checksum verification",
    "Install Rust verification tools": "Kani and Creusot install step",
    "cargo install kani-verifier": "Kani installer",
    "cargo kani setup": "Kani setup",
    "git clone https://github.com/creusot-rs/creusot": "Creusot source checkout",
    "cargo creusot version": "Creusot post-install probe",
}

missing = [
    description
    for marker, description in required_markers.items()
    if not any(marker in line for line in lines)
]
if missing:
    raise SystemExit("release-qualification missing: " + ", ".join(missing))

def first_line(marker: str) -> int:
    for idx, line in enumerate(lines, start=1):
        if marker in line:
            return idx
    raise AssertionError(marker)

release_step = first_line("run: ./scripts/qualify-release.sh")
rust_cache_step = first_line("uses: Swatinem/rust-cache@")
formal_steps = [
    first_line("name: Install Aeneas and Charon"),
    first_line("name: Install Rust verification tools"),
]
early_installs = [line for line in formal_steps if line < rust_cache_step]
if early_installs:
    raise SystemExit(
        "rust-cache restore must precede formal tool install steps "
        f"(early line numbers: {early_installs}, rust-cache line: {rust_cache_step})"
    )

late = [line for line in formal_steps if line > release_step]
if late:
    raise SystemExit(
        "formal tool install steps must precede ./scripts/qualify-release.sh "
        f"(late line numbers: {late}, release line: {release_step})"
    )

print("PASS: release-qualification installs strict formal tools before ci-workspace")
PY
