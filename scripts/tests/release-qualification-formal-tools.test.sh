#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/release-qualification.yml"
GENERATOR="${REPO_ROOT}/scripts/generate-proof-report.sh"
CHECKER="${REPO_ROOT}/scripts/check-proof-report.sh"

python3 - <<'PY' "${WORKFLOW}" "${GENERATOR}" "${CHECKER}"
from pathlib import Path
import sys

workflow = Path(sys.argv[1])
generator = Path(sys.argv[2]).read_text(encoding="utf-8")
checker = Path(sys.argv[3]).read_text(encoding="utf-8")
lines = workflow.read_text(encoding="utf-8").splitlines()

required_markers = {
    "CHIO_AENEAS_RELEASE_TAG": "Aeneas release pin",
    "CHIO_CREUSOT_REV": "Creusot revision pin",
    "CHIO_KANI_VERSION": "Kani version pin",
    "Install Java runtime": "Java runtime install step",
    "Install Apalache": "Apalache install step",
    "./tools/install-apalache.sh": "pinned Apalache installer",
    "Install Aeneas and Charon": "Aeneas and Charon install step",
    "./scripts/install-aeneas-toolchain.py": "authenticated Aeneas installer",
    "target/formal/aeneas-toolchain/${architecture}/bin": "authenticated Aeneas tool path",
    "Install Rust verification tools": "Kani and Creusot install step",
    "cargo install kani-verifier": "Kani installer",
    "cargo kani setup": "Kani setup",
    "git clone https://github.com/creusot-rs/creusot": "Creusot source checkout",
    "cargo creusot version": "Creusot post-install probe",
    "cargo install wasm-bindgen-cli --version \"$(cat .tooling/wasm-bindgen.version)\" --locked": "pinned wasm-bindgen-cli installer",
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
apalache_step = first_line("name: Install Apalache")
portable_steps = [
    first_line("cargo install wasm-pack --version \"$(cat .tooling/wasm-pack.version)\" --locked"),
    first_line("cargo install wasm-bindgen-cli --version \"$(cat .tooling/wasm-bindgen.version)\" --locked"),
]
early_installs = [line for line in formal_steps if line < rust_cache_step]
if early_installs:
    raise SystemExit(
        "rust-cache restore must precede formal tool install steps "
        f"(early line numbers: {early_installs}, rust-cache line: {rust_cache_step})"
    )

late = [line for line in formal_steps + [apalache_step] if line > release_step]
if late:
    raise SystemExit(
        "formal tool install steps must precede ./scripts/qualify-release.sh "
        f"(late line numbers: {late}, release line: {release_step})"
    )

late_portable = [line for line in portable_steps if line > release_step]
if late_portable:
    raise SystemExit(
        "portable wasm tool install steps must precede ./scripts/qualify-release.sh "
        f"(late line numbers: {late_portable}, release line: {release_step})"
    )

for command in (
    "cd formal/lean4/Chio && lean --version",
    "cd formal/lean4/Chio && lake --version",
):
    if command not in generator or command not in checker:
        raise SystemExit(
            "strict proof reports must probe the checked-in Lean project: " + command
        )

print("PASS: release-qualification installs strict formal tools before ci-workspace")
PY
