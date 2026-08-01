#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

nightly=".github/workflows/nightly.yml"
for required in \
  'unset CHIO_RUST_VERIFICATION_METADATA_ONLY' \
  './scripts/check-proof-report.sh --require-strict' \
  'if [[ "${mode}" != "strict" ]]; then'
do
  if ! grep -Fq "${required}" "${nightly}"; then
    echo "nightly formal qualification lacks strict-mode control: ${required}" >&2
    exit 1
  fi
done
if grep -Fq '"${mode}" != "strict" &&' "${nightly}"; then
  echo "nightly formal qualification still accepts a non-strict proof mode" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

workflow = Path(".github/workflows/formal-pr-smoke.yml").read_text(encoding="utf-8")
lake_cache_lines = [line for line in workflow.splitlines() if "runner.os }}-lake-" in line]
if len(lake_cache_lines) != 2:
    raise SystemExit("formal PR workflow must define one Lean cache key and restore key")
if any("formal/lean4/Chio/lakefile.lean" not in line for line in lake_cache_lines):
    raise SystemExit("formal PR Lean cache does not hash lakefile.lean")
if any("formal/lean4/Chio/lakefile.toml" in line for line in lake_cache_lines):
    raise SystemExit("formal PR Lean cache still hashes nonexistent lakefile.toml")
metadata_lines = [line for line in workflow.splitlines() if "set_output metadata" in line]
if len(metadata_lines) != 1 or r"\.kani/harnesses\.toml$" not in metadata_lines[0]:
    raise SystemExit("multi-crate Kani manifest changes do not trigger metadata validation")
job_start = workflow.index("  kani-public-pr:")
job_end = workflow.index("\n  kani-manifest-pr:", job_start)
job = workflow[job_start:job_end]
if "timeout-minutes: 120" not in job:
    raise SystemExit("public Kani PR job does not retain its 120-minute budget")
if workflow.count("if ! cargo kani --version >/dev/null 2>&1; then") != 2:
    raise SystemExit("formal PR Kani jobs do not repair incomplete tool caches")
if workflow.count("cargo kani setup") != 2:
    raise SystemExit("formal PR Kani jobs do not ensure the verifier is installed")

ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
for command in (
    "bash ./scripts/tests/check-rust-verification-gates.test.sh",
    "bash ./scripts/tests/formal-workflow-wiring.test.sh",
):
    if ci.count(command) != 1:
        raise SystemExit(f"required PR CI must execute exactly once: {command}")
PY

echo "Formal workflow wiring contract passed"
