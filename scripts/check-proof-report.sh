#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f target/formal/proof-report.json ]]; then
  ./scripts/generate-proof-report.sh
fi

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

path = Path("target/formal/proof-report.json")
report = json.loads(path.read_text(encoding="utf-8"))

required_top = [
    "schema",
    "gateResults",
    "toolVersions",
    "artifactHashes",
    "sourceLocations",
    "git",
    "claimGate",
    "proofCoverage",
]
missing = [key for key in required_top if key not in report]
if missing:
    raise SystemExit(f"proof report missing top-level keys: {missing}")

if report["claimGate"].get("status") != "passed":
    raise SystemExit("proof report claim gate did not pass")

gate_results = report.get("gateResults", [])
if not gate_results:
    raise SystemExit("proof report missing gate results")

not_passed = [
    result for result in report.get("gateResults", [])
    if result.get("status") != "passed"
]
if not_passed:
    first = not_passed[0]
    command = first.get("command")
    status = first.get("status")
    raise SystemExit(f"proof report gate did not pass: {command} status={status}")

if not report.get("toolVersions"):
    raise SystemExit("proof report missing tool versions")
if not report.get("artifactHashes", {}).get("tracked"):
    raise SystemExit("proof report missing tracked artifact hashes")
if not report.get("sourceLocations"):
    raise SystemExit("proof report missing source theorem locations")
coverage = report.get("proofCoverage", {})
coverage_path = coverage.get("path")
coverage_sha256 = coverage.get("sha256")
if coverage_path != "target/formal/coverage.json" or not coverage_sha256:
    raise SystemExit("proof report missing generated proof coverage artifact")
if report.get("artifactHashes", {}).get("generated", {}).get(coverage_path) != coverage_sha256:
    raise SystemExit("proof report proof coverage hash is not in generated artifacts")
coverage_file = Path(coverage_path)
if not coverage_file.is_file():
    raise SystemExit("proof report coverage artifact is missing on disk")
actual_coverage_sha256 = hashlib.sha256(coverage_file.read_bytes()).hexdigest()
if actual_coverage_sha256 != coverage_sha256:
    raise SystemExit("proof report coverage artifact hash does not match disk")
PY

echo "Proof report shape check passed"
