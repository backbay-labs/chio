#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

require_strict=0
if [[ "$#" -gt 1 ]]; then
  echo "usage: check-proof-report.sh [--require-strict]" >&2
  exit 2
fi
if [[ "${1:-}" == "--require-strict" ]]; then
  require_strict=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: check-proof-report.sh [--require-strict]" >&2
  exit 2
fi

report_path="${CHIO_PROOF_REPORT_PATH:-target/formal/proof-report.json}"
if [[ ! -f "${report_path}" ]]; then
  ./scripts/generate-proof-report.sh
fi

python3 - "${report_path}" "${require_strict}" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required to check the proof report") from exc


COVERAGE_COMMAND = "cargo xtask gen proof-coverage --check"
EVIDENCE_BOUNDARY = (
    "gate statuses attest the trusted generator process; this checker validates "
    "structure and source binding but does not replay proof commands"
)
SELF_COMMANDS = {
    "./scripts/check-proof-report.sh",
    "./scripts/check-proof-report.sh --require-strict",
}
GENERATOR_COMMANDS = {
    "./scripts/generate-proof-report.sh",
    "./scripts/generate-proof-report.sh --no-run-gates",
}
AENEAS_ARTIFACTS = {
    "target/formal/aeneas-production/llbc/formal_aeneas.llbc",
    "target/formal/aeneas-production/lean/Funs.lean",
    "target/formal/aeneas-production/lean/Types.lean",
    "target/formal/aeneas-production/equivalence-artifacts.json",
}
TOOL_COMMANDS = {
    "lean": "lean --version",
    "lake": "lake --version",
    "cargo": "cargo --version",
    "rustc": "rustc --version",
    "kani": "cargo kani --version",
    "creusot": "cargo creusot version",
    "aeneas": "aeneas -version",
    "charon": "charon version",
}


def fail(message: str) -> None:
    raise SystemExit(f"proof-report: {message}")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hash_map(
    actual: Any, expected_paths: set[str], label: str, repo: Path
) -> dict[str, str]:
    hashes = require_object(actual, label)
    if set(hashes) != expected_paths:
        missing = sorted(expected_paths - set(hashes))
        extra = sorted(set(hashes) - expected_paths)
        fail(f"{label} path set mismatch: missing={missing} extra={extra}")
    for relative_path, digest in hashes.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"{label} has invalid SHA-256 for {relative_path}")
        path = repo / relative_path
        if path.is_symlink() or not path.is_file():
            fail(f"{label} path is missing or symlinked: {relative_path}")
        if sha256_file(path) != digest:
            fail(f"{label} hash does not match disk: {relative_path}")
    return hashes


def find_source_line(path: Path, lean_name: str) -> int:
    if not path.is_file():
        fail(f"theorem source file is missing: {path.relative_to(repo)}")
    declaration = re.compile(
        r"^\s*(?:(?:private|protected|noncomputable|unsafe)\s+|@\[[^]]+\]\s*)*"
        r"(?:theorem|axiom|def)\s+([^\s(:{]+)"
    )
    matches = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = declaration.match(line)
        if match is None:
            continue
        declared_name = match.group(1)
        if lean_name == declared_name or lean_name.endswith(f".{declared_name}"):
            matches.append(index)
    if len(matches) != 1:
        fail(
            f"expected one declaration for {lean_name} in "
            f"{path.relative_to(repo)}, found {len(matches)}"
        )
    return matches[0]


def validate_command_record(
    record: Any, command: str, label: str, *, require_success: bool
) -> dict[str, Any]:
    value = require_object(record, label)
    if value.get("command") != command:
        fail(f"{label} command mismatch")
    exit_code = value.get("exitCode")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        fail(f"{label} exitCode must be an integer")
    output = value.get("output")
    if not isinstance(output, list) or not all(isinstance(line, str) for line in output):
        fail(f"{label} output must be a string list")
    if require_success and (exit_code != 0 or not output):
        fail(f"{label} did not record a successful probe")
    return value


repo = Path.cwd().resolve()
path = Path(sys.argv[1])
if not path.is_absolute():
    path = repo / path
require_strict = sys.argv[2] == "1"
try:
    report = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    fail(f"cannot read report: {exc}")
report = require_object(report, "report")

required_top = {
    "schema",
    "mode",
    "evidenceBoundary",
    "generatedAt",
    "manifest",
    "theoremInventory",
    "assumptionRegistry",
    "proofCoverage",
    "proofBoundaryStatus",
    "verificationTarget",
    "primaryToolchain",
    "rustRefinementLanes",
    "propertyCoverage",
    "assumptionIds",
    "theoremCount",
    "assumptionCount",
    "gateResults",
    "toolVersions",
    "artifactHashes",
    "sourceLocations",
    "git",
    "ci",
    "claimGate",
}
missing = sorted(required_top - set(report))
if missing:
    fail(f"missing top-level keys: {missing}")
if report["schema"] != "chio.proof-report.v1":
    fail(f"unknown schema: {report['schema']}")
if report["evidenceBoundary"] != EVIDENCE_BOUNDARY:
    fail("evidenceBoundary does not describe the checker trust boundary")
try:
    generated_at = dt.datetime.fromisoformat(str(report["generatedAt"]).replace("Z", "+00:00"))
except ValueError as exc:
    fail(f"invalid generatedAt: {exc}")
if generated_at.tzinfo is None:
    fail("generatedAt lacks a timezone")

manifest_path = repo / "formal/proof-manifest.toml"
inventory_path = repo / "formal/theorem-inventory.json"
assumptions_path = repo / "formal/assumptions.toml"
if report["manifest"] != "formal/proof-manifest.toml":
    fail("manifest path is not canonical")
if report["theoremInventory"] != "formal/theorem-inventory.json":
    fail("theorem inventory path is not canonical")
if report["assumptionRegistry"] != "formal/assumptions.toml":
    fail("assumption registry path is not canonical")
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
assumptions = tomllib.loads(assumptions_path.read_text(encoding="utf-8"))
for report_key, manifest_key, default in (
    ("proofBoundaryStatus", "proof_boundary_status", None),
    ("verificationTarget", "verification_target", None),
    ("primaryToolchain", "primary_toolchain", []),
    ("rustRefinementLanes", "rust_refinement_lanes", []),
):
    if report.get(report_key) != manifest.get(manifest_key, default):
        fail(f"{report_key} does not match the proof manifest")
theorem_ids = {entry["id"] for entry in inventory.get("theorems", [])}
assumption_ids = sorted(set(assumptions.get("required_assumption_ids", [])))
if report.get("theoremCount") != len(theorem_ids):
    fail("theoremCount does not match the theorem inventory")
if report.get("assumptionCount") != len(assumption_ids):
    fail("assumptionCount does not match the assumption registry")
if report.get("assumptionIds") != assumption_ids:
    fail("assumptionIds do not match the assumption registry")
expected_property_coverage = []
for encoded in manifest.get("property_matrix", []):
    property_id, summary, evidence, theorem_csv = encoded.split("|")
    mapped_theorems = [item.strip() for item in theorem_csv.split(",") if item.strip()]
    expected_property_coverage.append(
        {
            "propertyId": property_id,
            "summary": summary,
            "evidence": [item.strip() for item in evidence.split(",") if item.strip()],
            "theoremIds": mapped_theorems,
            "missingTheoremIds": [
                theorem_id for theorem_id in mapped_theorems if theorem_id not in theorem_ids
            ],
        }
    )
if report.get("propertyCoverage") != expected_property_coverage:
    fail("propertyCoverage does not match the proof manifest and theorem inventory")

gate_commands = manifest.get("gate_commands")
if not isinstance(gate_commands, list) or not all(
    isinstance(command, str) and command for command in gate_commands
):
    fail("manifest gate_commands must be non-empty strings")
if len(gate_commands) != len(set(gate_commands)):
    fail("manifest contains duplicate gate commands")
if gate_commands.count(COVERAGE_COMMAND) != 1:
    fail("manifest must register the proof-coverage preflight exactly once")
expected_commands = [
    command
    for command in gate_commands
    if command not in SELF_COMMANDS and command not in GENERATOR_COMMANDS
]
if not expected_commands or expected_commands[0] != COVERAGE_COMMAND:
    fail("the proof-coverage preflight must be the first report gate command")

mode = report.get("mode")
if mode not in {"strict", "metadata_only"}:
    fail(f"unknown mode: {mode}")
if require_strict and mode != "strict":
    fail(
        "RISK_REGISTER Formal Verification Claim Rules require a strict proof report "
        "for release qualification"
    )

gate_results = report.get("gateResults")
if not isinstance(gate_results, list) or not gate_results:
    fail("gateResults must be a non-empty list")
actual_commands = []
for index, result in enumerate(gate_results):
    result = require_object(result, f"gateResults[{index}]")
    command = result.get("command")
    if not isinstance(command, str):
        fail(f"gateResults[{index}] command must be a string")
    actual_commands.append(command)
    status = result.get("status")
    exit_code = result.get("exitCode")
    if status == "passed" and exit_code != 0:
        fail(f"passed gate has nonzero exitCode: {command}")
    if status == "failed" and (
        isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code == 0
    ):
        fail(f"failed gate lacks a nonzero exitCode: {command}")
    if status == "not_run" and exit_code is not None:
        fail(f"not_run gate has an exitCode: {command}")
    if status not in {"passed", "failed", "not_run"}:
        fail(f"gate has invalid status: {command} status={status}")
if actual_commands != expected_commands or len(actual_commands) != len(set(actual_commands)):
    fail("gateResults do not match the exact unique manifest command order")
if mode == "strict":
    for result in gate_results:
        if result["status"] != "passed":
            fail(f"strict gate did not pass: {result['command']} status={result['status']}")
else:
    for result in gate_results:
        expected_status = "passed" if result["command"] == COVERAGE_COMMAND else "not_run"
        if result["status"] != expected_status:
            fail(
                f"metadata-only gate status mismatch: {result['command']} "
                f"status={result['status']}"
            )
    print("WARNING: proof report is metadata-only; only coverage preflight was executed")

claim_gate = require_object(report.get("claimGate"), "claimGate")
if claim_gate.get("status") != "passed":
    fail("claim gate did not pass")
if claim_gate.get("claimRegistry") != manifest.get("claim_registry"):
    fail("claim gate registry does not match the manifest")
if claim_gate.get("inputs") != manifest.get("claim_gate_inputs", []):
    fail("claim gate inputs do not match the manifest")
required_claim_terms = [
    "FORM-IMPLEMENTATION-LINKED",
    "formal/proof-manifest.toml",
    "formal/theorem-inventory.json",
    "formal/assumptions.toml",
    "target/formal/proof-report.json",
    "docs/formal/COVERAGE.md",
]
if claim_gate.get("requiredTerms") != required_claim_terms:
    fail("claim gate required terms are not canonical")
claim_registry_path = repo / str(manifest.get("claim_registry"))
claim_registry = claim_registry_path.read_text(encoding="utf-8")
if any(term not in claim_registry for term in required_claim_terms):
    fail("claim registry no longer contains every required proof-report term")
for claim_input in manifest.get("claim_gate_inputs", []):
    if not (repo / claim_input).is_file():
        fail(f"claim gate input is missing: {claim_input}")

tracked_paths = {
    "formal/proof-manifest.toml",
    "formal/theorem-inventory.json",
    "formal/assumptions.toml",
    "docs/formal/COVERAGE.md",
    "scripts/check-formal-proofs.sh",
    "scripts/check-aeneas-production.sh",
    "scripts/check-aeneas-equivalence.sh",
    "scripts/check-rust-verification-gates.sh",
    "scripts/check-kani-core.sh",
    "scripts/check-kani-public-core.sh",
    "scripts/check-creusot-core.sh",
    "scripts/check-adapter-no-bypass.sh",
    "scripts/generate-proof-report.sh",
    "scripts/check-proof-report.sh",
    str(manifest.get("claim_registry")),
}
tracked_paths.update(manifest.get("claim_gate_inputs", []))
tracked_paths.update(manifest.get("root_modules", []))
tracked_paths.update(manifest.get("covered_rust_modules", []))
for command in expected_commands:
    words = shlex.split(command)
    if words and words[0].startswith("./"):
        tracked_paths.add(words[0].removeprefix("./"))
artifact_hashes = require_object(report.get("artifactHashes"), "artifactHashes")
check_hash_map(artifact_hashes.get("tracked"), tracked_paths, "tracked hashes", repo)
generated_paths = {"target/formal/coverage.json"}
if mode == "strict":
    generated_paths.update(AENEAS_ARTIFACTS)
generated_hashes = check_hash_map(
    artifact_hashes.get("generated"), generated_paths, "generated hashes", repo
)

proof_coverage = require_object(report.get("proofCoverage"), "proofCoverage")
if proof_coverage.get("path") != "target/formal/coverage.json":
    fail("proofCoverage path is not canonical")
if proof_coverage.get("sha256") != generated_hashes["target/formal/coverage.json"]:
    fail("proofCoverage hash does not match generated hashes")
coverage = json.loads((repo / "target/formal/coverage.json").read_text(encoding="utf-8"))
if coverage.get("schema") != "chio.proof-coverage.v1":
    fail("coverage artifact has an unknown schema")

head = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=repo,
    check=True,
    text=True,
    stdout=subprocess.PIPE,
).stdout.strip()
if coverage.get("commit") != head:
    fail("coverage artifact commit does not match HEAD")

tools = require_object(report.get("toolVersions"), "toolVersions")
if set(tools) != set(TOOL_COMMANDS):
    fail("toolVersions do not match the required probe set")
for name, command in TOOL_COMMANDS.items():
    record = validate_command_record(
        tools[name], command, f"toolVersions.{name}", require_success=mode == "strict"
    )
    if mode == "strict":
        completed = subprocess.run(
            command,
            cwd=repo,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        live_output = completed.stdout.strip().splitlines()[:3]
        if completed.returncode != 0 or not live_output:
            fail(f"live strict tool probe failed: {name}")
        if record["output"] != live_output:
            fail(f"strict tool probe output is stale or forged: {name}")

git = require_object(report.get("git"), "git")
if set(git) != {"commit", "branch", "dirty"}:
    fail("git record has an unexpected key set")
commit_record = validate_command_record(
    git["commit"], "git rev-parse HEAD", "git.commit", require_success=True
)
branch_record = validate_command_record(
    git["branch"], "git branch --show-current", "git.branch", require_success=False
)
dirty_record = validate_command_record(
    git["dirty"], "git status --short", "git.dirty", require_success=False
)
if branch_record["exitCode"] != 0 or dirty_record["exitCode"] != 0:
    fail("git branch or dirty-state probe failed")
actual_branch = subprocess.run(
    ["git", "branch", "--show-current"],
    cwd=repo,
    check=True,
    text=True,
    stdout=subprocess.PIPE,
).stdout.strip().splitlines()
actual_dirty = subprocess.run(
    ["git", "status", "--short"],
    cwd=repo,
    check=True,
    text=True,
    stdout=subprocess.PIPE,
).stdout.strip().splitlines()
if branch_record["output"] != actual_branch or dirty_record["output"] != actual_dirty:
    fail("report branch or dirty-state probe is stale")
if mode == "strict" and (dirty_record["output"] or actual_dirty):
    fail("strict proof reports require a clean git worktree")
if commit_record["output"] != [head]:
    fail("report commit does not match HEAD")
ci = require_object(report.get("ci"), "ci")
recorded_sha = ci.get("githubSha")
if recorded_sha is not None and recorded_sha != head:
    fail("report GITHUB_SHA does not match HEAD")
environment_sha = os.environ.get("GITHUB_SHA")
if environment_sha is not None and (environment_sha != head or recorded_sha != environment_sha):
    fail("report, coverage, HEAD, and GITHUB_SHA are not bound to one commit")

source_locations = require_object(report.get("sourceLocations"), "sourceLocations")
entries = inventory.get("assumptions", []) + inventory.get("theorems", [])
expected_ids = {entry["id"] for entry in entries}
if set(source_locations) != expected_ids:
    fail("sourceLocations do not match the theorem inventory IDs")
for entry in entries:
    location = require_object(source_locations[entry["id"]], f"sourceLocations.{entry['id']}")
    expected = {
        "leanName": entry["leanName"],
        "file": entry["file"],
        "line": find_source_line(repo / entry["file"], entry["leanName"]),
    }
    if location != expected:
        fail(f"source location does not match disk: {entry['id']}")
    if not isinstance(location["line"], int) or location["line"] <= 0:
        fail(f"source location is not a positive line number: {entry['id']}")
PY

echo "Proof report structure and source-binding check passed"
