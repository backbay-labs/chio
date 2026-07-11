#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_gates=1
mode="strict"
if [[ "$#" -gt 1 ]]; then
  echo "usage: generate-proof-report.sh [--no-run-gates]" >&2
  exit 2
fi
case "${CHIO_RUST_VERIFICATION_METADATA_ONLY:-0}" in
  0) ;;
  1)
    run_gates=0
    mode="metadata_only"
    ;;
  *)
    echo "CHIO_RUST_VERIFICATION_METADATA_ONLY must be 0 or 1" >&2
    exit 2
    ;;
esac
if [[ "${1:-}" == "--no-run-gates" ]]; then
  run_gates=0
  mode="metadata_only"
elif [[ -n "${1:-}" ]]; then
  echo "usage: generate-proof-report.sh [--no-run-gates]" >&2
  exit 2
fi

python3 - "${run_gates}" "${mode}" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required to generate the proof report") from exc


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
AENEAS_ARTIFACTS = [
    "target/formal/aeneas-production/llbc/formal_aeneas.llbc",
    "target/formal/aeneas-production/lean/Funs.lean",
    "target/formal/aeneas-production/lean/Types.lean",
    "target/formal/aeneas-production/equivalence-artifacts.json",
]


def fail(message: str) -> None:
    raise SystemExit(f"proof-report: {message}")


def command_output(command: str, max_lines: int | None = 3) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=repo,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = completed.stdout.strip().splitlines()
    if max_lines is not None:
        output = output[:max_lines]
    return {"command": command, "exitCode": completed.returncode, "output": output}


def run_gate(command: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=repo,
        env=env,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return {
        "command": command,
        "status": "passed" if completed.returncode == 0 else "failed",
        "exitCode": completed.returncode,
        "outputTail": completed.stdout[-4000:],
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def maybe_hash(path: Path) -> str | None:
    return sha256_file(path) if path.is_file() and not path.is_symlink() else None


def find_source_line(file_path: Path, lean_name: str) -> int:
    if not file_path.is_file():
        fail(f"theorem source file is missing: {file_path.relative_to(repo)}")
    declaration = re.compile(
        r"^\s*(?:(?:private|protected|noncomputable|unsafe)\s+|@\[[^]]+\]\s*)*"
        r"(?:theorem|axiom|def)\s+([^\s(:{]+)"
    )
    matches = []
    for index, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        match = declaration.match(line)
        if match is None:
            continue
        declared_name = match.group(1)
        if lean_name == declared_name or lean_name.endswith(f".{declared_name}"):
            matches.append(index)
    if len(matches) != 1:
        fail(
            f"expected one declaration for {lean_name} in "
            f"{file_path.relative_to(repo)}, found {len(matches)}"
        )
    return matches[0]


def safe_report_path(raw_path: str) -> Path:
    target_root = repo / "target" / "formal"
    current = repo
    for component in ("target", "formal"):
        current /= component
        if current.is_symlink():
            fail(f"refusing symlinked report directory: {current.relative_to(repo)}")
        if current.exists() and not current.is_dir():
            fail(f"report directory component is not a directory: {current.relative_to(repo)}")
        current.mkdir(exist_ok=True)

    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(target_root)
    except ValueError:
        fail("CHIO_PROOF_REPORT_PATH must stay under target/formal")
    if not relative.parts or candidate.suffix != ".json":
        fail("CHIO_PROOF_REPORT_PATH must name a JSON file under target/formal")
    if relative.as_posix() == "coverage.json" or relative.parts[0] == "aeneas-production":
        fail("CHIO_PROOF_REPORT_PATH overlaps a reserved formal artifact")

    current = target_root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink():
            fail(f"refusing symlinked report parent: {current.relative_to(repo)}")
        if current.exists() and not current.is_dir():
            fail(f"report parent is not a directory: {current.relative_to(repo)}")
        current.mkdir(exist_ok=True)
    if candidate.is_symlink():
        fail(f"refusing symlinked report file: {candidate.relative_to(repo)}")
    if candidate.exists() and not candidate.is_file():
        fail(f"report output is not a regular file: {candidate.relative_to(repo)}")
    return candidate


def atomic_write(path: Path, payload: str) -> None:
    if path.is_symlink():
        fail(f"refusing symlinked report file: {path.relative_to(repo)}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink():
            fail(f"refusing symlinked report file: {path.relative_to(repo)}")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


repo = Path.cwd().resolve()
run_gates = sys.argv[1] == "1"
mode = sys.argv[2]
report_path = safe_report_path(
    os.environ.get("CHIO_PROOF_REPORT_PATH", "target/formal/proof-report.json")
)
manifest_path = repo / "formal" / "proof-manifest.toml"
inventory_path = repo / "formal" / "theorem-inventory.json"
assumptions_path = repo / "formal" / "assumptions.toml"
coverage_path = repo / "target" / "formal" / "coverage.json"

manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
assumptions = tomllib.loads(assumptions_path.read_text(encoding="utf-8"))

gate_commands = manifest.get("gate_commands")
if not isinstance(gate_commands, list) or not all(
    isinstance(command, str) and command for command in gate_commands
):
    fail("formal/proof-manifest.toml gate_commands must be non-empty strings")
if len(gate_commands) != len(set(gate_commands)):
    fail("formal/proof-manifest.toml contains duplicate gate commands")
if gate_commands.count(COVERAGE_COMMAND) != 1:
    fail("the proof manifest must register the coverage preflight exactly once")
report_commands = [
    command
    for command in gate_commands
    if command not in SELF_COMMANDS and command not in GENERATOR_COMMANDS
]
if not report_commands or report_commands[0] != COVERAGE_COMMAND:
    fail("the proof-coverage preflight must be the first report gate command")
initial_dirty = command_output("git status --short", max_lines=None)
if run_gates and (initial_dirty["exitCode"] != 0 or initial_dirty["output"]):
    fail("strict proof reports require a clean git worktree before gates run")
coverage_result = run_gate(COVERAGE_COMMAND)

theorem_ids = {entry["id"] for entry in inventory.get("theorems", [])}
assumption_ids = set(assumptions.get("required_assumption_ids", []))
property_coverage = []
for encoded in manifest.get("property_matrix", []):
    property_id, summary, evidence, theorem_csv = encoded.split("|")
    mapped_theorems = [item.strip() for item in theorem_csv.split(",") if item.strip()]
    missing = [theorem_id for theorem_id in mapped_theorems if theorem_id not in theorem_ids]
    property_coverage.append(
        {
            "propertyId": property_id,
            "summary": summary,
            "evidence": [item.strip() for item in evidence.split(",") if item.strip()],
            "theoremIds": mapped_theorems,
            "missingTheoremIds": missing,
        }
    )
missing_properties = [
    item["propertyId"] for item in property_coverage if item["missingTheoremIds"]
]
if missing_properties:
    fail(f"cannot map theorem IDs for properties: {missing_properties}")

claim_inputs = manifest.get("claim_gate_inputs", [])
for relative_path in claim_inputs:
    if not (repo / relative_path).is_file():
        fail(f"claim gate input missing: {relative_path}")
claim_registry = (repo / manifest["claim_registry"]).read_text(encoding="utf-8")
required_claim_terms = [
    "FORM-IMPLEMENTATION-LINKED",
    "formal/proof-manifest.toml",
    "formal/theorem-inventory.json",
    "formal/assumptions.toml",
    "target/formal/proof-report.json",
    "docs/formal/COVERAGE.md",
]
missing_claim_terms = [term for term in required_claim_terms if term not in claim_registry]
if missing_claim_terms:
    fail(f"claim registry missing report mapping terms: {missing_claim_terms}")

gate_results: list[dict[str, Any]] = []
if run_gates:
    halted = coverage_result["status"] == "failed"
    for command in report_commands:
        if command == COVERAGE_COMMAND:
            result = coverage_result
        elif halted:
            result = {
                "command": command,
                "status": "not_run",
                "exitCode": None,
                "outputTail": "",
            }
        else:
            env = os.environ.copy()
            if command == "./scripts/check-rust-verification-gates.sh":
                env.pop("CHIO_RUST_VERIFICATION_METADATA_ONLY", None)
            result = run_gate(command, env)
        gate_results.append(result)
        if result["status"] == "failed":
            halted = True
else:
    gate_results = [
        coverage_result
        if command == COVERAGE_COMMAND
        else {"command": command, "status": "not_run", "exitCode": None, "outputTail": ""}
        for command in report_commands
    ]

source_locations = {}
for entry in inventory.get("assumptions", []) + inventory.get("theorems", []):
    file_path = repo / entry["file"]
    source_locations[entry["id"]] = {
        "leanName": entry["leanName"],
        "file": entry["file"],
        "line": find_source_line(file_path, entry["leanName"]),
    }

tracked_paths = [
    manifest_path,
    inventory_path,
    assumptions_path,
    repo / "docs/formal/COVERAGE.md",
    repo / "scripts/check-formal-proofs.sh",
    repo / "scripts/check-aeneas-production.sh",
    repo / "scripts/check-aeneas-equivalence.sh",
    repo / "scripts/check-rust-verification-gates.sh",
    repo / "scripts/check-kani-core.sh",
    repo / "scripts/check-kani-public-core.sh",
    repo / "scripts/check-creusot-core.sh",
    repo / "scripts/check-adapter-no-bypass.sh",
    repo / "scripts/generate-proof-report.sh",
    repo / "scripts/check-proof-report.sh",
    repo / manifest["claim_registry"],
]
tracked_paths.extend(repo / relative_path for relative_path in claim_inputs)
tracked_paths.extend(repo / relative_path for relative_path in manifest.get("root_modules", []))
tracked_paths.extend(
    repo / relative_path for relative_path in manifest.get("covered_rust_modules", [])
)
for command in report_commands:
    words = shlex.split(command)
    if words and words[0].startswith("./"):
        tracked_paths.append(repo / words[0])
tracked_artifacts = {}
for path in tracked_paths:
    digest = maybe_hash(path)
    if digest is None:
        fail(f"tracked proof artifact is missing or symlinked: {path.relative_to(repo)}")
    tracked_artifacts[path.relative_to(repo).as_posix()] = digest

generated_paths = [coverage_path]
if run_gates:
    generated_paths.extend(repo / relative_path for relative_path in AENEAS_ARTIFACTS)
generated_artifacts = {}
for path in generated_paths:
    digest = maybe_hash(path)
    if digest is not None:
        generated_artifacts[path.relative_to(repo).as_posix()] = digest

tool_versions = {
    "lean": command_output("lean --version"),
    "lake": command_output("lake --version"),
    "cargo": command_output("cargo --version"),
    "rustc": command_output("rustc --version"),
    "kani": command_output("cargo kani --version"),
    "creusot": command_output("cargo creusot version"),
    "aeneas": command_output("aeneas -version"),
    "charon": command_output("charon version"),
}
dirty_record = command_output("git status --short", max_lines=None)
if run_gates and (dirty_record["exitCode"] != 0 or dirty_record["output"]):
    fail("strict proof reports require a clean git worktree after gates run")
git = {
    "commit": command_output("git rev-parse HEAD"),
    "branch": command_output("git branch --show-current"),
    "dirty": dirty_record,
}
ci = {
    "githubRunId": os.environ.get("GITHUB_RUN_ID"),
    "githubSha": os.environ.get("GITHUB_SHA"),
    "githubRefName": os.environ.get("GITHUB_REF_NAME"),
}
coverage_digest = maybe_hash(coverage_path)
report = {
    "schema": "chio.proof-report.v1",
    "mode": mode,
    "evidenceBoundary": EVIDENCE_BOUNDARY,
    "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    "manifest": manifest_path.relative_to(repo).as_posix(),
    "theoremInventory": inventory_path.relative_to(repo).as_posix(),
    "assumptionRegistry": assumptions_path.relative_to(repo).as_posix(),
    "proofCoverage": {
        "path": coverage_path.relative_to(repo).as_posix(),
        "sha256": coverage_digest,
    },
    "proofBoundaryStatus": manifest.get("proof_boundary_status"),
    "verificationTarget": manifest.get("verification_target"),
    "primaryToolchain": manifest.get("primary_toolchain", []),
    "rustRefinementLanes": manifest.get("rust_refinement_lanes", []),
    "propertyCoverage": property_coverage,
    "assumptionIds": sorted(assumption_ids),
    "theoremCount": len(theorem_ids),
    "assumptionCount": len(assumption_ids),
    "claimGate": {
        "claimRegistry": manifest.get("claim_registry"),
        "inputs": claim_inputs,
        "requiredTerms": required_claim_terms,
        "status": "passed",
    },
    "gateResults": gate_results,
    "toolVersions": tool_versions,
    "artifactHashes": {"tracked": tracked_artifacts, "generated": generated_artifacts},
    "sourceLocations": source_locations,
    "git": git,
    "ci": ci,
}
atomic_write(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")

failed = [result for result in gate_results if result["status"] == "failed"]
if failed:
    print(f"Proof report written to {report_path.relative_to(repo)}")
    output_tail = failed[0].get("outputTail", "").strip()
    if output_tail:
        print("Failing proof gate output tail:")
        print(output_tail)
    fail(f"gate failed: {failed[0]['command']}")

print(f"Proof report written to {report_path.relative_to(repo)}")
PY
