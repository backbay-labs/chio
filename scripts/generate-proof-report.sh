#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_gates=1
if [[ "${1:-}" == "--no-run-gates" ]]; then
  run_gates=0
fi

python3 - "${run_gates}" <<'PY'
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required to generate the proof report") from exc

repo = Path(".")
run_gates = sys.argv[1] == "1"
manifest_path = repo / "formal" / "proof-manifest.toml"
inventory_path = repo / "formal" / "theorem-inventory.json"
assumptions_path = repo / "formal" / "assumptions.toml"
report_path = repo / "target" / "formal" / "proof-report.json"

manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
assumptions = tomllib.loads(assumptions_path.read_text(encoding="utf-8"))

def command_output(command: str, max_lines: int | None = 3) -> dict:
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
    return {
        "command": command,
        "exitCode": completed.returncode,
        "output": output,
    }

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def maybe_hash(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return sha256_file(path)

def find_source_line(file_path: Path, lean_name: str) -> int | None:
    if not file_path.exists():
        return None
    needle = lean_name.split(".")[-1]
    for index, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        if f"theorem {needle}" in line or f"axiom {needle}" in line or f"def {needle}" in line:
            return index
    return None

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
    item["propertyId"]
    for item in property_coverage
    if item["missingTheoremIds"]
]
if missing_properties:
    raise SystemExit(f"proof report cannot map theorem IDs for properties: {missing_properties}")

claim_inputs = manifest.get("claim_gate_inputs", [])
for rel in claim_inputs:
    if not (repo / rel).exists():
        raise SystemExit(f"claim gate input missing: {rel}")

claim_registry = (repo / manifest["claim_registry"]).read_text(encoding="utf-8")
required_claim_terms = [
    "FORM-IMPLEMENTATION-LINKED",
    "formal/proof-manifest.toml",
    "formal/theorem-inventory.json",
    "formal/assumptions.toml",
    "target/formal/proof-report.json",
]
missing_claim_terms = [term for term in required_claim_terms if term not in claim_registry]
if missing_claim_terms:
    raise SystemExit(f"claim registry missing report mapping terms: {missing_claim_terms}")

gate_results = []
if run_gates:
    for command in manifest.get("gate_commands", []):
        if command.startswith("./scripts/generate-proof-report.sh") or command == "./scripts/check-proof-report.sh":
            continue
        env = os.environ.copy()
        if command == "./scripts/check-rust-verification-gates.sh":
            env.pop("CHIO_RUST_VERIFICATION_METADATA_ONLY", None)
        completed = subprocess.run(
            command,
            cwd=repo,
            env=env,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        gate_results.append(
            {
                "command": command,
                "status": "passed" if completed.returncode == 0 else "failed",
                "exitCode": completed.returncode,
                "outputTail": completed.stdout[-4000:],
            }
        )
        if completed.returncode != 0:
            break
else:
    gate_results = [
        {
            "command": command,
            "status": "not_run",
            "exitCode": None,
            "outputTail": "",
        }
        for command in manifest.get("gate_commands", [])
    ]

source_locations = {}
for entry in inventory.get("assumptions", []) + inventory.get("theorems", []):
    file_path = repo / entry["file"]
    source_locations[entry["id"]] = {
        "leanName": entry["leanName"],
        "file": entry["file"],
        "line": find_source_line(file_path, entry["leanName"]),
    }

tracked_artifacts = {}
tracked_paths = [
    manifest_path,
    inventory_path,
    assumptions_path,
    repo / "scripts/check-formal-proofs.sh",
    repo / "scripts/check-aeneas-production.sh",
    repo / "scripts/check-aeneas-equivalence.sh",
    repo / "scripts/check-rust-verification-gates.sh",
    repo / "scripts/check-kani-core.sh",
    repo / "scripts/check-kani-public-core.sh",
    repo / "scripts/check-creusot-core.sh",
    repo / "scripts/check-adapter-no-bypass.sh",
]
tracked_paths.extend(repo / rel for rel in manifest.get("root_modules", []))
tracked_paths.extend(repo / rel for rel in manifest.get("covered_rust_modules", []))
for path in tracked_paths:
    digest = maybe_hash(path)
    if digest:
        tracked_artifacts[str(path)] = digest

generated_artifacts = {}
for path in [
    repo / "target/formal/aeneas-production/llbc/formal_aeneas.llbc",
    repo / "target/formal/aeneas-production/lean/Funs.lean",
    repo / "target/formal/aeneas-production/lean/Types.lean",
    repo / "target/formal/aeneas-production/equivalence-artifacts.json",
]:
    digest = maybe_hash(path)
    if digest:
        generated_artifacts[str(path)] = digest

tool_versions = {
    "lean": command_output("lean --version"),
    "lake": command_output("lake --version"),
    "cargo": command_output("cargo --version"),
    "rustc": command_output("rustc --version"),
    "kani": command_output("cargo kani --version"),
    "creusot": command_output("cargo creusot --version"),
    "aeneas": command_output("aeneas --version"),
    "charon": command_output("charon --version"),
}

git = {
    "commit": command_output("git rev-parse HEAD"),
    "branch": command_output("git branch --show-current"),
    "dirty": command_output("git status --short", max_lines=None),
}

ci = {
    "githubRunId": os.environ.get("GITHUB_RUN_ID"),
    "githubSha": os.environ.get("GITHUB_SHA"),
    "githubRefName": os.environ.get("GITHUB_REF_NAME"),
}

report = {
    "schema": "chio.proof-report.v1",
    "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    "manifest": str(manifest_path),
    "theoremInventory": str(inventory_path),
    "assumptionRegistry": str(assumptions_path),
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
    "artifactHashes": {
        "tracked": tracked_artifacts,
        "generated": generated_artifacts,
    },
    "sourceLocations": source_locations,
    "git": git,
    "ci": ci,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

failed = [result for result in gate_results if result["status"] == "failed"]
if failed:
    print(f"Proof report written to {report_path}")
    output_tail = failed[0].get("outputTail", "").strip()
    if output_tail:
        print("Failing proof gate output tail:")
        print(output_tail)
    raise SystemExit(f"proof report gate failed: {failed[0]['command']}")

print(f"Proof report written to {report_path}")
PY
