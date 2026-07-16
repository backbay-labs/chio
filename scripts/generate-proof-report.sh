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
    "target/formal/aeneas-production/economy/llbc/formal_economy.llbc",
    "target/formal/aeneas-production/economy/lean/Funs.lean",
    "target/formal/aeneas-production/economy/lean/Types.lean",
    "target/formal/aeneas-production/equivalence-artifacts.json",
    "target/formal/aeneas-production/negative-tests.json",
]
TRACE_TRACKED_ARTIFACTS = [
    "Cargo.toml",
    "Cargo.lock",
    "formal/MAPPING.md",
    "formal/assumptions.toml",
    "formal/tla/RevocationPropagation.tla",
    "formal/tla/trace/TraceCheckRevocationPropagation.tla",
    "formal/tla/trace/TraceEvaluateRevocationPropagation.tla",
    "formal/tla/trace/README.md",
    "formal/tla/trace/fixtures/revocation-good.ndjson",
    "formal/tla/trace/fixtures/allow-after-revoke.ndjson",
    "formal/tla/trace/fixtures/trusted-observer-key.txt",
    "formal/tla/trace/fixtures/native-conformance-observer-key.txt",
    "formal/tla/trace/negative-registry.toml",
    "crates/kernel/chio-kernel/src/runtime_trace.rs",
    "crates/kernel/chio-kernel/src/lib.rs",
    "crates/kernel/chio-kernel/src/kernel/kernel_struct.rs",
    "crates/kernel/chio-kernel/src/kernel/construction.rs",
    "crates/kernel/chio-kernel/src/kernel/validation.rs",
    "crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs",
    "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs",
    "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs",
    "crates/tooling/chio-trace-validate/Cargo.toml",
    "crates/tooling/chio-trace-validate/src/apalache.rs",
    "crates/tooling/chio-trace-validate/src/capture.rs",
    "crates/tooling/chio-trace-validate/src/decode.rs",
    "crates/tooling/chio-trace-validate/src/itf.rs",
    "crates/tooling/chio-trace-validate/src/intern.rs",
    "crates/tooling/chio-trace-validate/src/lib.rs",
    "crates/tooling/chio-trace-validate/src/main.rs",
    "crates/tooling/chio-trace-validate/src/map/mod.rs",
    "crates/tooling/chio-trace-validate/src/map/revocation.rs",
    "crates/tooling/chio-trace-validate/src/observation.rs",
    "crates/tooling/chio-trace-validate/src/report.rs",
    "crates/tooling/chio-trace-validate/tests/apalache_protocol.rs",
    "crates/tooling/chio-trace-validate/tests/artifact_paths.rs",
    "crates/tooling/chio-trace-validate/tests/capture.rs",
    "crates/tooling/chio-trace-validate/tests/checked_fixtures.rs",
    "crates/tooling/chio-trace-validate/tests/observation_decode.rs",
    "crates/tooling/chio-trace-validate/tests/projection.rs",
    "crates/tooling/chio-trace-validate/tests/reachability.rs",
    "crates/tooling/chio-trace-validate/tests/support/mod.rs",
    "crates/tooling/chio-conformance/Cargo.toml",
    "crates/tooling/chio-conformance/src/lib.rs",
    "crates/tooling/chio-conformance/src/native_suite.rs",
    "crates/tooling/chio-conformance/src/bin/chio_native_conformance_runner.rs",
    "crates/tooling/chio-conformance/tests/runtime_trace_corpus.rs",
    "crates/products/chio-cli/src/cli/trust/trace_verify.rs",
    "crates/products/chio-cli/Cargo.toml",
    "crates/products/chio-cli/src/cli/dispatch/trust.rs",
    "crates/products/chio-cli/src/cli/trust_commands.rs",
    "crates/products/chio-cli/src/cli/types.rs",
    "crates/products/chio-cli/src/cli/types/trust.rs",
    "crates/products/chio-cli/src/main.rs",
    "scripts/check-receipt-trace.sh",
    "scripts/check-receipt-trace-bindings.py",
    "scripts/check-receipt-trace-negative-registry.py",
    "scripts/tests/check-receipt-trace-bindings.test.sh",
]
TRACE_GENERATED_ARTIFACTS = [
    "target/formal/trace-validation.json",
    "target/formal/receipt-trace/bindings.json",
    "target/formal/receipt-trace/conformance.ndjson",
    "target/formal/receipt-trace/conformance.itf.json",
    "target/formal/receipt-trace/conformance-witness.itf.json",
    "target/formal/receipt-trace/conformance-observer-key.txt",
    "target/formal/receipt-trace/native-results.json",
    "target/formal/receipt-trace/native-report.md",
    "target/formal/receipt-trace/fixture-http.log",
    "target/formal/receipt-trace/fixture-good.itf.json",
    "target/formal/receipt-trace/fixture-good-witness.itf.json",
    "target/formal/receipt-trace/fixture-good-report.json",
    "target/formal/receipt-trace/fixture-bad.itf.json",
    "target/formal/receipt-trace/fixture-bad-witness.itf.json",
    "target/formal/receipt-trace/fixture-bad-report.json",
    "target/formal/receipt-trace/fixture-bad.log",
]
for _slug in ("", "-monotone", "-attenuation", "-freshness"):
    _base = f"target/formal/receipt-trace/runtime-negative{_slug}"
    TRACE_GENERATED_ARTIFACTS.extend(
        [
            f"{_base}.ndjson",
            f"{_base}.itf.json",
            f"{_base}-witness.itf.json",
            f"{_base}-report.json",
            f"{_base}.log",
        ]
    )
TRACE_INVARIANTS = [
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
]
TRACE_WITNESSES = [
    "allowReceipt",
    "orderedReceiptPair",
    "attenuatedAdmission",
    "nonzeroRevocationEpoch",
]
ADAPTER_SOURCE_INVENTORY = "formal/adapter-source-inventory.toml"
RUST_VERIFICATION_STATIC_INPUTS = [
    ".cargo/config.toml",
    ".kani/harnesses.toml",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "formal/rust-verification/creusot-contracts.toml",
    "formal/rust-verification/kani-harnesses.toml",
    "formal/rust-verification/kani-public-harnesses.toml",
    "formal/rust-verification/creusot-core/Cargo.lock",
    "formal/rust-verification/creusot-core/Cargo.toml",
    "formal/rust-verification/creusot-core/src/lib.rs",
    "formal/rust-verification/creusot-core/why3find.json",
    "scripts/check-rust-verification-gates.sh",
    "scripts/check-creusot-body-sync.sh",
    "scripts/check-creusot-smoke.sh",
    "scripts/check-kani-smoke.sh",
    "scripts/check-creusot-core.sh",
    "scripts/check-kani-core.sh",
    "scripts/check-kani-public-core.sh",
    "scripts/run-kani-manifest.sh",
]


def fail(message: str) -> None:
    raise SystemExit(f"proof-report: {message}")


def discover_adapter_gate_sources(repo: Path) -> list[str]:
    inventory_path = repo / ADAPTER_SOURCE_INVENTORY
    if inventory_path.is_symlink() or not inventory_path.is_file():
        fail(f"adapter source inventory is missing or symlinked: {ADAPTER_SOURCE_INVENTORY}")
    try:
        inventory = tomllib.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read adapter source inventory: {exc}")
    expected_keys = {
        "schema",
        "crate_name_markers",
        "explicit_roots",
        "contract_sources",
    }
    if set(inventory) != expected_keys:
        fail(
            "adapter source inventory keys do not match the closed schema: "
            f"expected={sorted(expected_keys)} actual={sorted(inventory)}"
        )
    if inventory.get("schema") != "chio.adapter-source-inventory.v1":
        fail(f"unknown adapter source inventory schema: {inventory.get('schema')}")

    def checked_strings(label: str, *, paths: bool) -> list[str]:
        values = inventory.get(label)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value and value.strip() == value for value in values
        ):
            fail(f"adapter source inventory {label} must be a nonempty string list")
        if len(values) != len(set(values)):
            fail(f"adapter source inventory {label} contains duplicates")
        for value in values:
            if paths:
                candidate = Path(value)
                if (
                    candidate.is_absolute()
                    or not candidate.parts
                    or candidate.parts[0] != "crates"
                    or any(part in {".", ".."} for part in candidate.parts)
                ):
                    fail(f"adapter source inventory {label} contains an unsafe path: {value}")
            elif re.fullmatch(r"[a-z-]+", value) is None:
                fail(f"adapter source inventory {label} contains an invalid marker: {value}")
        return values

    markers = checked_strings("crate_name_markers", paths=False)
    explicit_roots = checked_strings("explicit_roots", paths=True)
    contract_sources = checked_strings("contract_sources", paths=True)
    roots: list[Path] = []
    crates_root = repo / "crates"
    try:
        groups = sorted(crates_root.iterdir())
    except OSError as exc:
        fail(f"cannot read adapter crate root: {exc}")
    for group in groups:
        if group.is_symlink() or not group.is_dir():
            continue
        try:
            candidates = sorted(group.iterdir())
        except OSError as exc:
            fail(f"cannot read adapter crate group {group.relative_to(repo)}: {exc}")
        for candidate in candidates:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            if any(marker in candidate.name for marker in markers):
                roots.append(candidate / "src")
    roots.extend(repo / relative for relative in explicit_roots)

    sources: set[str] = set()

    def collect(path: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            fail(f"adapter source root is not a regular directory: {path.relative_to(repo)}")
        try:
            entries = sorted(path.iterdir())
        except OSError as exc:
            fail(f"cannot read adapter source directory {path.relative_to(repo)}: {exc}")
        for entry in entries:
            relative = entry.relative_to(repo)
            if entry.is_symlink():
                fail(f"adapter source tree contains a symlink: {relative}")
            if entry.is_dir():
                collect(entry)
            elif entry.is_file() and entry.suffix == ".rs":
                if "tests" in relative.parts or relative.name == "tests.rs" or relative.name.endswith(
                    "_tests.rs"
                ):
                    continue
                sources.add(relative.as_posix())

    for root in roots:
        collect(root)
    for relative in contract_sources:
        path = repo / relative
        if path.is_symlink() or not path.is_file():
            fail(f"adapter contract source is missing or symlinked: {relative}")
        sources.add(relative)
    if not sources:
        fail("adapter source discovery produced no Rust files")
    return sorted(sources)


def discover_kani_target_sources(repo: Path) -> list[str]:
    manifest_path = repo / ".kani/harnesses.toml"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("Kani multi-crate manifest is missing or symlinked")
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read Kani multi-crate manifest: {exc}")
    entries = manifest.get("harness")
    if not isinstance(entries, list) or not entries:
        fail("Kani multi-crate manifest must contain a nonempty harness array")
    crate_names: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("crate"), str):
            fail(f"Kani multi-crate harness[{index}] lacks a crate name")
        crate_names.add(entry["crate"])

    workspace_path = repo / "Cargo.toml"
    try:
        workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read workspace manifest for Kani source discovery: {exc}")
    members = workspace.get("workspace", {}).get("members")
    if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
        fail("workspace members must be a string list for Kani source discovery")

    crate_roots: dict[str, Path] = {}
    for member in members:
        relative = Path(member)
        if relative.is_absolute() or any(part in {".", ".."} for part in relative.parts):
            fail(f"workspace contains an unsafe member path: {member}")
        crate_root = repo / relative
        cargo_path = crate_root / "Cargo.toml"
        if crate_root.is_symlink() or cargo_path.is_symlink() or not cargo_path.is_file():
            fail(f"workspace member manifest is missing or symlinked: {member}/Cargo.toml")
        try:
            package = tomllib.loads(cargo_path.read_text(encoding="utf-8")).get("package", {})
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            fail(f"cannot read workspace member manifest {member}/Cargo.toml: {exc}")
        name = package.get("name")
        if name not in crate_names:
            continue
        if name in crate_roots:
            fail(f"duplicate workspace package for registered Kani crate: {name}")
        crate_roots[name] = crate_root

    missing = sorted(crate_names - set(crate_roots))
    if missing:
        fail(f"registered Kani crates are not workspace packages: {missing}")

    sources: set[str] = set()

    def collect_rust(path: Path) -> None:
        if path.is_symlink() or not path.is_dir():
            fail(f"Kani source root is missing or symlinked: {path.relative_to(repo)}")
        try:
            children = sorted(path.iterdir())
        except OSError as exc:
            fail(f"cannot read Kani source directory {path.relative_to(repo)}: {exc}")
        for child in children:
            relative = child.relative_to(repo)
            if child.is_symlink():
                fail(f"Kani source tree contains a symlink: {relative}")
            if child.is_dir():
                collect_rust(child)
            elif child.is_file() and child.suffix == ".rs":
                sources.add(relative.as_posix())

    for crate_root in crate_roots.values():
        sources.add((crate_root / "Cargo.toml").relative_to(repo).as_posix())
        collect_rust(crate_root / "src")
        build_script = crate_root / "build.rs"
        if build_script.is_symlink():
            fail(f"Kani build script is symlinked: {build_script.relative_to(repo)}")
        if build_script.is_file():
            sources.add(build_script.relative_to(repo).as_posix())
    return sorted(sources)


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
    repo / "scripts/lean-assumption-audit.lean",
    repo / "scripts/tests/lean-assumption-audit.test.sh",
    repo / "scripts/check-aeneas-production.sh",
    repo / "scripts/check-aeneas-equivalence.sh",
    repo / "scripts/check-rust-verification-gates.sh",
    repo / "scripts/check-kani-core.sh",
    repo / "scripts/check-kani-public-core.sh",
    repo / "scripts/run-kani-manifest.sh",
    repo / ".kani/harnesses.toml",
    repo / "scripts/check-creusot-core.sh",
    repo / "scripts/check-adapter-no-bypass.sh",
    repo / ADAPTER_SOURCE_INVENTORY,
    repo / "xtask/src/adapter_no_bypass.rs",
    repo / "xtask/src/cli.rs",
    repo / "xtask/src/dispatch.rs",
    repo / "xtask/src/error.rs",
    repo / "xtask/src/main.rs",
    repo / "xtask/src/support.rs",
    repo / "xtask/Cargo.toml",
    repo / ".cargo/config.toml",
    repo / "Cargo.lock",
    repo / "scripts/generate-proof-report.sh",
    repo / "scripts/check-proof-report.sh",
    repo / manifest["claim_registry"],
]
tracked_paths.extend(repo / relative_path for relative_path in TRACE_TRACKED_ARTIFACTS)
tracked_paths.extend(repo / relative_path for relative_path in RUST_VERIFICATION_STATIC_INPUTS)
tracked_paths.extend(repo / relative_path for relative_path in claim_inputs)
tracked_paths.extend(repo / relative_path for relative_path in manifest.get("root_modules", []))
tracked_paths.extend(
    repo / relative_path for relative_path in manifest.get("covered_rust_modules", [])
)
tracked_paths.extend(repo / relative_path for relative_path in discover_adapter_gate_sources(repo))
tracked_paths.extend(repo / relative_path for relative_path in discover_kani_target_sources(repo))
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
    generated_paths.extend(repo / relative_path for relative_path in TRACE_GENERATED_ARTIFACTS)
generated_artifacts = {}
for path in generated_paths:
    digest = maybe_hash(path)
    if digest is None:
        fail(f"generated proof artifact is missing or symlinked: {path.relative_to(repo)}")
    generated_artifacts[path.relative_to(repo).as_posix()] = digest

trace_validation: dict[str, Any] = {"result": "not_run"}
if run_gates:
    trace_report_path = repo / "target/formal/trace-validation.json"
    trace_bindings_path = repo / "target/formal/receipt-trace/bindings.json"
    trace_report = json.loads(trace_report_path.read_text(encoding="utf-8"))
    trace_bindings = json.loads(trace_bindings_path.read_text(encoding="utf-8"))
    if trace_report.get("schema") != "chio.trace-validation.v1":
        fail("trace validation report schema is invalid")
    if trace_report.get("status") != "passed" or trace_report.get("invariants") != TRACE_INVARIANTS:
        fail("trace validation report is not a passing exact-invariant result")
    action_coverage = trace_report.get("actionCoverage")
    witnesses = trace_report.get("invariantWitnesses")
    if not isinstance(action_coverage, dict) or action_coverage.get("revoke", 0) < 1 or action_coverage.get("postRevocationEvaluate", 0) < 1:
        fail("trace validation action coverage is vacuous")
    if not isinstance(witnesses, dict) or any(
        not isinstance(witnesses.get(name), int) or witnesses[name] < 1
        for name in TRACE_WITNESSES
    ):
        fail("trace validation invariant witnesses are vacuous")
    if trace_bindings.get("schema") != "chio.trace-artifact-bindings.v1" or trace_bindings.get("status") != "passed":
        fail("trace artifact binding record is invalid")
    binding_hashes = trace_bindings.get("artifactHashes")
    if not isinstance(binding_hashes, dict) or binding_hashes.get("report") != sha256_file(trace_report_path):
        fail("trace artifact binding record does not bind the validation report")
    trace_validation = {
        "result": "passed",
        "schema": trace_report["schema"],
        "spec": trace_report.get("spec"),
        "traceId": trace_report.get("traceId"),
        "traceLength": trace_report.get("traceLength"),
        "itfStateCount": trace_report.get("itfStateCount"),
        "invariants": trace_report["invariants"],
        "actionCoverage": action_coverage,
        "invariantWitnesses": witnesses,
        "checker": trace_report.get("checker"),
        "checkerBinarySha256": trace_report.get("checkerBinarySha256"),
        "timeoutBinarySha256": trace_report.get("timeoutBinarySha256"),
        "reportPath": "target/formal/trace-validation.json",
        "bindingsPath": "target/formal/receipt-trace/bindings.json",
        "negativeRegistryPath": "formal/tla/trace/negative-registry.toml",
    }

tool_versions = {
    "lean": command_output("lean --version"),
    "lake": command_output("lake --version"),
    "cargo": command_output("cargo --version"),
    "rustc": command_output("rustc --version"),
    "kani": command_output("cargo kani --version"),
    "creusot": command_output("cargo creusot version"),
    "aeneas": command_output("aeneas -version"),
    "charon": command_output("charon version"),
    "apalache": command_output(
        f"{shlex.quote(os.environ.get('APALACHE_BIN', 'apalache-mc'))} version"
    ),
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
    "traceValidation": trace_validation,
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
