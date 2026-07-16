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
    "target/formal/aeneas-production/economy/llbc/formal_economy.llbc",
    "target/formal/aeneas-production/economy/lean/Funs.lean",
    "target/formal/aeneas-production/economy/lean/Types.lean",
    "target/formal/aeneas-production/equivalence-artifacts.json",
    "target/formal/aeneas-production/negative-tests.json",
}
TRACE_TRACKED_ARTIFACTS = {
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
}
TRACE_GENERATED_ARTIFACTS = {
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
}
for _slug in ("", "-monotone", "-attenuation", "-freshness"):
    _base = f"target/formal/receipt-trace/runtime-negative{_slug}"
    TRACE_GENERATED_ARTIFACTS.update(
        {
            f"{_base}.ndjson",
            f"{_base}.itf.json",
            f"{_base}-witness.itf.json",
            f"{_base}-report.json",
            f"{_base}.log",
        }
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
RUST_VERIFICATION_STATIC_INPUTS = {
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
    "apalache": f"{shlex.quote(os.environ.get('APALACHE_BIN', 'apalache-mc'))} version",
}


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


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_object(
    value: Any, expected_keys: set[str], label: str
) -> dict[str, Any]:
    obj = require_object(value, label)
    if set(obj) != expected_keys:
        fail(
            f"{label} key set mismatch: "
            f"missing={sorted(expected_keys - set(obj))} "
            f"extra={sorted(set(obj) - expected_keys)}"
        )
    return obj


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
    value = require_exact_object(record, {"command", "exitCode", "output"}, label)
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
    "traceValidation",
}
missing = sorted(required_top - set(report))
extra = sorted(set(report) - required_top)
if missing or extra:
    fail(f"top-level key set mismatch: missing={missing} extra={extra}")
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
    result = require_exact_object(
        result,
        {"command", "status", "exitCode", "outputTail"},
        f"gateResults[{index}]",
    )
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
    if not isinstance(result["outputTail"], str):
        fail(f"gate outputTail must be a string: {command}")
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

claim_gate = require_exact_object(
    report.get("claimGate"),
    {"claimRegistry", "inputs", "requiredTerms", "status"},
    "claimGate",
)
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
    "scripts/lean-assumption-audit.lean",
    "scripts/tests/lean-assumption-audit.test.sh",
    "scripts/check-aeneas-production.sh",
    "scripts/check-aeneas-equivalence.sh",
    "scripts/check-rust-verification-gates.sh",
    "scripts/check-kani-core.sh",
    "scripts/check-kani-public-core.sh",
    "scripts/run-kani-manifest.sh",
    ".kani/harnesses.toml",
    "scripts/check-creusot-core.sh",
    "scripts/check-adapter-no-bypass.sh",
    ADAPTER_SOURCE_INVENTORY,
    "xtask/src/adapter_no_bypass.rs",
    "xtask/src/cli.rs",
    "xtask/src/dispatch.rs",
    "xtask/src/error.rs",
    "xtask/src/main.rs",
    "xtask/src/support.rs",
    "xtask/Cargo.toml",
    ".cargo/config.toml",
    "Cargo.lock",
    "scripts/generate-proof-report.sh",
    "scripts/check-proof-report.sh",
    str(manifest.get("claim_registry")),
}
tracked_paths.update(TRACE_TRACKED_ARTIFACTS)
tracked_paths.update(RUST_VERIFICATION_STATIC_INPUTS)
tracked_paths.update(manifest.get("claim_gate_inputs", []))
tracked_paths.update(manifest.get("root_modules", []))
tracked_paths.update(manifest.get("covered_rust_modules", []))
tracked_paths.update(discover_adapter_gate_sources(repo))
tracked_paths.update(discover_kani_target_sources(repo))
for command in expected_commands:
    words = shlex.split(command)
    if words and words[0].startswith("./"):
        tracked_paths.add(words[0].removeprefix("./"))
artifact_hashes = require_exact_object(
    report.get("artifactHashes"), {"tracked", "generated"}, "artifactHashes"
)
check_hash_map(artifact_hashes.get("tracked"), tracked_paths, "tracked hashes", repo)
generated_paths = {"target/formal/coverage.json"}
if mode == "strict":
    generated_paths.update(AENEAS_ARTIFACTS)
    generated_paths.update(TRACE_GENERATED_ARTIFACTS)
generated_hashes = check_hash_map(
    artifact_hashes.get("generated"), generated_paths, "generated hashes", repo
)

if mode == "strict":
    negative_registry_path = repo / "formal/aeneas/negative-tests.toml"
    negative_report_path = repo / "target/formal/aeneas-production/negative-tests.json"
    negative_registry_bytes = negative_registry_path.read_bytes()
    negative_registry = tomllib.loads(negative_registry_bytes.decode("utf-8"))
    negative_report = json.loads(negative_report_path.read_text(encoding="utf-8"))
    if negative_registry.get("schema") != "chio.aeneas-negative-tests.v1":
        fail("Aeneas negative-test registry schema is invalid")
    if negative_report.get("schema") != "chio.aeneas-negative-tests-report.v1":
        fail("Aeneas negative-test report schema is invalid")
    if negative_report.get("registry") != "formal/aeneas/negative-tests.toml":
        fail("Aeneas negative-test report registry path is invalid")
    if negative_report.get("registrySha256") != hashlib.sha256(negative_registry_bytes).hexdigest():
        fail("Aeneas negative-test report is not bound to its registry")
    expected_negative_results = [
        {
            "name": mutation["name"],
            "status": "killed",
            "expectedGate": mutation["expected_gate"],
            "expectedEvidence": mutation["expected_evidence"],
        }
        for mutation in negative_registry.get("mutation", [])
    ]
    actual_negative_results = negative_report.get("results")
    if not isinstance(actual_negative_results, list) or len(actual_negative_results) != len(expected_negative_results):
        fail("Aeneas negative-test report inventory is incomplete")
    for actual, expected in zip(actual_negative_results, expected_negative_results, strict=True):
        if not isinstance(actual, dict):
            fail("Aeneas negative-test report contains a malformed result")
        if any(actual.get(key) != value for key, value in expected.items()):
            fail("Aeneas negative-test report result does not match its registry")
        if not re.fullmatch(r"[0-9a-f]{64}", actual.get("logSha256", "")):
            fail("Aeneas negative-test report contains an invalid log hash")

proof_coverage = require_exact_object(
    report.get("proofCoverage"), {"path", "sha256"}, "proofCoverage"
)
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

trace_validation = require_object(report.get("traceValidation"), "traceValidation")
if mode == "metadata_only":
    if trace_validation != {"result": "not_run"}:
        fail("metadata-only traceValidation must be exactly not_run")
else:
    trace_report_path = repo / "target/formal/trace-validation.json"
    trace_bindings_path = repo / "target/formal/receipt-trace/bindings.json"
    trace_report = require_object(
        json.loads(trace_report_path.read_text(encoding="utf-8")), "trace report"
    )
    trace_bindings = require_object(
        json.loads(trace_bindings_path.read_text(encoding="utf-8")), "trace bindings"
    )
    if trace_report.get("schema") != "chio.trace-validation.v1" or trace_report.get("status") != "passed":
        fail("strict trace report is not a passing v2 report")
    if trace_report.get("invariants") != TRACE_INVARIANTS:
        fail("strict trace report invariant set is not exact")
    action_coverage = require_object(trace_report.get("actionCoverage"), "trace actionCoverage")
    witnesses = require_object(trace_report.get("invariantWitnesses"), "trace invariantWitnesses")
    if action_coverage.get("revoke", 0) < 1 or action_coverage.get("postRevocationEvaluate", 0) < 1:
        fail("strict trace report is action-vacuous")
    if any(
        not isinstance(witnesses.get(name), int) or witnesses[name] < 1
        for name in TRACE_WITNESSES
    ):
        fail("strict trace report is invariant-vacuous")
    if trace_bindings.get("schema") != "chio.trace-artifact-bindings.v1" or trace_bindings.get("status") != "passed":
        fail("strict trace binding record is invalid")
    binding_hashes = require_object(trace_bindings.get("artifactHashes"), "trace binding hashes")
    if binding_hashes.get("report") != sha256_file(trace_report_path):
        fail("strict trace binding record does not bind the report")
    binding_paths = require_object(trace_bindings.get("artifactPaths"), "trace binding paths")
    if set(binding_paths) != set(binding_hashes):
        fail("strict trace binding path and hash labels differ")
    expected_bound_paths = TRACE_GENERATED_ARTIFACTS - {
        "target/formal/receipt-trace/bindings.json"
    }
    expected_bound_paths.update(
        {
            "formal/tla/RevocationPropagation.tla",
            "formal/tla/trace/TraceCheckRevocationPropagation.tla",
            "formal/tla/trace/TraceEvaluateRevocationPropagation.tla",
            "formal/tla/trace/fixtures/native-conformance-observer-key.txt",
            "formal/tla/trace/negative-registry.toml",
        }
    )
    for executable_label in ("checkerBinary", "timeoutBinary"):
        executable_path = binding_paths.get(executable_label)
        if not isinstance(executable_path, str) or not Path(executable_path).is_absolute():
            fail(f"strict trace binding {executable_label} path is not absolute")
    actual_bound_paths = {
        value
        for name, value in binding_paths.items()
        if name not in {"checkerBinary", "timeoutBinary"} and isinstance(value, str)
    }
    if actual_bound_paths != expected_bound_paths or len(actual_bound_paths) != len(binding_paths) - 2:
        fail("strict trace binding does not cover the exact trace artifact set")
    for name, raw_path in binding_paths.items():
        if not isinstance(raw_path, str):
            fail(f"strict trace binding path is invalid: {name}")
        artifact_path = Path(raw_path)
        if not artifact_path.is_absolute():
            artifact_path = repo / artifact_path
        if artifact_path.is_symlink() or not artifact_path.is_file():
            fail(f"strict trace bound artifact is missing or symlinked: {name}")
        digest = binding_hashes.get(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"strict trace binding hash is invalid: {name}")
        if sha256_file(artifact_path) != digest:
            fail(f"strict trace binding hash does not match disk: {name}")
    expected_trace_validation = {
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
    if trace_validation != expected_trace_validation:
        fail("traceValidation does not match its bound trace artifacts")
    negative_reports = {
        "NoAllowAfterRevoke": "target/formal/receipt-trace/runtime-negative-report.json",
        "MonotoneLog": "target/formal/receipt-trace/runtime-negative-monotone-report.json",
        "AttenuationPreserving": "target/formal/receipt-trace/runtime-negative-attenuation-report.json",
        "RevocationFreshness": "target/formal/receipt-trace/runtime-negative-freshness-report.json",
    }
    for invariant, relative_path in negative_reports.items():
        negative = require_object(
            json.loads((repo / relative_path).read_text(encoding="utf-8")),
            f"negative trace report {invariant}",
        )
        divergence = require_object(
            negative.get("divergence"), f"negative trace divergence {invariant}"
        )
        evaluation = require_object(
            divergence.get("apalacheEvaluation"),
            f"negative trace Apalache evaluation {invariant}",
        )
        if (
            negative.get("schema") != "chio.trace-validation.v1"
            or negative.get("status") != "failed"
            or divergence.get("failedConjunct") != invariant
            or evaluation.get(invariant) is not False
        ):
            fail(f"registered runtime negative does not falsify {invariant}")

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
expected_ci_keys = {"githubRunId", "githubSha", "githubRefName"}
if set(ci) != expected_ci_keys:
    fail(
        "ci key set mismatch: "
        f"missing={sorted(expected_ci_keys - set(ci))} "
        f"extra={sorted(set(ci) - expected_ci_keys)}"
    )
if any(value is not None and not isinstance(value, str) for value in ci.values()):
    fail("ci values must be strings or null")
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
