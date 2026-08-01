#!/usr/bin/env python3
"""Fail on oversized hand-maintained Rust files and malformed generated Rust."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import subprocess
import sys


PRODUCTION_LIMIT = 2_000
LIB_ROOT_LIMIT = 1_000
WARN_LIMIT = 1_200
LIB_WARN_LIMIT = 900
TEST_LIMIT = 2_000
SUMMARY_LIMIT = 25
WIRE_GENERATED_PREFIX = "crates/core/chio-core-types/src/_generated/"
GENERATED_HEADER_SOURCE = "crates/tooling/chio-spec-codegen/src/lib.rs"
GENERATED_HEADER_CONST_MARKER = 'pub const GENERATED_HEADER: &str = "\\\n'
ERRORS_GENERATED_PREFIX = "crates/core/chio-errors/src/_generated/"
ERRORS_GENERATED_HEADER_SOURCE = "crates/tooling/chio-spec-codegen/src/errors_pass.rs"
ERRORS_GENERATED_HEADER_CONST_MARKER = 'const ERROR_CODES_GENERATED_HEADER: &str = "\\\n'
STATEMACHINE_GENERATED_PREFIXES = (
    "crates/tooling/chio-conformance/tests/_generated/",
    "crates/trust/chio-federation/src/_generated/",
)
STATEMACHINE_GENERATED_HEADER_SOURCE = (
    "crates/tooling/chio-spec-codegen/src/statemachines_pass.rs"
)
STATEMACHINE_GENERATED_HEADER_CONST_MARKER = (
    'const STATE_MACHINE_GENERATED_HEADER_PREFIX: &str = "\\\n'
)
TEXT_HYGIENE_PREFIXES = ("crates/", "docs/", "sdks/", "scripts/", "spec/", "xtask/")
TEXT_HYGIENE_SUFFIXES = (".rs", ".md")
TEXT_HYGIENE_PATTERNS = ("*.rs", "*.md")
EM_DASH = "\u2014"


@dataclass(frozen=True)
class AllowlistEntry:
    rationale: str
    expires: str
    max_lines: int | None = None


def allow(expires: str, rationale: str, *, max_lines: int | None = None) -> AllowlistEntry:
    return AllowlistEntry(rationale=rationale, expires=expires, max_lines=max_lines)


ALLOWLIST: dict[str, AllowlistEntry] = {
    "crates/products/chio-cli/tests/mcp_serve_http.rs": allow(
        "2026-08-31",
        "existing oversized CLI MCP HTTP integration suite; capped to current size until split",
        max_lines=6_316,
    ),
    "crates/products/chio-cli/tests/passport.rs": allow(
        "2026-08-31",
        "existing oversized CLI passport integration suite; capped to current size until split",
        max_lines=5_395,
    ),
    "crates/products/chio-cli/tests/mcp_serve.rs": allow(
        "2026-08-31",
        "existing oversized CLI MCP serve integration suite; capped to current size until split",
        max_lines=4_500,
    ),
    "crates/protocol/chio-mcp-edge/src/runtime/runtime_tests.rs": allow(
        "2026-08-31",
        "existing oversized MCP edge runtime test suite; capped to current size until split",
        max_lines=4_643,
    ),
    "crates/products/chio-cli/tests/certify.rs": allow(
        "2026-08-31",
        "existing oversized CLI certify integration suite; capped to current size until split",
        max_lines=3_645,
    ),
    "crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs": allow(
        "2026-08-31",
        "launch proof fixture dispatch surface; capped to current size until split",
        max_lines=6_360,
    ),
    "crates/products/chio-cli/src/cli/dispatch/proof.rs": allow(
        "2026-08-31",
        "launch proof dispatch surface; capped to current size until split",
        max_lines=3_445,
    ),
    "crates/products/chio-mercury/tests/cli.rs": allow(
        "2026-08-31",
        "existing oversized Mercury CLI integration suite; capped to current size until split",
        max_lines=3_264,
    ),
    "crates/products/chio-cli/tests/trust_cluster.rs": allow(
        "2026-08-31",
        "existing oversized CLI trust-cluster integration suite; capped to current size until split",
        max_lines=3_229,
    ),
    "crates/products/chio-api-protect/src/proxy/tests.rs": allow(
        "2026-08-31",
        "existing oversized API protect proxy test suite; capped to current size until split",
        max_lines=3_477,
    ),
    "crates/protocol/chio-acp-edge/src/tests/all.rs": allow(
        "2026-08-31",
        "existing oversized ACP edge aggregate test suite; capped to current size until split",
        max_lines=3_338,
    ),
    "crates/protocol/chio-a2a-edge/src/tests/all.rs": allow(
        "2026-08-31",
        "existing oversized A2A edge aggregate test suite; capped to current size until split",
        max_lines=3_207,
    ),
    "crates/products/chio-cli/tests/proof_cli_contract/support.rs": allow(
        "2026-08-31",
        "launch proof CLI contract support module; capped to current size until split",
        max_lines=4_072,
    ),
    "crates/products/chio-cli/tests/proof_verify.rs": allow(
        "2026-08-31",
        "launch proof verifier integration suite; capped to current size until split",
        max_lines=3_115,
    ),
    "crates/platform/chio-enterprise-export/tests/enterprise_export.rs": allow(
        "2026-08-31",
        "launch enterprise export integration suite; capped to current size until split",
        max_lines=2_724,
    ),
    "crates/products/chio-cli/tests/federated_issue.rs": allow(
        "2026-08-31",
        "existing oversized CLI federated issue integration suite; capped to current size until split",
        max_lines=2_333,
    ),
    "crates/trust/chio-credentials/src/tests.rs": allow(
        "2026-08-31",
        "existing oversized credentials test suite; capped to current size until split",
        max_lines=2_164,
    ),
    "crates/core/chio-core-types/src/capability/tests.rs": allow(
        "2026-08-31",
        "existing oversized capability type test suite; capped to current size until split; covers time-checked verification, attenuation narrowing, and wildcard/concrete reflection regressions",
        max_lines=3_296,
    ),
    "crates/kernel/chio-runtime-core/tests/runtime_buyer_review.rs": allow(
        "2026-08-31",
        "existing oversized runtime buyer review integration suite; capped to current size until split",
        max_lines=2_068,
    ),
    "crates/kernel/chio-runtime-core/tests/runtime_admission.rs": allow(
        "2026-08-31",
        "runtime admission integration suite; capped to current size after swarm authority split",
        max_lines=2_875,
    ),
    "crates/platform/chio-transaction-passport/tests/transaction_passport.rs": allow(
        "2026-08-31",
        "transaction passport integration suite with runtime-security and transparency-anchor review regressions; capped until split",
        max_lines=2_800,
    ),
    "crates/protocol/chio-mcp-remote/src/remote_mcp/tests.rs": allow(
        "2026-08-31",
        "existing oversized remote MCP test suite; capped to current size until split",
        max_lines=2_012,
    ),
    "crates/trust/chio-selective-disclosure/src/lib.rs": allow(
        "2026-08-31",
        "launch selective disclosure verifier surface; capped to current size until split",
        max_lines=1_355,
    ),
    "crates/platform/chio-risk-comptroller/src/lib.rs": allow(
        "2026-08-31",
        "launch risk comptroller verifier surface; capped to current size until split",
        max_lines=1_356,
    ),
    "crates/economy/chio-web3/src/tests.rs": allow(
        "2026-08-31",
        "web3 test module with public-settlement review regressions; capped until split",
        max_lines=2_697,
    ),
    "crates/kernel/chio-runtime-proof-parity/src/lib.rs": allow(
        "2026-08-31",
        "runtime proof parity surface; capped to current size until split",
        max_lines=1_058,
    ),
    "crates/kernel/chio-swarm-authority/src/verifier.rs": allow(
        "2026-08-31",
        "swarm authority verifier surface; capped to current size until split",
        max_lines=2_279,
    ),
    "crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs": allow(
        "2026-08-31",
        "runtime security artifact verifier with trusted join and overflow hardening; capped until split",
        max_lines=2_322,
    ),
    "crates/products/chio-cli/tests/proof_cli_contract/fixture.rs": allow(
        "2026-08-31",
        "launch proof CLI fixture contract suite; capped to current size until split",
        max_lines=2_210,
    ),
    "crates/products/chio-cli/tests/proof_verify/support.rs": allow(
        "2026-08-31",
        "launch proof verifier support module; capped to current size until split",
        max_lines=2_260,
    ),
    "crates/products/chio-proof-room/src/lib.rs": allow(
        "2026-08-31",
        "Proof Room product surface; capped to current size until split",
        max_lines=1_196,
    ),
    "crates/economy/chio-settle/src/evm/tests.rs": allow(
        "2026-08-31",
        "EVM settlement unit test module with anchor content-hash regression coverage; capped until split",
        max_lines=2_388,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/chio_runtime.rs": allow(
        "2026-08-31",
        "existing oversized kernel runtime test suite; capped to current size until split",
        max_lines=4_817,
    ),
    "crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs": allow(
        "2026-08-31",
        "pheromone iroh mount dispatch surface; capped to current size until split",
        max_lines=3_411,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store.rs": allow(
        "2026-08-31",
        "receipt store hot-path module after batch-bounded rework; capped to current size until split",
        max_lines=5_375,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/tests/retention.rs": allow(
        "2026-08-31",
        "receipt retention regression suite; capped to current size until split",
        max_lines=4_632,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/pheromone.rs": allow(
        "2026-08-31",
        "iroh pheromone lane; capped to current size until split",
        max_lines=2_830,
    ),
    "crates/platform/chio-control-plane/src/trust_control/cluster_and_reports.rs": allow(
        "2026-08-31",
        "trust-control cluster and reports surface; capped to current size until split",
        max_lines=2_746,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/tests.rs": allow(
        "2026-08-31",
        "existing oversized budget store test suite; capped to current size until split",
        max_lines=2_657,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs": allow(
        "2026-08-31",
        "iroh revocation lane; capped to current size until split",
        max_lines=2_511,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs": allow(
        "2026-08-31",
        "iroh fanout lane; capped to current size until split",
        max_lines=2_443,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/support.rs": allow(
        "2026-08-31",
        "existing oversized kernel test support module; capped to current size until split",
        max_lines=2_331,
    ),
    "crates/economy/chio-web3/src/settlement_proof.rs": allow(
        "2026-08-31",
        "web3 settlement proof surface; capped to current size until split",
        max_lines=2_067,
    ),
    "crates/products/chio-wall/src/commands.rs": allow(
        "2026-08-31",
        "wall command surface; capped to current size until split",
        max_lines=2_048,
    ),
    "crates/platform/chio-http-session/src/lib.rs": allow(
        "2026-08-31",
        "shared HTTP session crate root; capped to current size until split",
        max_lines=1_103,
    ),
    "crates/economy/chio-credit/src/obligation/credit_admission.rs": allow(
        "2026-08-31",
        "authoritative credit admission surface; capped to current size until split",
        max_lines=2_042,
    ),
    "crates/economy/chio-market/src/tests.rs": allow(
        "2026-08-31",
        "market admission and quote test suite; capped to current size until split",
        max_lines=2_747,
    ),
    "crates/economy/chio-settle/src/channel/tests/support.rs": allow(
        "2026-08-31",
        "settlement channel test support module; capped to current size until split",
        max_lines=2_030,
    ),
    "crates/kernel/chio-kernel/src/admission_operation_tests.rs": allow(
        "2026-08-31",
        "durable admission operation regression suite with authoritative outcome binding coverage; capped to current size until split",
        max_lines=2_359,
    ),
    "crates/kernel/chio-kernel/src/admission_operation/projection.rs": allow(
        "2026-08-31",
        "durable admission projection surface with authoritative outcome bindings; capped to current size until split",
        max_lines=2_151,
    ),
    "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs": allow(
        "2026-08-31",
        "durable terminal coordinator with signed outcome projection; capped to current size until split",
        max_lines=2_320,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/budget.rs": allow(
        "2026-08-31",
        "kernel budget and monetary evaluation regression suite; capped to current size until split",
        max_lines=2_017,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission.rs": allow(
        "2026-08-31",
        "durable kernel admission regression suite; capped to current size until split",
        max_lines=2_795,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/execution_nonce.rs": allow(
        "2026-08-31",
        "execution nonce regression suite; capped to current size until split",
        max_lines=3_395,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/session.rs": allow(
        "2026-08-31",
        "kernel session regression suite; capped to current size until split",
        max_lines=2_083,
    ),
    "crates/kernel/chio-kernel/src/kernel/validation.rs": allow(
        "2026-08-31",
        "kernel capability and admission validation surface; capped to current size until split",
        max_lines=2_900,
    ),
    "crates/platform/chio-control-plane/src/lib.rs": allow(
        "2026-08-31",
        "control-plane crate root; capped to current size until split",
        max_lines=1_039,
    ),
    "crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs": allow(
        "2026-08-31",
        "capital liability control surface; capped to current size until split",
        max_lines=2_166,
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_market_exit_tests.rs": allow(
        "2026-08-31",
        "cognition market exit regression suite; capped to current size until split",
        max_lines=2_428,
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_wedge_purchase_e2e_tests.rs": allow(
        "2026-08-31",
        "cognition purchase and recovery end-to-end regression suite; capped to current size until split",
        max_lines=4_662,
    ),
    "crates/platform/chio-store-sqlite/src/admission_operation_store/factor_assignment.rs": allow(
        "2026-08-31",
        "admission factor assignment store surface; capped to current size until split",
        max_lines=2_246,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite_schema.rs": allow(
        "2026-08-31",
        "durable composite budget schema and migration surface; capped to current size until split",
        max_lines=2_104,
    ),
    "crates/platform/chio-store-sqlite/src/finding_market_store.rs": allow(
        "2026-08-31",
        "cognition finding market authority store; capped to current size until split",
        max_lines=2_017,
    ),
    "crates/platform/chio-store-sqlite/src/finding_purchase_store.rs": allow(
        "2026-08-31",
        "cognition purchase and recovery authority store; capped to current size until split",
        max_lines=2_025,
    ),
    "crates/platform/chio-store-sqlite/src/fiscal_store.rs": allow(
        "2026-08-31",
        "fiscal persistence surface; capped to current size until split",
        max_lines=2_937,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/tests/support.rs": allow(
        "2026-08-31",
        "receipt store test support module; capped to current size until split",
        max_lines=2_050,
    ),
    "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs": allow(
        "2026-08-31",
        "serving-owner commit chain persistence surface; capped to current size until split",
        max_lines=2_155,
    ),
    "crates/platform/chio-store-sqlite/src/serving_owner/tests.rs": allow(
        "2026-08-31",
        "serving-owner provisioning test suite; capped to current size until split",
        max_lines=2_075,
    ),
    "crates/products/chio-api-protect/src/proxy/mediated.rs": allow(
        "2026-08-31",
        "mediated API protection proxy surface; capped to current size until split",
        max_lines=3_574,
    ),
}


@dataclass(frozen=True)
class RustFile:
    path: str
    lines: int
    category: str
    violations: tuple[str, ...]
    allowlist: AllowlistEntry | None


@dataclass(frozen=True)
class GeneratedHeaderSpec:
    prefix: str
    source: str
    const_marker: str
    label: str


GENERATED_HEADER_SPECS = (
    GeneratedHeaderSpec(
        prefix=WIRE_GENERATED_PREFIX,
        source=GENERATED_HEADER_SOURCE,
        const_marker=GENERATED_HEADER_CONST_MARKER,
        label="chio_spec_codegen::GENERATED_HEADER",
    ),
    GeneratedHeaderSpec(
        prefix=ERRORS_GENERATED_PREFIX,
        source=ERRORS_GENERATED_HEADER_SOURCE,
        const_marker=ERRORS_GENERATED_HEADER_CONST_MARKER,
        label="chio_spec_codegen::errors_pass::ERROR_CODES_GENERATED_HEADER",
    ),
    *(
        GeneratedHeaderSpec(
            prefix=prefix,
            source=STATEMACHINE_GENERATED_HEADER_SOURCE,
            const_marker=STATEMACHINE_GENERATED_HEADER_CONST_MARKER,
            label="chio_spec_codegen::statemachines_pass::STATE_MACHINE_GENERATED_HEADER_PREFIX",
        )
        for prefix in STATEMACHINE_GENERATED_PREFIXES
    ),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover_rust_files(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "*.rs",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line and (root / line).is_file()
    ]


def discover_text_hygiene_files(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *TEXT_HYGIENE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line
        and (root / line).is_file()
        and line.startswith(TEXT_HYGIENE_PREFIXES)
        and line.endswith(TEXT_HYGIENE_SUFFIXES)
        and "/_generated/" not in f"/{line}/"
    ]


def line_count(path: Path) -> int:
    data = path.read_bytes()
    return data.count(b"\n")


def load_generated_header(root: Path, spec: GeneratedHeaderSpec) -> str | None:
    source = root / spec.source
    if not source.exists():
        return None
    text = source.read_text()
    start = text.find(spec.const_marker)
    if start == -1:
        return None
    start += len(spec.const_marker)
    end = text.find('";', start)
    if end == -1:
        return None
    return text[start:end]


def classify(path: str) -> str:
    parts = path.split("/")
    name = parts[-1]
    if "/_generated/" in f"/{path}/":
        return "generated"
    if path.startswith("examples/") or "/examples/" in f"/{path}/":
        return "example"
    if (
        path.startswith("tests/")
        or "/tests/" in f"/{path}/"
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.endswith("_test.rs")
        or name.endswith("_tests_support.rs")
        or name.endswith("_test_support.rs")
    ):
        return "test"
    return "production"


def is_lib_root(path: str) -> bool:
    return path.endswith("/src/lib.rs")


def validate_allowlist(errors: list[str]) -> None:
    for path, entry in sorted(ALLOWLIST.items()):
        if not entry.rationale.strip():
            errors.append(f"{path}: allowlist entry has an empty rationale")
        if not entry.expires.strip():
            errors.append(f"{path}: allowlist entry has an empty expiry date")
            continue
        try:
            expires_on = date.fromisoformat(entry.expires)
        except ValueError:
            errors.append(
                f"{path}: allowlist entry expiry {entry.expires!r} is not an ISO date"
            )
            continue
        if expires_on < date.today():
            errors.append(f"{path}: allowlist entry expired on {entry.expires}")
        if entry.max_lines is not None and entry.max_lines <= 0:
            errors.append(f"{path}: allowlist entry has a non-positive max_lines cap")


def validate_generated_headers(
    root: Path,
    paths: list[str],
    failures: list[str],
) -> None:
    generated_paths = [path for path in paths if classify(path) == "generated"]
    if not generated_paths:
        return
    covered_paths: set[str] = set()
    for spec in GENERATED_HEADER_SPECS:
        spec_paths = [
            path
            for path in generated_paths
            if path.startswith(spec.prefix) and path.endswith(".rs")
        ]
        if not spec_paths:
            continue
        header = load_generated_header(root, spec)
        if header is None:
            failures.append(f"{spec.source}: could not read {spec.label}")
            continue
        for path in spec_paths:
            covered_paths.add(path)
            try:
                body = (root / path).read_text()
            except OSError as err:
                failures.append(f"{path}: could not read generated Rust file: {err}")
                continue
            if not body.startswith(header):
                failures.append(
                    f"{path}: generated Rust file does not begin with {spec.label}"
                )

    for path in generated_paths:
        if path not in covered_paths:
            failures.append(
                f"{path}: generated Rust path is not covered by a known generator header check"
            )


def validate_rust_example_packages(
    root: Path,
    paths: list[str],
    failures: list[str],
) -> None:
    checked: set[str] = set()
    for path in paths:
        parts = Path(path).parts
        if len(parts) < 4 or parts[0] != "examples" or parts[2] != "src":
            continue
        example = str(Path(parts[0]) / parts[1])
        if example in checked:
            continue
        checked.add(example)
        if not (root / example / "Cargo.toml").is_file():
            failures.append(
                f"{example}: contains Rust src files but has no Cargo.toml"
            )


def validate_text_hygiene(root: Path, failures: list[str]) -> None:
    try:
        paths = discover_text_hygiene_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        failures.append(f"failed to list text hygiene files under {root}: {stderr}")
        return

    for path in sorted(paths):
        try:
            text = (root / path).read_text(encoding="utf-8")
        except UnicodeDecodeError as err:
            failures.append(f"{path}: could not decode text hygiene file: {err}")
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            column = line.find(EM_DASH)
            if column != -1:
                failures.append(f"{path}:{index}:{column + 1}: contains U+2014 em dash")
                break


def inspect_file(root: Path, path: str) -> RustFile:
    lines = line_count(root / path)
    category = classify(path)
    violations: list[str] = []
    if category == "production" and lines > PRODUCTION_LIMIT:
        violations.append(
            f"production file has {lines} lines, limit is {PRODUCTION_LIMIT}"
        )
    if category == "production" and is_lib_root(path) and lines > LIB_ROOT_LIMIT:
        violations.append(f"src/lib.rs has {lines} lines, limit is {LIB_ROOT_LIMIT}")
    if category == "test" and lines > TEST_LIMIT:
        violations.append(f"test file has {lines} lines, limit is {TEST_LIMIT}")
    allowlist = ALLOWLIST.get(path)
    if allowlist and allowlist.max_lines is not None and lines > allowlist.max_lines:
        violations.append(
            f"allowlisted file has {lines} lines, cap is {allowlist.max_lines}"
        )
    return RustFile(
        path=path,
        lines=lines,
        category=category,
        violations=tuple(violations),
        allowlist=allowlist,
    )


def warning_for_file(file: RustFile) -> str | None:
    if file.category != "production":
        return None
    if is_lib_root(file.path):
        if LIB_WARN_LIMIT < file.lines <= LIB_ROOT_LIMIT:
            return (
                f"warning: {file.path} has {file.lines} lines, "
                f"warn limit is {LIB_WARN_LIMIT}"
            )
        return None
    if WARN_LIMIT < file.lines <= PRODUCTION_LIMIT:
        return (
            f"warning: {file.path} has {file.lines} lines, "
            f"warn limit is {WARN_LIMIT}"
        )
    return None


def print_summary(files: list[RustFile]) -> None:
    categories = ["generated", "production", "test", "example"]
    print("Rust file hygiene summary")
    for category in categories:
        category_files = sorted(
            (file for file in files if file.category == category),
            key=lambda file: (-file.lines, file.path),
        )
        if not category_files:
            continue
        print(f"\n==> {category} top {min(SUMMARY_LIMIT, len(category_files))}")
        for file in category_files[:SUMMARY_LIMIT]:
            marker = ""
            if file.violations and file.allowlist:
                marker = f" allowlisted until {file.allowlist.expires}"
            elif file.violations:
                marker = " violation"
            print(f"{file.lines:5d} {file.path}{marker}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Rust source file line-count hygiene."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=repo_root(),
        help="repository root to inspect",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    errors: list[str] = []
    validate_allowlist(errors)

    try:
        paths = discover_rust_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        print(f"failed to list Rust files under {root}: {stderr}", file=sys.stderr)
        return 1

    files = [inspect_file(root, path) for path in paths]
    print_summary(files)

    warnings = [
        warning
        for warning in (
            warning_for_file(file) for file in sorted(files, key=lambda item: item.path)
        )
        if warning is not None
    ]
    if warnings:
        print(
            f"\nRust file hygiene warnings: {len(warnings)} files exceed warning limits"
        )
        for warning in warnings:
            print(warning)

    failures: list[str] = []
    for file in sorted(files, key=lambda candidate: candidate.path):
        if not file.violations:
            continue
        if file.allowlist:
            uncovered = []
            if file.category == "test" and file.lines > TEST_LIMIT:
                if file.allowlist.max_lines is None:
                    uncovered.append(
                        "oversized test allowlist entry must set a max_lines cap"
                    )
            uncovered.extend(
                violation
                for violation in file.violations
                if violation.startswith("allowlisted file has ")
            )
            if uncovered:
                for violation in uncovered:
                    failures.append(f"{file.path}: {violation}")
                continue
            print(
                f"allowlisted: {file.path}: {file.allowlist.rationale}; "
                f"expires {file.allowlist.expires}; "
                f"max_lines {file.allowlist.max_lines or 'uncapped'}"
            )
            continue
        for violation in file.violations:
            failures.append(f"{file.path}: {violation}")

    validate_generated_headers(root, paths, failures)
    validate_rust_example_packages(root, paths, failures)
    validate_text_hygiene(root, failures)

    if errors:
        failures.extend(errors)

    if failures:
        print("\nRust file hygiene failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nRust file hygiene check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
