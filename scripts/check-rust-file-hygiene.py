#!/usr/bin/env python3
"""Fail on oversized hand-maintained Rust files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys


PRODUCTION_LIMIT = 2_000
LIB_ROOT_LIMIT = 1_000
SUMMARY_LIMIT = 25


@dataclass(frozen=True)
class AllowlistEntry:
    rationale: str
    expires: str


def allow(phase: str, rationale: str) -> AllowlistEntry:
    return AllowlistEntry(rationale=rationale, expires=phase)


ALLOWLIST: dict[str, AllowlistEntry] = {
    "crates/chio-governance/src/lib.rs": allow(
        "Phase 1.1", "baseline lib root split target"
    ),
    "crates/chio-open-market/src/lib.rs": allow(
        "Phase 1.2", "baseline lib root split target"
    ),
    "crates/chio-web3/src/lib.rs": allow(
        "Phase 1.3", "baseline lib root split target"
    ),
    "crates/chio-attest-buyer-core/src/lib.rs": allow(
        "Phase 2.1", "baseline lib root split target"
    ),
    "crates/chio-federation/src/lib.rs": allow(
        "Phase 2.2", "baseline lib root split target"
    ),
    "crates/chio-cross-protocol/src/lib.rs": allow(
        "Phase 2.3", "baseline lib root split target"
    ),
    "crates/chio-mcp-adapter/src/lib.rs": allow(
        "Phase 2.4", "baseline lib root split target"
    ),
    "crates/chio-core-types/src/capability.rs": allow(
        "Phase 3.1", "baseline core protocol split target"
    ),
    "crates/chio-core-types/src/receipt.rs": allow(
        "Phase 3.2", "baseline core protocol split target"
    ),
    "crates/chio-control-plane/src/trust_control/service_runtime.rs": allow(
        "Phase 4.1", "baseline trust-control runtime split target"
    ),
    "crates/chio-control-plane/src/trust_control/cluster_and_reports.rs": allow(
        "Phase 4.2", "baseline trust-control cluster/report split target"
    ),
    "crates/chio-cli/src/cli/types.rs": allow(
        "Phase 4.3", "baseline CLI schema split target"
    ),
    "crates/chio-cli/src/cli/trust_commands.rs": allow(
        "Phase 4.3", "baseline CLI handler split target"
    ),
    "crates/chio-wasm-guards/src/runtime.rs": allow(
        "Phase 5.1", "baseline wasm runtime split target"
    ),
    "crates/chio-mcp-edge/src/runtime.rs": allow(
        "Phase 5.2", "baseline MCP edge runtime split target"
    ),
    "crates/chio-api-protect/src/proxy.rs": allow(
        "Phase 5.3", "baseline API protect proxy split target"
    ),
    "crates/chio-store-sqlite/src/budget_store.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-control-plane/src/attestation.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-control-plane/src/policy.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-control-plane/src/evidence_export.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-control-plane/src/certify.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-control-plane/src/trust_control/capital_and_liability.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-control-plane/src/trust_control/service_types.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-control-plane/src/trust_control/underwriting_and_support.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-control-plane/src/trust_control/credit_and_loss.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-control-plane/src/trust_control/config_and_public.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-federation/src/bilateral_verifier.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-federation/src/bilateral_dsse.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-mcp-remote/src/remote_mcp/session_core.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-mcp-remote/src/remote_mcp/http_service.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-kernel/src/kernel/validation.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-kernel/src/budget_store.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-kernel/src/kernel/mod.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-kernel/src/session.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-kernel/src/receipt_support.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-policy/src/models.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-core/src/extension.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-http-core/src/authority.rs": allow(
        "Phase 6.1", "baseline remaining production hotspot"
    ),
    "crates/chio-cli/src/passport.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-cli/src/cli/runtime.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-core-types/src/session.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "crates/chio-mercury/src/commands/core_cli.rs": allow(
        "Phase 6.1", "baseline current production hotspot"
    ),
    "xtask/src/main.rs": allow("Phase 6.1", "baseline xtask dispatcher split target"),
    "crates/chio-autonomy/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-attest-loopback/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-runtime/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-pheromone/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-appraisal/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-egress-contract/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-federation-authority/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-listing/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-pheromone-runtime/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-kernel-browser/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-underwriting/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-credit/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-market/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-openai/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-link/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-openapi-mcp-bridge/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-cpp-kernel-ffi/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-groq-tools-adapter/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-selective-disclosure/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
    "crates/chio-mistral-tools-adapter/src/lib.rs": allow(
        "Phase 6.2", "baseline remaining lib root split target"
    ),
}


@dataclass(frozen=True)
class RustFile:
    path: str
    lines: int
    category: str
    violations: tuple[str, ...]
    allowlist: AllowlistEntry | None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def tracked_rust_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.rs"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def line_count(path: Path) -> int:
    data = path.read_bytes()
    return data.count(b"\n")


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
            errors.append(f"{path}: allowlist entry has an empty expiry phase")


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
    return RustFile(
        path=path,
        lines=lines,
        category=category,
        violations=tuple(violations),
        allowlist=ALLOWLIST.get(path),
    )


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
        paths = tracked_rust_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        print(f"failed to list tracked Rust files under {root}: {stderr}", file=sys.stderr)
        return 1

    files = [inspect_file(root, path) for path in paths]
    print_summary(files)

    failures: list[str] = []
    for file in sorted(files, key=lambda candidate: candidate.path):
        if not file.violations:
            continue
        if file.allowlist:
            print(
                f"allowlisted: {file.path}: {file.allowlist.rationale}; "
                f"expires {file.allowlist.expires}"
            )
            continue
        for violation in file.violations:
            failures.append(f"{file.path}: {violation}")

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
