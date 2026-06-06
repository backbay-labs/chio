#!/usr/bin/env python3
"""Fail on oversized hand-maintained Rust files and malformed generated Rust."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys


PRODUCTION_LIMIT = 2_000
LIB_ROOT_LIMIT = 1_000
SUMMARY_LIMIT = 25
WIRE_GENERATED_PREFIX = "crates/chio-core-types/src/_generated/"
GENERATED_HEADER_SOURCE = "crates/chio-spec-codegen/src/lib.rs"
GENERATED_HEADER_CONST_MARKER = 'pub const GENERATED_HEADER: &str = "\\\n'
ERRORS_GENERATED_PREFIX = "crates/chio-errors/src/_generated/"
ERRORS_GENERATED_HEADER_SOURCE = "crates/chio-spec-codegen/src/errors_pass.rs"
ERRORS_GENERATED_HEADER_CONST_MARKER = 'const ERROR_CODES_GENERATED_HEADER: &str = "\\\n'


@dataclass(frozen=True)
class AllowlistEntry:
    rationale: str
    expires: str


def allow(phase: str, rationale: str) -> AllowlistEntry:
    return AllowlistEntry(rationale=rationale, expires=phase)


ALLOWLIST: dict[str, AllowlistEntry] = {}


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
)


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
            errors.append(f"{path}: allowlist entry has an empty expiry phase")


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

    validate_generated_headers(root, paths, failures)

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
