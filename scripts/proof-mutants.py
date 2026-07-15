#!/usr/bin/env python3

"""Score cargo-mutants model mutations with Kani in a scratch worktree."""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "chio.proof-mutants-report.v1"
EXPECTED_CARGO_MUTANTS = "cargo-mutants 25.3.1"
EXPECTED_KANI = "0.67.0"
EXPECTED_RUSTC = "1.93.0"
CONFIG = Path("formal/rust-verification/formal-mutants.toml")
FILES = (
    Path("crates/kernel/chio-kernel-core/src/formal_core.rs"),
    Path("crates/kernel/chio-kernel-core/src/formal_aeneas.rs"),
)
SHARDS = ("0/3", "1/3", "2/3")
DEFAULT_SAMPLE_SIZE = 15
DEFAULT_TIMEOUT_SECS = 5400
DISCOVERY_TIMEOUT_SECS = 600
DEFAULT_ACTIVATION_TARGET = 90.0
MIN_VIABILITY_PERCENT = 80.0
DEFAULT_JOBS = 1
MAX_JOBS = 8
DEFAULT_OUTPUT = Path("target/formal/proof-mutants")
MUTATION_MARKER = "/* ~ changed by cargo-mutants ~ */"
FIXED_PROOF_INPUTS = (
    Path("Cargo.toml"),
    Path("Cargo.lock"),
    Path(".cargo/config.toml"),
    Path("crates/kernel/chio-kernel-core/Cargo.toml"),
    Path("crates/core/chio-core-types/Cargo.toml"),
    Path("rust-toolchain.toml"),
    CONFIG,
    Path("scripts/proof-mutants.py"),
    Path("scripts/proof-mutants.sh"),
    Path("scripts/kani-mutant-killer.sh"),
    Path("scripts/check-kani-core.sh"),
)
PROOF_SOURCE_ROOTS = (
    Path("crates/kernel/chio-kernel-core/src"),
    Path("crates/core/chio-core-types/src"),
)
KANI_FAILURE_MARKERS = (
    re.compile(r"VERIFICATION:\s*-?\s*FAILED", re.I),
    re.compile(r"Failed Checks:\s*[1-9][0-9]*", re.I),
    re.compile(r"VERIFICATION FAILED", re.I),
)
COMPILE_FAILURE_PATTERNS = (
    re.compile(r"error\[E[0-9]{4}\]"),
    re.compile(r"could not compile", re.I),
    re.compile(r"compilation failed", re.I),
    re.compile(r"error: aborting due to", re.I),
)
TOOL_FAILURE_PATTERNS = (
    re.compile(r"error:\s+failed to (?:execute|invoke|load|run)", re.I),
    re.compile(r"(?:command not found|No such file or directory)", re.I),
    re.compile(r"internal compiler error", re.I),
    re.compile(r"thread ['\"].*['\"] panicked", re.I),
    re.compile(r"Kani core check requires cargo-kani", re.I),
    re.compile(r"kani-mutant-killer: expected Kani", re.I),
)
KANI_CARGO_COMPILE_WRAPPER = re.compile(
    r"(?m)^error: Failed to execute cargo \(exit status: 101\)\."
    r" Found [1-9][0-9]* compilation errors?\.[ \t]*$"
)
ERROR_LINE = re.compile(r"(?m)^(?:error|fatal):", re.I)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
KANI_FAILED_BLOCK = re.compile(
    r"(?:^|\n)SUMMARY:[ \t]*\n"
    r"[ \t]*\*\*[ \t]+([1-9][0-9]*)[ \t]+of[ \t]+([1-9][0-9]*)"
    r"[ \t]+failed(?:[ \t]+\([0-9]+[ \t]+unreachable\))?[ \t]*\n"
    r"(?:Failed Checks:[^\r\n]+\n[ \t]+File:[^\r\n]+\n)+"
    r"[ \t]*\nVERIFICATION:[ \t]*-[ \t]*FAILED[ \t]*\n"
    r"Verification Time:[ \t]+[0-9]+(?:\.[0-9]+)?s[ \t]*\n",
    re.I,
)
KANI_MANUAL_FAILURE = re.compile(
    r"(?:^|\n)Manual Harness Summary:[ \t]*\n"
    r"((?:Verification failed for[ \t]+-[ \t]+[^\r\n]+[ \t]*\n)+)"
    r"Complete[ \t]*-[ \t]*([0-9]+)[ \t]+successfully verified harnesses,"
    r"[ \t]+([1-9][0-9]*)[ \t]+failures,[ \t]+([1-9][0-9]*)[ \t]+total\."
    r"[ \t]*(?:\n)?\Z",
    re.I,
)
KANI_FAILED_SUMMARY = re.compile(
    r"(?m)^[ \t]*\*\*[ \t]+[1-9][0-9]*[ \t]+of[ \t]+[1-9][0-9]*"
    r"[ \t]+failed(?:[ \t]+\([0-9]+[ \t]+unreachable\))?[ \t]*$",
    re.I,
)
KANI_FAILED_VERDICT = re.compile(
    r"(?m)^VERIFICATION:[ \t]*-[ \t]*FAILED[ \t]*$", re.I
)
KANI_FAILED_CHECK = re.compile(
    r"(?m)^Failed Checks:[^\r\n]+\n[ \t]+File:[^\r\n]+$", re.I
)
KANI_FAILED_HARNESS = re.compile(
    r"(?m)^Verification failed for[ \t]+-[ \t]+[^\r\n]+$", re.I
)


class ProofMutationError(RuntimeError):
    """Raised when discovery, isolation, or Kani evidence fails closed."""


@dataclass(frozen=True)
class ExecutionSnapshot:
    commit: str
    worktree: dict[str, bool]
    inputs: tuple[tuple[str, str], ...]

    def report_inputs(self) -> list[dict[str, str]]:
        return [
            {"path": path, "sha256": digest} for path, digest in self.inputs
        ]


@dataclass(frozen=True)
class DiscoveredMutant:
    id: str
    shard: str
    file: Path
    function: str | None
    genre: str
    replacement: str
    span: dict[str, dict[str, int]]
    diff: str
    raw: dict[str, Any]

    def public(self, *, include_diff: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.id,
            "shard": self.shard,
            "file": self.file.as_posix(),
            "function": self.function,
            "genre": self.genre,
            "replacement": self.replacement,
            "span": self.span,
            "diff_sha256": sha256_bytes(self.diff.encode()),
        }
        if include_diff:
            value["diff"] = self.diff
        return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def inventory_sha256(mutants: Iterable[DiscoveredMutant]) -> str:
    encoded = json.dumps(
        [mutant.public(include_diff=False) for mutant in mutants],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha256_bytes(encoded)


def require_regular_repo_file(root: Path, relative: Path, label: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ProofMutationError(f"{label} has an invalid repository path: {relative}")
    current = root.absolute()
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ProofMutationError(f"{label} contains a symlink component: {relative}")
    try:
        mode = current.stat(follow_symlinks=False).st_mode
    except FileNotFoundError as error:
        raise ProofMutationError(f"{label} is missing: {relative}") from error
    if not stat.S_ISREG(mode):
        raise ProofMutationError(f"{label} is not a regular file: {relative}")
    return current


def mutable_source_path(root: Path, relative: Path) -> Path:
    if relative not in FILES:
        raise ProofMutationError(f"path is not a mutable proof source: {relative}")
    return require_regular_repo_file(root, relative, "mutable proof source")


def validate_mutable_sources(root: Path) -> None:
    for relative in FILES:
        mutable_source_path(root, relative)


def write_mutable_source(root: Path, relative: Path, source: str) -> None:
    mutable_source_path(root, relative).write_text(source, encoding="utf-8")


def proof_input_paths(root: Path) -> list[Path]:
    paths = set(FIXED_PROOF_INPUTS)
    for relative in FIXED_PROOF_INPUTS:
        require_regular_repo_file(root, relative, "proof evidence input")
    for source_root in PROOF_SOURCE_ROOTS:
        absolute_root = root / source_root
        if absolute_root.is_symlink() or not absolute_root.is_dir():
            raise ProofMutationError(f"proof source root is invalid: {source_root}")
        for directory, directories, filenames in os.walk(absolute_root, followlinks=False):
            directory_path = Path(directory)
            for name in directories:
                candidate = directory_path / name
                if candidate.is_symlink():
                    relative = candidate.relative_to(root)
                    raise ProofMutationError(
                        f"proof source tree contains a symlink component: {relative}"
                    )
            for name in filenames:
                if not name.endswith(".rs"):
                    continue
                relative = (directory_path / name).relative_to(root)
                require_regular_repo_file(root, relative, "proof evidence input")
                paths.add(relative)
    return sorted(paths, key=lambda path: path.as_posix())


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def cargo_mutants_version(binary: str) -> str:
    try:
        completed = subprocess.run(
            [binary, "mutants", "--version"] if Path(binary).name == "cargo" else [binary, "--version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProofMutationError(f"cannot run cargo-mutants version probe: {error}") from error
    version = completed.stdout.strip()
    if completed.returncode != 0 or version != EXPECTED_CARGO_MUTANTS:
        raise ProofMutationError(
            f"expected {EXPECTED_CARGO_MUTANTS}, found {version!r}"
        )
    return version


def cargo_mutants_prefix(binary: str) -> list[str]:
    return [binary, "mutants"] if Path(binary).name == "cargo" else [binary]


def kani_version() -> str:
    configured = os.environ.get("CHIO_KANI_VERSION")
    if configured is not None and configured != EXPECTED_KANI:
        raise ProofMutationError(f"CHIO_KANI_VERSION must remain {EXPECTED_KANI}")
    try:
        completed = subprocess.run(
            ["cargo", "kani", "--version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProofMutationError(f"cannot run Kani version probe: {error}") from error
    version = completed.stdout.strip()
    exact = re.compile(rf"(?<![0-9.]){re.escape(EXPECTED_KANI)}(?![0-9.])")
    if completed.returncode != 0 or exact.search(version) is None:
        raise ProofMutationError(f"expected Kani {EXPECTED_KANI}, found {version!r}")
    return version


def rustc_version() -> str:
    try:
        completed = subprocess.run(
            ["rustc", "--version", "--verbose"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProofMutationError(f"cannot run rustc version probe: {error}") from error
    version = completed.stdout.strip()
    if completed.returncode != 0 or f"release: {EXPECTED_RUSTC}" not in version.splitlines():
        raise ProofMutationError(f"expected rustc {EXPECTED_RUSTC}, found {version!r}")
    return version


def canonical_identity(raw: dict[str, Any]) -> str:
    identity = {
        "file": raw.get("file"),
        "function": raw.get("function"),
        "genre": raw.get("genre"),
        "replacement": raw.get("replacement"),
        "span": raw.get("span"),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)[:20]


def normalize_file(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw or ".." in Path(raw).parts:
        raise ProofMutationError(f"cargo-mutants emitted an invalid file path: {raw!r}")
    path = Path(raw)
    for allowed in FILES:
        if path == allowed or path.as_posix() == allowed.relative_to(
            "crates/kernel/chio-kernel-core"
        ).as_posix():
            return allowed
    raise ProofMutationError(f"cargo-mutants escaped the formal model files: {raw}")


def parse_position(raw: Any, label: str) -> dict[str, int]:
    if not isinstance(raw, dict) or set(raw) != {"line", "column"}:
        raise ProofMutationError(f"mutant {label} position has the wrong shape")
    line = raw["line"]
    column = raw["column"]
    if type(line) is not int or type(column) is not int or line < 1 or column < 1:
        raise ProofMutationError(f"mutant {label} position is not positive")
    return {"line": line, "column": column}


def parse_mutant(raw: Any, shard: str) -> DiscoveredMutant:
    if not isinstance(raw, dict):
        raise ProofMutationError(f"cargo-mutants shard {shard} emitted a non-object")
    required = {"file", "genre", "package", "replacement", "span", "diff"}
    if not required.issubset(raw):
        raise ProofMutationError(
            f"cargo-mutants shard {shard} omitted fields: {sorted(required - set(raw))}"
        )
    if raw["package"] != "chio-kernel-core":
        raise ProofMutationError(f"cargo-mutants emitted another package: {raw['package']!r}")
    if not isinstance(raw["genre"], str) or not raw["genre"]:
        raise ProofMutationError("cargo-mutants emitted an invalid genre")
    if not isinstance(raw["replacement"], str) or "\n" in raw["replacement"]:
        raise ProofMutationError("cargo-mutants emitted an invalid replacement")
    if not isinstance(raw["diff"], str) or not raw["diff"].startswith("--- "):
        raise ProofMutationError("cargo-mutants emitted an invalid diff")
    span = raw["span"]
    if not isinstance(span, dict) or set(span) != {"start", "end"}:
        raise ProofMutationError("cargo-mutants emitted an invalid span")
    parsed_span = {
        "start": parse_position(span["start"], "start"),
        "end": parse_position(span["end"], "end"),
    }
    start = parsed_span["start"]
    end = parsed_span["end"]
    if (end["line"], end["column"]) < (start["line"], start["column"]):
        raise ProofMutationError("cargo-mutants emitted a reversed span")
    function_raw = raw.get("function")
    if not isinstance(function_raw, dict):
        raise ProofMutationError("cargo-mutants emitted a mutation outside a function")
    name = function_raw.get("function_name")
    function_span = function_raw.get("span")
    if not isinstance(name, str) or not name:
        raise ProofMutationError("cargo-mutants emitted a function without a name")
    if not isinstance(function_span, dict) or set(function_span) != {"start", "end"}:
        raise ProofMutationError("cargo-mutants emitted a function without an exact span")
    parsed_function_span = {
        "start": parse_position(function_span["start"], "function start"),
        "end": parse_position(function_span["end"], "function end"),
    }
    function_start = parsed_function_span["start"]
    function_end = parsed_function_span["end"]
    if (
        (start["line"], start["column"])
        < (function_start["line"], function_start["column"])
        or (end["line"], end["column"])
        > (function_end["line"], function_end["column"])
    ):
        raise ProofMutationError("cargo-mutants emitted a mutation outside its function body")
    function = name
    return DiscoveredMutant(
        canonical_identity(raw),
        shard,
        normalize_file(raw["file"]),
        function,
        raw["genre"],
        raw["replacement"],
        parsed_span,
        raw["diff"],
        raw,
    )


def source_offset(source: str, position: dict[str, int]) -> int:
    lines = source.splitlines(keepends=True)
    line = position["line"]
    column = position["column"]
    if line > len(lines) or column > len(lines[line - 1]) + 1:
        raise ProofMutationError("cargo-mutants span escapes its source file")
    return sum(len(value) for value in lines[: line - 1]) + column - 1


def function_body_offsets(
    source: str,
    function: str,
    declared_span: tuple[int, int] | None = None,
) -> tuple[int, int]:
    short_name = function.rsplit("::", 1)[-1]
    declaration = re.compile(
        rf"(?m)^\s*(?:pub(?:\([^\n)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*"
        rf"fn\s+{re.escape(short_name)}\s*(?:<[^\n{{>]*>)?\s*\("
    )
    matches = list(declaration.finditer(source))
    if declared_span is not None:
        declared_start, declared_end = declared_span
        matches = [
            match
            for match in matches
            if declared_start <= match.end() <= declared_end
        ]
    if len(matches) != 1:
        raise ProofMutationError(
            f"cannot locate exactly one Rust function declaration for {function}"
        )
    search_end = declared_span[1] if declared_span is not None else len(source)
    opening = source.find("{", matches[0].end(), search_end)
    if opening < 0:
        raise ProofMutationError(f"Rust function {function} has no body")
    depth = 0
    for index in range(opening, search_end):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return opening + 1, index
    raise ProofMutationError(f"Rust function {function} has an unterminated body")


def enforce_function_body(root: Path, mutant: DiscoveredMutant) -> None:
    if mutant.function is None:
        raise ProofMutationError("cargo-mutants emitted a mutation without a function")
    source = mutable_source_path(root, mutant.file).read_text(encoding="utf-8")
    declared_span = None
    raw_function = mutant.raw.get("function")
    if isinstance(raw_function, dict):
        raw_span = raw_function.get("span")
        if isinstance(raw_span, dict) and set(raw_span) == {"start", "end"}:
            declared_span = (
                source_offset(source, parse_position(raw_span["start"], "function start")),
                source_offset(source, parse_position(raw_span["end"], "function end")),
            )
    body_start, body_end = function_body_offsets(source, mutant.function, declared_span)
    mutation_start = source_offset(source, mutant.span["start"])
    mutation_end = source_offset(source, mutant.span["end"])
    if mutation_start < body_start or mutation_end > body_end:
        raise ProofMutationError(
            f"cargo-mutants mutation {mutant.id} escapes the body of {mutant.function}"
        )


def discovery_command(binary: str, shard: str) -> list[str]:
    command = cargo_mutants_prefix(binary) + [
        "--config",
        CONFIG.as_posix(),
        "--package",
        "chio-kernel-core",
        "--list",
        "--json",
        "--diff",
        "--no-shuffle",
        "--shard",
        shard,
    ]
    for path in FILES:
        command.extend(["-f", path.as_posix()])
    return command


def unsharded_discovery_command(binary: str) -> list[str]:
    command = cargo_mutants_prefix(binary) + [
        "--config",
        CONFIG.as_posix(),
        "--package",
        "chio-kernel-core",
        "--list",
        "--json",
        "--diff",
        "--no-shuffle",
    ]
    for path in FILES:
        command.extend(["-f", path.as_posix()])
    return command


def run_discovery_process(
    command: list[str], root: Path, description: str
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise ProofMutationError(f"cannot execute cargo-mutants {description}: {error}") from error
    try:
        stdout, stderr = process.communicate(timeout=DISCOVERY_TIMEOUT_SECS)
    except subprocess.TimeoutExpired as error:
        kill_process_group(process)
        process.communicate()
        raise ProofMutationError(
            f"cargo-mutants {description} exceeded {DISCOVERY_TIMEOUT_SECS}s"
        ) from error
    except BaseException:
        kill_process_group(process)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def discover(root: Path, binary: str) -> tuple[list[DiscoveredMutant], list[dict[str, Any]]]:
    validate_mutable_sources(root)
    cargo_mutants_version(binary)
    mutants: list[DiscoveredMutant] = []
    commands: list[dict[str, Any]] = []
    for shard in SHARDS:
        validate_mutable_sources(root)
        command = discovery_command(binary, shard)
        completed = run_discovery_process(command, root, f"discovery shard {shard}")
        commands.append(
            {
                "shard": shard,
                "argv": command,
                "exit_code": completed.returncode,
                "stderr_sha256": sha256_bytes(completed.stderr.encode()),
            }
        )
        if completed.returncode != 0:
            raise ProofMutationError(
                f"cargo-mutants discovery shard {shard} failed: {completed.stderr.strip()}"
            )
        validate_mutable_sources(root)
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ProofMutationError(
                f"cargo-mutants discovery shard {shard} emitted invalid JSON"
            ) from error
        if not isinstance(payload, list) or not payload:
            raise ProofMutationError(f"cargo-mutants discovery shard {shard} is empty")
        parsed = [parse_mutant(raw, shard) for raw in payload]
        for mutant in parsed:
            enforce_function_body(root, mutant)
        mutants.extend(parsed)
    ids = [mutant.id for mutant in mutants]
    if len(ids) != len(set(ids)):
        raise ProofMutationError("cargo-mutants shards overlap")
    mutants.sort(
        key=lambda item: (
            item.file.as_posix(),
            item.span["start"]["line"],
            item.span["start"]["column"],
            item.genre,
            item.replacement,
        )
    )
    covered_shards = {mutant.shard for mutant in mutants}
    if covered_shards != set(SHARDS):
        raise ProofMutationError(f"cargo-mutants shard coverage mismatch: {covered_shards}")
    if {mutant.file for mutant in mutants} != set(FILES):
        raise ProofMutationError("cargo-mutants did not enumerate both formal model files")
    unsharded_command = unsharded_discovery_command(binary)
    validate_mutable_sources(root)
    unsharded_run = run_discovery_process(
        unsharded_command, root, "unsharded discovery"
    )
    commands.append(
        {
            "shard": "unsharded-control",
            "argv": unsharded_command,
            "exit_code": unsharded_run.returncode,
            "stderr_sha256": sha256_bytes(unsharded_run.stderr.encode()),
        }
    )
    if unsharded_run.returncode != 0:
        raise ProofMutationError(
            f"cargo-mutants unsharded discovery failed: {unsharded_run.stderr.strip()}"
        )
    validate_mutable_sources(root)
    try:
        unsharded_payload = json.loads(unsharded_run.stdout)
    except json.JSONDecodeError as error:
        raise ProofMutationError("cargo-mutants unsharded discovery emitted invalid JSON") from error
    if not isinstance(unsharded_payload, list) or not unsharded_payload:
        raise ProofMutationError("cargo-mutants unsharded discovery is empty")
    unsharded = [parse_mutant(raw, "unsharded-control") for raw in unsharded_payload]
    for mutant in unsharded:
        enforce_function_body(root, mutant)
    sharded_inventory = {mutant.id: sha256_bytes(mutant.diff.encode()) for mutant in mutants}
    unsharded_inventory = {
        mutant.id: sha256_bytes(mutant.diff.encode()) for mutant in unsharded
    }
    if len(unsharded_inventory) != len(unsharded) or sharded_inventory != unsharded_inventory:
        raise ProofMutationError("cargo-mutants sharded inventory differs from unsharded control")
    return mutants, commands


def replace_span(source: str, span: dict[str, dict[str, int]], replacement: str) -> str:
    result: list[str] = []
    line_no = 1
    column_no = 1
    start = span["start"]
    end = span["end"]
    inserted = False
    for character in source:
        if line_no == start["line"] and column_no == start["column"]:
            result.append(f"{replacement} {MUTATION_MARKER}")
            inserted = True
        outside = (
            line_no < start["line"]
            or line_no > end["line"]
            or (line_no == start["line"] and column_no < start["column"])
            or (line_no == end["line"] and column_no >= end["column"])
        )
        if outside:
            result.append(character)
        if character == "\n":
            line_no += 1
            column_no = 1
        elif character != "\r":
            column_no += 1
    if not inserted and line_no == start["line"] and column_no == start["column"]:
        result.append(f"{replacement} {MUTATION_MARKER}")
        inserted = True
    if not inserted:
        raise ProofMutationError("mutation span starts outside its source file")
    return "".join(result)


def git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ProofMutationError("cannot resolve the current Git commit")
    return value


def ci_run_evidence() -> dict[str, int] | None:
    names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_NUMBER")
    values = [os.environ.get(name) for name in names]
    if all(value is None for value in values):
        return None
    if any(value is None or not value.isdigit() or int(value) < 1 for value in values):
        raise ProofMutationError("GitHub run identity is incomplete or invalid")
    return {
        "run_id": int(values[0]),
        "run_attempt": int(values[1]),
        "run_number": int(values[2]),
    }


def worktree_evidence(root: Path) -> dict[str, bool]:
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 or completed.stdout:
        raise ProofMutationError("proof mutation execution requires a clean tracked worktree")
    return {"clean": True}


def require_clean(root: Path) -> None:
    worktree_evidence(root)


def input_evidence(root: Path, paths: Iterable[Path]) -> tuple[tuple[str, str], ...]:
    ordered = sorted(set(paths), key=lambda path: path.as_posix())
    return tuple((path.as_posix(), sha256_file(root / path)) for path in ordered)


def capture_execution_snapshot(
    root: Path, paths: Iterable[Path] | None = None
) -> ExecutionSnapshot:
    evidence_paths = proof_input_paths(root) if paths is None else paths
    return ExecutionSnapshot(
        commit=git_head(root),
        worktree=worktree_evidence(root),
        inputs=input_evidence(root, evidence_paths),
    )


def verify_execution_snapshot(
    root: Path,
    snapshot: ExecutionSnapshot,
    paths: Iterable[Path] | None = None,
) -> None:
    if git_head(root) != snapshot.commit:
        raise ProofMutationError("Git HEAD drifted during proof mutation execution")
    try:
        current_worktree = worktree_evidence(root)
    except ProofMutationError as error:
        raise ProofMutationError("worktree drifted during proof mutation execution") from error
    if current_worktree != snapshot.worktree:
        raise ProofMutationError("worktree drifted during proof mutation execution")
    evidence_paths = proof_input_paths(root) if paths is None else paths
    current_inputs = input_evidence(root, evidence_paths)
    if tuple(path for path, _ in current_inputs) != tuple(
        path for path, _ in snapshot.inputs
    ):
        raise ProofMutationError(
            "evidence input path set drifted during proof mutation execution"
        )
    if current_inputs != snapshot.inputs:
        raise ProofMutationError("evidence inputs drifted during proof mutation execution")


def discover_at_snapshot(
    root: Path, binary: str, snapshot: ExecutionSnapshot
) -> tuple[list[DiscoveredMutant], list[dict[str, Any]]]:
    scratch_parent = Path(tempfile.mkdtemp(prefix="chio-proof-discovery-"))
    scratch = scratch_parent / "worktree"
    worktree_added = False
    discovery_binary = binary
    if not Path(binary).is_absolute() and os.sep in binary:
        discovery_binary = str((root / binary).resolve())
    try:
        added = subprocess.run(
            ["git", "worktree", "add", "--detach", str(scratch), snapshot.commit],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if added.returncode != 0:
            raise ProofMutationError(
                f"cannot create proof discovery worktree: {added.stderr.strip()}"
            )
        worktree_added = True
        detached_inputs = input_evidence(scratch, proof_input_paths(scratch))
        if detached_inputs != snapshot.inputs:
            raise ProofMutationError(
                "detached proof discovery inputs differ from the starting snapshot"
            )
        return discover(scratch, discovery_binary)
    finally:
        if worktree_added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(scratch)],
                cwd=root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        shutil.rmtree(scratch_parent, ignore_errors=True)


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class ProcessRegistry:
    """Tracks worker process groups so one failure can stop the whole campaign."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: set[subprocess.Popen[bytes]] = set()
        self._cancelled = False

    def add(self, process: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if not self._cancelled:
                self._processes.add(process)
                return
        kill_process_group(process)
        raise ProofMutationError("proof mutation execution was cancelled")

    def remove(self, process: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._processes.discard(process)

    def claim_for_termination(self, process: subprocess.Popen[bytes]) -> bool:
        with self._lock:
            if process not in self._processes:
                return False
            self._processes.remove(process)
            return True

    def kill_all(self) -> None:
        with self._lock:
            self._cancelled = True
            processes = tuple(self._processes)
            self._processes.clear()
        for process in processes:
            kill_process_group(process)


def run_process(
    command: list[str],
    cwd: Path,
    log_path: Path,
    timeout_secs: int,
    registry: ProcessRegistry | None = None,
) -> tuple[int | None, float]:
    start = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if registry is not None:
            registry.add(process)
        try:
            exit_code = process.wait(timeout=timeout_secs)
        except subprocess.TimeoutExpired:
            if registry is None or registry.claim_for_termination(process):
                kill_process_group(process)
            else:
                process.wait()
            exit_code = None
        except BaseException:
            if registry is None or registry.claim_for_termination(process):
                kill_process_group(process)
            else:
                process.wait()
            raise
        finally:
            if registry is not None:
                registry.remove(process)
    return exit_code, time.monotonic() - start


def classify_kani(exit_code: int | None, log_path: Path) -> str:
    if exit_code is None:
        return "timeout"
    if exit_code == 0:
        return "survived"
    text = ANSI_ESCAPE.sub("", log_path.read_text(encoding="utf-8", errors="replace"))
    compile_failure = any(pattern.search(text) for pattern in COMPILE_FAILURE_PATTERNS)
    tool_evidence = KANI_CARGO_COMPILE_WRAPPER.sub("", text, count=1)
    tool_failure = any(pattern.search(tool_evidence) for pattern in TOOL_FAILURE_PATTERNS)
    terminal_failure = KANI_MANUAL_FAILURE.search(text)
    failed_blocks = list(KANI_FAILED_BLOCK.finditer(text))
    failure_marker = any(pattern.search(text) for pattern in KANI_FAILURE_MARKERS)
    if terminal_failure is not None:
        harnesses_passed = int(terminal_failure.group(2))
        harnesses_failed = int(terminal_failure.group(3))
        harnesses_total = int(terminal_failure.group(4))
        failed_checks = sum(int(block.group(1)) for block in failed_blocks)
        impossible_block = any(
            int(block.group(1)) > int(block.group(2))
            or len(KANI_FAILED_CHECK.findall(block.group(0))) != int(block.group(1))
            for block in failed_blocks
        )
        if (
            impossible_block
            or harnesses_passed + harnesses_failed != harnesses_total
            or len(failed_blocks) != harnesses_failed
            or len(KANI_FAILED_SUMMARY.findall(text)) != len(failed_blocks)
            or len(KANI_FAILED_VERDICT.findall(text)) != len(failed_blocks)
            or len(KANI_FAILED_CHECK.findall(text)) != failed_checks
            or len(KANI_FAILED_HARNESS.findall(text)) != harnesses_failed
        ):
            raise ProofMutationError("Kani terminal summary has an impossible failure count")
        if compile_failure or tool_failure or ERROR_LINE.search(text) is not None:
            raise ProofMutationError(
                "Kani log mixes a proof failure with compile or tool-failure evidence"
            )
        return "killed"
    if tool_failure:
        raise ProofMutationError(f"Kani exit {exit_code} contains tool-failure evidence")
    if compile_failure:
        if failure_marker:
            raise ProofMutationError(
                "Kani log mixes non-terminal proof-failure and compile-failure evidence"
            )
        return "unviable"
    if failure_marker:
        raise ProofMutationError("Kani proof failure lacks an exact terminal summary")
    raise ProofMutationError(f"Kani exit {exit_code} has no recognized proof or compile verdict")


def select_mutants(
    mutants: list[DiscoveredMutant],
    commit: str,
    sample_size: int,
    full: bool,
    sample_epoch: int,
) -> tuple[list[DiscoveredMutant], str]:
    seed = commit[:16]
    if full or sample_size >= len(mutants):
        return list(mutants), seed
    if sample_epoch < 0:
        raise ProofMutationError("sample epoch must not be negative")
    source_groups = [
        [index for index, mutant in enumerate(mutants) if mutant.file == source]
        for source in FILES
    ]
    if any(not group for group in source_groups):
        raise ProofMutationError("proof inventory does not cover every model file")
    if len(source_groups) == 2 and len(mutants) % sample_size == 0:
        cycle_epochs = len(mutants) // sample_size
        epoch = sample_epoch % cycle_epochs
        cycle = sample_epoch // cycle_epochs
        generator = random.Random(int(seed, 16) + cycle)
        for group in source_groups:
            generator.shuffle(group)
        first_size = len(source_groups[0])
        base, remainder = divmod(first_size, cycle_epochs)
        first_counts = [base + (position < remainder) for position in range(cycle_epochs)]
        second_counts = [sample_size - count for count in first_counts]
        first_start = sum(first_counts[:epoch])
        second_start = sum(second_counts[:epoch])
        indexes = sorted(
            source_groups[0][first_start : first_start + first_counts[epoch]]
            + source_groups[1][second_start : second_start + second_counts[epoch]]
        )
        if len(indexes) != sample_size:
            raise ProofMutationError("stratified proof sample schedule is inconsistent")
        return [mutants[index] for index in indexes], seed

    generator = random.Random(int(seed, 16))
    permutation = list(range(len(mutants)))
    generator.shuffle(permutation)
    rank = {index: position for position, index in enumerate(permutation)}
    indexes: set[int] = set()
    for source in FILES:
        candidates = sorted(
            (index for index, mutant in enumerate(mutants) if mutant.file == source),
            key=rank.__getitem__,
        )
        if not candidates:
            raise ProofMutationError(f"proof inventory has no mutations for {source}")
        indexes.add(candidates[sample_epoch % len(candidates)])
    if len(indexes) > sample_size:
        raise ProofMutationError("sample size cannot cover every proof model file")
    remaining = [index for index in permutation if index not in indexes]
    slots = sample_size - len(indexes)
    if slots:
        start = sample_epoch * slots % len(remaining)
        indexes.update(
            remaining[(start + offset) % len(remaining)] for offset in range(slots)
        )
    indexes = sorted(indexes)
    return [mutants[index] for index in indexes], seed


def score(results: list[dict[str, Any]], target: float) -> dict[str, Any]:
    counts = {name: 0 for name in ("killed", "survived", "unviable", "timeout")}
    for result in results:
        counts[result["verdict"]] += 1
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    activation = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    viability = round(100.0 * denominator / len(results), 3) if results else 0.0
    completed = counts["killed"] + counts["survived"] + counts["unviable"]
    completion = round(100.0 * completed / len(results), 3) if results else 0.0
    activation_threshold_met = activation >= target
    viability_met = viability >= MIN_VIABILITY_PERCENT
    return {
        "sampled": len(results),
        **counts,
        "score_denominator": denominator,
        "timeout_policy": "timeouts count as not killed",
        "activation_ratio_percent": activation,
        "completion_ratio_percent": completion,
        "activation_target_percent": target,
        "activation_threshold_met": activation_threshold_met,
        "viability_ratio_percent": viability,
        "viability_target_percent": MIN_VIABILITY_PERCENT,
        "viability_met": viability_met,
        "activation_met": activation_threshold_met and viability_met,
    }


def aggregate_scores(
    results: list[dict[str, Any]], target: float
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    expected_sources = {path.as_posix() for path in FILES}
    actual_sources = {result.get("file") for result in results}
    if actual_sources != expected_sources:
        raise ProofMutationError(
            "proof sample source coverage mismatch: "
            f"expected={sorted(expected_sources)} actual={sorted(actual_sources)}"
        )
    source_aggregates = {
        source: score(
            [result for result in results if result.get("file") == source], target
        )
        for source in sorted(expected_sources)
    }
    aggregate = score(results, target)
    global_met = aggregate["activation_met"]
    sources_met = all(entry["activation_met"] for entry in source_aggregates.values())
    aggregate["global_activation_met"] = global_met
    aggregate["source_activation_met"] = sources_met
    aggregate["activation_met"] = global_met and sources_met
    return aggregate, source_aggregates


def safe_output(root: Path, raw: str | None) -> Path:
    requested = Path(raw) if raw else DEFAULT_OUTPUT
    if not requested.is_absolute():
        requested = root / requested
    lexical = requested.absolute()
    lexical_formal = (root / "target/formal").absolute()
    if lexical_formal not in lexical.parents:
        raise ProofMutationError("output must be a strict child of target/formal")
    current = root.absolute()
    try:
        relative = lexical.relative_to(current)
    except ValueError as error:
        raise ProofMutationError("output must be inside the repository") from error
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ProofMutationError("output must not contain symlink components")

    candidate = lexical.resolve()
    formal_root = (root / "target/formal").resolve()
    if root.resolve() not in candidate.parents or formal_root not in candidate.parents:
        raise ProofMutationError("output must be a strict child of target/formal")
    return candidate


def require_restored_scratch(root: Path, mutant_id: str) -> None:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if status.returncode != 0 or status.stdout:
        raise ProofMutationError(f"scratch worktree did not restore after {mutant_id}")


def execute_mutant(
    scratch: Path,
    mutant: DiscoveredMutant,
    output: Path,
    timeout_secs: int,
    registry: ProcessRegistry,
) -> dict[str, Any]:
    source_path = mutable_source_path(scratch, mutant.file)
    original = source_path.read_text(encoding="utf-8")
    mutated = replace_span(original, mutant.span, mutant.replacement)
    write_mutable_source(scratch, mutant.file, mutated)
    try:
        log_path = output / "runs" / mutant.id / "kani.log"
        command = ["bash", "scripts/kani-mutant-killer.sh"]
        exit_code, wall_secs = run_process(
            command,
            scratch,
            log_path,
            timeout_secs,
            registry,
        )
        verdict = classify_kani(exit_code, log_path)
        result = mutant.public(include_diff=False)
        result.update(
            {
                "verdict": verdict,
                "kani_exit": exit_code,
                "wall_secs": round(wall_secs, 3),
                "source_sha256": sha256_bytes(original.encode()),
                "mutated_sha256": sha256_bytes(mutated.encode()),
                "log_sha256": sha256_file(log_path),
            }
        )
        return result
    finally:
        write_mutable_source(scratch, mutant.file, original)
        require_restored_scratch(scratch, mutant.id)


def execute_selected_mutants(
    scratches: list[Path],
    selected: list[DiscoveredMutant],
    output: Path,
    timeout_secs: int,
) -> list[dict[str, Any]]:
    pending: queue.Queue[tuple[int, DiscoveredMutant]] = queue.Queue()
    for index, mutant in enumerate(selected):
        pending.put((index, mutant))

    stop = threading.Event()
    registry = ProcessRegistry()
    print_lock = threading.Lock()

    def worker(scratch: Path) -> list[tuple[int, dict[str, Any]]]:
        completed: list[tuple[int, dict[str, Any]]] = []
        while not stop.is_set():
            try:
                index, mutant = pending.get_nowait()
            except queue.Empty:
                break
            try:
                result = execute_mutant(
                    scratch,
                    mutant,
                    output,
                    timeout_secs,
                    registry,
                )
                completed.append((index, result))
                with print_lock:
                    print(f"{mutant.id}: {result['verdict']} ({result['wall_secs']}s)")
            except BaseException:
                stop.set()
                registry.kill_all()
                raise
            finally:
                pending.task_done()
        return completed

    executor = ThreadPoolExecutor(max_workers=len(scratches), thread_name_prefix="proof-mutant")
    futures: list[Future[list[tuple[int, dict[str, Any]]]]] = []
    indexed: list[tuple[int, dict[str, Any]]] = []
    try:
        for scratch in scratches:
            futures.append(executor.submit(worker, scratch))
        for future in as_completed(futures):
            indexed.extend(future.result())
    except BaseException:
        stop.set()
        registry.kill_all()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)

    indexed.sort(key=lambda entry: entry[0])
    if [index for index, _ in indexed] != list(range(len(selected))):
        raise ProofMutationError("parallel proof mutation execution omitted a selected mutant")
    return [result for _, result in indexed]


def execute(
    root: Path,
    mutants: list[DiscoveredMutant],
    discovery_commands: list[dict[str, Any]],
    *,
    output: Path,
    sample_size: int,
    full: bool,
    timeout_secs: int,
    activation_target: float,
    sample_epoch: int,
    jobs: int,
    snapshot: ExecutionSnapshot,
) -> int:
    commit = snapshot.commit
    version = kani_version()
    rustc = rustc_version()
    selected, seed = select_mutants(mutants, commit, sample_size, full, sample_epoch)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    scratch_parent = Path(tempfile.mkdtemp(prefix="chio-proof-mutants-"))
    worker_count = min(jobs, len(selected))
    scratches = [scratch_parent / f"worktree-{index}" for index in range(worker_count)]
    worktrees_added: list[Path] = []
    commands = list(discovery_commands)
    try:
        for scratch in scratches:
            add = subprocess.run(
                ["git", "worktree", "add", "--detach", str(scratch), commit],
                cwd=root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if add.returncode != 0:
                raise ProofMutationError(
                    f"cannot create scratch worktree: {add.stderr.strip()}"
                )
            worktrees_added.append(scratch)
            validate_mutable_sources(scratch)
            if input_evidence(scratch, proof_input_paths(scratch)) != snapshot.inputs:
                raise ProofMutationError(
                    "detached proof execution inputs differ from the starting snapshot"
                )

        baseline_log = output / "baseline.log"
        baseline_command = ["bash", "scripts/kani-mutant-killer.sh"]
        baseline_exit, baseline_wall = run_process(
            baseline_command, scratches[0], baseline_log, timeout_secs
        )
        commands.append(
            {
                "kind": "clean-baseline",
                "argv": baseline_command,
                "exit_code": baseline_exit,
                "wall_secs": round(baseline_wall, 3),
                "log_sha256": sha256_file(baseline_log),
            }
        )
        if baseline_exit != 0:
            raise ProofMutationError("clean Kani baseline failed or timed out")

        results = execute_selected_mutants(
            scratches,
            selected,
            output,
            timeout_secs,
        )
        command = ["bash", "scripts/kani-mutant-killer.sh"]
        commands.extend({"mutant_id": mutant.id, "argv": command} for mutant in selected)
    finally:
        for scratch in reversed(worktrees_added):
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(scratch)],
                cwd=root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        shutil.rmtree(scratch_parent, ignore_errors=True)

    aggregate, source_aggregates = aggregate_scores(results, activation_target)
    report = {
        "schema": SCHEMA,
        "commit": commit,
        "ci_run": ci_run_evidence(),
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "worktree": snapshot.worktree,
        "execution_mode": "cargo-mutants-enumeration-with-scratch-worktree-kani-oracle",
        "native_test_tool_supported": False,
        "native_test_tool_reason": "cargo-mutants 25.3.1 accepts only cargo or nextest",
        "sample_seed": seed,
        "sample_epoch": sample_epoch,
        "full_cycle": len(selected) == len(mutants),
        "enumerated": len(mutants),
        "inventory_sha256": inventory_sha256(mutants),
        "inventory": [mutant.public(include_diff=False) for mutant in mutants],
        "sample_size_requested": sample_size,
        "tools": {
            "cargo_mutants": EXPECTED_CARGO_MUTANTS.removeprefix("cargo-mutants "),
            "kani": EXPECTED_KANI,
            "kani_raw": version,
            "rustc": EXPECTED_RUSTC,
            "rustc_raw": rustc,
            "python": sys.version.split()[0],
        },
        "bounds": {
            "per_mutant_timeout_secs": timeout_secs,
            "discovery_timeout_secs": DISCOVERY_TIMEOUT_SECS,
            "workers": worker_count,
            "shards": list(SHARDS),
            "files": [path.as_posix() for path in FILES],
        },
        "inputs": snapshot.report_inputs(),
        "commands": commands,
        "mutants": results,
        "source_aggregates": source_aggregates,
        "aggregate": aggregate,
    }
    verify_execution_snapshot(root, snapshot)
    atomic_json(output / "outcomes.json", report)
    atomic_json(output / "mutants.json", [mutant.public() for mutant in mutants])
    atomic_json(output / "commands.json", commands)
    print(
        "proof-mutants: "
        f"activation={aggregate['activation_ratio_percent']}% "
        f"target={aggregate['activation_target_percent']}% report={output / 'outcomes.json'}"
    )
    return 0 if aggregate["activation_met"] else 1


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list all discovered mutants")
    parser.add_argument("--full", action="store_true", help="run the full mutation set")
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--timeout-secs", type=int, default=DEFAULT_TIMEOUT_SECS)
    parser.add_argument(
        "--jobs",
        type=int,
        default=os.environ.get("CHIO_PROOF_MUTANTS_JOBS", str(DEFAULT_JOBS)),
        help=f"isolated Kani workers (1-{MAX_JOBS})",
    )
    parser.add_argument("--activation-target", type=float, default=DEFAULT_ACTIVATION_TARGET)
    parser.add_argument(
        "--sample-epoch",
        type=int,
        default=os.environ.get("CHIO_MUTATION_SAMPLE_EPOCH", "0"),
        help="recorded rotation epoch mixed into the commit-seeded sample",
    )
    parser.add_argument("--output", default=os.environ.get("CHIO_PROOF_MUTANTS_OUTPUT"))
    parser.add_argument("--cargo-mutants-bin", default=os.environ.get("CARGO_MUTANTS_BIN", "cargo"))
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    root = REPO_ROOT.resolve()
    validate_mutable_sources(root)
    require_regular_repo_file(root, CONFIG, "mutation configuration")
    if options.sample_size < 1:
        raise ProofMutationError("sample size must be positive")
    if options.timeout_secs < 1:
        raise ProofMutationError("timeout must be positive")
    if not 1 <= options.jobs <= MAX_JOBS:
        raise ProofMutationError(f"jobs must be between 1 and {MAX_JOBS}")
    if not 0.0 <= options.activation_target <= 100.0:
        raise ProofMutationError("activation target must be between 0 and 100")
    if options.sample_epoch < 0:
        raise ProofMutationError("sample epoch must be non-negative")
    if options.list:
        mutants, _ = discover(root, options.cargo_mutants_bin)
        print(json.dumps([mutant.public() for mutant in mutants], indent=2, sort_keys=True))
        return 0
    output = safe_output(root, options.output)
    snapshot = capture_execution_snapshot(root)
    mutants, commands = discover_at_snapshot(
        root, options.cargo_mutants_bin, snapshot
    )
    verify_execution_snapshot(root, snapshot)
    return execute(
        root,
        mutants,
        commands,
        output=output,
        sample_size=options.sample_size,
        full=options.full,
        timeout_secs=options.timeout_secs,
        activation_target=options.activation_target,
        sample_epoch=options.sample_epoch,
        jobs=options.jobs,
        snapshot=snapshot,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ProofMutationError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"proof-mutants: {error}", file=sys.stderr)
        raise SystemExit(2) from error
