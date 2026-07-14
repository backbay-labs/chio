#!/usr/bin/env python3

"""Measure theorem sensitivity to allowlisted Lean model mutations."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "chio.lean-mutants-report.v1"
ALLOWLIST_SCHEMA = "chio.lean-mutants-allowlist.v1"
ALLOWLIST = Path("formal/lean4/lean-mutants-allowlist.toml")
OUTPUT = Path("target/formal/lean-mutants")
LEAN_PROJECT = Path("formal/lean4/Chio")
LEAN_TOOLCHAIN = LEAN_PROJECT / "lean-toolchain"
MUTABLE_MODEL_ROOTS = (
    Path("formal/lean4/Chio/Chio/Core"),
    Path("formal/lean4/Chio/Chio/Treaty"),
    Path("formal/lean4/Chio/Chio/Json"),
)
DECLARATION = re.compile(
    r"^(?:(?:private|noncomputable|protected)\s+)*(def|theorem|lemma|axiom|abbrev|structure|inductive|class|instance)\s+([A-Za-z_][A-Za-z0-9_.']*)"
)
TOP_LEVEL_COMMAND = re.compile(
    r"^(?:@\[|#|set_option\b|local\b|"
    r"(?:(?:private|noncomputable|protected)\s+)*"
    r"(?:def|theorem|lemma|axiom|abbrev|structure|inductive|class|instance|"
    r"example|opaque|constant|variable|variables|namespace|section|end|open|"
    r"export|attribute|macro|syntax|elab|mutual)\b)"
)
BOOLEAN = re.compile(r"\b(true|false)\b")
CONNECTIVE = re.compile(r"&&|\|\|")
COMPARISON = re.compile(r"(?<![-:<>=!])([<>=]|≤|≥|≠)(?![=>])")
LEAN_DIAGNOSTIC = re.compile(
    r"^(?:error:\s+(?P<prefixed>.+?\.lean):[0-9]+:[0-9]+:.*|"
    r"(?P<plain>.+?\.lean):[0-9]+:[0-9]+: (?:error|unsolved goals):.*)$"
)
LEAN_IMPORT_MODULE = re.compile(
    r"(?:[^\W\d]|_)[\w']*(?:\.(?:[^\W\d]|_)[\w']*)*", re.UNICODE
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
EXPECTED_LAKE_ERROR = re.compile(r"^error: (?:Lean exited with code 1|build failed)$")
TOOL_FAILURE_PATTERNS = (
    re.compile(r"(?im)^(?:fatal:|panic:|thread .* panicked|uncaught exception)"),
    re.compile(
        r"(?i)\b(?:segmentation fault|out of memory|no space left on device|"
        r"permission denied|network is unreachable|connection refused|timed out)\b"
    ),
)


class LeanMutationError(RuntimeError):
    """Raised when mutation inputs or build evidence fail closed."""


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
class Definition:
    name: str
    path: Path


@dataclass(frozen=True)
class DeclarationSpan:
    kind: str
    name: str
    start: int
    end: int


@dataclass(frozen=True)
class Mutation:
    id: str
    definition: str
    path: Path
    operator: str
    line: int
    column: int
    start: int
    end: int
    original: str
    replacement: str
    source_sha256: str

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "definition": self.definition,
            "path": self.path.as_posix(),
            "operator": self.operator,
            "line": self.line,
            "column": self.column,
            "original": self.original,
            "replacement": self.replacement,
            "source_sha256": self.source_sha256,
        }


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_regular_repo_file(root: Path, relative: Path, label: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise LeanMutationError(f"{label} has an invalid repository path: {relative}")
    current = root.absolute()
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise LeanMutationError(f"{label} contains a symlink component: {relative}")
    try:
        mode = current.stat(follow_symlinks=False).st_mode
    except FileNotFoundError as error:
        raise LeanMutationError(f"{label} is missing: {relative}") from error
    if not stat.S_ISREG(mode):
        raise LeanMutationError(f"{label} is not a regular file: {relative}")
    return current


def mutable_source_path(root: Path, relative: Path) -> Path:
    return require_regular_repo_file(root, relative, "mutable Lean source")


def write_mutable_source(root: Path, relative: Path, source: str) -> None:
    mutable_source_path(root, relative).write_text(source, encoding="utf-8")


def lean_input_paths(root: Path) -> list[Path]:
    paths = {
        ALLOWLIST,
        LEAN_TOOLCHAIN,
        LEAN_PROJECT / "lakefile.lean",
        LEAN_PROJECT / "lake-manifest.json",
        Path("scripts/lean-mutants.py"),
    }
    project_root = root / LEAN_PROJECT
    if project_root.is_symlink() or not project_root.is_dir():
        raise LeanMutationError("Lean project root is not a regular repository directory")
    for directory, directories, filenames in os.walk(project_root, followlinks=False):
        directory_path = Path(directory)
        directories[:] = [name for name in directories if name != ".lake"]
        for name in directories:
            candidate = directory_path / name
            if candidate.is_symlink():
                raise LeanMutationError(
                    f"Lean project contains a symlink directory: {candidate.relative_to(root)}"
                )
        for name in filenames:
            if not name.endswith(".lean"):
                continue
            relative = (directory_path / name).relative_to(root)
            require_regular_repo_file(root, relative, "Lean build input")
            paths.add(relative)
    for path in paths:
        require_regular_repo_file(root, path, "Lean build input")
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


def repo_file(root: Path, raw: Any) -> Path:
    if not isinstance(raw, str) or not raw or ".." in Path(raw).parts:
        raise LeanMutationError(f"invalid Lean source path: {raw!r}")
    relative = Path(raw)
    if relative.is_absolute():
        raise LeanMutationError(f"Lean source path escapes the repository: {raw}")
    if relative.suffix != ".lean" or not any(
        root in relative.parents for root in MUTABLE_MODEL_ROOTS
    ):
        raise LeanMutationError(f"Lean source path escapes the approved model roots: {raw}")
    require_regular_repo_file(root, relative, "Lean source path")
    return relative


def load_allowlist(root: Path) -> tuple[int, int, int, list[Definition]]:
    try:
        data = tomllib.loads((root / ALLOWLIST).read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise LeanMutationError(f"cannot parse {ALLOWLIST}: {error}") from error
    if set(data) != {
        "schema",
        "sample_size",
        "timeout_secs",
        "baseline_timeout_secs",
        "definition",
    }:
        raise LeanMutationError("Lean mutation allowlist has missing or unknown fields")
    if data["schema"] != ALLOWLIST_SCHEMA:
        raise LeanMutationError(f"Lean mutation schema must be {ALLOWLIST_SCHEMA}")
    sample_size = data["sample_size"]
    timeout_secs = data["timeout_secs"]
    baseline_timeout_secs = data["baseline_timeout_secs"]
    if type(sample_size) is not int or sample_size < 5:
        raise LeanMutationError("Lean mutation sample size must be at least 5")
    if type(timeout_secs) is not int or timeout_secs < 1:
        raise LeanMutationError("Lean mutation timeout must be positive")
    if type(baseline_timeout_secs) is not int or baseline_timeout_secs < 1:
        raise LeanMutationError("Lean clean-baseline timeout must be positive")
    raw_definitions = data["definition"]
    if not isinstance(raw_definitions, list) or not raw_definitions:
        raise LeanMutationError("Lean mutation allowlist has no definitions")
    definitions: list[Definition] = []
    identities: set[tuple[Path, str]] = set()
    for index, raw in enumerate(raw_definitions, start=1):
        if not isinstance(raw, dict) or set(raw) != {"name", "path"}:
            raise LeanMutationError(f"Lean definition {index} has invalid fields")
        name = raw["name"]
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.']*", name) is None:
            raise LeanMutationError(f"Lean definition {index} has an invalid name")
        path = repo_file(root, raw["path"])
        if (path, name) in identities:
            raise LeanMutationError(f"Lean definition {index} is repeated")
        identities.add((path, name))
        definitions.append(Definition(name, path))
    return sample_size, timeout_secs, baseline_timeout_secs, definitions


def mask_comments(lines: list[str]) -> list[str]:
    masked: list[str] = []
    depth = 0
    for line in lines:
        result = list(line)
        index = 0
        while index < len(line):
            if depth == 0 and line.startswith("--", index):
                for position in range(index, len(line)):
                    if line[position] != "\n":
                        result[position] = " "
                break
            if line.startswith("/-", index):
                depth += 1
                result[index : index + 2] = [" ", " "]
                index += 2
                continue
            if depth > 0 and line.startswith("-/", index):
                depth -= 1
                result[index : index + 2] = [" ", " "]
                index += 2
                continue
            if depth > 0 and line[index] != "\n":
                result[index] = " "
            index += 1
        masked.append("".join(result))
    if depth != 0:
        raise LeanMutationError("Lean source has an unterminated block comment")
    return masked


def skip_lean_header_space(text: str, index: int) -> int:
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("--", index):
            end = text.find("\n", index + 2)
            index = len(text) if end == -1 else end
            continue
        if not text.startswith("/-", index):
            return index
        depth = 1
        index += 2
        while index < len(text) and depth:
            if text.startswith("/-", index):
                depth += 1
                index += 2
            elif text.startswith("-/", index):
                depth -= 1
                index += 2
            else:
                index += 1
        if depth:
            raise LeanMutationError("Lean module header has an unterminated block comment")
    return index


def lean_header_keyword(text: str, index: int, keyword: str) -> bool:
    end = index + len(keyword)
    return text.startswith(keyword, index) and (
        end == len(text)
        or not (text[end].isalnum() or text[end] in "_'!?")
    )


def lean_header_imports(lines: list[str]) -> set[str]:
    text = "".join(lines)
    index = skip_lean_header_space(text, 0)
    if lean_header_keyword(text, index, "prelude"):
        index = skip_lean_header_space(text, index + len("prelude"))
    imports: set[str] = set()
    while lean_header_keyword(text, index, "import"):
        index = skip_lean_header_space(text, index + len("import"))
        module = LEAN_IMPORT_MODULE.match(text, index)
        if module is None:
            raise LeanMutationError("Lean module header has an incomplete import command")
        imports.add(module.group(0))
        index = skip_lean_header_space(text, module.end())
    return imports


def declarations(lines: list[str]) -> dict[str, DeclarationSpan]:
    masked = mask_comments(lines)
    starts: list[tuple[str, str, int]] = []
    boundaries: list[int] = []
    for index, line in enumerate(masked):
        if TOP_LEVEL_COMMAND.match(line) is not None:
            boundaries.append(index)
        match = DECLARATION.match(line)
        if match is not None:
            starts.append((match.group(1), match.group(2), index))
    result: dict[str, DeclarationSpan] = {}
    for kind, name, start in starts:
        end = next((boundary for boundary in boundaries if boundary > start), len(lines))
        if name in result:
            raise LeanMutationError(f"Lean source repeats declaration {name}")
        result[name] = DeclarationSpan(kind, name, start, end)
    return result


def make_mutation(
    definition: Definition,
    operator: str,
    line_index: int,
    start: int,
    end: int,
    original: str,
    replacement: str,
    source_sha256: str,
) -> Mutation:
    identity = {
        "definition": definition.name,
        "path": definition.path.as_posix(),
        "operator": operator,
        "line": line_index + 1,
        "column": start + 1,
        "original": original,
        "replacement": replacement,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return Mutation(
        sha256_bytes(encoded)[:20],
        definition.name,
        definition.path,
        operator,
        line_index + 1,
        start + 1,
        start,
        end,
        original,
        replacement,
        source_sha256,
    )


def enumerate_mutations(root: Path, definitions: list[Definition]) -> list[Mutation]:
    grouped: dict[Path, list[Definition]] = {}
    for definition in definitions:
        grouped.setdefault(definition.path, []).append(definition)
    mutants: list[Mutation] = []
    for path, selected in grouped.items():
        source_path = mutable_source_path(root, path)
        lines = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
        masked = mask_comments(lines)
        spans = declarations(lines)
        source_sha = sha256_file(source_path)
        for definition in selected:
            span = spans.get(definition.name)
            if span is None or span.kind != "def":
                raise LeanMutationError(
                    f"allowlisted Lean definition is missing or is not a def: {definition.name}"
                )
            found = 0
            for line_index in range(span.start, span.end):
                code = masked[line_index]
                for match in CONNECTIVE.finditer(code):
                    token = match.group(0)
                    replacement = "||" if token == "&&" else "&&"
                    mutants.append(
                        make_mutation(
                            definition,
                            "swap_connective",
                            line_index,
                            match.start(),
                            match.end(),
                            token,
                            replacement,
                            source_sha,
                        )
                    )
                    found += 1
                for match in BOOLEAN.finditer(code):
                    token = match.group(1)
                    replacement = "false" if token == "true" else "true"
                    mutants.append(
                        make_mutation(
                            definition,
                            "swap_boolean",
                            line_index,
                            match.start(),
                            match.end(),
                            token,
                            replacement,
                            source_sha,
                        )
                    )
                    found += 1
                for match in COMPARISON.finditer(code):
                    token = match.group(1)
                    replacement = {
                        "<": "≤",
                        "≤": "<",
                        ">": "≥",
                        "≥": ">",
                        "=": "≠",
                        "≠": "=",
                    }[token]
                    mutants.append(
                        make_mutation(
                            definition,
                            "flip_comparison",
                            line_index,
                            match.start(),
                            match.end(),
                            token,
                            replacement,
                            source_sha,
                        )
                    )
                    found += 1
            if found == 0:
                raise LeanMutationError(f"Lean definition yielded no mutants: {definition.name}")
    mutants.sort(
        key=lambda mutant: (
            mutant.path.as_posix(),
            mutant.definition,
            mutant.line,
            mutant.column,
            mutant.operator,
        )
    )
    if len({mutant.id for mutant in mutants}) != len(mutants):
        raise LeanMutationError("Lean mutant identifiers are not unique")
    return mutants


def apply_mutation(root: Path, mutation: Mutation) -> str:
    lines = mutable_source_path(root, mutation.path).read_text(
        encoding="utf-8"
    ).splitlines(keepends=True)
    index = mutation.line - 1
    line = lines[index]
    if line[mutation.start : mutation.end] != mutation.original:
        raise LeanMutationError(f"Lean mutant {mutation.id} source span drifted")
    lines[index] = line[: mutation.start] + mutation.replacement + line[mutation.end :]
    return "".join(lines)


def git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    commit = completed.stdout.strip()
    if completed.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise LeanMutationError("cannot resolve the current Git commit")
    return commit


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
        raise LeanMutationError("Lean mutation execution requires a clean tracked worktree")
    return {"clean": True}


def require_clean(root: Path) -> None:
    worktree_evidence(root)


def input_evidence(root: Path, paths: Iterable[Path]) -> tuple[tuple[str, str], ...]:
    ordered = sorted(set(paths), key=lambda path: path.as_posix())
    return tuple((path.as_posix(), sha256_file(root / path)) for path in ordered)


def capture_execution_snapshot(
    root: Path, paths: Iterable[Path] | None = None
) -> ExecutionSnapshot:
    evidence_paths = lean_input_paths(root) if paths is None else paths
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
        raise LeanMutationError("Git HEAD drifted during Lean mutation execution")
    try:
        current_worktree = worktree_evidence(root)
    except LeanMutationError as error:
        raise LeanMutationError("worktree drifted during Lean mutation execution") from error
    if current_worktree != snapshot.worktree:
        raise LeanMutationError("worktree drifted during Lean mutation execution")
    evidence_paths = lean_input_paths(root) if paths is None else paths
    current_inputs = input_evidence(root, evidence_paths)
    if tuple(path for path, _ in current_inputs) != tuple(
        path for path, _ in snapshot.inputs
    ):
        raise LeanMutationError(
            "evidence input path set drifted during Lean mutation execution"
        )
    if current_inputs != snapshot.inputs:
        raise LeanMutationError("evidence inputs drifted during Lean mutation execution")


def enumerate_at_snapshot(
    root: Path, snapshot: ExecutionSnapshot
) -> tuple[int, int, int, list[Mutation]]:
    scratch_parent = Path(tempfile.mkdtemp(prefix="chio-lean-discovery-"))
    scratch = scratch_parent / "worktree"
    worktree_added = False
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
            raise LeanMutationError(
                f"cannot create Lean discovery worktree: {added.stderr.strip()}"
            )
        worktree_added = True
        detached_inputs = input_evidence(scratch, lean_input_paths(scratch))
        if detached_inputs != snapshot.inputs:
            raise LeanMutationError(
                "detached Lean discovery inputs differ from the starting snapshot"
            )
        sample_size, timeout_secs, baseline_timeout_secs, definitions = (
            load_allowlist(scratch)
        )
        return (
            sample_size,
            timeout_secs,
            baseline_timeout_secs,
            enumerate_mutations(scratch, definitions),
        )
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


def run_process(
    command: list[str], cwd: Path, log: Path, timeout_secs: int
) -> tuple[int | None, float]:
    start = time.monotonic()
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=timeout_secs)
        except subprocess.TimeoutExpired:
            kill_process_group(process)
            exit_code = None
        except BaseException:
            kill_process_group(process)
            raise
    return exit_code, time.monotonic() - start


def lean_module_name(path: Path) -> str:
    if path.suffix != ".lean":
        raise LeanMutationError(f"Lean module path must end in .lean: {path}")
    return ".".join(path.with_suffix("").parts)


def attributable_lean_sources(lean_root: Path, mutation_path: Path) -> set[Path]:
    try:
        target = mutation_path.relative_to(LEAN_PROJECT)
    except ValueError:
        target = mutation_path
    require_regular_repo_file(lean_root, target, "mutated Lean source")

    modules: dict[str, Path] = {}
    imports: dict[str, set[str]] = {}
    for source in sorted(lean_root.rglob("*.lean")):
        relative = source.relative_to(lean_root)
        if ".lake" in relative.parts or source.is_symlink() or not source.is_file():
            continue
        module = lean_module_name(relative)
        if module in modules:
            raise LeanMutationError(f"Lean project repeats module {module}")
        modules[module] = relative
        source_lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
        imports[module] = lean_header_imports(source_lines)

    target_module = lean_module_name(target)
    if modules.get(target_module) != target:
        raise LeanMutationError(f"mutated Lean module is absent from the project: {target}")
    reverse_imports: dict[str, set[str]] = {module: set() for module in modules}
    for module, dependencies in imports.items():
        for dependency in dependencies:
            if dependency in reverse_imports:
                reverse_imports[dependency].add(module)

    attributable = {target_module}
    pending = [target_module]
    while pending:
        dependency = pending.pop()
        for importer in reverse_imports[dependency]:
            if importer not in attributable:
                attributable.add(importer)
                pending.append(importer)
    return {modules[module] for module in attributable}


def diagnostic_project_path(lean_root: Path, raw_path: str) -> Path | None:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(lean_root.resolve())
        except ValueError:
            return None
    else:
        relative = candidate
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        return None
    try:
        require_regular_repo_file(lean_root, relative, "Lean diagnostic source")
    except LeanMutationError:
        return None
    return relative


def classify_lake(
    exit_code: int | None,
    log_path: Path,
    *,
    lean_root: Path,
    mutation_path: Path,
) -> str:
    if exit_code is None:
        return "timeout"
    text = ANSI_ESCAPE.sub("", log_path.read_text(encoding="utf-8", errors="replace"))
    diagnostics: list[str] = []
    independent_failure = any(pattern.search(text) for pattern in TOOL_FAILURE_PATTERNS)
    for line in text.splitlines():
        diagnostic = LEAN_DIAGNOSTIC.fullmatch(line)
        if diagnostic is not None:
            diagnostics.append(
                diagnostic.group("prefixed") or diagnostic.group("plain")
            )
        elif line.startswith("error:") and EXPECTED_LAKE_ERROR.fullmatch(line) is None:
            independent_failure = True

    if exit_code == 0:
        if diagnostics or independent_failure:
            raise LeanMutationError(
                "unviable Lean run: successful Lake exit contains failure evidence"
            )
        return "survived"
    if exit_code != 1:
        raise LeanMutationError(
            f"unviable Lean run: unexpected Lake source-failure exit {exit_code}"
        )
    if independent_failure:
        raise LeanMutationError(
            "unviable Lean run: log contains independent tool-failure evidence"
        )
    if not diagnostics:
        raise LeanMutationError(
            "unviable Lean run: Lake failure has no Lean source diagnostic"
        )

    attributable = attributable_lean_sources(lean_root, mutation_path)
    diagnostic_paths = [
        diagnostic_project_path(lean_root, path) for path in diagnostics
    ]
    if any(path is None or path not in attributable for path in diagnostic_paths):
        raise LeanMutationError(
            "unviable Lean run: source diagnostics are not attributable to the mutation"
        )
    return "killed"


def select_mutants(
    mutants: list[Mutation],
    commit: str,
    sample_size: int,
    full: bool,
    sample_epoch: int,
) -> tuple[list[Mutation], str]:
    seed = commit[:16]
    if full or sample_size >= len(mutants):
        return list(mutants), seed
    generator = random.Random(int(seed, 16))
    permutation = list(range(len(mutants)))
    generator.shuffle(permutation)
    start = sample_epoch * sample_size % len(permutation)
    indexes = sorted(
        permutation[(start + offset) % len(permutation)] for offset in range(sample_size)
    )
    return [mutants[index] for index in indexes], seed


def safe_output(root: Path) -> Path:
    lexical = (root / OUTPUT).absolute()
    current = root.absolute()
    for part in lexical.relative_to(current).parts:
        current /= part
        if current.is_symlink():
            raise LeanMutationError("Lean mutation output must not contain symlink components")
    candidate = lexical.resolve()
    formal_root = (root / "target/formal").resolve()
    if root.resolve() not in candidate.parents or formal_root not in candidate.parents:
        raise LeanMutationError("Lean mutation output must be below target/formal")
    return candidate


def report_bounds(
    sample_size: int, timeout_secs: int, baseline_timeout_secs: int
) -> dict[str, int]:
    return {
        "sample_size": sample_size,
        "clean_baseline_timeout_secs": baseline_timeout_secs,
        "per_mutant_timeout_secs": timeout_secs,
    }


def execute(
    root: Path,
    mutants: list[Mutation],
    *,
    sample_size: int,
    timeout_secs: int,
    baseline_timeout_secs: int,
    full: bool,
    lake: str,
    sample_epoch: int,
    snapshot: ExecutionSnapshot,
) -> int:
    commit = snapshot.commit
    selected, seed = select_mutants(mutants, commit, sample_size, full, sample_epoch)
    output = safe_output(root)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    scratch_parent = Path(tempfile.mkdtemp(prefix="chio-lean-mutants-"))
    scratch = scratch_parent / "worktree"
    worktree_added = False
    results: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    try:
        added = subprocess.run(
            ["git", "worktree", "add", "--detach", str(scratch), commit],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if added.returncode != 0:
            raise LeanMutationError(f"cannot create Lean scratch worktree: {added.stderr.strip()}")
        worktree_added = True
        for path in sorted({mutant.path for mutant in selected}):
            mutable_source_path(scratch, path)
        lean_root = scratch / LEAN_PROJECT
        toolchain = (scratch / LEAN_TOOLCHAIN).read_text(encoding="utf-8").strip()
        toolchain_match = re.fullmatch(
            r"leanprover/lean4:v([0-9]+\.[0-9]+\.[0-9]+)", toolchain
        )
        if toolchain_match is None:
            raise LeanMutationError(
                "Lean project must pin an exact leanprover/lean4 toolchain"
            )
        version = subprocess.run(
            [lake, "--version"],
            cwd=lean_root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        version_text = version.stdout.strip()
        expected_lean = toolchain_match.group(1)
        if (
            version.returncode != 0
            or f"(Lean version {expected_lean})" not in version_text
        ):
            raise LeanMutationError(
                f"Lake does not use pinned Lean {expected_lean}: {version_text!r}"
            )
        baseline_log = output / "baseline.log"
        baseline_exit, baseline_wall = run_process(
            [lake, "build"], lean_root, baseline_log, baseline_timeout_secs
        )
        commands.append(
            {
                "kind": "clean-baseline",
                "argv": [lake, "build"],
                "exit_code": baseline_exit,
                "timeout_secs": baseline_timeout_secs,
                "wall_secs": round(baseline_wall, 3),
                "log_sha256": sha256_file(baseline_log),
            }
        )
        if baseline_exit != 0:
            raise LeanMutationError("clean Lean baseline failed or timed out")
        for mutant in selected:
            source_path = mutable_source_path(scratch, mutant.path)
            original = source_path.read_text(encoding="utf-8")
            mutated = apply_mutation(scratch, mutant)
            write_mutable_source(scratch, mutant.path, mutated)
            log_path = output / "runs" / mutant.id / "lake.log"
            exit_code, wall_secs = run_process(
                [lake, "build"], lean_root, log_path, timeout_secs
            )
            verdict = classify_lake(
                exit_code,
                log_path,
                lean_root=lean_root,
                mutation_path=mutant.path,
            )
            result = mutant.public()
            result.update(
                {
                    "verdict": verdict,
                    "lake_exit": exit_code,
                    "wall_secs": round(wall_secs, 3),
                    "mutated_sha256": sha256_bytes(mutated.encode()),
                    "log_sha256": sha256_file(log_path),
                }
            )
            results.append(result)
            commands.append(
                {
                    "mutant_id": mutant.id,
                    "argv": [lake, "build"],
                    "timeout_secs": timeout_secs,
                }
            )
            write_mutable_source(scratch, mutant.path, original)
            status = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                cwd=scratch,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if status.returncode != 0 or status.stdout:
                raise LeanMutationError(f"Lean scratch worktree did not restore after {mutant.id}")
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
    counts = {
        verdict: sum(result["verdict"] == verdict for result in results)
        for verdict in ("killed", "survived", "timeout")
    }
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    activation = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    report = {
        "schema": SCHEMA,
        "commit": commit,
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "worktree": snapshot.worktree,
        "sample_seed": seed,
        "sample_epoch": sample_epoch,
        "full_cycle": len(selected) == len(mutants),
        "enumerated": len(mutants),
        "tools": {
            "lake": version_text,
            "lean_toolchain": toolchain,
            "python": sys.version.split()[0],
        },
        "bounds": report_bounds(sample_size, timeout_secs, baseline_timeout_secs),
        "inputs": snapshot.report_inputs(),
        "commands": commands,
        "mutants": results,
        "aggregate": {
            "sampled": len(results),
            **counts,
            "timeout_policy": "timeouts count as not killed",
            "activation_ratio_percent": activation,
        },
    }
    verify_execution_snapshot(root, snapshot)
    atomic_json(output / "report.json", report)
    print(f"lean-mutants: activation={activation}% report={output / 'report.json'}")
    return 0


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--sample-size", type=int)
    parser.add_argument("--timeout-secs", type=int)
    parser.add_argument("--baseline-timeout-secs", type=int)
    parser.add_argument(
        "--sample-epoch",
        type=int,
        default=os.environ.get("CHIO_MUTATION_SAMPLE_EPOCH", "0"),
        help="recorded rotation epoch mixed into the commit-seeded sample",
    )
    parser.add_argument("--lake", default=os.environ.get("LAKE_BIN", "lake"))
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    root = REPO_ROOT.resolve()
    if options.list:
        _, _, _, definitions = load_allowlist(root)
        mutants = enumerate_mutations(root, definitions)
        print(json.dumps([mutant.public() for mutant in mutants], indent=2, sort_keys=True))
        return 0
    snapshot = capture_execution_snapshot(root)
    default_sample, default_timeout, default_baseline_timeout, mutants = (
        enumerate_at_snapshot(root, snapshot)
    )
    verify_execution_snapshot(root, snapshot)
    sample_size = default_sample if options.sample_size is None else options.sample_size
    timeout_secs = default_timeout if options.timeout_secs is None else options.timeout_secs
    baseline_timeout_secs = (
        default_baseline_timeout
        if options.baseline_timeout_secs is None
        else options.baseline_timeout_secs
    )
    if sample_size < 1 or timeout_secs < 1 or baseline_timeout_secs < 1:
        raise LeanMutationError("sample size and timeouts must be positive")
    if options.sample_epoch < 0:
        raise LeanMutationError("sample epoch must be non-negative")
    return execute(
        root,
        mutants,
        sample_size=sample_size,
        timeout_secs=timeout_secs,
        baseline_timeout_secs=baseline_timeout_secs,
        full=options.full,
        lake=options.lake,
        sample_epoch=options.sample_epoch,
        snapshot=snapshot,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (LeanMutationError, OSError, subprocess.TimeoutExpired) as error:
        print(f"lean-mutants: {error}", file=sys.stderr)
        raise SystemExit(2) from error
