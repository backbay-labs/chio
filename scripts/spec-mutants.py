#!/usr/bin/env python3

"""Deterministically mutate allowlisted TLA+ actions and score Apalache."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, replace
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
from typing import Any, Iterable, Iterator

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))

from apalache_evidence import (  # noqa: E402
    EvidenceError,
    classify_completed_run,
    discover_trace,
    validate_trace,
)


SCHEMA = "chio.spec-mutants-report.v1"
ALLOWLIST_SCHEMA = "chio.spec-mutants-allowlist.v1"
DEFAULT_ALLOWLIST = Path("formal/apalache/spec-mutants-allowlist.toml")
DEFAULT_REPORT = Path("target/formal/spec-mutants-report.json")
DEFAULT_RUN_ROOT = Path("target/formal/spec-mutants")
EXPECTED_APALACHE = "0.50.1"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OPERATOR_HEADER = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)(?:\([^\n]*\))?\s*==(?:\s*(.*))?$"
)
MODULE_HEADER = re.compile(r"^-+\s+MODULE\s+([A-Za-z_][A-Za-z0-9_]*)\s+-+\s*$")
UNVIABLE_PATTERNS = (
    re.compile(r"\b(?:parse|parser|parsing|lexer|type|typing|typechecker)[ -]?(?:error|failed|failure)\b", re.I),
    re.compile(r"\b(?:error|failed|failure)\b.*\b(?:parse|parser|type|typing|typechecker)\b", re.I),
    re.compile(r"\bunexpected (?:character|token|symbol)\b", re.I),
)


class MutationError(RuntimeError):
    """Raised when mutation inputs or tool evidence fail closed."""


@dataclass(frozen=True)
class ExecutionSnapshot:
    commit: str
    worktree: dict[str, Any]
    inputs: tuple[tuple[str, str], ...]
    blobs: tuple[tuple[str, bytes], ...]

    def report_inputs(self) -> list[dict[str, str]]:
        return [{"path": path, "sha256": digest} for path, digest in self.inputs]


@dataclass(frozen=True)
class OperatorSpan:
    name: str
    start: int
    end: int


@dataclass(frozen=True)
class SpecConfig:
    name: str
    path: Path
    cfg: Path
    invariant: str
    length: int
    actions: tuple[str, ...]


@dataclass(frozen=True)
class SeedConfig:
    name: str
    spec: str
    action: str
    operator: str
    match: str
    replacement: str
    negative_spec: Path
    negative_action: str


@dataclass(frozen=True)
class ProbeConfig:
    name: str
    spec: str
    action: str
    operator: str
    match: str
    replacement: str
    classification: str
    rationale: str


@dataclass(frozen=True)
class Settings:
    path: Path
    negative_registry: Path
    sample_size: int
    timeout_secs: int
    baseline_timeout_secs: int
    activation_target_percent: float
    specs: tuple[SpecConfig, ...]
    probes: tuple[ProbeConfig, ...]
    seeds: tuple[SeedConfig, ...]


@dataclass(frozen=True)
class Mutation:
    id: str
    spec: str
    path: Path
    cfg: Path
    invariant: str
    length: int
    action: str
    operator: str
    line: int
    column: int
    start: int
    end: int
    original: str
    replacement: str
    source_sha256: str
    classification: str
    rationale: str
    seed: str | None = None

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "spec": self.spec,
            "path": self.path.as_posix(),
            "cfg": self.cfg.as_posix(),
            "invariant": self.invariant,
            "length": self.length,
            "action": self.action,
            "operator": self.operator,
            "line": self.line,
            "column": self.column,
            "original": self.original,
            "replacement": self.replacement,
            "source_sha256": self.source_sha256,
            "classification": self.classification,
            "rationale": self.rationale,
        }
        if self.seed is not None:
            result["registered_seed"] = self.seed
        return result


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_id(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)[:20]


def inventory_sha256(mutations: Iterable[Mutation]) -> str:
    encoded = json.dumps(
        [mutation.public() for mutation in mutations],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha256_bytes(encoded)


def repo_path(root: Path, raw: Any, field: str, *, suffix: str | None = None) -> Path:
    if not isinstance(raw, str) or not raw or any(value in raw for value in "\r\n\t"):
        raise MutationError(f"{field} must be a non-empty repository path")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
        raise MutationError(f"{field} must not escape the repository: {raw}")
    if suffix is not None and relative.suffix != suffix:
        raise MutationError(f"{field} must end in {suffix}: {raw}")
    candidate = root.absolute()
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            raise MutationError(f"{field} contains a symlink component: {raw}")
    candidate = candidate.resolve()
    resolved_root = root.resolve()
    if resolved_root not in candidate.parents or not candidate.is_file():
        raise MutationError(f"{field} is not a repository file: {raw}")
    return relative


def require_keys(table: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - set(table)
    unknown = set(table) - expected
    if missing or unknown:
        raise MutationError(
            f"{label} has missing={sorted(missing)} unknown={sorted(unknown)}"
        )


def load_settings(root: Path, allowlist: Path) -> Settings:
    relative_allowlist = repo_path(root, allowlist.as_posix(), "allowlist", suffix=".toml")
    try:
        data = tomllib.loads((root / relative_allowlist).read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise MutationError(f"cannot parse {relative_allowlist}: {error}") from error
    expected_top = {
        "schema",
        "negative_registry",
        "sample_size",
        "timeout_secs",
        "baseline_timeout_secs",
        "activation_target_percent",
        "spec",
        "probe",
        "seed",
    }
    require_keys(data, expected_top, "allowlist")
    if data["schema"] != ALLOWLIST_SCHEMA:
        raise MutationError(f"allowlist schema must be {ALLOWLIST_SCHEMA}")
    sample_size = data["sample_size"]
    timeout_secs = data["timeout_secs"]
    baseline_timeout_secs = data["baseline_timeout_secs"]
    activation = data["activation_target_percent"]
    if type(sample_size) is not int or sample_size < 16:
        raise MutationError("allowlist sample_size must be an integer of at least 16")
    if type(timeout_secs) is not int or timeout_secs < 1:
        raise MutationError("allowlist timeout_secs must be a positive integer")
    if (
        type(baseline_timeout_secs) is not int
        or baseline_timeout_secs < timeout_secs
    ):
        raise MutationError(
            "allowlist baseline_timeout_secs must be an integer at least timeout_secs"
        )
    if type(activation) not in (int, float) or isinstance(activation, bool):
        raise MutationError("allowlist activation_target_percent must be numeric")
    activation = float(activation)
    if not 0.0 <= activation <= 100.0:
        raise MutationError("allowlist activation_target_percent must be between 0 and 100")
    negative_registry = repo_path(
        root, data["negative_registry"], "negative_registry", suffix=".toml"
    )

    raw_specs = data["spec"]
    if not isinstance(raw_specs, list) or not raw_specs:
        raise MutationError("allowlist needs at least one spec")
    specs: list[SpecConfig] = []
    seen_names: set[str] = set()
    seen_paths: set[Path] = set()
    spec_fields = {"name", "path", "cfg", "invariant", "length", "actions"}
    for index, raw_spec in enumerate(raw_specs, start=1):
        if not isinstance(raw_spec, dict):
            raise MutationError(f"spec {index} must be a table")
        require_keys(raw_spec, spec_fields, f"spec {index}")
        name = raw_spec["name"]
        invariant = raw_spec["invariant"]
        actions = raw_spec["actions"]
        length = raw_spec["length"]
        if not isinstance(name, str) or IDENTIFIER.fullmatch(name) is None:
            raise MutationError(f"spec {index} has an invalid name")
        if not isinstance(invariant, str) or IDENTIFIER.fullmatch(invariant) is None:
            raise MutationError(f"spec {index} has an invalid invariant")
        if type(length) is not int or length < 1:
            raise MutationError(f"spec {index} has an invalid length")
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(action, str) and IDENTIFIER.fullmatch(action) for action in actions)
            or len(set(actions)) != len(actions)
        ):
            raise MutationError(f"spec {index} actions must be unique identifiers")
        path = repo_path(root, raw_spec["path"], f"spec {index} path", suffix=".tla")
        cfg = repo_path(root, raw_spec["cfg"], f"spec {index} cfg", suffix=".cfg")
        if path.stem != name or cfg.name != f"MC{name}.cfg":
            raise MutationError(f"spec {index} names do not match path and cfg")
        if name in seen_names or path in seen_paths:
            raise MutationError(f"spec {index} repeats a name or path")
        seen_names.add(name)
        seen_paths.add(path)
        specs.append(
            SpecConfig(name, path, cfg, invariant, length, tuple(actions))
        )

    raw_probes = data["probe"]
    if not isinstance(raw_probes, list) or len(raw_probes) < 16:
        raise MutationError("allowlist needs at least 16 classified probes")
    probe_fields = {
        "name",
        "spec",
        "action",
        "operator",
        "match",
        "replacement",
        "classification",
        "rationale",
    }
    probes: list[ProbeConfig] = []
    seen_probe_names: set[str] = set()
    supported_classifications = {"guard-weakening", "post-state-corruption"}
    for index, raw_probe in enumerate(raw_probes, start=1):
        if not isinstance(raw_probe, dict):
            raise MutationError(f"probe {index} must be a table")
        require_keys(raw_probe, probe_fields, f"probe {index}")
        if any(
            not isinstance(raw_probe[field], str)
            or any(character in raw_probe[field] for character in "\r\n\t")
            or (field != "replacement" and not raw_probe[field])
            for field in probe_fields
        ):
            raise MutationError(f"probe {index} fields must be non-empty single-line strings")
        name = raw_probe["name"]
        if re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None or name in seen_probe_names:
            raise MutationError(f"probe {index} has an invalid or repeated name")
        if raw_probe["spec"] not in seen_names:
            raise MutationError(f"probe {index} names an unknown spec")
        spec = next(candidate for candidate in specs if candidate.name == raw_probe["spec"])
        if raw_probe["action"] not in spec.actions:
            raise MutationError(f"probe {index} names a non-allowlisted action")
        if raw_probe["operator"] not in {"delete_conjunct", "replace_expression"}:
            raise MutationError(f"probe {index} has an unsupported operator")
        if raw_probe["classification"] not in supported_classifications:
            raise MutationError(f"probe {index} has an unsupported classification")
        if raw_probe["operator"] == "delete_conjunct" and raw_probe["replacement"]:
            raise MutationError(f"probe {index} conjunct deletion must have an empty replacement")
        if raw_probe["match"] == raw_probe["replacement"]:
            raise MutationError(f"probe {index} does not change its expression")
        seen_probe_names.add(name)
        probes.append(
            ProbeConfig(
                name,
                raw_probe["spec"],
                raw_probe["action"],
                raw_probe["operator"],
                raw_probe["match"],
                raw_probe["replacement"],
                raw_probe["classification"],
                raw_probe["rationale"],
            )
        )
    for spec in specs:
        covered_actions = {probe.action for probe in probes if probe.spec == spec.name}
        if covered_actions != set(spec.actions):
            raise MutationError(
                f"spec {spec.name} probe coverage differs from its action allowlist: "
                f"covered={sorted(covered_actions)} actions={sorted(spec.actions)}"
            )

    raw_seeds = data["seed"]
    if not isinstance(raw_seeds, list) or len(raw_seeds) < 2:
        raise MutationError("allowlist needs at least two registered seeds")
    seed_fields = {
        "name",
        "spec",
        "action",
        "operator",
        "match",
        "replacement",
        "negative_spec",
        "negative_action",
    }
    seeds: list[SeedConfig] = []
    seen_seed_names: set[str] = set()
    for index, raw_seed in enumerate(raw_seeds, start=1):
        if not isinstance(raw_seed, dict):
            raise MutationError(f"seed {index} must be a table")
        require_keys(raw_seed, seed_fields, f"seed {index}")
        for field in seed_fields - {"negative_spec"}:
            if not isinstance(raw_seed[field], str) or any(
                value in raw_seed[field] for value in "\r\n\t"
            ):
                raise MutationError(f"seed {index} field {field} must be one line")
        if not raw_seed["name"] or raw_seed["name"] in seen_seed_names:
            raise MutationError(f"seed {index} has an invalid or repeated name")
        if raw_seed["spec"] not in seen_names:
            raise MutationError(f"seed {index} names an unknown spec")
        spec = next(spec for spec in specs if spec.name == raw_seed["spec"])
        if raw_seed["action"] not in spec.actions:
            raise MutationError(f"seed {index} names a non-allowlisted action")
        if raw_seed["operator"] not in {"delete_conjunct", "replace_expression"}:
            raise MutationError(f"seed {index} has an unsupported operator")
        if not raw_seed["match"] or raw_seed["match"] == raw_seed["replacement"]:
            raise MutationError(f"seed {index} must change a non-empty expression")
        negative_spec = repo_path(
            root,
            raw_seed["negative_spec"],
            f"seed {index} negative_spec",
            suffix=".tla",
        )
        if IDENTIFIER.fullmatch(raw_seed["negative_action"]) is None:
            raise MutationError(f"seed {index} has an invalid negative_action")
        seen_seed_names.add(raw_seed["name"])
        seeds.append(
            SeedConfig(
                raw_seed["name"],
                raw_seed["spec"],
                raw_seed["action"],
                raw_seed["operator"],
                raw_seed["match"],
                raw_seed["replacement"],
                negative_spec,
                raw_seed["negative_action"],
            )
        )
    return Settings(
        relative_allowlist,
        negative_registry,
        sample_size,
        timeout_secs,
        baseline_timeout_secs,
        activation,
        tuple(specs),
        tuple(probes),
        tuple(seeds),
    )


def mask_comments(lines: list[str]) -> list[str]:
    """Replace TLA+ comments with spaces while preserving every column."""

    masked: list[str] = []
    depth = 0
    for line in lines:
        result = list(line)
        index = 0
        while index < len(line):
            if depth == 0 and line.startswith("\\*", index):
                for position in range(index, len(line)):
                    if line[position] != "\n":
                        result[position] = " "
                break
            if line.startswith("(*", index):
                depth += 1
                result[index : index + 2] = [" ", " "]
                index += 2
                continue
            if depth > 0 and line.startswith("*)", index):
                depth -= 1
                result[index : index + 2] = [" ", " "]
                index += 2
                continue
            if depth > 0 and line[index] != "\n":
                result[index] = " "
            index += 1
        masked.append("".join(result))
    if depth != 0:
        raise MutationError("TLA+ source has an unterminated block comment")
    return masked


def parse_operators(lines: list[str]) -> dict[str, OperatorSpan]:
    masked = mask_comments(lines)
    starts: list[tuple[str, int]] = []
    for index, line in enumerate(masked):
        match = OPERATOR_HEADER.fullmatch(line.rstrip("\n"))
        if match is not None:
            starts.append((match.group(1), index))
    operators: dict[str, OperatorSpan] = {}
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        if name in operators:
            raise MutationError(f"TLA+ source repeats top-level operator {name}")
        operators[name] = OperatorSpan(name, start, end)
    return operators


def operator_text(masked: list[str], span: OperatorSpan) -> str:
    return "".join(masked[span.start : span.end])


def dependency_graph(masked: list[str], operators: dict[str, OperatorSpan]) -> dict[str, set[str]]:
    names = set(operators)
    graph: dict[str, set[str]] = {}
    for name, span in operators.items():
        text = operator_text(masked, span)
        graph[name] = {
            candidate
            for candidate in names
            if candidate != name and re.search(rf"\b{re.escape(candidate)}\b", text)
        }
    return graph


def closure(graph: dict[str, set[str]], start: str) -> set[str]:
    pending = [start]
    visited: set[str] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        pending.extend(sorted(graph.get(name, set()) - visited))
    return visited


def cfg_invariants(text: str) -> list[str]:
    without_comments = re.sub(r"(?m)\\\*.*$", "", text)
    directives = re.findall(r"(?m)^\s*INVARIANTS?\b.*$", without_comments)
    selected = re.findall(
        r"(?m)^\s*INVARIANT\s*$\n^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
        without_comments,
    )
    if len(directives) != 1 or len(selected) != 1:
        raise MutationError("each mutation cfg must select exactly one invariant")
    return selected


def validate_spec(root: Path, spec: SpecConfig) -> tuple[list[str], list[str], dict[str, OperatorSpan]]:
    lines = (root / spec.path).read_text(encoding="utf-8").splitlines(keepends=True)
    module_names = [
        match.group(1)
        for line in lines
        if (match := MODULE_HEADER.fullmatch(line.rstrip("\n")))
    ]
    if module_names != [spec.name]:
        raise MutationError(f"{spec.path} module name does not match {spec.name}")
    if cfg_invariants((root / spec.cfg).read_text(encoding="utf-8")) != [spec.invariant]:
        raise MutationError(f"{spec.cfg} does not select exactly {spec.invariant}")
    masked = mask_comments(lines)
    operators = parse_operators(lines)
    required = {"Init", "Next", spec.invariant, *spec.actions}
    missing = required - set(operators)
    if missing:
        raise MutationError(f"{spec.path} is missing operators: {sorted(missing)}")
    if "Init" in spec.actions or "Next" in spec.actions or spec.invariant in spec.actions:
        raise MutationError(f"{spec.path} allowlists a protected operator")
    graph = dependency_graph(masked, operators)
    reachable = closure(graph, "Next")
    unreachable = set(spec.actions) - reachable
    if unreachable:
        raise MutationError(
            f"{spec.path} allowlists actions unreachable from Next: {sorted(unreachable)}"
        )
    property_closure = closure(graph, spec.invariant)
    overlap = set(spec.actions) & property_closure
    if overlap:
        raise MutationError(
            f"{spec.path} allowlists property definitions: {sorted(overlap)}"
        )
    return lines, masked, operators


def make_mutation(
    spec: SpecConfig,
    action: str,
    operator: str,
    line_index: int,
    start: int,
    end: int,
    original: str,
    replacement_text: str,
    source_sha256: str,
    classification: str,
    rationale: str,
    seed: str | None = None,
) -> Mutation:
    identity = {
        "spec": spec.name,
        "path": spec.path.as_posix(),
        "action": action,
        "operator": operator,
        "line": line_index + 1,
        "column": start + 1,
        "original": original,
        "replacement": replacement_text,
    }
    return Mutation(
        canonical_id(identity),
        spec.name,
        spec.path,
        spec.cfg,
        spec.invariant,
        spec.length,
        action,
        operator,
        line_index + 1,
        start + 1,
        start,
        end,
        original,
        replacement_text,
        source_sha256,
        classification,
        rationale,
        seed,
    )


def enumerate_spec_mutations(
    root: Path,
    spec: SpecConfig,
    probes: Iterable[ProbeConfig],
    seeds: Iterable[SeedConfig],
) -> tuple[list[Mutation], dict[str, OperatorSpan]]:
    lines, masked, operators = validate_spec(root, spec)
    source_sha = sha256_file(root / spec.path)
    mutations: dict[tuple[int, int, int, str], Mutation] = {}
    for probe in probes:
        if probe.spec != spec.name:
            continue
        span = operators[probe.action]
        sites: list[tuple[int, int]] = []
        for line_index in range(span.start + 1, span.end):
            code = masked[line_index].rstrip("\n")
            offset = code.find(probe.match)
            while offset >= 0:
                sites.append((line_index, offset))
                offset = code.find(probe.match, offset + 1)
        if len(sites) != 1:
            raise MutationError(
                f"probe {probe.name} expected one production match, found {len(sites)}"
            )
        line_index, start = sites[0]
        end = start + len(probe.match)
        original = probe.match
        replacement_text = probe.replacement
        if probe.operator == "delete_conjunct":
            if masked[line_index].strip() != probe.match:
                raise MutationError(f"probe {probe.name} does not name a complete conjunct")
            start = 0
            end = len(lines[line_index].rstrip("\n"))
            original = probe.match
        key = (line_index, start, end, replacement_text)
        if key in mutations:
            raise MutationError(f"probe {probe.name} duplicates another mutation")
        mutations[key] = make_mutation(
            spec,
            probe.action,
            probe.operator,
            line_index,
            start,
            end,
            original,
            replacement_text,
            source_sha,
            probe.classification,
            probe.rationale,
        )

    for seed in seeds:
        if seed.spec != spec.name:
            continue
        span = operators[seed.action]
        sites: list[tuple[int, int]] = []
        for line_index in range(span.start + 1, span.end):
            code = masked[line_index]
            offset = code.find(seed.match)
            while offset >= 0:
                sites.append((line_index, offset))
                offset = code.find(seed.match, offset + 1)
        if len(sites) != 1:
            raise MutationError(
                f"seed {seed.name} expected one production match, found {len(sites)}"
            )
        line_index, start = sites[0]
        end = start + len(seed.match)
        if seed.operator == "delete_conjunct":
            start = 0
            end = len(lines[line_index].rstrip("\n"))
            original = masked[line_index].strip()
            replacement_text = ""
        else:
            original = seed.match
            replacement_text = seed.replacement
        key = (line_index, start, end, replacement_text)
        existing = mutations.get(key)
        if existing is not None:
            mutations[key] = replace(existing, seed=seed.name)
        else:
            mutations[key] = make_mutation(
                spec,
                seed.action,
                seed.operator,
                line_index,
                start,
                end,
                original,
                replacement_text,
                source_sha,
                "historical-regression",
                f"Reproduces registered negative variant {seed.name}.",
                seed.name,
            )
    ordered = sorted(
        mutations.values(),
        key=lambda item: (
            item.path.as_posix(),
            item.action,
            item.line,
            item.column,
            item.operator,
            item.replacement,
        ),
    )
    return ordered, operators


def validate_seed_variants(
    root: Path, settings: Settings, mutations: list[Mutation]
) -> list[dict[str, str]]:
    try:
        registry = tomllib.loads((root / settings.negative_registry).read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise MutationError(f"cannot parse {settings.negative_registry}: {error}") from error
    registered = {
        entry.get("spec")
        for entry in registry.get("negative", [])
        if isinstance(entry, dict)
    }
    by_seed = {mutation.seed: mutation for mutation in mutations if mutation.seed is not None}
    results: list[dict[str, str]] = []
    for seed in settings.seeds:
        if seed.name not in by_seed:
            raise MutationError(f"seed {seed.name} was not generated")
        if seed.negative_spec.as_posix() not in registered:
            raise MutationError(f"seed {seed.name} is absent from the negative registry")
        negative_lines = (root / seed.negative_spec).read_text(encoding="utf-8").splitlines(
            keepends=True
        )
        negative_masked = mask_comments(negative_lines)
        negative_operators = parse_operators(negative_lines)
        if seed.negative_action not in negative_operators:
            raise MutationError(
                f"seed {seed.name} negative action {seed.negative_action} is missing"
            )
        body = operator_text(negative_masked, negative_operators[seed.negative_action])
        if seed.match in body:
            raise MutationError(f"seed {seed.name} negative variant retains the original expression")
        if seed.replacement and seed.replacement not in body:
            raise MutationError(f"seed {seed.name} negative variant lacks its replacement")
        mutation = by_seed[seed.name]
        results.append(
            {
                "name": seed.name,
                "mutant_id": mutation.id,
                "negative_spec": seed.negative_spec.as_posix(),
                "status": "subsumed",
            }
        )
    return results


def enumerate_mutations(
    root: Path, settings: Settings
) -> tuple[list[Mutation], list[dict[str, str]]]:
    mutations: list[Mutation] = []
    for spec in settings.specs:
        spec_mutations, _ = enumerate_spec_mutations(
            root, spec, settings.probes, settings.seeds
        )
        if not spec_mutations:
            raise MutationError(f"{spec.path} yielded no mutants")
        mutations.extend(spec_mutations)
    ids = [mutation.id for mutation in mutations]
    if len(ids) != len(set(ids)):
        raise MutationError("mutation identifiers are not unique")
    mutations.sort(
        key=lambda item: (
            item.path.as_posix(),
            item.action,
            item.line,
            item.column,
            item.operator,
            item.replacement,
        )
    )
    seeds = validate_seed_variants(root, settings, mutations)
    return mutations, seeds


def apply_mutation(root: Path, mutation: Mutation) -> str:
    path = root / mutation.path
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    index = mutation.line - 1
    line = lines[index]
    newline = "\n" if line.endswith("\n") else ""
    content = line[:-1] if newline else line
    if content[mutation.start : mutation.end] != mutation.original:
        if mutation.operator != "delete_conjunct" or content.strip() != mutation.original:
            raise MutationError(f"mutant {mutation.id} source span drifted")
    lines[index] = (
        content[: mutation.start] + mutation.replacement + content[mutation.end :] + newline
    )
    return "".join(lines)


def resolve_output_root(root: Path, raw: str | None) -> Path:
    requested = Path(raw) if raw else DEFAULT_RUN_ROOT
    if not requested.is_absolute():
        requested = root / requested
    lexical = requested.absolute()
    lexical_target = (root / "target/formal").absolute()
    requested_under_target = lexical_target == lexical or lexical_target in lexical.parents
    if requested_under_target:
        current = root.absolute()
        try:
            relative = lexical.relative_to(current)
        except ValueError as error:
            raise MutationError("output root has an invalid repository path") from error
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise MutationError("output root must not contain symlink components")
    elif lexical.is_symlink():
        raise MutationError("output root must not be a symlink")

    candidate = lexical.resolve()
    target_formal = (root / "target/formal").resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    under_target = (
        requested_under_target
        and root.resolve() in candidate.parents
        and (target_formal == candidate or target_formal in candidate.parents)
    )
    outside_repo = root.resolve() not in candidate.parents and candidate != root.resolve()
    under_temp = not requested_under_target and temporary in candidate.parents and outside_repo
    if not (under_target or under_temp):
        raise MutationError("output root must be under target/formal or the system temp directory")
    if candidate == target_formal:
        raise MutationError("output root must be a strict child of target/formal")
    return candidate


def resolve_report_path(root: Path, output_root: Path, raw: str | None) -> Path:
    if raw:
        requested = Path(raw)
        if not requested.is_absolute():
            requested = root / requested
    else:
        requested = (
            root / DEFAULT_REPORT
            if output_root == (root / DEFAULT_RUN_ROOT).resolve()
            else output_root.parent / "spec-mutants-report.json"
        )
    if requested.is_symlink():
        raise MutationError("report path must not be a symlink")
    report = requested.resolve()
    if report.parent != output_root.parent:
        raise MutationError("report must be a sibling of the mutation output root")
    return report


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
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
        raise MutationError("cannot resolve a full Git commit")
    return value


def ci_run_evidence() -> dict[str, int] | None:
    names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_NUMBER")
    values = [os.environ.get(name) for name in names]
    if all(value is None for value in values):
        return None
    if any(value is None or not value.isdigit() or int(value) < 1 for value in values):
        raise MutationError("GitHub run identity is incomplete or invalid")
    return {
        "run_id": int(values[0]),
        "run_attempt": int(values[1]),
        "run_number": int(values[2]),
    }


def worktree_evidence(root: Path, *, allow_dirty: bool) -> dict[str, Any]:
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if status.returncode != 0:
        raise MutationError("cannot determine the worktree state")
    dirty = bool(status.stdout)
    if dirty and not allow_dirty:
        raise MutationError("spec mutation execution requires a clean worktree")
    evidence: dict[str, Any] = {"clean": not dirty}
    if dirty:
        diff = subprocess.run(
            ["git", "diff", "HEAD", "--binary"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if diff.returncode != 0:
            raise MutationError("cannot hash the dirty worktree diff")
        evidence.update(
            {
                "status_sha256": sha256_bytes(status.stdout.encode()),
                "tracked_diff_sha256": sha256_bytes(diff.stdout),
            }
        )
    return evidence


def spec_input_paths(root: Path, settings: Settings) -> list[Path]:
    paths = {
        settings.path,
        settings.negative_registry,
        Path("formal/MAPPING.md"),
        *(spec.path for spec in settings.specs),
        *(spec.cfg for spec in settings.specs),
        *(seed.negative_spec for seed in settings.seeds),
        Path("scripts/check-apalache-negative.sh"),
        Path("scripts/lib/apalache_evidence.py"),
        Path("scripts/spec-mutants.py"),
        Path("tools/install-apalache.sh"),
    }
    for spec in settings.specs:
        paths.update(
            sibling.relative_to(root)
            for sibling in (root / spec.path.parent).glob("*.tla")
            if sibling.is_file() and not sibling.is_symlink()
        )
    try:
        negative_registry = tomllib.loads(
            (root / settings.negative_registry).read_text(encoding="utf-8")
        )
        negative_entries = negative_registry.get("negative", [])
        for entry in negative_entries:
            negative_spec = Path(entry["spec"])
            paths.update((negative_spec, Path(entry["cfg"])))
            paths.update(
                sibling.relative_to(root)
                for sibling in (root / negative_spec.parent).glob("*.tla")
                if sibling.is_file() and not sibling.is_symlink()
            )
            runtime_test = entry["runtime_test"]
            if not runtime_test.startswith("n/a"):
                paths.add(Path(runtime_test.split("::", 1)[0]))
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise MutationError("cannot inventory registered negative-test inputs") from error
    return sorted(
        (repo_path(root, path.as_posix(), "evidence input") for path in paths),
        key=lambda path: path.as_posix(),
    )


def input_evidence(root: Path, paths: Iterable[Path]) -> tuple[tuple[str, str], ...]:
    ordered = sorted(set(paths), key=lambda path: path.as_posix())
    return tuple((path.as_posix(), sha256_file(root / path)) for path in ordered)


def capture_execution_snapshot(
    root: Path, paths: Iterable[Path], *, allow_dirty: bool
) -> ExecutionSnapshot:
    commit = git_head(root)
    worktree = worktree_evidence(root, allow_dirty=allow_dirty)
    ordered = sorted(set(paths), key=lambda path: path.as_posix())
    blobs = tuple((path.as_posix(), (root / path).read_bytes()) for path in ordered)
    return ExecutionSnapshot(
        commit=commit,
        worktree=worktree,
        inputs=tuple((path, sha256_bytes(contents)) for path, contents in blobs),
        blobs=blobs,
    )


def verify_execution_snapshot(
    root: Path,
    snapshot: ExecutionSnapshot,
    paths: Iterable[Path],
    *,
    allow_dirty: bool,
) -> None:
    if git_head(root) != snapshot.commit:
        raise MutationError("Git HEAD drifted during specification mutation execution")
    if worktree_evidence(root, allow_dirty=allow_dirty) != snapshot.worktree:
        raise MutationError("worktree drifted during specification mutation execution")
    current_inputs = input_evidence(root, paths)
    if tuple(path for path, _ in current_inputs) != tuple(
        path for path, _ in snapshot.inputs
    ):
        raise MutationError(
            "evidence input path set drifted during specification mutation execution"
        )
    if current_inputs != snapshot.inputs:
        raise MutationError("evidence inputs drifted during specification mutation execution")


@contextmanager
def materialized_execution_root(
    root: Path, snapshot: ExecutionSnapshot
) -> Iterator[Path]:
    scratch_parent = Path(tempfile.mkdtemp(prefix="chio-spec-mutants-source-"))
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
            raise MutationError(
                f"cannot create specification source worktree: {added.stderr.strip()}"
            )
        worktree_added = True
        captured_paths = {Path(path) for path, _ in snapshot.blobs}
        tla_parents = {path.parent for path in captured_paths if path.suffix == ".tla"}
        for parent in tla_parents:
            for candidate in (scratch / parent).glob("*.tla"):
                if candidate.relative_to(scratch) not in captured_paths:
                    candidate.unlink()
        for raw_path, contents in snapshot.blobs:
            relative = Path(raw_path)
            target = scratch
            for part in relative.parts:
                target /= part
                if target.is_symlink():
                    raise MutationError(
                        f"captured specification input contains a symlink: {relative}"
                    )
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and not target.is_file():
                raise MutationError(
                    f"captured specification input is not a file: {relative}"
                )
            target.write_bytes(contents)
            target.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        yield scratch
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


def tool_version(binary: str) -> str:
    try:
        completed = subprocess.run(
            [binary, "version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MutationError(f"cannot execute Apalache version probe: {error}") from error
    version = completed.stdout.strip()
    if completed.returncode != 0 or version != EXPECTED_APALACHE:
        raise MutationError(f"Apalache {EXPECTED_APALACHE} is required, found {version!r}")
    return version


def run_process(
    command: list[str],
    cwd: Path,
    log_path: Path,
    timeout_secs: int,
    environment: dict[str, str] | None = None,
) -> tuple[int | None, float]:
    start = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=environment,
                start_new_session=True,
            )
        except OSError as error:
            raise MutationError(f"cannot execute {command[0]}: {error}") from error
        try:
            exit_code = process.wait(timeout=timeout_secs)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            exit_code = None
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    return exit_code, time.monotonic() - start


def copy_spec_inputs(
    root: Path,
    path: Path,
    cfg: Path,
    input_dir: Path,
    source: str,
) -> tuple[Path, Path]:
    input_dir.mkdir(parents=True, exist_ok=True)
    source_dir = root / path.parent
    for sibling in sorted(source_dir.glob("*.tla")):
        if (
            sibling.name != path.name
            and sibling.is_file()
            and not sibling.is_symlink()
        ):
            shutil.copy2(sibling, input_dir / sibling.name)
    spec_path = input_dir / path.name
    spec_path.write_text(source, encoding="utf-8")
    cfg_path = input_dir / cfg.name
    shutil.copy2(root / cfg, cfg_path)
    return spec_path, cfg_path


def copy_model_inputs(
    root: Path, mutation: Mutation, input_dir: Path, mutated: str
) -> tuple[Path, Path]:
    return copy_spec_inputs(
        root,
        mutation.path,
        mutation.cfg,
        input_dir,
        mutated,
    )


def apalache_check_command(
    binary: str,
    *,
    out_dir: Path,
    run_dir: Path,
    length: int,
    cfg_path: Path,
    spec_path: Path,
) -> list[str]:
    return [
        binary,
        f"--out-dir={out_dir}",
        f"--run-dir={run_dir}",
        "check",
        "--no-deadlock",
        "--output-traces",
        f"--length={length}",
        f"--config={cfg_path}",
        str(spec_path),
    ]


def unviable_log(log_path: Path) -> bool:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return any(pattern.search(text) for pattern in UNVIABLE_PATTERNS)


def positive_baseline_preflight(
    root: Path,
    report_root: Path,
    settings: Settings,
    binary: str,
    output_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baselines: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    for spec in settings.specs:
        entry_root = output_root / "positive-baselines" / spec.name
        input_dir = entry_root / "input"
        out_dir = entry_root / "out"
        run_dir = entry_root / "run"
        log_path = entry_root / "apalache.log"
        source = (root / spec.path).read_text(encoding="utf-8")
        spec_path, cfg_path = copy_spec_inputs(
            root,
            spec.path,
            spec.cfg,
            input_dir,
            source,
        )
        out_dir.mkdir(parents=True)
        run_dir.mkdir(parents=True)
        command = apalache_check_command(
            binary,
            out_dir=out_dir,
            run_dir=run_dir,
            length=spec.length,
            cfg_path=cfg_path,
            spec_path=spec_path,
        )
        exit_code, wall_secs = run_process(
            command, report_root, log_path, settings.baseline_timeout_secs
        )
        if report_root in entry_root.parents:
            relative_entry = entry_root.relative_to(report_root)
            recorded_command = apalache_check_command(
                binary,
                out_dir=relative_entry / "out",
                run_dir=relative_entry / "run",
                length=spec.length,
                cfg_path=relative_entry / "input" / spec.cfg.name,
                spec_path=relative_entry / "input" / spec.path.name,
            )
        else:
            recorded_command = command
        log_sha256 = sha256_file(log_path)
        commands.append(
            {
                "kind": "clean-baseline",
                "spec": spec.name,
                "argv": recorded_command,
                "exit_code": exit_code,
                "wall_secs": round(wall_secs, 3),
                "log_sha256": log_sha256,
            }
        )
        if exit_code is None:
            raise MutationError(
                f"positive baseline {spec.name} exceeded its configured timeout"
            )
        try:
            verdict, trace = classify_completed_run(
                log_path=log_path,
                expected_invariant=spec.invariant,
                expected_length=spec.length,
                exit_code=exit_code,
                run_root=run_dir,
                allow_executions_too_short=False,
            )
        except EvidenceError as error:
            raise MutationError(
                f"positive baseline {spec.name} has invalid evidence: {error}"
            ) from error
        if exit_code != 0 or verdict != "survived" or trace is not None:
            raise MutationError(
                f"positive baseline {spec.name} did not survive its configured invariant"
            )
        baselines.append(
            {
                "spec": spec.name,
                "path": spec.path.as_posix(),
                "cfg": spec.cfg.as_posix(),
                "invariant": spec.invariant,
                "length": spec.length,
                "verdict": "survived",
                "apalache_exit": 0,
                "wall_secs": round(wall_secs, 3),
                "log_sha256": log_sha256,
            }
        )
    return baselines, commands


def negative_preflight(
    root: Path,
    report_root: Path,
    settings: Settings,
    binary: str,
    output_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    negative_root = output_root / "registered-negative"
    log_path = output_root / "registered-negative.log"
    isolated_parent = Path(tempfile.mkdtemp(prefix="chio-spec-negative-"))
    isolated_negative_root = isolated_parent / "registered-negative"
    environment = os.environ.copy()
    environment["APALACHE_BIN"] = binary
    environment["CHIO_APALACHE_NEGATIVE_REGISTRY"] = settings.negative_registry.as_posix()
    environment["CHIO_APALACHE_NEGATIVE_OUTPUT_DIR"] = str(isolated_negative_root)
    command = ["bash", "scripts/check-apalache-negative.sh"]
    registry = tomllib.loads((root / settings.negative_registry).read_text(encoding="utf-8"))
    entries = registry.get("negative", [])
    if (
        not isinstance(entries, list)
        or not entries
        or any(
            not isinstance(entry, dict)
            or type(entry.get("timeout_secs")) is not int
            or entry["timeout_secs"] < 1
            for entry in entries
        )
    ):
        raise MutationError("negative registry has invalid preflight timeouts")
    preflight_timeout = sum(entry["timeout_secs"] for entry in entries) + 60
    try:
        exit_code, wall_secs = run_process(
            command,
            root,
            log_path,
            preflight_timeout,
            environment,
        )
        if exit_code is None:
            raise MutationError(
                "registered negative-suite preflight exceeded its total timeout"
            )
        if exit_code != 0:
            raise MutationError(
                f"registered negative-suite preflight failed with exit {exit_code}"
            )
        shutil.copytree(isolated_negative_root, negative_root)
    finally:
        shutil.rmtree(isolated_parent, ignore_errors=True)
    results: list[dict[str, Any]] = []
    for entry in entries:
        spec_path = Path(entry["spec"])
        name = spec_path.stem
        entry_log = negative_root / name / "apalache.log"
        if not entry_log.is_file():
            raise MutationError(f"negative preflight omitted log for {name}")
        try:
            trace = discover_trace(negative_root / name / "run")
            validate_trace(trace)
        except EvidenceError as error:
            raise MutationError(f"negative preflight has invalid trace for {name}: {error}") from error
        results.append(
            {
                "spec": entry["spec"],
                "cfg": entry["cfg"],
                "invariant": entry["falsifies"],
                "length": entry["length"],
                "timeout_secs": entry["timeout_secs"],
                "verdict": "killed",
                "log_sha256": sha256_file(entry_log),
                "trace": str(trace.relative_to(report_root))
                if report_root in trace.parents
                else str(trace),
                "trace_sha256": sha256_file(trace),
            }
        )
    return results, {
        "argv": command,
        "exit_code": exit_code,
        "wall_secs": round(wall_secs, 3),
        "log": str(log_path.relative_to(report_root))
        if report_root in log_path.parents
        else str(log_path),
        "log_sha256": sha256_file(log_path),
    }


def score(results: list[dict[str, Any]], target: float) -> dict[str, Any]:
    counts = {name: 0 for name in ("killed", "survived", "unviable", "timeout")}
    for result in results:
        verdict = result["verdict"]
        if verdict not in counts:
            raise MutationError(f"unknown mutation verdict: {verdict}")
        counts[verdict] += 1
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    activation = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    completed = counts["killed"] + counts["survived"] + counts["unviable"]
    completion = round(100.0 * completed / len(results), 3) if results else 0.0
    return {
        "sampled": len(results),
        **counts,
        "score_denominator": denominator,
        "timeout_policy": "timeouts count as not killed",
        "activation_ratio_percent": activation,
        "completion_ratio_percent": completion,
        "activation_target_percent": target,
        "activation_met": activation >= target,
    }


def aggregate_scores(
    results: list[dict[str, Any]], specs: Iterable[SpecConfig], target: float
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    aggregate = score(results, target)
    expected_sources = {spec.name for spec in specs}
    actual_sources = {result.get("spec") for result in results}
    if actual_sources != expected_sources:
        raise MutationError(
            "sample source coverage mismatch: "
            f"expected={sorted(expected_sources)} actual={sorted(actual_sources)}"
        )
    source_aggregates = {
        source: score(
            [result for result in results if result.get("spec") == source], target
        )
        for source in sorted(expected_sources)
    }
    global_met = aggregate["activation_met"]
    sources_met = all(entry["activation_met"] for entry in source_aggregates.values())
    aggregate["global_activation_met"] = global_met
    aggregate["source_activation_met"] = sources_met
    aggregate["activation_met"] = global_met and sources_met
    return aggregate, source_aggregates


def select_mutations(
    mutations: list[Mutation], *, commit: str, sample_size: int, full: bool, sample_epoch: int
) -> tuple[list[Mutation], str]:
    seed = commit[:16]
    if full or sample_size >= len(mutations):
        return list(mutations), seed
    if sample_epoch < 0:
        raise MutationError("sample epoch must not be negative")
    generator = random.Random(int(seed, 16))
    permutation = list(range(len(mutations)))
    generator.shuffle(permutation)
    rank = {index: position for position, index in enumerate(permutation)}
    mandatory = {index for index, mutation in enumerate(mutations) if mutation.seed is not None}
    sources = sorted({mutation.spec for mutation in mutations})
    selected_indexes = set(mandatory)
    for source in sources:
        candidates = sorted(
            (
                index
                for index, mutation in enumerate(mutations)
                if mutation.spec == source and mutation.seed is None
            ),
            key=rank.__getitem__,
        )
        if not candidates:
            raise MutationError(f"source {source} has no non-seed mutation probe")
        selected_indexes.add(candidates[sample_epoch % len(candidates)])
    if len(selected_indexes) > sample_size:
        raise MutationError(
            f"sample size {sample_size} cannot cover all sources and registered seeds"
        )
    remaining = [index for index in permutation if index not in selected_indexes]
    slots = sample_size - len(selected_indexes)
    if slots:
        start = sample_epoch * slots % len(remaining)
        selected_indexes.update(
            remaining[(start + offset) % len(remaining)] for offset in range(slots)
        )
    selected_indexes = sorted(selected_indexes)
    return [mutations[index] for index in selected_indexes], seed


def run_mutations(
    root: Path,
    source_root: Path,
    settings: Settings,
    mutations: list[Mutation],
    seeds: list[dict[str, str]],
    *,
    binary: str,
    output_root: Path,
    report_path: Path,
    full: bool,
    sample_size: int,
    sample_epoch: int,
    allow_dirty: bool,
    snapshot: ExecutionSnapshot,
) -> int:
    report_path.unlink(missing_ok=True)
    version = tool_version(binary)
    commit = snapshot.commit
    selected, sample_seed = select_mutations(
        mutations,
        commit=commit,
        sample_size=sample_size,
        full=full,
        sample_epoch=sample_epoch,
    )
    if output_root.exists():
        if output_root.is_symlink():
            raise MutationError("refusing to replace a symlinked output root")
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)
    positive_baselines, baseline_commands = positive_baseline_preflight(
        source_root, root, settings, binary, output_root
    )
    registered, preflight_command = negative_preflight(
        source_root, root, settings, binary, output_root
    )
    results: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = [*baseline_commands, preflight_command]
    for mutation in selected:
        entry_root = output_root / "generated" / mutation.id
        input_dir = entry_root / "input"
        out_dir = entry_root / "out"
        run_dir = entry_root / "run"
        log_path = entry_root / "apalache.log"
        mutated = apply_mutation(source_root, mutation)
        spec_path, cfg_path = copy_model_inputs(
            source_root, mutation, input_dir, mutated
        )
        out_dir.mkdir(parents=True)
        run_dir.mkdir(parents=True)
        command = apalache_check_command(
            binary,
            out_dir=out_dir,
            run_dir=run_dir,
            length=mutation.length,
            cfg_path=cfg_path,
            spec_path=spec_path,
        )
        exit_code, wall_secs = run_process(command, root, log_path, settings.timeout_secs)
        result = mutation.public()
        result.update(
            {
                "mutated_sha256": sha256_bytes(mutated.encode()),
                "wall_secs": round(wall_secs, 3),
                "apalache_exit": exit_code,
                "log_sha256": sha256_file(log_path),
            }
        )
        normalized_command = (
            apalache_check_command(
                binary,
                out_dir=entry_root.relative_to(root) / "out",
                run_dir=entry_root.relative_to(root) / "run",
                length=mutation.length,
                cfg_path=entry_root.relative_to(root) / "input" / mutation.cfg.name,
                spec_path=entry_root.relative_to(root) / "input" / mutation.path.name,
            )
            if root in entry_root.parents
            else command
        )
        commands.append({"mutant_id": mutation.id, "argv": normalized_command})
        if exit_code is None:
            result["verdict"] = "timeout"
        elif exit_code in (0, 12):
            try:
                verdict, trace = classify_completed_run(
                    log_path=log_path,
                    expected_invariant=mutation.invariant,
                    expected_length=mutation.length,
                    exit_code=exit_code,
                    run_root=run_dir,
                )
            except EvidenceError as error:
                raise MutationError(f"mutant {mutation.id} has invalid evidence: {error}") from error
            result["verdict"] = verdict
            if trace is not None:
                result["trace_sha256"] = sha256_file(trace)
                result["trace"] = str(trace.relative_to(root)) if root in trace.parents else str(trace)
        elif unviable_log(log_path):
            raise MutationError(
                f"curated mutant {mutation.id} is not type-valid Apalache input"
            )
        else:
            raise MutationError(
                f"mutant {mutation.id} returned unclassified Apalache exit {exit_code}"
            )
        results.append(result)
        print(f"{mutation.id}: {result['verdict']} ({result['wall_secs']}s)")

    aggregate, source_aggregates = aggregate_scores(
        results, settings.specs, settings.activation_target_percent
    )
    report = {
        "schema": SCHEMA,
        "commit": commit,
        "ci_run": ci_run_evidence(),
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "worktree": snapshot.worktree,
        "sample_seed": sample_seed,
        "sample_epoch": sample_epoch,
        "full_cycle": len(selected) == len(mutations),
        "enumerated": len(mutations),
        "inventory_sha256": inventory_sha256(mutations),
        "inventory": [mutation.public() for mutation in mutations],
        "sample_size_requested": sample_size,
        "tools": {"apalache": version, "python": sys.version.split()[0]},
        "bounds": {
            "per_mutant_timeout_secs": settings.timeout_secs,
            "positive_baseline_timeout_secs": settings.baseline_timeout_secs,
            "specs": [
                {
                    "spec": spec.name,
                    "length": spec.length,
                    "invariant": spec.invariant,
                }
                for spec in settings.specs
            ],
        },
        "inputs": snapshot.report_inputs(),
        "commands": commands,
        "positive_baselines": positive_baselines,
        "registered_seeds": seeds,
        "registered_negative": registered,
        "mutants": results,
        "source_aggregates": source_aggregates,
        "aggregate": aggregate,
    }
    current_settings = load_settings(root, settings.path)
    verify_execution_snapshot(
        root,
        snapshot,
        spec_input_paths(root, current_settings),
        allow_dirty=allow_dirty,
    )
    atomic_json(report_path, report)
    print(
        "spec-mutants: "
        f"activation={aggregate['activation_ratio_percent']}% "
        f"target={aggregate['activation_target_percent']}% report={report_path}"
    )
    return 0 if aggregate["activation_met"] else 1


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list every mutant as JSON")
    parser.add_argument("--full", action="store_true", help="run the full enumerated set")
    parser.add_argument(
        "--sample-from-head",
        action="store_true",
        help="select a deterministic sample using the current Git commit",
    )
    parser.add_argument("--sample-size", type=int, help="override the configured sample size")
    parser.add_argument(
        "--sample-epoch",
        type=int,
        default=os.environ.get("CHIO_MUTATION_SAMPLE_EPOCH", "0"),
        help="recorded rotation epoch mixed into the commit-seeded sample",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="permit a dirty local run while recording its tracked diff hash",
    )
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST.as_posix())
    parser.add_argument("--apalache-bin", default=os.environ.get("APALACHE_BIN", "apalache-mc"))
    parser.add_argument("--output-root", default=os.environ.get("CHIO_SPEC_MUTANTS_OUTPUT_ROOT"))
    parser.add_argument("--report", default=os.environ.get("CHIO_SPEC_MUTANTS_REPORT"))
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    root = REPO_ROOT.resolve()
    settings = load_settings(root, Path(options.allowlist))
    if options.list:
        mutations, _ = enumerate_mutations(root, settings)
        if options.full or options.sample_from_head or options.sample_size is not None:
            raise MutationError("--list cannot be combined with run selection options")
        print(json.dumps([mutation.public() for mutation in mutations], indent=2, sort_keys=True))
        return 0
    if options.full and options.sample_from_head:
        raise MutationError("--full and --sample-from-head are mutually exclusive")
    if options.sample_epoch < 0:
        raise MutationError("sample epoch must be non-negative")
    output_root = resolve_output_root(root, options.output_root)
    report_path = resolve_report_path(root, output_root, options.report)
    snapshot = capture_execution_snapshot(
        root, spec_input_paths(root, settings), allow_dirty=options.allow_dirty
    )
    settings = load_settings(root, settings.path)
    verify_execution_snapshot(
        root,
        snapshot,
        spec_input_paths(root, settings),
        allow_dirty=options.allow_dirty,
    )
    with materialized_execution_root(root, snapshot) as source_root:
        settings = load_settings(source_root, settings.path)
        source_inputs = spec_input_paths(source_root, settings)
        if input_evidence(source_root, source_inputs) != snapshot.inputs:
            raise MutationError(
                "materialized specification inputs differ from the starting snapshot"
            )
        sample_size = (
            settings.sample_size if options.sample_size is None else options.sample_size
        )
        if sample_size < 16 and not options.full:
            raise MutationError("sample size must be at least 16")
        mutations, seeds = enumerate_mutations(source_root, settings)
        return run_mutations(
            root,
            source_root,
            settings,
            mutations,
            seeds,
            binary=options.apalache_bin,
            output_root=output_root,
            report_path=report_path,
            full=options.full,
            sample_size=sample_size,
            sample_epoch=options.sample_epoch,
            allow_dirty=options.allow_dirty,
            snapshot=snapshot,
        )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (MutationError, EvidenceError, OSError, UnicodeError) as error:
        print(f"spec-mutants: {error}", file=sys.stderr)
        raise SystemExit(2) from error
