#!/usr/bin/env bash
# Counts exact GitHub Actions job results for one registered lane. Workflow
# conclusions and manual dispatches are not evidence. Promotion requires a
# fresh configured streak after the reset, a CODEOWNERS-reviewed posture edit,
# and manual ruleset work for pull-request checks. Demotion reverses those
# changes and records the incident. Frozen lanes cannot become required.
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - "$@" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import math
import os
import random
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("lane-gate: tomllib or tomli is required") from exc


class GateError(RuntimeError):
    pass


class ApiError(GateError):
    pass


class ApiUnavailableError(ApiError):
    pass


class ApiIntegrityError(ApiError):
    pass


class ScoredInputError(GateError):
    pass


@dataclass(frozen=True)
class PromotionEvidence:
    run_ids: tuple[int, ...]
    report_sha256: str


@dataclass(frozen=True)
class Lane:
    name: str
    workflow: str
    job: str
    event: str
    posture: str
    required_streak: int
    evidence_after_run_id: int
    max_age_hours: int
    activation_target: int | None
    scored_artifact_prefix: str | None
    scored_artifact_schema: str | None
    scored_sample_size: int | None
    scored_inventory_size: int | None
    scored_inventory_sha256: str | None
    scored_sources: tuple[tuple[str, str], ...]
    scored_seeds: tuple[str, ...]
    scored_files: tuple[str, ...]
    scored_viability_target: int | None
    scored_tools: tuple[tuple[str, str], ...]
    strict_mode_required: bool
    strict_artifact_prefix: str | None
    base_branch: str | None
    execution_artifact_prefix: str | None
    frozen: bool
    frozen_reason: str | None
    promotion_evidence: PromotionEvidence | None


@dataclass(frozen=True)
class RunEvidence:
    run_id: int
    run_attempt: int
    created_at: str
    conclusion: str
    url: str
    strict: bool | None
    real_execution: bool | None
    scored: bool | None


@dataclass(frozen=True)
class History:
    lane: Lane
    successes: list[RunEvidence]
    latest: RunEvidence | None
    barrier: RunEvidence | None
    barrier_reason: str | None
    freshness: str


@dataclass(frozen=True)
class GitTreeEntry:
    mode: str
    object_type: str
    object_id: str
    path: str


ALLOWED_FIELDS = {
    "workflow",
    "job",
    "event",
    "posture",
    "required_streak",
    "evidence_after_run_id",
    "max_age_hours",
    "activation_target",
    "scored_artifact_prefix",
    "scored_artifact_schema",
    "scored_sample_size",
    "scored_inventory_size",
    "scored_inventory_sha256",
    "scored_sources",
    "scored_seeds",
    "scored_files",
    "scored_viability_target",
    "scored_tools",
    "strict_mode_required",
    "strict_artifact_prefix",
    "base_branch",
    "execution_artifact_prefix",
    "frozen",
    "frozen_reason",
    "promotion_evidence",
}


def positive_int(value: Any, field: str, lane_name: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GateError(
            f"lane-gate: lane={lane_name} field={field} must be an integer >= {minimum}"
        )
    return value


def required_string(table: dict[str, Any], field: str, lane_name: str) -> str:
    value = table.get(field)
    if not isinstance(value, str) or not value.strip():
        raise GateError(f"lane-gate: lane={lane_name} field={field} must be a non-empty string")
    return value


def parse_promotion_evidence(
    value: Any, lane_name: str, required_streak: int, reset: int
) -> PromotionEvidence | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"run_ids", "report_sha256"}:
        raise GateError(
            f"lane-gate: lane={lane_name} promotion_evidence must contain only "
            "run_ids and report_sha256"
        )
    run_ids = value.get("run_ids")
    if not isinstance(run_ids, list) or len(run_ids) != required_streak:
        raise GateError(
            f"lane-gate: lane={lane_name} promotion_evidence.run_ids must contain "
            f"exactly {required_streak} runs"
        )
    if any(
        isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= reset
        for run_id in run_ids
    ):
        raise GateError(
            f"lane-gate: lane={lane_name} promotion run IDs must be integers after "
            "evidence_after_run_id"
        )
    if len(run_ids) != len(set(run_ids)):
        raise GateError(f"lane-gate: lane={lane_name} promotion run IDs must be unique")
    report_sha256 = value.get("report_sha256")
    if not isinstance(report_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", report_sha256
    ):
        raise GateError(
            f"lane-gate: lane={lane_name} promotion_evidence.report_sha256 must be "
            "a lowercase SHA-256"
        )
    return PromotionEvidence(run_ids=tuple(run_ids), report_sha256=report_sha256)


def parse_lane(name: str, table: Any) -> Lane:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        raise GateError(f"lane-gate: invalid lane name: {name}")
    if not isinstance(table, dict):
        raise GateError(f"lane-gate: lane={name} must be a TOML table")
    unknown = sorted(set(table) - ALLOWED_FIELDS)
    if unknown:
        raise GateError(f"lane-gate: lane={name} has unknown fields: {unknown}")

    workflow = required_string(table, "workflow", name)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow):
        raise GateError(f"lane-gate: lane={name} workflow must be a workflow filename")
    job = required_string(table, "job", name)
    if any(ord(character) < 32 for character in job):
        raise GateError(f"lane-gate: lane={name} job contains a control character")
    event = required_string(table, "event", name)
    if event not in {"schedule", "pull_request"}:
        raise GateError(f"lane-gate: lane={name} event must be schedule or pull_request")
    posture = required_string(table, "posture", name)
    if posture not in {"advisory", "required"}:
        raise GateError(f"lane-gate: lane={name} posture must be advisory or required")

    required_streak = positive_int(table.get("required_streak"), "required_streak", name)
    reset = positive_int(
        table.get("evidence_after_run_id"),
        "evidence_after_run_id",
        name,
        allow_zero=True,
    )
    max_age_hours = positive_int(table.get("max_age_hours"), "max_age_hours", name)
    activation_target = table.get("activation_target")
    if activation_target is not None:
        activation_target = positive_int(activation_target, "activation_target", name)
        if activation_target > 100:
            raise GateError(
                f"lane-gate: lane={name} field=activation_target must be an integer <= 100"
            )
    scored_prefix = table.get("scored_artifact_prefix")
    if scored_prefix is not None and (
        not isinstance(scored_prefix, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", scored_prefix)
    ):
        raise GateError(
            f"lane-gate: lane={name} scored_artifact_prefix is invalid"
        )
    scored_schema = table.get("scored_artifact_schema")
    if scored_schema is not None and (
        not isinstance(scored_schema, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", scored_schema)
    ):
        raise GateError(
            f"lane-gate: lane={name} scored_artifact_schema is invalid"
        )
    if activation_target is not None and (
        scored_prefix is None or scored_schema is None
    ):
        raise GateError(
            f"lane-gate: lane={name} activation_target needs scored artifact prefix and schema"
        )
    if activation_target is None and (
        scored_prefix is not None or scored_schema is not None
    ):
        raise GateError(
            f"lane-gate: lane={name} scored artifact configuration needs activation_target"
        )
    scored_sample_size = table.get("scored_sample_size")
    scored_inventory_size = table.get("scored_inventory_size")
    scored_inventory_sha256 = table.get("scored_inventory_sha256")
    if activation_target is not None:
        scored_sample_size = positive_int(scored_sample_size, "scored_sample_size", name)
        scored_inventory_size = positive_int(
            scored_inventory_size, "scored_inventory_size", name
        )
        if scored_sample_size > scored_inventory_size:
            raise GateError(
                f"lane-gate: lane={name} scored sample cannot exceed its inventory"
            )
        if not isinstance(scored_inventory_sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", scored_inventory_sha256
        ) is None:
            raise GateError(
                f"lane-gate: lane={name} scored_inventory_sha256 is invalid"
            )
    elif (
        scored_sample_size is not None
        or scored_inventory_size is not None
        or scored_inventory_sha256 is not None
    ):
        raise GateError(
            f"lane-gate: lane={name} scored sizes need activation_target"
        )
    raw_scored_sources = table.get("scored_sources")
    scored_sources: list[tuple[str, str]] = []
    if raw_scored_sources is not None:
        if not isinstance(raw_scored_sources, list) or not raw_scored_sources:
            raise GateError(f"lane-gate: lane={name} scored_sources must be a non-empty list")
        for entry in raw_scored_sources:
            if not isinstance(entry, str) or entry.count("=") != 1:
                raise GateError(f"lane-gate: lane={name} scored_sources entry is invalid")
            source, path = entry.split("=", 1)
            if (
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", source) is None
                or re.fullmatch(r"formal/[A-Za-z0-9_./-]+\.tla", path) is None
                or ".." in Path(path).parts
                or any(existing == source for existing, _ in scored_sources)
                or any(existing == path for _, existing in scored_sources)
            ):
                raise GateError(f"lane-gate: lane={name} scored_sources entry is invalid")
            scored_sources.append((source, path))
    if scored_schema == "chio.spec-mutants-report.v1" and not scored_sources:
        raise GateError(
            f"lane-gate: lane={name} specification score needs exact source bindings"
        )
    if scored_schema != "chio.spec-mutants-report.v1" and scored_sources:
        raise GateError(
            f"lane-gate: lane={name} scored_sources is supported only for specification reports"
        )
    raw_scored_seeds = table.get("scored_seeds")
    scored_seeds: list[str] = []
    if raw_scored_seeds is not None:
        if (
            not isinstance(raw_scored_seeds, list)
            or not raw_scored_seeds
            or not all(
                isinstance(seed, str)
                and re.fullmatch(r"[a-z0-9][a-z0-9-]*", seed)
                for seed in raw_scored_seeds
            )
            or len(raw_scored_seeds) != len(set(raw_scored_seeds))
        ):
            raise GateError(f"lane-gate: lane={name} scored_seeds is invalid")
        scored_seeds = list(raw_scored_seeds)
    if scored_schema == "chio.spec-mutants-report.v1" and not scored_seeds:
        raise GateError(
            f"lane-gate: lane={name} specification score needs exact seed bindings"
        )
    if scored_schema != "chio.spec-mutants-report.v1" and scored_seeds:
        raise GateError(
            f"lane-gate: lane={name} scored_seeds is supported only for specification reports"
        )
    raw_scored_files = table.get("scored_files")
    scored_files: list[str] = []
    if raw_scored_files is not None:
        if (
            not isinstance(raw_scored_files, list)
            or not raw_scored_files
            or not all(
                isinstance(path, str)
                and re.fullmatch(r"crates/[A-Za-z0-9_./-]+\.rs", path)
                and ".." not in Path(path).parts
                for path in raw_scored_files
            )
            or len(raw_scored_files) != len(set(raw_scored_files))
        ):
            raise GateError(f"lane-gate: lane={name} scored_files is invalid")
        scored_files = list(raw_scored_files)
    if scored_schema == "chio.proof-mutants-report.v1" and not scored_files:
        raise GateError(f"lane-gate: lane={name} proof score needs exact file bindings")
    if scored_schema != "chio.proof-mutants-report.v1" and scored_files:
        raise GateError(
            f"lane-gate: lane={name} scored_files is supported only for proof reports"
        )
    scored_viability_target = table.get("scored_viability_target")
    if scored_schema == "chio.proof-mutants-report.v1":
        scored_viability_target = positive_int(
            scored_viability_target, "scored_viability_target", name
        )
        if scored_viability_target > 100:
            raise GateError(
                f"lane-gate: lane={name} scored_viability_target must not exceed 100"
            )
    elif scored_viability_target is not None:
        raise GateError(
            f"lane-gate: lane={name} scored_viability_target is supported only for proof reports"
        )
    raw_scored_tools = table.get("scored_tools")
    scored_tools: list[tuple[str, str]] = []
    if raw_scored_tools is not None:
        if not isinstance(raw_scored_tools, list) or not raw_scored_tools:
            raise GateError(f"lane-gate: lane={name} scored_tools must be a non-empty list")
        for entry in raw_scored_tools:
            if not isinstance(entry, str) or entry.count("=") != 1:
                raise GateError(f"lane-gate: lane={name} scored_tools entry is invalid")
            tool, version = entry.split("=", 1)
            if (
                re.fullmatch(r"[a-z][a-z0-9_]*", tool) is None
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) is None
                or any(existing == tool for existing, _ in scored_tools)
            ):
                raise GateError(f"lane-gate: lane={name} scored_tools entry is invalid")
            scored_tools.append((tool, version))
    if activation_target is not None and not scored_tools:
        raise GateError(f"lane-gate: lane={name} scored report needs exact tool versions")
    if activation_target is None and scored_tools:
        raise GateError(f"lane-gate: lane={name} scored_tools needs activation_target")

    strict = table.get("strict_mode_required", False)
    frozen = table.get("frozen", False)
    if not isinstance(strict, bool) or not isinstance(frozen, bool):
        raise GateError(f"lane-gate: lane={name} boolean fields must be true or false")
    prefix = table.get("strict_artifact_prefix")
    if prefix is not None and (not isinstance(prefix, str) or not prefix):
        raise GateError(
            f"lane-gate: lane={name} strict_artifact_prefix must be a non-empty string"
        )
    if strict and prefix is None:
        raise GateError(
            f"lane-gate: lane={name} strict_mode_required needs strict_artifact_prefix"
        )
    if not strict and prefix is not None:
        raise GateError(
            f"lane-gate: lane={name} strict_artifact_prefix needs strict_mode_required=true"
        )
    base_branch = table.get("base_branch")
    if base_branch is not None and (
        not isinstance(base_branch, str)
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", base_branch)
    ):
        raise GateError(f"lane-gate: lane={name} base_branch is invalid")
    execution_prefix = table.get("execution_artifact_prefix")
    if execution_prefix is not None and (
        not isinstance(execution_prefix, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", execution_prefix)
    ):
        raise GateError(
            f"lane-gate: lane={name} execution_artifact_prefix is invalid"
        )
    if event == "pull_request" and base_branch is None:
        raise GateError(f"lane-gate: lane={name} pull_request lane needs base_branch")
    if event == "pull_request" and execution_prefix is None:
        raise GateError(
            f"lane-gate: lane={name} pull_request lane needs execution_artifact_prefix"
        )
    if event != "pull_request" and (base_branch is not None or execution_prefix is not None):
        raise GateError(
            f"lane-gate: lane={name} base and execution markers are pull_request-only"
        )
    frozen_reason = table.get("frozen_reason")
    if frozen_reason is not None and (
        not isinstance(frozen_reason, str) or not frozen_reason.strip()
    ):
        raise GateError(f"lane-gate: lane={name} frozen_reason must be a non-empty string")
    if frozen and frozen_reason is None:
        raise GateError(f"lane-gate: lane={name} frozen=true needs frozen_reason")
    if not frozen and frozen_reason is not None:
        raise GateError(f"lane-gate: lane={name} frozen_reason needs frozen=true")
    if frozen and posture == "required":
        raise GateError(
            f"lane-gate: lane={name} frozen lane cannot use required posture: {frozen_reason}"
        )
    promotion_evidence = parse_promotion_evidence(
        table.get("promotion_evidence"), name, required_streak, reset
    )
    if posture == "required" and promotion_evidence is None:
        raise GateError(
            f"lane-gate: lane={name} required posture needs promotion_evidence"
        )
    if posture == "advisory" and promotion_evidence is not None:
        raise GateError(
            f"lane-gate: lane={name} advisory posture cannot claim promotion_evidence"
        )
    return Lane(
        name=name,
        workflow=workflow,
        job=job,
        event=event,
        posture=posture,
        required_streak=required_streak,
        evidence_after_run_id=reset,
        max_age_hours=max_age_hours,
        activation_target=activation_target,
        scored_artifact_prefix=scored_prefix,
        scored_artifact_schema=scored_schema,
        scored_sample_size=scored_sample_size,
        scored_inventory_size=scored_inventory_size,
        scored_inventory_sha256=scored_inventory_sha256,
        scored_sources=tuple(scored_sources),
        scored_seeds=tuple(scored_seeds),
        scored_files=tuple(scored_files),
        scored_viability_target=scored_viability_target,
        scored_tools=tuple(scored_tools),
        strict_mode_required=strict,
        strict_artifact_prefix=prefix,
        base_branch=base_branch,
        execution_artifact_prefix=execution_prefix,
        frozen=frozen,
        frozen_reason=frozen_reason,
        promotion_evidence=promotion_evidence,
    )


def load_lanes() -> dict[str, Lane]:
    path = Path(os.environ.get("LANE_GATE_CONFIG", "releases.toml"))
    if not path.is_file():
        raise GateError(f"lane-gate: configuration not found: {path}")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"lane-gate: cannot parse {path}: {exc}") from exc
    gates = document.get("gates")
    if not isinstance(gates, dict) or not gates:
        raise GateError(f"lane-gate: {path} does not define any gates")
    return {name: parse_lane(name, table) for name, table in sorted(gates.items())}


def parse_json_documents(payload: str, endpoint: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    documents: list[dict[str, Any]] = []
    offset = 0
    while offset < len(payload):
        while offset < len(payload) and payload[offset].isspace():
            offset += 1
        if offset == len(payload):
            break
        try:
            document, offset = decoder.raw_decode(payload, offset)
        except json.JSONDecodeError as exc:
            raise ApiIntegrityError(
                f"lane-gate: invalid GitHub API JSON for {endpoint}: {exc}"
            ) from exc
        if not isinstance(document, dict):
            raise ApiIntegrityError(
                f"lane-gate: GitHub API returned a non-object for {endpoint}"
            )
        documents.append(document)
    if not documents:
        raise ApiIntegrityError(f"lane-gate: GitHub API returned no JSON for {endpoint}")
    return documents


def raise_api_failure(endpoint: str, detail: str) -> None:
    unavailable_patterns = (
        r"rate limit",
        r"\bHTTP (?:429|5(?:02|03|04))\b",
        r"could not resolve host",
        r"failed to connect",
        r"connection (?:timed out|reset|refused)",
        r"network is unreachable",
        r"TLS handshake timeout",
    )
    error_type = (
        ApiUnavailableError
        if any(re.search(pattern, detail, re.IGNORECASE) for pattern in unavailable_patterns)
        else ApiIntegrityError
    )
    raise error_type(f"lane-gate: GitHub API failed for {endpoint}: {detail}")


def gh_api(endpoint: str) -> list[dict[str, Any]]:
    gh = os.environ.get("LANE_GATE_GH", "gh")
    try:
        completed = subprocess.run(
            [gh, "api", endpoint],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ApiUnavailableError(f"lane-gate: cannot execute {gh}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise_api_failure(endpoint, detail)
    return parse_json_documents(completed.stdout, endpoint)


def gh_api_bytes(endpoint: str, max_bytes: int) -> bytes:
    gh = os.environ.get("LANE_GATE_GH", "gh")
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(
                [gh, "api", endpoint],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise ApiUnavailableError(f"lane-gate: cannot execute {gh}: {exc}") from exc
        size = output.tell()
        output.seek(0)
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            stdout = output.read(min(size, 64 * 1024)).decode(
                "utf-8", errors="replace"
            ).strip()
            raise_api_failure(endpoint, stderr or stdout or "unknown error")
        if size > max_bytes:
            raise ApiIntegrityError(
                f"lane-gate: GitHub API payload exceeds {max_bytes} bytes for {endpoint}"
            )
        return output.read()


def repository() -> str:
    configured = os.environ.get("LANE_GATE_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY")
    if configured:
        repo = configured
    else:
        gh = os.environ.get("LANE_GATE_GH", "gh")
        try:
            completed = subprocess.run(
                [gh, "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise GateError(f"lane-gate: cannot determine repository: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "gh repo view failed"
            raise GateError(f"lane-gate: cannot determine repository: {detail}")
        repo = completed.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise GateError(f"lane-gate: invalid repository: {repo}")
    return repo


def parse_time(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiIntegrityError(f"lane-gate: invalid run timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ApiIntegrityError(f"lane-gate: run timestamp lacks timezone: {value}")
    return parsed.astimezone(dt.timezone.utc)


def current_time() -> dt.datetime:
    value = os.environ.get("LANE_GATE_NOW")
    if value:
        return parse_time(value)
    return dt.datetime.now(dt.timezone.utc)


def flatten(documents: list[dict[str, Any]], key: str, endpoint: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for document in documents:
        page = document.get(key)
        if not isinstance(page, list):
            raise ApiIntegrityError(
                f"lane-gate: GitHub API response lacks {key} list for {endpoint}"
            )
        for entry in page:
            if not isinstance(entry, dict):
                raise ApiIntegrityError(
                    f"lane-gate: GitHub API returned invalid {key} entry"
                )
            entries.append(entry)
    return entries


def run_artifacts(repo: str, run_id: int) -> list[dict[str, Any]]:
    endpoint = f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    documents = gh_api(endpoint)
    artifacts = flatten(documents, "artifacts", endpoint)
    if len(documents) != 1:
        raise ApiIntegrityError("lane-gate: artifact listing returned ambiguous pages")
    total = documents[0].get("total_count")
    if isinstance(total, bool) or not isinstance(total, int) or total != len(artifacts):
        raise ApiIntegrityError(
            "lane-gate: artifact listing is incomplete or has an invalid total_count"
        )
    return artifacts


def artifact_names(artifacts: list[dict[str, Any]]) -> set[str]:
    return {
        artifact["name"]
        for artifact in artifacts
        if artifact.get("expired") is False and isinstance(artifact.get("name"), str)
    }


def exact_artifact_present(names: set[str], prefix: str, run_id: int, run_attempt: int) -> bool:
    return f"{prefix}{run_id}-{run_attempt}" in names


def json_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) else None


GIT_TREE_CACHE: dict[str, dict[str, GitTreeEntry]] = {}
GIT_BLOB_CACHE: dict[str, bytes] = {}
REGULAR_GIT_MODES = {"100644", "100755"}


def normalized_input_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(
        character in value for character in "\\\r\n\t"
    ):
        raise ScoredInputError(f"lane-gate: {label} is not a normalized path")
    candidate = Path(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or any(part in ("", ".", "..") for part in candidate.parts)
    ):
        raise ScoredInputError(f"lane-gate: {label} is not a normalized path")
    return value


def git_bytes(arguments: list[str], *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    git = os.environ.get("LANE_GATE_GIT", "git")
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        completed = subprocess.run(
            [git, *arguments],
            check=False,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScoredInputError(f"lane-gate: cannot inspect scored commit: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ScoredInputError(
            f"lane-gate: cannot inspect scored commit: {detail or 'git command failed'}"
        )
    if len(completed.stdout) > max_bytes:
        raise ScoredInputError("lane-gate: scored commit object exceeds its size bound")
    return completed.stdout


def commit_tree(commit: str) -> dict[str, GitTreeEntry]:
    cached = GIT_TREE_CACHE.get(commit)
    if cached is not None:
        return cached
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ScoredInputError("lane-gate: scored commit is invalid")
    if git_bytes(["cat-file", "-t", commit], max_bytes=64) != b"commit\n":
        raise ScoredInputError("lane-gate: scored object is not a commit")
    raw = git_bytes(["ls-tree", "-rz", "--full-tree", commit])
    entries: dict[str, GitTreeEntry] = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            metadata, raw_path = encoded.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ScoredInputError("lane-gate: scored commit has a malformed tree") from error
        normalized_input_path(path, "scored tree entry")
        if (
            re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
            or path in entries
        ):
            raise ScoredInputError("lane-gate: scored commit has a malformed tree")
        entries[path] = GitTreeEntry(mode, object_type, object_id, path)
    if not entries:
        raise ScoredInputError("lane-gate: scored commit tree is empty")
    GIT_TREE_CACHE[commit] = entries
    return entries


def regular_blob(commit: str, path: str) -> bytes:
    normalized = normalized_input_path(path, "scored input")
    entry = commit_tree(commit).get(normalized)
    if (
        entry is None
        or entry.mode not in REGULAR_GIT_MODES
        or entry.object_type != "blob"
    ):
        raise ScoredInputError(
            f"lane-gate: scored input is not a regular blob: {normalized}"
        )
    cached = GIT_BLOB_CACHE.get(entry.object_id)
    if cached is not None:
        return cached
    value = git_bytes(["cat-file", "blob", entry.object_id], max_bytes=16 * 1024 * 1024)
    GIT_BLOB_CACHE[entry.object_id] = value
    return value


def committed_toml(commit: str, path: str, label: str) -> dict[str, Any]:
    try:
        raw = regular_blob(commit, path).decode("utf-8")
        document = tomllib.loads(raw)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ScoredInputError(f"lane-gate: cannot parse committed {label}: {error}") from error
    if not isinstance(document, dict):
        raise ScoredInputError(f"lane-gate: committed {label} is not a TOML table")
    return document


def committed_files_in_directory(
    commit: str, directory: str, extension: str, *, recursive: bool
) -> set[str]:
    normalized = normalized_input_path(directory, "scored input directory")
    entries = commit_tree(commit)
    directory_entry = entries.get(normalized)
    if directory_entry is not None:
        raise ScoredInputError(
            f"lane-gate: scored input directory is not a regular tree: {normalized}"
        )
    prefix = f"{normalized}/"
    descendants = [entry for path, entry in entries.items() if path.startswith(prefix)]
    if not descendants:
        raise ScoredInputError(f"lane-gate: scored input directory is missing: {normalized}")
    paths: set[str] = set()
    for entry in descendants:
        remainder = entry.path[len(prefix) :]
        direct = "/" not in remainder
        if not recursive and not direct:
            continue
        matches_extension = Path(entry.path).suffix == f".{extension}"
        if entry.mode == "120000" and (recursive or matches_extension):
            raise ScoredInputError(
                f"lane-gate: scored mutation dependency is a symlink: {entry.path}"
            )
        if recursive and entry.object_type != "blob":
            raise ScoredInputError(
                f"lane-gate: scored mutation dependency is not a blob: {entry.path}"
            )
        if not matches_extension:
            continue
        if entry.mode not in REGULAR_GIT_MODES or entry.object_type != "blob":
            raise ScoredInputError(
                f"lane-gate: scored mutation dependency is not a regular blob: {entry.path}"
            )
        paths.add(entry.path)
    return paths


def expected_spec_input_paths(commit: str) -> set[str]:
    allowlist_path = "formal/apalache/spec-mutants-allowlist.toml"
    allowlist = committed_toml(commit, allowlist_path, "specification mutation allowlist")
    if allowlist.get("schema") != "chio.spec-mutants-allowlist.v1":
        raise ScoredInputError("lane-gate: committed specification allowlist schema is invalid")
    negative_path = normalized_input_path(
        allowlist.get("negative_registry"), "specification negative registry"
    )
    negative = committed_toml(commit, negative_path, "specification negative registry")
    if negative.get("schema") != "chio.apalache-negative.v1":
        raise ScoredInputError("lane-gate: committed negative registry schema is invalid")

    paths = {
        allowlist_path,
        negative_path,
        "formal/MAPPING.md",
        "scripts/check-apalache-negative.sh",
        "scripts/lib/apalache_evidence.py",
        "scripts/spec-mutants.py",
        "tools/install-apalache.sh",
    }
    specs = allowlist.get("spec")
    if not isinstance(specs, list) or not specs:
        raise ScoredInputError("lane-gate: committed specification allowlist is empty")
    for entry in specs:
        if not isinstance(entry, dict):
            raise ScoredInputError("lane-gate: committed specification entry is invalid")
        source = normalized_input_path(entry.get("path"), "specification source")
        cfg = normalized_input_path(entry.get("cfg"), "specification configuration")
        paths.update((source, cfg))
        parent = Path(source).parent.as_posix()
        paths.update(committed_files_in_directory(commit, parent, "tla", recursive=False))

    seeds = allowlist.get("seed")
    if not isinstance(seeds, list) or not seeds:
        raise ScoredInputError("lane-gate: committed specification seed registry is empty")
    for entry in seeds:
        if not isinstance(entry, dict):
            raise ScoredInputError("lane-gate: committed specification seed is invalid")
        paths.add(normalized_input_path(entry.get("negative_spec"), "negative seed source"))

    negative_entries = negative.get("negative")
    if not isinstance(negative_entries, list) or not negative_entries:
        raise ScoredInputError("lane-gate: committed negative registry is empty")
    negative_parents: set[str] = set()
    for entry in negative_entries:
        if not isinstance(entry, dict):
            raise ScoredInputError("lane-gate: committed negative entry is invalid")
        source = normalized_input_path(entry.get("spec"), "negative source")
        cfg = normalized_input_path(entry.get("cfg"), "negative configuration")
        paths.update((source, cfg))
        negative_parents.add(Path(source).parent.as_posix())
        runtime_test = entry.get("runtime_test")
        if not isinstance(runtime_test, str) or not runtime_test:
            raise ScoredInputError("lane-gate: committed negative runtime test is invalid")
        if not runtime_test.startswith("n/a"):
            runtime_path = runtime_test.split("::", 1)[0]
            paths.add(normalized_input_path(runtime_path, "negative runtime test"))
    for parent in negative_parents:
        paths.update(committed_files_in_directory(commit, parent, "tla", recursive=False))
    return paths


def expected_spec_baselines(commit: str) -> dict[str, dict[str, Any]]:
    allowlist_path = "formal/apalache/spec-mutants-allowlist.toml"
    allowlist = committed_toml(commit, allowlist_path, "specification mutation allowlist")
    if allowlist.get("schema") != "chio.spec-mutants-allowlist.v1":
        raise ScoredInputError("lane-gate: committed specification allowlist schema is invalid")
    raw_specs = allowlist.get("spec")
    if not isinstance(raw_specs, list) or not raw_specs:
        raise ScoredInputError("lane-gate: committed specification allowlist is empty")
    expected: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for entry in raw_specs:
        if not isinstance(entry, dict):
            raise ScoredInputError("lane-gate: committed specification entry is invalid")
        name = entry.get("name")
        source = normalized_input_path(entry.get("path"), "specification source")
        cfg = normalized_input_path(entry.get("cfg"), "specification configuration")
        invariant = entry.get("invariant")
        length = entry.get("length")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or not isinstance(invariant, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", invariant) is None
            or type(length) is not int
            or length < 1
            or name in expected
            or source in paths
        ):
            raise ScoredInputError("lane-gate: committed specification entry is invalid")
        expected[name] = {
            "spec": name,
            "path": source,
            "cfg": cfg,
            "invariant": invariant,
            "length": length,
        }
        paths.add(source)
    return expected


def scored_positive_baseline_reason(
    report: dict[str, Any], commit: str
) -> str | None:
    baselines = report.get("positive_baselines")
    if not isinstance(baselines, list):
        return "scored_report_positive_baselines_invalid"
    try:
        expected = expected_spec_baselines(commit)
    except ScoredInputError:
        return "scored_report_positive_baselines_invalid"
    if len(baselines) != len(expected):
        return "scored_report_positive_baselines_invalid"
    required_fields = {
        "spec",
        "path",
        "cfg",
        "invariant",
        "length",
        "verdict",
        "apalache_exit",
        "wall_secs",
        "log_sha256",
    }
    seen: set[str] = set()
    for baseline in baselines:
        if not isinstance(baseline, dict) or set(baseline) != required_fields:
            return "scored_report_positive_baselines_invalid"
        name = baseline.get("spec")
        metadata = expected.get(name) if isinstance(name, str) else None
        wall_secs = json_number(baseline.get("wall_secs"))
        if (
            metadata is None
            or name in seen
            or any(baseline.get(key) != value for key, value in metadata.items())
            or baseline.get("verdict") != "survived"
            or type(baseline.get("apalache_exit")) is not int
            or baseline.get("apalache_exit") != 0
            or wall_secs is None
            or wall_secs < 0.0
            or not isinstance(baseline.get("log_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", baseline["log_sha256"]) is None
        ):
            return "scored_report_positive_baselines_invalid"
        seen.add(name)
    if seen != set(expected):
        return "scored_report_positive_baselines_invalid"
    return None


def expected_proof_input_paths(commit: str) -> set[str]:
    paths = {
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config.toml",
        "crates/kernel/chio-kernel-core/Cargo.toml",
        "crates/core/chio-core-types/Cargo.toml",
        "rust-toolchain.toml",
        "formal/rust-verification/formal-mutants.toml",
        "scripts/proof-mutants.py",
        "scripts/proof-mutants.sh",
        "scripts/kani-mutant-killer.sh",
        "scripts/check-kani-core.sh",
    }
    paths.update(
        committed_files_in_directory(
            commit, "crates/kernel/chio-kernel-core/src", "rs", recursive=True
        )
    )
    paths.update(
        committed_files_in_directory(
            commit, "crates/core/chio-core-types/src", "rs", recursive=True
        )
    )
    return paths


def scored_report_input_reason(
    report: dict[str, Any], schema: str, commit: str
) -> str | None:
    raw_inputs = report.get("inputs")
    if not isinstance(raw_inputs, list) or not raw_inputs:
        return "scored_report_inputs_invalid"
    reported: dict[str, str] = {}
    reported_order: list[str] = []
    try:
        for entry in raw_inputs:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                return "scored_report_inputs_invalid"
            path = normalized_input_path(entry.get("path"), "reported input")
            digest = entry.get("sha256")
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or path in reported
            ):
                return "scored_report_inputs_invalid"
            reported[path] = digest
            reported_order.append(path)
        if reported_order != sorted(reported_order):
            return "scored_report_inputs_invalid"
        if schema == "chio.spec-mutants-report.v1":
            expected_paths = expected_spec_input_paths(commit)
        elif schema == "chio.proof-mutants-report.v1":
            expected_paths = expected_proof_input_paths(commit)
        else:
            return "scored_report_inputs_invalid"
        if set(reported) != expected_paths:
            return "scored_report_inputs_invalid"
        for path in expected_paths:
            if hashlib.sha256(regular_blob(commit, path)).hexdigest() != reported[path]:
                return "scored_report_inputs_invalid"
    except ScoredInputError:
        return "scored_report_inputs_invalid"
    return None


def regular_repository_toml(path: str, label: str) -> dict[str, Any]:
    candidate = Path(path)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != path
        or any(part in ("", ".", "..") for part in candidate.parts)
    ):
        raise GateError(f"lane-gate: {label} path is not normalized")
    cursor = Path()
    for part in candidate.parts:
        cursor /= part
        if cursor.is_symlink():
            raise GateError(f"lane-gate: {label} contains a symlink component")
    if not candidate.is_file():
        raise GateError(f"lane-gate: {label} is not a regular repository file")
    try:
        document = tomllib.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"lane-gate: cannot parse {label}: {error}") from error
    if not isinstance(document, dict):
        raise GateError(f"lane-gate: {label} is not a TOML table")
    return document


def specification_preflight_registries() -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    allowlist = regular_repository_toml(
        "formal/apalache/spec-mutants-allowlist.toml",
        "specification mutation allowlist",
    )
    if allowlist.get("schema") != "chio.spec-mutants-allowlist.v1":
        raise GateError("lane-gate: specification mutation allowlist schema is invalid")
    negative_path = allowlist.get("negative_registry")
    if not isinstance(negative_path, str):
        raise GateError("lane-gate: specification mutation negative registry is missing")
    negative_registry = regular_repository_toml(
        negative_path, "specification mutation negative registry"
    )
    if negative_registry.get("schema") != "chio.apalache-negative.v1":
        raise GateError("lane-gate: specification mutation negative registry schema is invalid")

    negatives: dict[str, dict[str, Any]] = {}
    cfgs: set[str] = set()
    raw_negatives = negative_registry.get("negative")
    if not isinstance(raw_negatives, list) or not raw_negatives:
        raise GateError("lane-gate: specification mutation negative registry is empty")
    for entry in raw_negatives:
        if not isinstance(entry, dict):
            raise GateError("lane-gate: specification mutation negative entry is invalid")
        spec = entry.get("spec")
        cfg = entry.get("cfg")
        falsifies = entry.get("falsifies")
        length = entry.get("length")
        timeout_secs = entry.get("timeout_secs")
        if (
            not isinstance(spec, str)
            or Path(spec).is_absolute()
            or Path(spec).as_posix() != spec
            or ".." in Path(spec).parts
            or not isinstance(cfg, str)
            or Path(cfg).is_absolute()
            or Path(cfg).as_posix() != cfg
            or ".." in Path(cfg).parts
            or not isinstance(falsifies, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", falsifies) is None
            or type(length) is not int
            or length < 1
            or type(timeout_secs) is not int
            or timeout_secs < 1
            or spec in negatives
            or cfg in cfgs
        ):
            raise GateError("lane-gate: specification mutation negative entry is invalid")
        negatives[spec] = {
            "cfg": cfg,
            "invariant": falsifies,
            "length": length,
            "timeout_secs": timeout_secs,
        }
        cfgs.add(cfg)

    seeds: dict[str, str] = {}
    negative_seed_specs: set[str] = set()
    raw_seeds = allowlist.get("seed")
    if not isinstance(raw_seeds, list) or not raw_seeds:
        raise GateError("lane-gate: specification mutation seed registry is empty")
    for entry in raw_seeds:
        if not isinstance(entry, dict):
            raise GateError("lane-gate: specification mutation seed entry is invalid")
        name = entry.get("name")
        negative_spec = entry.get("negative_spec")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None
            or not isinstance(negative_spec, str)
            or negative_spec not in negatives
            or name in seeds
            or negative_spec in negative_seed_specs
        ):
            raise GateError("lane-gate: specification mutation seed entry is invalid")
        seeds[name] = negative_spec
        negative_seed_specs.add(negative_spec)
    return seeds, negatives


def valid_registered_negative_trace(path: Any, spec: str) -> bool:
    if not isinstance(path, str) or any(character in path for character in "\\\r\n\t"):
        return False
    candidate = Path(path)
    parts = candidate.parts
    return (
        not candidate.is_absolute()
        and candidate.as_posix() == path
        and len(parts) >= 6
        and not any(part in ("", ".", "..") for part in parts)
        and parts[:2] == ("target", "formal")
        and parts[-4:-1] == ("registered-negative", Path(spec).stem, "run")
        and re.fullmatch(r"violation[0-9]+\.itf\.json", parts[-1]) is not None
    )


def expected_spec_sample_ids(
    inventory: list[dict[str, Any]], commit: str, sample_size: int, sample_epoch: int
) -> list[str] | None:
    if sample_size >= len(inventory):
        return [entry["id"] for entry in inventory]
    try:
        generator = random.Random(int(commit[:16], 16))
        permutation = list(range(len(inventory)))
        generator.shuffle(permutation)
        rank = {index: position for position, index in enumerate(permutation)}
        mandatory = {
            index for index, entry in enumerate(inventory) if "registered_seed" in entry
        }
        sources = sorted({entry["spec"] for entry in inventory})
        selected = set(mandatory)
        for source in sources:
            candidates = sorted(
                (
                    index
                    for index, entry in enumerate(inventory)
                    if entry["spec"] == source and "registered_seed" not in entry
                ),
                key=rank.__getitem__,
            )
            if not candidates:
                return None
            selected.add(candidates[sample_epoch % len(candidates)])
        if len(selected) > sample_size:
            return None
        remaining = [index for index in permutation if index not in selected]
        slots = sample_size - len(selected)
        if slots:
            if not remaining:
                return None
            start = sample_epoch * slots % len(remaining)
            selected.update(
                remaining[(start + offset) % len(remaining)] for offset in range(slots)
            )
        return [inventory[index]["id"] for index in sorted(selected)]
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None


PROOF_MUTATION_FILES = (
    "crates/kernel/chio-kernel-core/src/formal_core.rs",
    "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
)


def expected_proof_sample_ids(
    inventory: list[dict[str, Any]], commit: str, sample_size: int, sample_epoch: int
) -> list[str] | None:
    if sample_size >= len(inventory):
        return [entry["id"] for entry in inventory]
    try:
        source_groups = [
            [index for index, entry in enumerate(inventory) if entry["file"] == source]
            for source in PROOF_MUTATION_FILES
        ]
        if any(not group for group in source_groups):
            return None
        if len(inventory) % sample_size == 0:
            cycle_epochs = len(inventory) // sample_size
            epoch = sample_epoch % cycle_epochs
            cycle = sample_epoch // cycle_epochs
            generator = random.Random(int(commit[:16], 16) + cycle)
            for group in source_groups:
                generator.shuffle(group)
            base, remainder = divmod(len(source_groups[0]), cycle_epochs)
            first_counts = [
                base + (position < remainder) for position in range(cycle_epochs)
            ]
            second_counts = [sample_size - count for count in first_counts]
            first_start = sum(first_counts[:epoch])
            second_start = sum(second_counts[:epoch])
            indexes = sorted(
                source_groups[0][first_start : first_start + first_counts[epoch]]
                + source_groups[1][second_start : second_start + second_counts[epoch]]
            )
            if len(indexes) != sample_size:
                return None
            return [inventory[index]["id"] for index in indexes]

        generator = random.Random(int(commit[:16], 16))
        permutation = list(range(len(inventory)))
        generator.shuffle(permutation)
        rank = {index: position for position, index in enumerate(permutation)}
        indexes: set[int] = set()
        for source in PROOF_MUTATION_FILES:
            candidates = sorted(
                (
                    index
                    for index, entry in enumerate(inventory)
                    if entry["file"] == source
                ),
                key=rank.__getitem__,
            )
            if not candidates:
                return None
            indexes.add(candidates[sample_epoch % len(candidates)])
        if len(indexes) > sample_size:
            return None
        remaining = [index for index in permutation if index not in indexes]
        slots = sample_size - len(indexes)
        if slots:
            if not remaining:
                return None
            start = sample_epoch * slots % len(remaining)
            indexes.update(
                remaining[(start + offset) % len(remaining)] for offset in range(slots)
            )
        return [inventory[index]["id"] for index in sorted(indexes)]
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None


def scored_aggregate_reason(
    aggregate: Any,
    mutants: list[dict[str, Any]],
    configured_target: int,
    viability_target: int | None = None,
) -> str | None:
    if not isinstance(aggregate, dict):
        return "scored_report_counts_invalid"
    count_fields = ("killed", "survived", "unviable", "timeout")
    counts: dict[str, int] = {}
    for field in ("sampled", *count_fields, "score_denominator"):
        value = aggregate.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return "scored_report_counts_invalid"
        counts[field] = value
    if counts["sampled"] != sum(counts[field] for field in count_fields):
        return "scored_report_counts_invalid"
    if counts["sampled"] != len(mutants):
        return "scored_report_counts_invalid"
    if counts["score_denominator"] != (
        counts["killed"] + counts["survived"] + counts["timeout"]
    ):
        return "scored_report_counts_invalid"

    observed = {field: 0 for field in count_fields}
    for mutant in mutants:
        if mutant.get("verdict") not in observed:
            return "scored_report_counts_invalid"
        observed[mutant["verdict"]] += 1
    if any(observed[field] != counts[field] for field in count_fields):
        return "scored_report_counts_invalid"

    recorded_target = json_number(aggregate.get("activation_target_percent"))
    if recorded_target is None or recorded_target != float(configured_target):
        return "scored_report_target_mismatch"
    ratio = json_number(aggregate.get("activation_ratio_percent"))
    denominator = counts["score_denominator"]
    expected_ratio = (
        round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    )
    if ratio is None or ratio != expected_ratio:
        return "scored_report_counts_invalid"
    threshold_met = ratio >= recorded_target
    if viability_target is not None:
        viability = round(100.0 * denominator / counts["sampled"], 3) if counts["sampled"] else 0.0
        if (
            json_number(aggregate.get("viability_target_percent"))
            != float(viability_target)
            or json_number(aggregate.get("viability_ratio_percent")) != viability
            or aggregate.get("activation_threshold_met") is not threshold_met
            or aggregate.get("viability_met") is not (viability >= viability_target)
            or aggregate.get("activation_met")
            is not (threshold_met and viability >= viability_target)
        ):
            return "scored_report_activation_not_met"
    if aggregate.get("activation_met") is not True or not threshold_met:
        return "scored_report_activation_not_met"
    return None


def scored_report_reason(
    report: dict[str, Any],
    lane: Lane,
    head_sha: str,
    run_id: int,
    run_attempt: int,
    run_number: int,
) -> str | None:
    if report.get("commit") != head_sha:
        return "scored_report_stale_commit"
    if report.get("worktree") != {"clean": True}:
        return "scored_report_dirty_worktree"
    if report.get("sample_seed") != head_sha[:16] or report.get("sample_epoch") != run_number:
        return "scored_report_stale_run"
    if report.get("ci_run") != {
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_number": run_number,
    }:
        return "scored_report_stale_run"
    tools = report.get("tools")
    if not isinstance(tools, dict) or any(
        tools.get(tool) != version for tool, version in lane.scored_tools
    ):
        return "scored_report_tool_mismatch"
    if lane.scored_artifact_schema is None:
        raise GateError(f"lane-gate: lane={lane.name} scored schema is missing")
    input_reason = scored_report_input_reason(
        report, lane.scored_artifact_schema, head_sha
    )
    if input_reason is not None:
        return input_reason
    if lane.scored_artifact_schema == "chio.spec-mutants-report.v1":
        baseline_reason = scored_positive_baseline_reason(report, head_sha)
        if baseline_reason is not None:
            return baseline_reason
    aggregate = report.get("aggregate")
    mutants = report.get("mutants")
    if not isinstance(mutants, list) or not all(isinstance(mutant, dict) for mutant in mutants):
        return "scored_report_counts_invalid"
    identifiers = [mutant.get("id") for mutant in mutants]
    if any(
        not isinstance(identifier, str)
        or re.fullmatch(r"[0-9a-f]{20}", identifier) is None
        for identifier in identifiers
    ) or len(identifiers) != len(set(identifiers)):
        return "scored_report_counts_invalid"
    configured_target = lane.activation_target
    configured_sample_size = lane.scored_sample_size
    configured_inventory_size = lane.scored_inventory_size
    configured_inventory_sha256 = lane.scored_inventory_sha256
    if (
        configured_target is None
        or configured_sample_size is None
        or configured_inventory_size is None
        or configured_inventory_sha256 is None
    ):
        raise GateError(f"lane-gate: lane={lane.name} scored target setup is invalid")
    if (
        report.get("sample_size_requested") != configured_sample_size
        or report.get("enumerated") != configured_inventory_size
        or not isinstance(aggregate, dict)
        or aggregate.get("sampled") != configured_sample_size
        or report.get("full_cycle") is not (configured_sample_size == configured_inventory_size)
    ):
        return "scored_report_inventory_mismatch"
    inventory = report.get("inventory")
    if not isinstance(inventory, list) or len(inventory) != configured_inventory_size:
        return "scored_report_inventory_mismatch"
    inventory_ids: list[str] = []
    for entry in inventory:
        if not isinstance(entry, dict):
            return "scored_report_inventory_mismatch"
        identifier = entry.get("id")
        if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{20}", identifier) is None:
            return "scored_report_inventory_mismatch"
        inventory_ids.append(identifier)
    if len(inventory_ids) != len(set(inventory_ids)):
        return "scored_report_inventory_mismatch"
    computed_inventory_sha256 = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        report.get("inventory_sha256") != computed_inventory_sha256
        or computed_inventory_sha256 != configured_inventory_sha256
    ):
        return "scored_report_inventory_mismatch"
    inventory_by_id = {entry["id"]: entry for entry in inventory}
    if any(identifier not in inventory_by_id for identifier in identifiers):
        return "scored_report_inventory_mismatch"
    for mutant in mutants:
        expected = inventory_by_id[mutant["id"]]
        if any(mutant.get(key) != value for key, value in expected.items()):
            return "scored_report_inventory_mismatch"
        if lane.scored_artifact_schema == "chio.spec-mutants-report.v1" and (
            ("registered_seed" in mutant) != ("registered_seed" in expected)
            or mutant.get("registered_seed") != expected.get("registered_seed")
        ):
            return "scored_report_inventory_mismatch"
    if lane.scored_artifact_schema == "chio.spec-mutants-report.v1":
        expected_sample_ids = expected_spec_sample_ids(
            inventory, head_sha, configured_sample_size, run_number
        )
    elif lane.scored_artifact_schema == "chio.proof-mutants-report.v1":
        expected_sample_ids = expected_proof_sample_ids(
            inventory, head_sha, configured_sample_size, run_number
        )
    else:
        expected_sample_ids = identifiers
    if expected_sample_ids is None or identifiers != expected_sample_ids:
        return "scored_report_inventory_mismatch"
    viability_target = (
        lane.scored_viability_target
        if lane.scored_artifact_schema == "chio.proof-mutants-report.v1"
        else None
    )
    reason = scored_aggregate_reason(
        aggregate, mutants, configured_target, viability_target
    )
    if reason is not None:
        return reason

    if lane.scored_artifact_schema == "chio.proof-mutants-report.v1":
        expected_files = set(lane.scored_files)
        files = {mutant.get("file") for mutant in mutants}
        inventory_files = {entry.get("file") for entry in inventory}
        if files != expected_files or inventory_files != expected_files:
            return "scored_report_inventory_mismatch"
        source_aggregates = report.get("source_aggregates")
        if not isinstance(source_aggregates, dict) or set(source_aggregates) != expected_files:
            return "scored_report_counts_invalid"
        for source in sorted(expected_files):
            source_mutants = [mutant for mutant in mutants if mutant.get("file") == source]
            reason = scored_aggregate_reason(
                source_aggregates[source],
                source_mutants,
                configured_target,
                viability_target,
            )
            if reason is not None:
                return reason
        if (
            not isinstance(aggregate, dict)
            or aggregate.get("global_activation_met") is not True
            or aggregate.get("source_activation_met") is not True
        ):
            return "scored_report_activation_not_met"
        return None

    if lane.scored_artifact_schema != "chio.spec-mutants-report.v1":
        return None
    if any(mutant.get("verdict") == "unviable" for mutant in mutants):
        return "scored_report_counts_invalid"
    expected_sources = dict(lane.scored_sources)
    sources = {mutant.get("spec") for mutant in mutants}
    if sources != set(expected_sources):
        return "scored_report_counts_invalid"
    if any(mutant.get("path") != expected_sources[mutant["spec"]] for mutant in mutants):
        return "scored_report_counts_invalid"
    inventory_sources = {entry.get("spec") for entry in inventory}
    if inventory_sources != set(expected_sources) or any(
        entry.get("path") != expected_sources.get(entry.get("spec")) for entry in inventory
    ):
        return "scored_report_inventory_mismatch"
    source_aggregates = report.get("source_aggregates")
    if not isinstance(source_aggregates, dict) or set(source_aggregates) != sources:
        return "scored_report_counts_invalid"
    for source in sorted(sources):
        source_mutants = [mutant for mutant in mutants if mutant.get("spec") == source]
        if not any("registered_seed" not in mutant for mutant in source_mutants):
            return "scored_report_counts_invalid"
        reason = scored_aggregate_reason(
            source_aggregates[source], source_mutants, configured_target
        )
        if reason is not None:
            return reason
    if (
        not isinstance(aggregate, dict)
        or aggregate.get("global_activation_met") is not True
        or aggregate.get("source_activation_met") is not True
    ):
        return "scored_report_activation_not_met"

    expected_seed_specs, expected_negative = specification_preflight_registries()
    inventory_seeds: dict[str, str] = {}
    inventory_seed_ids: set[str] = set()
    for entry in inventory:
        if "registered_seed" not in entry:
            continue
        name = entry.get("registered_seed")
        identifier = entry["id"]
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None
            or name in inventory_seeds
            or identifier in inventory_seed_ids
        ):
            return "scored_report_counts_invalid"
        inventory_seeds[name] = identifier
        inventory_seed_ids.add(identifier)
    if (
        set(inventory_seeds) != set(lane.scored_seeds)
        or set(inventory_seeds) != set(expected_seed_specs)
    ):
        return "scored_report_counts_invalid"

    registered_seeds = report.get("registered_seeds")
    if not isinstance(registered_seeds, list):
        return "scored_report_counts_invalid"
    declared_seeds: dict[str, str] = {}
    declared_seed_ids: set[str] = set()
    for seed in registered_seeds:
        if not isinstance(seed, dict) or set(seed) != {
            "name",
            "mutant_id",
            "negative_spec",
            "status",
        }:
            return "scored_report_counts_invalid"
        name = seed.get("name")
        mutant_id = seed.get("mutant_id")
        if (
            not isinstance(name, str)
            or not isinstance(mutant_id, str)
            or re.fullmatch(r"[0-9a-f]{20}", mutant_id) is None
            or seed.get("negative_spec") != expected_seed_specs.get(name)
            or seed.get("status") != "subsumed"
            or name in declared_seeds
            or mutant_id in declared_seed_ids
        ):
            return "scored_report_counts_invalid"
        declared_seeds[name] = mutant_id
        declared_seed_ids.add(mutant_id)
    if declared_seeds != inventory_seeds:
        return "scored_report_counts_invalid"
    results_by_id = {mutant["id"]: mutant for mutant in mutants}
    for name, identifier in inventory_seeds.items():
        result = results_by_id.get(identifier)
        if (
            not isinstance(result, dict)
            or result.get("registered_seed") != name
            or result.get("verdict") != "killed"
        ):
            return "scored_report_counts_invalid"

    registered_negative = report.get("registered_negative")
    if not isinstance(registered_negative, list):
        return "scored_report_counts_invalid"
    seen_negative: set[str] = set()
    seen_traces: set[str] = set()
    for entry in registered_negative:
        if not isinstance(entry, dict):
            return "scored_report_counts_invalid"
        spec = entry.get("spec")
        expected = expected_negative.get(spec) if isinstance(spec, str) else None
        trace = entry.get("trace")
        if (
            expected is None
            or spec in seen_negative
            or not isinstance(trace, str)
            or trace in seen_traces
            or entry.get("cfg") != expected["cfg"]
            or entry.get("invariant") != expected["invariant"]
            or type(entry.get("length")) is not int
            or entry.get("length") != expected["length"]
            or type(entry.get("timeout_secs")) is not int
            or entry.get("timeout_secs") != expected["timeout_secs"]
            or entry.get("verdict") != "killed"
            or not isinstance(entry.get("log_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["log_sha256"]) is None
            or not isinstance(entry.get("trace_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["trace_sha256"]) is None
            or not valid_registered_negative_trace(trace, spec)
        ):
            return "scored_report_counts_invalid"
        seen_negative.add(spec)
        seen_traces.add(trace)
    if seen_negative != set(expected_negative):
        return "scored_report_counts_invalid"
    return None


def scored_artifact_reason(
    repo: str,
    lane: Lane,
    run: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> str | None:
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    head_sha = run.get("head_sha")
    prefix = lane.scored_artifact_prefix
    schema = lane.scored_artifact_schema
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or prefix is None
        or schema is None
    ):
        raise GateError(f"lane-gate: lane={lane.name} scored artifact setup is invalid")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        return "scored_run_commit_missing"

    expected_name = f"{prefix}{run_id}-{run_attempt}"
    matches = [artifact for artifact in artifacts if artifact.get("name") == expected_name]
    if not matches:
        return "scored_artifact_missing"
    if len(matches) != 1:
        return "scored_artifact_ambiguous"
    artifact = matches[0]
    if artifact.get("expired") is not False:
        return "scored_artifact_stale"
    artifact_id = artifact.get("id")
    workflow_run = artifact.get("workflow_run")
    if (
        isinstance(artifact_id, bool)
        or not isinstance(artifact_id, int)
        or artifact_id < 1
        or not isinstance(workflow_run, dict)
        or workflow_run.get("id") != run_id
        or workflow_run.get("head_sha") != head_sha
    ):
        return "scored_artifact_stale"
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return "scored_artifact_digest_missing"
    declared_size = artifact.get("size_in_bytes")
    if (
        isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or declared_size < 1
        or declared_size > 16 * 1024 * 1024
    ):
        return "scored_artifact_invalid"

    archive = gh_api_bytes(
        f"repos/{repo}/actions/artifacts/{artifact_id}/zip", 16 * 1024 * 1024
    )
    if len(archive) != declared_size:
        return "scored_artifact_invalid"
    if f"sha256:{hashlib.sha256(archive).hexdigest()}" != digest:
        return "scored_artifact_digest_mismatch"
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            files = [entry for entry in bundle.infolist() if not entry.is_dir()]
            if sum(entry.file_size for entry in files) > 64 * 1024 * 1024:
                return "scored_artifact_invalid"
            reports: list[dict[str, Any]] = []
            for entry in files:
                if not entry.filename.lower().endswith(".json"):
                    continue
                if entry.file_size > 8 * 1024 * 1024:
                    return "scored_artifact_invalid"
                try:
                    document = json.loads(bundle.read(entry).decode("utf-8"))
                except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(document, dict) and document.get("schema") == schema:
                    reports.append(document)
    except (OSError, zipfile.BadZipFile):
        return "scored_artifact_invalid"
    if not reports:
        return "scored_report_missing"
    if len(reports) != 1:
        return "scored_report_ambiguous"
    run_number = run.get("run_number")
    if isinstance(run_number, bool) or not isinstance(run_number, int) or run_number < 1:
        return "scored_run_number_missing"
    return scored_report_reason(
        reports[0], lane, head_sha, run_id, run_attempt, run_number
    )


def run_targets_base(run: dict[str, Any], lane: Lane) -> bool:
    if lane.event != "pull_request":
        return True
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list):
        raise ApiIntegrityError("lane-gate: pull_request run lacks pull_requests list")
    for pull_request in pull_requests:
        if not isinstance(pull_request, dict):
            raise ApiIntegrityError("lane-gate: workflow run has invalid pull request metadata")
        base = pull_request.get("base")
        if not isinstance(base, dict):
            raise ApiIntegrityError("lane-gate: workflow run pull request lacks base metadata")
        if base.get("ref") == lane.base_branch:
            return True
    return False


def run_sort_key(run: dict[str, Any]) -> tuple[dt.datetime, int]:
    run_id = run.get("id")
    created_at = run.get("created_at")
    if isinstance(run_id, bool) or not isinstance(run_id, int):
        raise ApiIntegrityError("lane-gate: workflow run is missing an integer id")
    if not isinstance(created_at, str):
        raise ApiIntegrityError(f"lane-gate: run {run_id} is missing created_at")
    return parse_time(created_at), run_id


def evidence_for_run(repo: str, lane: Lane, run: dict[str, Any]) -> tuple[RunEvidence, str | None]:
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    created_at = run.get("created_at")
    if isinstance(run_id, bool) or not isinstance(run_id, int):
        raise ApiIntegrityError("lane-gate: workflow run is missing an integer id")
    if (
        isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt < 1
    ):
        raise ApiIntegrityError(
            f"lane-gate: run {run_id} is missing a positive run_attempt"
        )
    if not isinstance(created_at, str):
        raise ApiIntegrityError(f"lane-gate: run {run_id} is missing created_at")
    endpoint = f"repos/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"
    jobs = flatten(gh_api(endpoint), "jobs", endpoint)
    matching = [job for job in jobs if job.get("name") == lane.job]
    if len(matching) != 1:
        conclusion = "missing" if not matching else "ambiguous"
        return (
            RunEvidence(
                run_id=run_id,
                run_attempt=run_attempt,
                created_at=created_at,
                conclusion=conclusion,
                url=str(run.get("html_url") or ""),
                strict=None,
                real_execution=None,
                scored=None,
            ),
            "job_missing" if not matching else "job_ambiguous",
        )
    conclusion = matching[0].get("conclusion")
    job_attempt = matching[0].get("run_attempt")
    if (
        isinstance(job_attempt, bool)
        or not isinstance(job_attempt, int)
        or job_attempt < 1
    ):
        raise ApiIntegrityError(
            f"lane-gate: job {lane.job!r} in run {run_id} lacks run_attempt"
        )
    if job_attempt != run_attempt:
        raise ApiIntegrityError(
            f"lane-gate: job {lane.job!r} attempt {job_attempt} does not match "
            f"workflow run {run_id} attempt {run_attempt}"
        )
    if not isinstance(conclusion, str):
        conclusion = "unknown"
    strict: bool | None = None
    real_execution: bool | None = None
    scored: bool | None = None
    reason = None
    if conclusion != "success":
        reason = "job_not_successful"
    artifacts: list[dict[str, Any]] | None = None
    if conclusion == "success" and (
        lane.strict_mode_required
        or lane.execution_artifact_prefix is not None
        or lane.scored_artifact_prefix is not None
    ):
        artifacts = run_artifacts(repo, run_id)
    names = artifact_names(artifacts) if artifacts is not None else None
    if reason is None and lane.strict_mode_required:
        prefix = lane.strict_artifact_prefix
        if prefix is None or names is None:
            raise GateError(f"lane-gate: lane={lane.name} strict artifact setup is invalid")
        strict = exact_artifact_present(names, prefix, run_id, run_attempt)
        if not strict:
            reason = "non_strict"
    if reason is None and lane.execution_artifact_prefix is not None:
        if names is None:
            raise GateError(f"lane-gate: lane={lane.name} execution marker setup is invalid")
        real_execution = exact_artifact_present(
            names,
            lane.execution_artifact_prefix,
            run_id,
            run_attempt,
        )
        if not real_execution:
            reason = "execution_marker_missing"
    if reason is None and lane.scored_artifact_prefix is not None:
        if artifacts is None:
            raise GateError(f"lane-gate: lane={lane.name} scored artifact setup is invalid")
        reason = scored_artifact_reason(repo, lane, run, artifacts)
        scored = reason is None
    return (
        RunEvidence(
            run_id=run_id,
            run_attempt=run_attempt,
            created_at=created_at,
            conclusion=conclusion,
            url=str(run.get("html_url") or ""),
            strict=strict,
            real_execution=real_execution,
            scored=scored,
        ),
        reason,
    )


def evaluate_history(repo: str, lane: Lane) -> History:
    workflow = quote(lane.workflow, safe="")
    successes: list[RunEvidence] = []
    latest: RunEvidence | None = None
    barrier: RunEvidence | None = None
    barrier_reason: str | None = None
    seen_run_ids: set[int] = set()
    terminal = False
    per_page = 100
    max_pages = 10
    for page in range(1, max_pages + 1):
        endpoint = (
            f"repos/{repo}/actions/workflows/{workflow}/runs"
            f"?event={lane.event}&status=completed&per_page={per_page}&page={page}"
        )
        runs = flatten(gh_api(endpoint), "workflow_runs", endpoint)
        runs.sort(key=run_sort_key, reverse=True)
        for run in runs:
            run_id = run.get("id")
            if isinstance(run_id, bool) or not isinstance(run_id, int):
                raise ApiIntegrityError("lane-gate: workflow run is missing an integer id")
            if run_id in seen_run_ids:
                raise ApiIntegrityError(f"lane-gate: duplicate workflow run id: {run_id}")
            seen_run_ids.add(run_id)
            if run_id <= lane.evidence_after_run_id:
                terminal = True
                break
            if run.get("event") != lane.event:
                continue
            if not run_targets_base(run, lane):
                continue
            evidence, reason = evidence_for_run(repo, lane, run)
            if latest is None:
                latest = evidence
            if reason is not None:
                barrier = evidence
                barrier_reason = reason
                terminal = True
                break
            successes.append(evidence)
            if len(successes) >= lane.required_streak:
                terminal = True
                break
        if terminal or len(runs) < per_page:
            break

    if latest is None:
        freshness = "missing"
    else:
        age = current_time() - parse_time(latest.created_at)
        if age < -dt.timedelta(minutes=5):
            raise ApiIntegrityError(
                f"lane-gate: latest run {latest.run_id} is more than five minutes in the future"
            )
        freshness = "fresh" if age <= dt.timedelta(hours=lane.max_age_hours) else "stale"
    return History(
        lane=lane,
        successes=successes,
        latest=latest,
        barrier=barrier,
        barrier_reason=barrier_reason,
        freshness=freshness,
    )


def print_history(history: History, verdict: str, current: str = "not_applicable") -> None:
    lane = history.lane
    latest = str(history.latest.run_id) if history.latest is not None else "none"
    activation_target = (
        "n/a" if lane.activation_target is None else str(lane.activation_target)
    )
    print(
        "lane-gate: "
        f"lane={lane.name} posture={lane.posture} event={lane.event} "
        f"job={json.dumps(lane.job)} streak={len(history.successes)}/{lane.required_streak} "
        f"activation_target={activation_target} "
        f"latest={latest} freshness={history.freshness} "
        f"reset_after={lane.evidence_after_run_id} current={current} verdict={verdict}"
    )
    for evidence in history.successes:
        strict = "n/a" if evidence.strict is None else str(evidence.strict).lower()
        execution = (
            "n/a"
            if evidence.real_execution is None
            else str(evidence.real_execution).lower()
        )
        scored = "n/a" if evidence.scored is None else str(evidence.scored).lower()
        print(
            "lane-gate-evidence: "
            f"lane={lane.name} run_id={evidence.run_id} attempt={evidence.run_attempt} "
            f"created_at={evidence.created_at} "
            f"conclusion={evidence.conclusion} strict={strict} "
            f"real_execution={execution} scored={scored} url={evidence.url or 'none'}"
        )
    if history.barrier is not None:
        print(
            "lane-gate-barrier: "
            f"lane={lane.name} run_id={history.barrier.run_id} "
            f"attempt={history.barrier.run_attempt} "
            f"created_at={history.barrier.created_at} "
            f"conclusion={history.barrier.conclusion} reason={history.barrier_reason}"
        )


def current_result(lane: Lane) -> tuple[bool, str]:
    value = os.environ.get("LANE_EXIT")
    if value is None:
        raise GateError("lane-gate: LANE_EXIT is required for a job-blocking invocation")
    if not re.fullmatch(r"[0-9]+", value):
        raise GateError("lane-gate: LANE_EXIT must be a non-negative integer")
    if int(value) != 0:
        return False, "current_job_failed"
    if lane.strict_mode_required:
        mode = os.environ.get("LANE_STRICT_MODE", "")
        if mode != "strict":
            return False, "current_run_not_strict"
    return True, "current_job_succeeded"


def single_api_object(endpoint: str) -> dict[str, Any]:
    documents = gh_api(endpoint)
    if len(documents) != 1:
        raise ApiIntegrityError(
            f"lane-gate: GitHub API returned ambiguous objects for {endpoint}"
        )
    return documents[0]


def promotion_evidence_matches(repo: str, history: History) -> bool:
    evidence = history.lane.promotion_evidence
    if evidence is None:
        return history.lane.posture != "required"
    report = "".join(f"{run_id}\n" for run_id in evidence.run_ids).encode("ascii")
    if hashlib.sha256(report).hexdigest() != evidence.report_sha256:
        return False

    lane = history.lane
    workflow = quote(lane.workflow, safe="")
    workflow_endpoint = f"repos/{repo}/actions/workflows/{workflow}"
    workflow_id = single_api_object(workflow_endpoint).get("id")
    if isinstance(workflow_id, bool) or not isinstance(workflow_id, int):
        raise ApiIntegrityError(
            f"lane-gate: workflow {lane.workflow} is missing an integer id"
        )

    promotion_runs: list[dict[str, Any]] = []
    for run_id in evidence.run_ids:
        run_endpoint = f"repos/{repo}/actions/runs/{run_id}"
        run = single_api_object(run_endpoint)
        if run.get("id") != run_id or run.get("workflow_id") != workflow_id:
            return False
        if (
            run.get("event") != lane.event
            or run.get("status") != "completed"
            or not run_targets_base(run, lane)
        ):
            return False
        run_evidence, reason = evidence_for_run(repo, lane, run)
        if reason is not None or run_evidence.conclusion != "success":
            return False
        promotion_runs.append(run)

    return promotion_runs == sorted(promotion_runs, key=run_sort_key, reverse=True)


def handle_api_error(lane: Lane, error: ApiError) -> int:
    mode = os.environ.get("LANE_GATE_RATE_LIMIT_MODE", "fail")
    if mode not in {"fail", "warn"}:
        raise GateError("lane-gate: LANE_GATE_RATE_LIMIT_MODE must be fail or warn")
    if (
        mode == "warn"
        and lane.posture == "advisory"
        and isinstance(error, ApiUnavailableError)
    ):
        print(f"lane-gate: WARNING: {error}", file=sys.stderr)
        print(
            f"lane-gate: lane={lane.name} posture=advisory evidence=unavailable verdict=advisory"
        )
        return 0
    raise error


def run_lane(repo: str, lane: Lane, *, report_only: bool) -> int:
    try:
        history = evaluate_history(repo, lane)
    except ApiError as error:
        return handle_api_error(lane, error)
    if report_only:
        print_history(history, "report")
        return 0
    if lane.posture == "required" and not promotion_evidence_matches(repo, history):
        print_history(history, "fail", "promotion_evidence_mismatch")
        return 1
    current_ok, current = current_result(lane)
    if lane.posture == "advisory":
        print_history(history, "advisory", current)
        return 0
    verdict = "pass" if current_ok else "fail"
    print_history(history, verdict, current)
    return 0 if current_ok else 1


def run_fleet(lanes: dict[str, Lane]) -> int:
    required = [lane for lane in lanes.values() if lane.posture == "required"]
    if not required:
        print("lane-gate: fleet required=0 verdict=pass")
        return 0
    repo = repository()
    failed = False
    for lane in required:
        try:
            history = evaluate_history(repo, lane)
        except ApiError as error:
            raise error
        latest_ok = (
            history.latest is not None
            and len(history.successes) >= lane.required_streak
            and history.successes[0].run_id == history.latest.run_id
            and history.freshness == "fresh"
            and promotion_evidence_matches(repo, history)
        )
        print_history(history, "pass" if latest_ok else "fail")
        failed = failed or not latest_ok
    print(f"lane-gate: fleet required={len(required)} verdict={'fail' if failed else 'pass'}")
    return 1 if failed else 0


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments:
        raise GateError("usage: lane-gate.sh <lane> [--report] | --fleet")
    lanes = load_lanes()
    if arguments == ["--fleet"]:
        return run_fleet(lanes)
    if len(arguments) not in {1, 2} or (len(arguments) == 2 and arguments[1] != "--report"):
        raise GateError("usage: lane-gate.sh <lane> [--report] | --fleet")
    name = arguments[0]
    lane = lanes.get(name)
    if lane is None:
        raise GateError(f"lane-gate: unknown lane: {name}")
    repo = repository()
    return run_lane(repo, lane, report_only=len(arguments) == 2)


try:
    raise SystemExit(main())
except GateError as error:
    print(error, file=sys.stderr)
    raise SystemExit(2)
PY
