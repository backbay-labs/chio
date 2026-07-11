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
import json
import os
import re
import subprocess
import sys
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


@dataclass(frozen=True)
class History:
    lane: Lane
    successes: list[RunEvidence]
    latest: RunEvidence | None
    barrier: RunEvidence | None
    barrier_reason: str | None
    freshness: str


ALLOWED_FIELDS = {
    "workflow",
    "job",
    "event",
    "posture",
    "required_streak",
    "evidence_after_run_id",
    "max_age_hours",
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
    return parse_json_documents(completed.stdout, endpoint)


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


def run_artifact_names(repo: str, run_id: int) -> set[str]:
    endpoint = f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    artifacts = flatten(gh_api(endpoint), "artifacts", endpoint)
    return {
        artifact["name"]
        for artifact in artifacts
        if artifact.get("expired") is False and isinstance(artifact.get("name"), str)
    }


def exact_artifact_present(names: set[str], prefix: str, run_id: int, run_attempt: int) -> bool:
    return f"{prefix}{run_id}-{run_attempt}" in names


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
    reason = None
    if conclusion != "success":
        reason = "job_not_successful"
    artifact_names: set[str] | None = None
    if conclusion == "success" and (
        lane.strict_mode_required or lane.execution_artifact_prefix is not None
    ):
        artifact_names = run_artifact_names(repo, run_id)
    if reason is None and lane.strict_mode_required:
        prefix = lane.strict_artifact_prefix
        if prefix is None or artifact_names is None:
            raise GateError(f"lane-gate: lane={lane.name} strict artifact setup is invalid")
        strict = exact_artifact_present(artifact_names, prefix, run_id, run_attempt)
        if not strict:
            reason = "non_strict"
    if reason is None and lane.execution_artifact_prefix is not None:
        if artifact_names is None:
            raise GateError(f"lane-gate: lane={lane.name} execution marker setup is invalid")
        real_execution = exact_artifact_present(
            artifact_names,
            lane.execution_artifact_prefix,
            run_id,
            run_attempt,
        )
        if not real_execution:
            reason = "execution_marker_missing"
    return (
        RunEvidence(
            run_id=run_id,
            run_attempt=run_attempt,
            created_at=created_at,
            conclusion=conclusion,
            url=str(run.get("html_url") or ""),
            strict=strict,
            real_execution=real_execution,
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
    print(
        "lane-gate: "
        f"lane={lane.name} posture={lane.posture} event={lane.event} "
        f"job={json.dumps(lane.job)} streak={len(history.successes)}/{lane.required_streak} "
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
        print(
            "lane-gate-evidence: "
            f"lane={lane.name} run_id={evidence.run_id} attempt={evidence.run_attempt} "
            f"created_at={evidence.created_at} "
            f"conclusion={evidence.conclusion} strict={strict} "
            f"real_execution={execution} url={evidence.url or 'none'}"
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
            and bool(history.successes)
            and history.successes[0].run_id == history.latest.run_id
            and history.freshness == "fresh"
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
