#!/usr/bin/env python3

"""Create one idempotent GitHub issue for each surviving formal mutant."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


SCHEMAS = {
    "chio.spec-mutants-report.v1": "spec-mutants",
    "chio.proof-mutants-report.v1": "proof-mutants",
    "chio.lean-mutants-report.v1": "lean-mutants",
}
MUTANT_ID = re.compile(r"[0-9a-f]{20}")
VERDICTS = {"killed", "survived", "unviable", "timeout"}


class IssueError(RuntimeError):
    """Raised when report integrity or GitHub issue evidence is invalid."""


def load_survivors(path: Path) -> tuple[str, str, list[dict[str, Any]]]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise IssueError(f"cannot decode {path}: {error}") from error
    if not isinstance(report, dict) or report.get("schema") not in SCHEMAS:
        raise IssueError(f"unsupported mutation report: {path}")
    commit = report.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise IssueError(f"mutation report has an invalid commit: {path}")
    mutants = report.get("mutants")
    if not isinstance(mutants, list):
        raise IssueError(f"mutation report has no mutant list: {path}")
    survivors: list[dict[str, Any]] = []
    seen: set[str] = set()
    counts = {verdict: 0 for verdict in VERDICTS}
    for mutant in mutants:
        if not isinstance(mutant, dict) or not isinstance(mutant.get("verdict"), str):
            raise IssueError(f"mutation report has an invalid mutant entry: {path}")
        if mutant["verdict"] not in VERDICTS:
            raise IssueError(f"mutation report has an invalid verdict: {path}")
        identifier = mutant.get("id")
        if not isinstance(identifier, str) or MUTANT_ID.fullmatch(identifier) is None:
            raise IssueError(f"mutation report has an invalid mutant identifier: {path}")
        if identifier in seen:
            raise IssueError(f"mutation report repeats mutant {identifier}: {path}")
        seen.add(identifier)
        counts[mutant["verdict"]] += 1
        if mutant["verdict"] == "survived":
            survivors.append(mutant)
    enumerated = report.get("enumerated")
    full_cycle = report.get("full_cycle")
    aggregate = report.get("aggregate")
    if (
        type(enumerated) is not int
        or enumerated < len(mutants)
        or type(full_cycle) is not bool
        or not isinstance(aggregate, dict)
        or type(aggregate.get("sampled")) is not int
        or aggregate["sampled"] != len(mutants)
    ):
        raise IssueError(f"mutation report has invalid inventory metadata: {path}")
    if full_cycle != (enumerated == len(mutants)):
        raise IssueError(f"mutation report has an inconsistent full-cycle marker: {path}")
    for verdict, count in counts.items():
        reported = aggregate.get(verdict, 0)
        if type(reported) is not int or reported != count:
            raise IssueError(f"mutation report aggregate disagrees on {verdict}: {path}")
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    expected = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    activation = aggregate.get("activation_ratio_percent")
    if (
        type(activation) not in (int, float)
        or not math.isfinite(float(activation))
        or abs(float(activation) - expected) > 0.000_5
    ):
        raise IssueError(f"mutation report has an inconsistent activation ratio: {path}")
    return SCHEMAS[report["schema"]], commit, survivors


def gh_json(arguments: list[str]) -> Any:
    gh = os.environ.get("GH_BIN", "gh")
    try:
        completed = subprocess.run(
            [gh, *arguments],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IssueError(f"cannot execute GitHub CLI: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise IssueError(f"GitHub CLI failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise IssueError("GitHub CLI emitted invalid JSON") from error


def existing_issue(identifier: str) -> int | None:
    result = gh_json(
        [
            "issue",
            "list",
            "--state",
            "all",
            "--search",
            f'"mutation-id: {identifier}" in:body',
            "--json",
            "number",
            "--limit",
            "100",
        ]
    )
    if not isinstance(result, list):
        raise IssueError("GitHub issue search did not return a list")
    numbers = []
    for entry in result:
        if not isinstance(entry, dict) or type(entry.get("number")) is not int:
            raise IssueError("GitHub issue search returned an invalid entry")
        numbers.append(entry["number"])
    if len(numbers) > 1:
        raise IssueError(f"multiple issues already track mutation {identifier}: {numbers}")
    return numbers[0] if numbers else None


def report_reference(path: Path) -> str:
    server = os.environ.get("GITHUB_SERVER_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repository and run_id and run_id.isdigit():
        return f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    return str(path)


def issue_body(
    lane: str, commit: str, mutant: dict[str, Any], report_path: Path
) -> str:
    details = {
        key: mutant[key]
        for key in (
            "spec",
            "path",
            "file",
            "action",
            "function",
            "definition",
            "operator",
            "genre",
            "line",
            "column",
            "original",
            "replacement",
            "source_sha256",
            "mutated_sha256",
            "diff_sha256",
            "trace_sha256",
        )
        if key in mutant
    }
    return (
        "A formal mutation survived its configured verification oracle.\n\n"
        f"mutation-id: {mutant['id']}\n"
        f"lane: {lane}\n"
        f"commit: {commit}\n"
        f"report: {report_reference(report_path)}\n"
        f"details: {json.dumps(details, sort_keys=True)}\n\n"
        "Disposition required: strengthen the property or oracle, remove dead model code, "
        "or document why this mutation is semantically equivalent."
    )


def create_issue(
    lane: str, commit: str, mutant: dict[str, Any], report_path: Path
) -> None:
    gh = os.environ.get("GH_BIN", "gh")
    title = f"formal mutation survivor: {lane} {mutant['id']}"
    try:
        completed = subprocess.run(
            [
                gh,
                "issue",
                "create",
                "--title",
                title,
                "--body",
                issue_body(lane, commit, mutant, report_path),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IssueError(f"cannot create issue for {mutant['id']}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise IssueError(f"cannot create issue for {mutant['id']}: {detail}")


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    options = parser.parse_args(arguments)
    created = 0
    existing = 0
    for report_path in options.reports:
        lane, commit, survivors = load_survivors(report_path)
        for mutant in survivors:
            if options.dry_run:
                print(json.dumps({"lane": lane, "commit": commit, "mutant": mutant}, sort_keys=True))
                continue
            number = existing_issue(mutant["id"])
            if number is not None:
                print(f"mutation {mutant['id']} already tracked by issue {number}")
                existing += 1
                continue
            create_issue(lane, commit, mutant, report_path)
            created += 1
    print(f"mutation-survivors: created={created} existing={existing}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except IssueError as error:
        print(f"mutation-survivors: {error}", file=sys.stderr)
        raise SystemExit(2) from error
