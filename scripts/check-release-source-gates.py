#!/usr/bin/env python3
"""Require completed, exact-source main checks before publishing a binary release."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import urlencode


REQUIRED = {
    "ci.yml": ("push", {
        "Build, lint, test",
        "MSRV build and test",
        "cargo-vet (locked supply-chain audit)",
        "cargo-deny (supply-chain bans/advisories/licenses)",
    }),
    "release-qualification.yml": (None, {"Release qualification"}),
    "cve-monitor.yml": (None, {"cargo-audit and osv-scanner"}),
    "cargo-vet.yml": (None, {"cargo-vet (locked supply-chain audit)"}),
}


def github(path: str) -> dict:
    result = subprocess.run(
        ["gh", "api", path], check=True, capture_output=True, text=True, timeout=60
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("GitHub returned a non-object response")
    return value


def require_gates(repository: str, head: str, read=github) -> list[dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("invalid source commit")
    evidence = []
    for filename, (event, names) in REQUIRED.items():
        prefix = f"repos/{repository}/actions"
        workflow = read(f"{prefix}/workflows/{filename}")
        workflow_id = workflow["id"]
        expected_path = f".github/workflows/{filename}"
        if workflow.get("path") != expected_path:
            raise ValueError(f"unexpected workflow path for {filename}")
        query = urlencode({"head_sha": head, "branch": "main", "per_page": 100})
        response = read(f"{prefix}/workflows/{workflow_id}/runs?{query}")
        runs = response["workflow_runs"]
        # Refuse a truncated history rather than silently choosing an older run.
        if response["total_count"] != len(runs):
            raise ValueError(f"incomplete run history for {filename}")
        eligible = [r for r in runs if (
            r.get("head_sha") == head and r.get("head_branch") == "main"
            and r.get("head_repository", {}).get("full_name") == repository
            and r.get("workflow_id") == workflow_id
            and r.get("path") == expected_path
            and r.get("event") in ({event} if event else {"push", "workflow_dispatch", "schedule"})
        )]
        if not eligible:
            raise ValueError(f"no exact-source main run for {filename}")
        run = max(eligible, key=lambda r: (r["run_number"], r["id"]))
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise ValueError(f"latest exact-source {filename} run did not succeed")
        attempt = run["run_attempt"]
        if not isinstance(attempt, int) or attempt < 1:
            raise ValueError("invalid run attempt")
        jobs_response = read(
            f"{prefix}/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100"
        )
        jobs = jobs_response["jobs"]
        if jobs_response["total_count"] != len(jobs):
            raise ValueError(f"incomplete job history for {filename}")
        for name in names:
            matching = [job for job in jobs if job.get("name") == name]
            if len(matching) != 1 or any(
                job.get("run_id") != run["id"] or job.get("run_attempt") != attempt
                or job.get("head_sha") != head
                or job.get("status") != "completed" or job.get("conclusion") != "success"
                for job in matching
            ):
                raise ValueError(f"required job did not succeed: {name}")
        evidence.append({"workflow": filename, "run": run["id"], "attempt": attempt,
                         "head": head, "jobs": sorted(names)})
    return evidence


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    head = os.environ["GITHUB_SHA"]
    tag = os.environ["GITHUB_REF_NAME"]
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        raise ValueError("binary publication requires a tag event")
    manifest = tomllib.loads((root / "crates/products/chio-cli/Cargo.toml").read_text())
    version = manifest["package"]["version"]
    if isinstance(version, dict) and version == {"workspace": True}:
        version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if tag != f"v{version}":
        raise ValueError("release tag does not match the compiled CLI package version")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != head:
        raise ValueError("checkout does not match the release source")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=True)
    evidence = require_gates(os.environ["GITHUB_REPOSITORY"], head)
    print(json.dumps({"source": head, "version": version, "checks": evidence}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, TypeError, OSError, subprocess.SubprocessError) as error:
        # Do not echo gh stderr or environment values into release logs.
        print(f"release source gate refused: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
