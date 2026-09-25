"""Perform bounded Python source checks and retain the actual reviewed artifacts."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from catalog import offer


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_text(path: Path, text: str) -> None:
    with path.open("w") as output:
        output.write(text)
        output.flush()
        os.fsync(output.fileno())


def artifacts_root() -> Path:
    workspace = Path(
        os.environ.get("PROVIDER_WORKSPACE", Path(__file__).resolve().parents[1] / "workspace")
    )
    return Path(os.environ.get("PROVIDER_ARTIFACTS", workspace.parent / ".state" / "provider"))


def open_dispute(arguments: dict) -> dict:
    job_id = arguments["job_id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", job_id):
        raise ValueError("Invalid job identifier")
    root = artifacts_root()
    if not (root / job_id / "fulfillment.json").is_file():
        raise ValueError("The provider has no retained fulfillment for this job")
    with sqlite3.connect(root / "disputes.sqlite3") as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS disputes(job_id TEXT PRIMARY KEY, body TEXT NOT NULL)"
        )
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT body FROM disputes WHERE job_id=?", (job_id,)).fetchone()
        if row:
            record = json.loads(row[0])
            if any(record[key] != arguments[key] for key in ("reason_code", "summary")):
                raise ValueError("This job already has a dispute with different terms")
            return record
        record = {
            "dispute_id": "dispute_" + uuid.uuid4().hex,
            "job_id": job_id,
            "reason_code": arguments["reason_code"],
            "summary": arguments["summary"],
            "status": "opened",
            "opened_at": datetime.now(UTC).isoformat(),
            "settlement_status": "reversal_pending",
        }
        db.execute("INSERT INTO disputes VALUES(?,?)", (job_id, json.dumps(record)))
        return record


def execute_review(arguments: dict) -> dict:
    root = Path(
        os.environ.get("PROVIDER_WORKSPACE", Path(__file__).resolve().parents[1] / "workspace")
    ).resolve(strict=True)
    target = Path(arguments["target"])
    if target.is_absolute() or ".." in target.parts:
        raise ValueError("The target must be a relative directory inside PROVIDER_WORKSPACE")
    target = root / target
    if target.is_symlink() or not target.resolve(strict=True).is_relative_to(root):
        raise ValueError("Review target escapes the configured workspace")
    target = target.resolve(strict=True)
    if not target.is_dir():
        raise ValueError("The review target must be a directory")
    selected = offer(arguments["requested_scope"])
    source = []
    findings = []
    total = 0
    for path in sorted(target.rglob("*")):
        if path.is_symlink():
            raise ValueError("Review inputs must not contain symbolic links")
        if not path.is_file():
            continue
        suffix = path.suffix
        include = (
            suffix == ".py"
            or (suffix == ".json" and "json-exposure-settings" in selected["checks"])
            or (
                path.name.startswith("requirements")
                and suffix == ".txt"
                and "dependency-pins" in selected["checks"]
            )
        )
        if not include:
            continue
        if len(source) >= selected["max_files"]:
            raise ValueError("Review exceeds the quoted file limit")
        with path.open("rb") as stream:
            data = stream.read(selected["max_bytes"] - total + 1)
        total += len(data)
        if total > selected["max_bytes"]:
            raise ValueError("Review exceeds the quoted byte limit")
        name = str(path.relative_to(target))
        source.append({"path": name, "sha256": sha256(data), "bytes": len(data)})
        if suffix == ".json":

            def inspect(value, pointer="", file_name=name):
                if isinstance(value, dict):
                    for key, item in value.items():
                        location = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                        if (
                            key.lower() in {"privileged", "publiclyaccessible", "publicaccess"}
                            and item is True
                        ) or (
                            key.lower() in {"cidr", "cidrip", "cidr_ipv4"} and item == "0.0.0.0/0"
                        ):
                            findings.append(
                                {
                                    "rule": "json-exposure",
                                    "severity": "high",
                                    "file": file_name,
                                    "line": 1,
                                    "pointer": location,
                                    "recommendation": "Review this public access or privileged setting against the intended deployment.",
                                }
                            )
                        inspect(item, location)
                elif isinstance(value, list):
                    for index, item in enumerate(value):
                        inspect(item, pointer + "/" + str(index))

            inspect(json.loads(data))
            continue
        if suffix == ".txt":
            for number, line in enumerate(data.decode().splitlines(), 1):
                requirement = line.strip()
                if (
                    requirement
                    and not requirement.startswith(("#", "-"))
                    and "==" not in requirement
                ):
                    findings.append(
                        {
                            "rule": "dependency-pin",
                            "severity": "low",
                            "file": name,
                            "line": number,
                            "recommendation": "Resolve this dependency through an exact version and a retained lockfile.",
                        }
                    )
            continue
        tree = ast.parse(data, filename=name)
        for node in ast.walk(tree):
            if (
                "exception-handling" in selected["checks"]
                and isinstance(node, ast.ExceptHandler)
                and (
                    node.type is None
                    or (
                        isinstance(node.type, ast.Name)
                        and node.type.id in {"Exception", "BaseException"}
                    )
                )
                and all(isinstance(statement, ast.Pass) for statement in node.body)
            ):
                findings.append(
                    {
                        "rule": "swallowed-exception",
                        "severity": "medium",
                        "file": name,
                        "line": node.lineno,
                        "recommendation": "Handle the expected exception explicitly and retain failure evidence.",
                    }
                )
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            rule = None
            if isinstance(function, ast.Name) and function.id in {"eval", "exec"}:
                rule = (
                    "dynamic-code",
                    "high",
                    "Replace dynamic Python execution with a bounded parser or explicit operations.",
                )
            if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
                if function.value.id == "subprocess" and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                ):
                    rule = (
                        "shell-command",
                        "high",
                        "Pass an argument list with shell=False and validate the executable and inputs.",
                    )
                if function.value.id == "hashlib" and function.attr in {"md5", "sha1"}:
                    rule = (
                        "weak-digest",
                        "medium",
                        "Use a modern digest where collision resistance is required.",
                    )
            if rule:
                findings.append(
                    {
                        "rule": rule[0],
                        "severity": rule[1],
                        "file": name,
                        "line": node.lineno,
                        "recommendation": rule[2],
                    }
                )
    if not source:
        raise ValueError("The target contains no files supported by the selected checks")
    job_id = arguments["job_id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", job_id):
        raise ValueError("Invalid job identifier")
    binding = {
        key: arguments[key]
        for key in ("job_id", "quote_id", "service_family", "requested_scope", "target")
    }
    binding["source"] = source
    binding["checks"] = selected["checks"]
    input_hash = sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode())
    output_root = artifacts_root()
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / job_id
    if destination.exists():
        prior = json.loads((destination / "fulfillment.json").read_text())
        if prior["input_sha256"] != input_hash:
            raise ValueError("Job identifier was already used with different source or terms")
        for artifact in prior["artifacts"]:
            if sha256((destination / artifact["name"]).read_bytes()) != artifact["sha256"]:
                raise ValueError("Retained fulfillment artifact has changed")
        return prior
    summary = dict(Counter(item["severity"] for item in findings))
    texts = {
        "findings.json": json.dumps({"source": source, "findings": findings}, indent=2) + "\n",
        "executive-summary.md": f"# Review of {arguments['target']}\n\nChecked {len(source)} files; found {len(findings)} matches.\n\nChecks: {', '.join(selected['checks'])}. This report describes those checks only.\n",
        "remediation-checklist.md": "# Remediation\n\n"
        + (
            "\n".join(
                f"- [ ] {item['file']}:{item['line']}: {item['recommendation']}"
                for item in findings
            )
            if findings
            else "No matching patterns found."
        )
        + "\n",
    }
    result = {
        "fulfillment_id": f"fulfillment_{job_id}",
        **binding,
        "input_sha256": input_hash,
        "status": "completed_with_findings" if findings else "completed",
        "severity_summary": {
            severity: summary.get(severity, 0) for severity in ("critical", "high", "medium", "low")
        },
        "deliverables": list(texts),
        "artifacts": [
            {"name": name, "content": text, "sha256": sha256(text.encode())}
            for name, text in texts.items()
        ],
    }
    with tempfile.TemporaryDirectory(dir=output_root) as temporary:
        staged = Path(temporary) / job_id
        staged.mkdir()
        for name, text in texts.items():
            durable_text(staged / name, text)
        durable_text(staged / "fulfillment.json", json.dumps(result, indent=2) + "\n")
        sync_directory(staged)
        try:
            staged.rename(destination)
            sync_directory(output_root)
        except FileExistsError:
            return execute_review(arguments)
    return result
