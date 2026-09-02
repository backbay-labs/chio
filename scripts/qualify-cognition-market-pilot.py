#!/usr/bin/env python3
"""Run the single-operator coding-agent pilot and emit aggregate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdks/python/chio-sdk-python"
EXAMPLE = ROOT / "examples/cognition-market-pilot"


@dataclass(frozen=True)
class Task:
    name: str
    broken: str
    fixed: str
    test: str


TASKS = (
    Task(
        "clamp-bounds",
        "def clamp(value, low, high):\n    return min(low, max(value, high))\n",
        "def clamp(value, low, high):\n    return max(low, min(value, high))\n",
        "from market_tasks import clamp\nassert clamp(20, 0, 10) == 10\n",
    ),
    Task(
        "stable-unique",
        "def stable_unique(values):\n    return list(set(values))\n",
        "def stable_unique(values):\n    return list(dict.fromkeys(values))\n",
        "from market_tasks import stable_unique\nassert stable_unique([3, 1, 3, 2]) == [3, 1, 2]\n",
    ),
    Task(
        "complete-chunks",
        "def chunks(values, size):\n    return [values[index:index + size] for index in range(0, len(values) - size, size)]\n",
        "def chunks(values, size):\n    return [values[index:index + size] for index in range(0, len(values), size)]\n",
        "from market_tasks import chunks\nassert chunks([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]\n",
    ),
    Task(
        "parse-boolean",
        "def parse_bool(value):\n    return bool(value)\n",
        "def parse_bool(value):\n    return value.strip().lower() in {\"1\", \"true\", \"yes\"}\n",
        "from market_tasks import parse_bool\nassert parse_bool(\"false\") is False\nassert parse_bool(\" YES \") is True\n",
    ),
    Task(
        "even-median",
        "def median(values):\n    ordered = sorted(values)\n    return ordered[len(ordered) // 2]\n",
        "def median(values):\n    ordered = sorted(values)\n    middle = len(ordered) // 2\n    return (ordered[middle - 1] + ordered[middle]) / 2 if len(ordered) % 2 == 0 else ordered[middle]\n",
        "from market_tasks import median\nassert median([1, 2, 8, 10]) == 5\n",
    ),
    Task(
        "capped-backoff",
        "def backoff(base, attempt, cap):\n    return base * (2 ** attempt)\n",
        "def backoff(base, attempt, cap):\n    return min(cap, base * (2 ** attempt))\n",
        "from market_tasks import backoff\nassert backoff(2, 8, 30) == 30\n",
    ),
    Task(
        "safe-ratio",
        "def safe_ratio(numerator, denominator):\n    return numerator / denominator\n",
        "def safe_ratio(numerator, denominator):\n    return 0 if denominator == 0 else numerator / denominator\n",
        "from market_tasks import safe_ratio\nassert safe_ratio(8, 0) == 0\n",
    ),
    Task(
        "casefold-headers",
        "def merge_headers(left, right):\n    return {**left, **right}\n",
        "def merge_headers(left, right):\n    return {key.lower(): value for source in (left, right) for key, value in source.items()}\n",
        "from market_tasks import merge_headers\nassert merge_headers({\"X-Id\": \"old\"}, {\"x-id\": \"new\"}) == {\"x-id\": \"new\"}\n",
    ),
    Task(
        "redact-secret",
        "def redact(text, secret):\n    return text\n",
        "def redact(text, secret):\n    return text.replace(secret, \"[REDACTED]\")\n",
        "from market_tasks import redact\nassert redact(\"token=secret\", \"secret\") == \"token=[REDACTED]\"\n",
    ),
    Task(
        "retryable-status",
        "def retryable(status):\n    return status >= 400\n",
        "def retryable(status):\n    return status in {408, 429} or status >= 500\n",
        "from market_tasks import retryable\nassert retryable(404) is False\nassert retryable(503) is True\n",
    ),
)


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    timeout: float = 300,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout[-8000:]}\nstderr:\n{completed.stderr[-8000:]}"
        )
    return completed


def git(repository: Path, *arguments: str) -> str:
    return run(["git", *arguments], cwd=repository).stdout.strip()


def create_corpus(repository: Path) -> list[dict[str, str]]:
    repository.mkdir()
    git(repository, "init", "-q")
    git(repository, "config", "user.name", "Chio Pilot")
    git(repository, "config", "user.email", "pilot@local.invalid")
    module = repository / "market_tasks.py"
    tests = repository / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("", encoding="utf-8")
    module.write_text('"""Small deterministic coding tasks for the Chio pilot."""\n\n')
    git(repository, "add", ".")
    git(repository, "commit", "-q", "-m", "chore: initialize pilot task corpus")
    revisions: list[dict[str, str]] = []
    for index, task in enumerate(TASKS, start=1):
        with module.open("a", encoding="utf-8") as handle:
            handle.write(f"\n\n{task.broken}")
        test_path = tests / f"task_{index:02d}.py"
        test_path.write_text(task.test, encoding="utf-8")
        git(repository, "add", ".")
        git(repository, "commit", "-q", "-m", f"test: add failing {task.name} case")
        base = git(repository, "rev-parse", "HEAD")
        module_name = f"tests.task_{index:02d}"
        baseline = run(["python3", "-B", "-m", module_name], cwd=repository, check=False)
        if baseline.returncode == 0:
            raise RuntimeError(f"pilot task {task.name} does not fail at its base revision")
        text = module.read_text(encoding="utf-8")
        if text.count(task.broken) != 1:
            raise RuntimeError(f"pilot task {task.name} broken source is not unique")
        module.write_text(text.replace(task.broken, task.fixed), encoding="utf-8")
        git(repository, "add", "market_tasks.py")
        git(repository, "commit", "-q", "-m", f"fix: correct {task.name}")
        candidate = git(repository, "rev-parse", "HEAD")
        run(["python3", "-B", "-m", module_name], cwd=repository)
        revisions.append(
            {
                "base": base,
                "candidate": candidate,
                "name": task.name,
                "test": f"python3 -B -m tests.task_{index:02d}",
            }
        )
    return revisions


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not a JSON object")
    return value


def request_json(
    endpoint: str,
    token: str,
    path: str,
    *,
    timeout: float = 5,
) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}{path}",
        headers={"authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise RuntimeError("operator response is not a JSON object")
    return value


def start_operator(binary: Path, profile: Path, log: Path) -> tuple[subprocess.Popen[str], Any]:
    handle = log.open("a", encoding="utf-8")
    process = subprocess.Popen(
        [str(binary), "finding", "operator", "serve", "--profile", str(profile)],
        cwd=ROOT,
        text=True,
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return process, handle


def wait_ready(process: subprocess.Popen[str], buyer: dict[str, Any]) -> None:
    endpoint = urllib.parse.urlsplit(str(buyer["endpoint"]))
    if endpoint.hostname is None or endpoint.port is None:
        raise RuntimeError("buyer profile endpoint is not a socket address")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"operator exited before readiness with {process.returncode}")
        try:
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=1):
                pass
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("operator did not become ready")


def stop_operator(process: subprocess.Popen[str], *, force: bool = False) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def agent_command(script: str, *arguments: str) -> list[str]:
    return [
        "uv",
        "run",
        "--project",
        str(SDK),
        str(EXAMPLE / script),
        *arguments,
    ]


def row_count(database: Path, table: str, where: str = "") -> int:
    with sqlite3.connect(database, timeout=1) as connection:
        row = connection.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()
    if row is None:
        raise RuntimeError(f"cannot count {table}")
    return int(row[0])


def terminal_digests(database: Path) -> list[str]:
    with sqlite3.connect(database, timeout=1) as connection:
        rows = connection.execute(
            "SELECT result_sha256 FROM chio_finding_operator_terminals ORDER BY request_id"
        ).fetchall()
    return [str(row[0]) for row in rows]


def seller_admit(
    seller_profile: Path,
    repository: Path,
    revision: dict[str, str],
    index: int,
) -> tuple[dict[str, Any], int]:
    started = time.monotonic_ns()
    completed = run(
        agent_command(
            "seller_agent.py",
            "--credential",
            str(seller_profile),
            "--repository",
            str(repository),
            "--base",
            revision["base"],
            "--candidate",
            revision["candidate"],
            "--test",
            revision["test"],
            "--topic",
            f"pilot/python/{index:02d}/{revision['name']}",
        ),
        timeout=600,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    return json.loads(completed.stdout), elapsed


def buyer_purchase(
    buyer_profile: Path,
    binary: Path,
    finding_id: str,
    patch: Path,
) -> tuple[dict[str, Any], int]:
    started = time.monotonic_ns()
    completed = run(
        agent_command(
            "buyer_agent.py",
            "--credential",
            str(buyer_profile),
            "--chio",
            str(binary),
            "--finding",
            finding_id,
            "--patch",
            str(patch),
        ),
        timeout=300,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    return json.loads(completed.stdout), elapsed


def purchase_with_active_restart(
    binary: Path,
    profile: Path,
    buyer_profile: Path,
    buyer: dict[str, Any],
    finding_id: str,
    patch: Path,
    operator_database: Path,
    process: subprocess.Popen[str],
    handle: Any,
    log: Path,
) -> tuple[subprocess.Popen[str], Any, dict[str, Any]]:
    jobs_before = row_count(operator_database, "chio_finding_operator_purchase_jobs")
    terminals_before = row_count(operator_database, "chio_finding_operator_terminals")
    captures_before = row_count(
        operator_database,
        "chio_finding_operator_payments",
        "WHERE state IN ('captured', 'refunded')",
    )
    command = agent_command(
        "buyer_agent.py",
        "--credential",
        str(buyer_profile),
        "--chio",
        str(binary),
        "--finding",
        finding_id,
        "--patch",
        str(patch),
    )
    buyer_process = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    observed_active = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and buyer_process.poll() is None:
        jobs = row_count(operator_database, "chio_finding_operator_purchase_jobs")
        terminals = row_count(operator_database, "chio_finding_operator_terminals")
        if jobs == jobs_before + 1 and terminals == terminals_before:
            os.killpg(process.pid, signal.SIGSTOP)
            observed_active = row_count(
                operator_database, "chio_finding_operator_terminals"
            ) == terminals_before
            break
        time.sleep(0.001)
    if not observed_active:
        buyer_process.kill()
        buyer_process.communicate(timeout=10)
        raise RuntimeError("could not stop the operator during a durable active purchase")
    stop_operator(process, force=True)
    handle.close()
    buyer_process.kill()
    buyer_process.communicate(timeout=10)

    restarted, restarted_handle = start_operator(binary, profile, log)
    wait_ready(restarted, buyer)
    recovered, _ = buyer_purchase(buyer_profile, binary, finding_id, patch)
    digest_before_replay = terminal_digests(operator_database)
    replayed, _ = buyer_purchase(buyer_profile, binary, finding_id, patch)
    digest_after_replay = terminal_digests(operator_database)
    captures_after = row_count(
        operator_database,
        "chio_finding_operator_payments",
        "WHERE state IN ('captured', 'refunded')",
    )
    evidence = {
        "activeJobObserved": observed_active,
        "captureDelta": captures_after - captures_before,
        "exactReplay": recovered == replayed and digest_before_replay == digest_after_replay,
        "recoveredFindingId": recovered["findingId"],
        "terminalDelta": len(digest_after_replay) - terminals_before,
    }
    if evidence["captureDelta"] != 1 or evidence["terminalDelta"] != 1 or not evidence["exactReplay"]:
        raise RuntimeError(f"active restart invariants failed: {evidence}")
    return restarted, restarted_handle, evidence


def typescript_purchase(
    buyer_profile: Path,
    binary: Path,
    finding_id: str,
    patch: Path,
    program: Path,
) -> tuple[dict[str, Any], int]:
    source = (ROOT / "sdks/typescript/chio-ts/src/cognition_market.ts").as_uri()
    program.write_text(
        "\n".join(
            [
                'import { writeFileSync } from "node:fs";',
                f'import {{ CognitionMarketBuyer }} from "{source}";',
                f'const buyer = new CognitionMarketBuyer({json.dumps(str(buyer_profile))}, '
                f'{{ chioBinary: {json.dumps(str(binary))} }});',
                f'const verified = await buyer.verifiedProof({json.dumps(finding_id)});',
                'const purchased = await buyer.purchaseVerifiedFix(verified, { maxPriceUnits: 300 });',
                f'writeFileSync({json.dumps(str(patch))}, purchased.patch);',
                'console.log(JSON.stringify({ findingId: purchased.findingId, settlement: '
                'purchased.purchase.settlement, verdict: purchased.purchase.verdict }));',
            ]
        ),
        encoding="utf-8",
    )
    started = time.monotonic_ns()
    completed = run(
        ["node", "--experimental-strip-types", str(program)],
        timeout=300,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    return json.loads(completed.stdout), elapsed


def tampered_proof_rejected(
    binary: Path,
    buyer_profile: Path,
    buyer: dict[str, Any],
    finding_id: str,
    directory: Path,
) -> dict[str, bool]:
    request = urllib.request.Request(
        f"{buyer['endpoint']}/v1/findings/{finding_id}/proof",
        headers={"authorization": f"Bearer {buyer['bearerToken']}"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        proof = json.loads(response.read())
    finding = proof["bundle"]["finding"]
    descriptor = finding["descriptor"]
    descriptor["topic"] = f"{descriptor['topic']}/tampered"
    tampered = directory / "tampered-proof.json"
    tampered.write_bytes(
        json.dumps(proof, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    rust = run(
        [
            str(binary),
            "finding",
            "verify-bundle",
            "--profile",
            str(buyer_profile),
            "--input",
            str(tampered),
            "--json",
        ],
        check=False,
    )
    source = (ROOT / "sdks/typescript/chio-ts/src/cognition_market.ts").as_uri()
    program = directory / "tamper-check.mjs"
    program.write_text(
        "\n".join(
            [
                'import { readFileSync } from "node:fs";',
                f'import {{ CognitionMarketBuyer }} from "{source}";',
                f'const buyer = new CognitionMarketBuyer({json.dumps(str(buyer_profile))}, '
                f'{{ chioBinary: {json.dumps(str(binary))} }});',
                "let rejected = false;",
                f"try {{ await buyer.verifyProof(readFileSync({json.dumps(str(tampered))})); }} "
                "catch { rejected = true; }",
                "if (!rejected) process.exit(1);",
            ]
        ),
        encoding="utf-8",
    )
    typescript = run(["node", "--experimental-strip-types", str(program)], check=False)
    return {"rustRejected": rust.returncode != 0, "typescriptRejected": typescript.returncode == 0}


def tampered_purchase_terminal_rejected(
    binary: Path,
    buyer_profile: Path,
    buyer: dict[str, Any],
    finding_id: str,
    operator_database: Path,
    directory: Path,
) -> bool:
    with sqlite3.connect(operator_database) as connection:
        rows = connection.execute(
            "SELECT result_json FROM chio_finding_operator_terminals"
        ).fetchall()
    result = next(
        value
        for (raw,) in rows
        if (value := json.loads(raw))["findingId"] == finding_id
    )
    identity = {
        "deadlineSecs": 3600,
        "findingId": finding_id,
        "maxPrice": {"currency": "USD", "units": 300},
        "payer": buyer["payer"],
        "schema": "chio.finding.purchase-request.v1",
    }
    canonical_identity = json.dumps(
        identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    request_id = hashlib.sha256(
        b"chio.finding.public-purchase-request.v1\0" + canonical_identity
    ).hexdigest()
    if request_id != result["requestId"]:
        raise RuntimeError("reconstructed purchase request does not match the stored terminal")
    request = {key: value for key, value in identity.items() if value is not None}
    request["requestId"] = request_id
    request_path = directory / "purchase-request.json"
    result_path = directory / "purchase-result.json"
    proof_path = directory / "purchase-proof.json"
    request_path.write_bytes(
        json.dumps(request, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    result_path.write_bytes(
        json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    proof_request = urllib.request.Request(
        f"{buyer['endpoint']}/v1/findings/{finding_id}/proof",
        headers={"authorization": f"Bearer {buyer['bearerToken']}"},
    )
    with urllib.request.urlopen(proof_request, timeout=10) as response:
        proof_path.write_bytes(response.read())
    verification_command = [
        str(binary),
        "finding",
        "verify-bundle",
        "--profile",
        str(buyer_profile),
        "--input",
        str(proof_path),
        "--purchase-request",
        str(request_path),
        "--purchase-result",
        str(result_path),
        "--json",
    ]
    unmodified = run(verification_command, check=False)
    if unmodified.returncode != 0:
        raise RuntimeError(
            "unmodified payer-bound purchase terminal failed verification: "
            f"{unmodified.stderr[-4000:]}"
        )
    signature = result["purchaseRecord"]["signature"]
    result["purchaseRecord"]["signature"] = (
        ("0" if signature[0] != "0" else "1") + signature[1:]
    )
    result_path.write_bytes(
        json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    completed = run(
        verification_command,
        check=False,
    )
    return completed.returncode != 0


def qualify(binary: Path, output: Path, candidate_sha: str) -> dict[str, Any]:
    if not binary.is_file():
        raise RuntimeError(f"chio binary does not exist: {binary}")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chio-m10-pilot-") as temporary:
        temporary_root = Path(temporary)
        repository = temporary_root / "task-repository"
        revisions = create_corpus(repository)
        deployment = temporary_root / "operator"
        port = free_port()
        init_command = [
            str(binary),
            "finding",
            "operator",
            "init",
            "--directory",
            str(deployment),
            "--listen",
            f"127.0.0.1:{port}",
            "--repository-root",
            str(temporary_root),
            "--json",
        ]
        run(init_command)
        profile = deployment / "operator-profile.json"
        buyer_profile = deployment / "buyer-client.json"
        seller_profile = deployment / "seller-client.json"
        init_files = [
            profile,
            deployment / "client-profile.json",
            buyer_profile,
            seller_profile,
            deployment / "operator-init-complete.json",
        ]
        initialized_bytes = {path.name: path.read_bytes() for path in init_files}
        run(init_command)
        init_retry_exact = all(
            path.read_bytes() == initialized_bytes[path.name] for path in init_files
        )
        if not init_retry_exact:
            raise RuntimeError("operator initialization retry changed deployment identity")
        buyer = load_json(buyer_profile)
        operator_profile = load_json(profile)
        operator_database = deployment / str(operator_profile["paths"]["operatorDatabase"])
        log = output / "operator.log"
        process, handle = start_operator(binary, profile, log)
        findings: list[dict[str, Any]] = []
        purchases: list[dict[str, Any]] = []
        restart: dict[str, Any] = {}
        try:
            wait_ready(process, buyer)
            for index, revision in enumerate(revisions, start=1):
                admitted, elapsed = seller_admit(
                    seller_profile,
                    repository,
                    revision,
                    index,
                )
                findings.append(
                    {
                        "admissionMillis": elapsed,
                        "findingId": admitted["findingId"],
                        "task": revision["name"],
                    }
                )
            if len({item["findingId"] for item in findings}) != len(TASKS):
                raise RuntimeError("pilot admissions did not produce 10 distinct Findings")

            patch = temporary_root / "purchase-01.patch"
            process, handle, restart = purchase_with_active_restart(
                binary,
                profile,
                buyer_profile,
                buyer,
                str(findings[0]["findingId"]),
                patch,
                operator_database,
                process,
                handle,
                log,
            )
            purchases.append(
                {
                    "client": "python",
                    "findingId": findings[0]["findingId"],
                    "patchSha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                    "restartRecovered": True,
                }
            )
            for index in range(1, 4):
                patch = temporary_root / f"purchase-{index + 1:02d}.patch"
                purchased, elapsed = buyer_purchase(
                    buyer_profile,
                    binary,
                    str(findings[index]["findingId"]),
                    patch,
                )
                purchases.append(
                    {
                        "client": "python",
                        "findingId": purchased["findingId"],
                        "patchSha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                        "purchaseMillis": elapsed,
                    }
                )
            patch = temporary_root / "purchase-05.patch"
            purchased, elapsed = typescript_purchase(
                buyer_profile,
                binary,
                str(findings[9]["findingId"]),
                patch,
                temporary_root / "typescript-purchase.mjs",
            )
            purchases.append(
                {
                    "client": "typescript",
                    "findingId": purchased["findingId"],
                    "patchSha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                    "purchaseMillis": elapsed,
                }
            )

            challenge = json.loads(
                run(
                    agent_command(
                        "challenge_agent.py",
                        "--credential",
                        str(buyer_profile),
                        "--chio",
                        str(binary),
                        "--finding",
                        str(findings[9]["findingId"]),
                    )
                ).stdout
            )
            retraction = json.loads(
                run(
                    agent_command(
                        "retract_agent.py",
                        "--credential",
                        str(seller_profile),
                        "--finding",
                        str(findings[9]["findingId"]),
                    )
                ).stdout
            )
            retraction_job = (
                deployment
                / str(operator_profile["paths"]["reportsDirectory"])
                / f"{retraction['requestId']}.seller-retraction-job.json"
            )
            pending_retraction = load_json(retraction_job)
            pending_retraction["result"] = None
            retraction_job.write_bytes(
                json.dumps(
                    pending_retraction,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            )
            replayed_retraction = json.loads(
                run(
                    agent_command(
                        "retract_agent.py",
                        "--credential",
                        str(seller_profile),
                        "--finding",
                        str(findings[9]["findingId"]),
                    )
                ).stdout
            )
            if replayed_retraction != retraction:
                raise RuntimeError("voluntary retraction crash replay changed its terminal")
            feed_id = buyer["market"]["statusFeedOperator"]["feedId"]
            status = request_json(
                str(buyer["endpoint"]),
                str(buyer["bearerToken"]),
                "/v1/findings/status/"
                f"{urllib.parse.quote(str(feed_id), safe='')}/proof/{findings[9]['findingId']}",
            )
            controlled_challenge = {
                "challengeId": challenge["challengeId"],
                "findingId": findings[9]["findingId"],
                "intentId": retraction["intentId"],
                "proofKind": status["proof_kind"],
                "retractionCrashReplayExact": True,
                "status": retraction["status"],
            }
            if controlled_challenge["proofKind"] != "inclusion" or controlled_challenge["status"] != "retracted":
                raise RuntimeError("controlled challenge did not reach public retraction")

            tamper = tampered_proof_rejected(
                binary,
                buyer_profile,
                buyer,
                str(findings[1]["findingId"]),
                temporary_root,
            )
            tamper["purchaseTerminalRustRejected"] = tampered_purchase_terminal_rejected(
                binary,
                buyer_profile,
                buyer,
                str(findings[1]["findingId"]),
                operator_database,
                temporary_root,
            )
            if not all(tamper.values()):
                raise RuntimeError(f"tampered proof rejection failed: {tamper}")

            tick = json.loads(
                run(
                    [
                        str(binary),
                        "finding",
                        "operator",
                        "tick",
                        "--profile",
                        str(profile),
                        "--json",
                    ]
                ).stdout
            )
            replay_before = terminal_digests(operator_database)
            buyer_purchase(
                buyer_profile,
                binary,
                str(findings[1]["findingId"]),
                temporary_root / "purchase-02-replay.patch",
            )
            replay_after = terminal_digests(operator_database)
            captures = row_count(
                operator_database,
                "chio_finding_operator_payments",
                "WHERE state IN ('captured', 'refunded')",
            )
            replay = {
                "captureCount": captures,
                "terminalDigestsUnchanged": replay_before == replay_after,
                "terminalCount": len(replay_after),
            }
            if captures != 5 or len(replay_after) != 5 or not replay["terminalDigestsUnchanged"]:
                raise RuntimeError(f"purchase replay accounting failed: {replay}")

            return {
                "schema": "chio.cognition-market.pilot-report.v1",
                "candidateSha": candidate_sha,
                "challenge": controlled_challenge,
                "counts": {
                    "captureCount": captures,
                    "failureCount": 0,
                    "findingCount": len(findings),
                    "purchaseCount": len(purchases),
                    "taskCount": len(revisions),
                },
                "findings": findings,
                "generatedAt": int(time.time()),
                "operatorInit": {"retryExact": init_retry_exact},
                "operatorTick": tick,
                "purchases": purchases,
                "replay": replay,
                "restart": restart,
                "tamper": tamper,
            }
        finally:
            stop_operator(process)
            handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, default=ROOT / "target/debug/chio")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "target/cognition-market-pilot",
    )
    arguments = parser.parse_args()
    status = run(
        [
            "git",
            "-C",
            str(ROOT),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]
    ).stdout.strip()
    if status:
        raise RuntimeError("cognition-market pilot requires a clean candidate worktree")
    candidate_sha = git(ROOT, "rev-parse", "HEAD")
    expected_binary = (ROOT / "target/debug/chio").resolve()
    if arguments.chio.resolve() != expected_binary:
        raise RuntimeError(
            "cognition-market pilot only accepts the candidate-built target/debug/chio binary"
        )
    run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--target-dir",
            str(ROOT / "target"),
        ],
        timeout=1800,
    )
    if git(ROOT, "rev-parse", "HEAD") != candidate_sha:
        raise RuntimeError("candidate HEAD changed while building the pilot binary")
    report = qualify(
        expected_binary, arguments.output.resolve(), candidate_sha
    )
    destination = arguments.output.resolve() / "report.json"
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["counts"], separators=(",", ":"), sort_keys=True))
    print(destination)


if __name__ == "__main__":
    main()
