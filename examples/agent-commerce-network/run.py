#!/usr/bin/env python3
"""Run a real procurement application with retained state, work products and receipts."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

import httpx
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent


def request(url, body=None, *, token=None, capability=None, headers=None):
    fields = {"Content-Type": "application/json", **(headers or {})}
    if token:
        fields["Authorization"] = "Bearer " + token
    if capability:
        fields["X-Chio-Capability"] = json.dumps(capability, separators=(",", ":"))
    query = urllib.request.Request(
        url, headers=fields, data=None if body is None else json.dumps(body).encode()
    )
    try:
        response = urllib.request.urlopen(query, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, json.loads(response.read())


def seed(path):
    if not path.exists():
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
            output.write(SigningKey.generate().encode().hex() + "\n")
    return SigningKey(bytes.fromhex(path.read_text().strip())).verify_key.encode().hex()


def free_address():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return "http://127.0.0.1:" + str(listener.getsockname()[1])


@contextmanager
def services(state, run):
    binary = os.getenv("CHIO_BIN") or shutil.which("chio")
    if not binary:
        raise RuntimeError("Install the Chio CLI revision documented in README.md, or set CHIO_BIN")
    binary = str(Path(binary).resolve())
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    state.chmod(0o700)
    run.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock = (state / "operator.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock.close()
        raise RuntimeError(
            "Another instance owns this application state; stop it before continuing"
        ) from error
    children, logs = [], []
    try:
        signers = {name: seed(state / (name + ".seed")) for name in ("trust", "buyer", "caller")}
        token, edge_token, approval_token = [secrets.token_hex(32) for _ in range(3)]
        control, provider, api, buyer = [free_address() for _ in range(4)]
        environment = {
            **os.environ,
            "CHIO_BIN": binary,
            "CHIO_CONTROL_URL": control,
            "CHIO_CONTROL_TOKEN": token,
            "CHIO_EDGE_TOKEN": edge_token,
            "CHIO_TRUSTED_ISSUER_KEY": signers["trust"],
            "PROVIDER_EDGE_LISTEN": provider.removeprefix("http://"),
            "PROVIDER_SESSION_DB": str(state / "provider-sessions.sqlite3"),
            "PROVIDER_ARTIFACTS": str(state / "provider-deliverables"),
            "BUYER_STATE_DB": str(state / "buyer.db"),
            "BUYER_APPROVAL_TOKEN": approval_token,
            "BUYER_PROVIDER_BASE_URL": provider,
            "BUYER_PROVIDER_AUTH_TOKEN": edge_token,
            "BUYER_AUTHORITY_SEED_FILE": str(state / "buyer.seed"),
            "BUYER_STATE_DIR": str(state / "buyer"),
            "BUYER_UPSTREAM_URL": api,
            "BUYER_SIDECAR_LISTEN": buyer.removeprefix("http://"),
            "BUYER_RECEIPT_STORE": str(state / "buyer-receipts.sqlite3"),
        }

        def start(name, command):
            log = (run / (name + ".log")).open("w")
            logs.append(log)
            child = subprocess.Popen(
                command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log
            )
            children.append(child)
            return child

        def ready(url=None, tcp=None):
            for _ in range(300):
                if any(child.poll() is not None for child in children):
                    raise RuntimeError(f"A service stopped; inspect {run}/*.log")
                try:
                    if url and request(url)[0] == 200:
                        return
                    if tcp:
                        with socket.create_connection(
                            ("127.0.0.1", int(tcp.rsplit(":", 1)[1])), timeout=0.2
                        ):
                            return
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            raise RuntimeError(f"Service startup timed out; inspect {run}/*.log")

        trust_process = start(
            "trust",
            [
                binary,
                "trust",
                "serve",
                "--listen",
                control.removeprefix("http://"),
                "--service-token",
                token,
                "--receipt-db",
                str(state / "trust-receipts.sqlite3"),
                "--authority-seed-file",
                str(state / "trust.seed"),
                "--session-db",
                str(state / "trust-joint.sqlite3"),
            ],
        )
        ready(control + "/health")
        provider_process = start("provider", ["bash", "provider/run-edge.sh"])
        ready(tcp=provider)
        # This is the public key file of the kernel this operator owns. It is
        # selected before the buyer accepts any provider response or receipt.
        signers["provider"] = (state / "provider-sessions.sqlite3.kernel.pub").read_text().strip()
        if len(bytes.fromhex(signers["provider"])) != 32:
            raise ValueError("Invalid provider kernel public key")
        pin = state / "operator-signers.json"
        if pin.exists() and json.loads(pin.read_text()) != signers:
            raise ValueError(
                "A retained kernel identity changed; inspect the state before proceeding"
            )
        pin.write_text(json.dumps(signers, indent=2) + "\n")
        (run / "trusted-signers.json").write_text(json.dumps(signers, indent=2) + "\n")
        environment["BUYER_PROVIDER_KERNEL_KEY"] = signers["provider"]
        start(
            "buyer-api",
            [
                sys.executable,
                "-m",
                "uvicorn",
                "buyer.app:app",
                "--host",
                "127.0.0.1",
                "--port",
                api.rsplit(":", 1)[1],
            ],
        )
        ready(api + "/healthz")
        start("buyer-gateway", ["bash", "buyer/run-sidecar.sh"])
        ready(buyer + "/chio/health")
        yield {
            "control": control,
            "provider": provider,
            "api": api,
            "buyer": buyer,
            "service_token": token,
            "edge_token": edge_token,
            "approval_token": approval_token,
            "signers": signers,
            "trust_process": trust_process,
            "provider_process": provider_process,
        }
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(children):
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()
        lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", default="buy", choices=["buy", "check", "approve", "fund", "status"]
    )
    parser.add_argument(
        "value", nargs="?", help="job ID for approve; additional allowance in cents for fund"
    )
    parser.add_argument(
        "--target", default="payments-api", help="relative directory inside workspace/"
    )
    parser.add_argument(
        "--scope",
        default="hotfix-review",
        choices=[
            "hotfix-review",
            "release-review",
            "release-plus-cloud-review",
            "full-estate-review",
        ],
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=90_000,
        help="maximum purchase amount in USD cents; cannot raise the operator budget",
    )
    parser.add_argument("--provider", choices=["direct", "openai", "anthropic"], default="direct")
    parser.add_argument("--model", help="model identifier accepted by your configured provider")
    args = parser.parse_args()
    if args.budget < 0:
        parser.error("--budget must be nonnegative")
    if args.provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        parser.error("Set OPENAI_API_KEY for the selected provider")
    if args.provider == "anthropic" and not (
        os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")
    ):
        parser.error("Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN for the selected provider")
    os.environ["COMMERCE_PROVIDER"] = args.provider
    if args.model:
        os.environ["OPENAI_MODEL" if args.provider == "openai" else "ANTHROPIC_MODEL"] = args.model
    os.umask(0o077)
    state = ROOT / ".state"
    if args.action == "check":
        os.environ["BUYER_DEFAULT_BUDGET_MINOR"] = "500000"
        state = state / "qualification" / str(uuid.uuid4())
    if args.action in {"fund", "status"}:
        from buyer.store import ProcurementStore

        state.mkdir(parents=True, mode=0o700, exist_ok=True)
        store = ProcurementStore(
            str(state / "buyer.db"), int(os.getenv("BUYER_DEFAULT_BUDGET_MINOR", "150000"))
        )
        try:
            with store.transaction() as db:
                if args.action == "fund":
                    if (
                        not args.value
                        or not args.value.isdigit()
                        or not 0 < int(args.value) <= 1_000_000_000
                    ):
                        parser.error(
                            "fund requires an additional allowance between 1 and 1000000000 cents"
                        )
                    db.execute(
                        "INSERT INTO allocations(id,amount,reason) VALUES(?,?,?)",
                        (str(uuid.uuid4()), int(args.value), "Explicit local operator allocation"),
                    )
                print(
                    json.dumps(
                        {
                            "allowance_minor": store.capacity(db),
                            "available_minor": store.available(db),
                            "jobs": [
                                {
                                    key: job[key]
                                    for key in ("job_id", "status", "target", "requested_scope")
                                }
                                for row in db.execute("SELECT body FROM jobs")
                                for job in [json.loads(row[0])]
                            ],
                        },
                        indent=2,
                    )
                )
        finally:
            store.db.close()
        return 0
    if args.action == "approve" and not args.value:
        parser.error("approve requires the pending job ID")
    run = state / "runs" / str(uuid.uuid4())
    with services(state, run) as endpoints:
        if args.action == "check":
            from qualify import qualify

            qualify(state, run, endpoints)
            return 0
        if args.action == "approve":
            from commerce_network.chio import TrustControl

            trust = TrustControl(endpoints["control"], endpoints["service_token"])
            grant = trust.issue_capability(
                subject_pk=endpoints["signers"]["caller"],
                ttl=300,
                scope={
                    "grants": [
                        {
                            "server_id": "chio_http_authority",
                            "tool_name": "authorize_http_request",
                            "operations": ["invoke"],
                            "constraints": [],
                        }
                    ],
                    "resource_grants": [],
                    "prompt_grants": [],
                },
            )
            path = "/procurement/jobs/" + args.value + "/approve"
            body = {
                "approver": "local-operator",
                "reason": "Explicit approval using the operator launcher",
            }
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    endpoints["buyer"] + path,
                    json=body,
                    headers={
                        "X-Chio-Capability": json.dumps(grant, separators=(",", ":")),
                        "X-Buyer-Approval": endpoints["approval_token"],
                    },
                )
            job = response.json()
            if response.status_code != 200:
                raise ValueError(f"Approval refused: HTTP {response.status_code}: {job}")
            job["_chio_http"] = {
                "receipt_id": response.headers.get("X-Chio-Receipt-Id"),
                "method": "POST",
                "path": path,
                "body": body,
                "body_sha256": hashlib.sha256(response.request.content).hexdigest(),
                "capability_id": grant["id"],
                "status": response.status_code,
            }
            agent = {
                "mode": "operator-approval",
                "final_status": job["status"],
                "job_id": job["job_id"],
                "tool_calls": [{"tool": "approve_job", "output": job}],
            }
            (run / "agent-output.json").write_text(json.dumps(agent, indent=2) + "\n")
            (run / "summary.json").write_text(
                json.dumps({"final_status": job["status"]}, indent=2) + "\n"
            )
            contracts = run / "contracts"
            contracts.mkdir()
            for name, key in [
                ("quote-response", "quote"),
                ("fulfillment-package", "fulfillment"),
                ("settlement-reconciliation", "settlement"),
            ]:
                (contracts / (name + ".json")).write_text(json.dumps(job[key], indent=2) + "\n")
            from commerce_network.verify import verify_bundle
            from export_evidence import export

            export(run, state)
            verification = verify_bundle(run, trusted_signers=list(endpoints["signers"].values()))
            (run / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
            if not verification["ok"]:
                raise ValueError(
                    "Approval verification failed: " + "; ".join(verification["errors"])
                )
            print(
                f"Job {job['job_id']}: {job['status']}\nVerified approval, delivered work and settlement.\nEvidence: {run.relative_to(ROOT)}"
            )
            return 0
        from orchestrate import main as procure

        result = procure(
            [
                "--control-url",
                endpoints["control"],
                "--service-token",
                endpoints["service_token"],
                "--buyer-url",
                endpoints["buyer"],
                "--buyer-auth-token",
                endpoints["edge_token"],
                "--scope",
                args.scope,
                "--target",
                args.target,
                "--budget-minor",
                str(args.budget),
                "--artifact-dir",
                str(run),
            ]
        )
        from export_evidence import export

        export(run, state)
        summary = json.loads((run / "summary.json").read_text())
        if summary["final_status"] == "fulfilled":
            from commerce_network.verify import verify_bundle

            verification = verify_bundle(run, trusted_signers=list(endpoints["signers"].values()))
            (run / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
            if not verification["ok"]:
                raise ValueError("Run verification failed: " + "; ".join(verification["errors"]))
            print(
                f"Verified {verification['verified_receipts']} signed receipts, {verification['artifacts']} delivered artifacts, and balanced book entries."
            )
        print(
            f"Status: {summary['final_status']}\nEvidence: {run.relative_to(ROOT)}\nApplication data and budget are retained in .state/."
        )
        return result


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
