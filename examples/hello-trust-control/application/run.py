# /// script
# requires-python = ">=3.11"
# dependencies = ["pynacl>=1.5,<2", "chio-sdk"]
# [tool.uv.sources]
# chio-sdk = { path = "../../../sdks/python/chio-py" }
# ///
"""Save a note, revoke its actual capability, then verify the refused repeated write."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from chio.invariants import (
    canonicalize_json,
    sha256_hex_utf8,
    verify_http_receipt_with_trusted_signers,
)
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent


def http(base, path, body=None, *, bearer=None, capability=None):
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    if capability:
        headers["X-Chio-Capability"] = json.dumps(capability, separators=(",", ":"))
    request = urllib.request.Request(
        base + path, headers=headers, data=None if body is None else json.dumps(body).encode()
    )
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = json.loads(response.read())
        return response.status, response.headers.get("X-Chio-Receipt-Id"), payload


def seed(path):
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(SigningKey.generate().encode().hex() + "\n")
    return SigningKey(bytes.fromhex(path.read_text().strip()))


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="?", default="Review the release checklist")
    args = parser.parse_args()
    binary = os.environ.get("CHIO_BIN") or shutil.which("chio")
    if not binary:
        parser.error("Install the Chio CLI selected in README.md, or set CHIO_BIN")
    binary = str(Path(binary).resolve())
    state = ROOT / ".state"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    # One operator process owns issuance and revocation. Concurrent starts must
    # not reuse the same state or impersonate a listener from another run.
    import fcntl

    lock = (state / "operator.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("This application is already running; wait for it to finish")
    caller = seed(state / "caller.seed")
    issuer = seed(state / "trust.seed")
    mediator = seed(state / "mediator.seed")
    signer = mediator.verify_key.encode().hex()
    run = state / "runs" / str(uuid.uuid4())
    run.mkdir(parents=True, mode=0o700)
    (run / "trusted-kernel-key.txt").write_text(signer + "\n")
    operator_token = secrets.token_hex(32)
    api, control, proxy = [f"http://127.0.0.1:{port()}" for _ in range(3)]
    children = []
    logs = []

    def start(name, command, environment=None):
        log = (run / (name + ".log")).open("w")
        logs.append(log)
        process = subprocess.Popen(
            command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log
        )
        children.append(process)
        return process

    def stop(process):
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        children.remove(process)

    def ready(base, path):
        for _ in range(150):
            if any(child.poll() is not None for child in children):
                raise RuntimeError(f"A service stopped; inspect {run.relative_to(ROOT)}/*.log")
            try:
                if http(base, path)[0] == 200:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        raise RuntimeError("Service startup timed out; inspect the retained logs")

    try:
        start(
            "notes",
            [sys.executable, "notes.py", "--port", api.rsplit(":", 1)[1], "--data", str(state)],
        )
        trust_command = [
            binary,
            "trust",
            "serve",
            "--listen",
            control.removeprefix("http://"),
            "--service-token",
            operator_token,
            "--authority-seed-file",
            str(state / "trust.seed"),
            "--session-db",
            str(state / "authority.db"),
            "--receipt-db",
            str(state / "trust-receipts.db"),
        ]
        trust_process = start("trust", trust_command)
        ready(api, "/healthz")
        ready(control, "/health")
        mediator_command = [
            binary,
            "--control-url",
            control,
            "--control-token",
            operator_token,
            "api",
            "protect",
            "--upstream",
            api,
            "--spec",
            "openapi.yaml",
            "--listen",
            proxy.removeprefix("http://"),
            "--authority-seed-file",
            str(state / "mediator.seed"),
            "--receipt-store",
            str(state / "receipts.db"),
        ]
        mediator_environment = dict(
            os.environ, CHIO_TRUSTED_ISSUER_KEY=issuer.verify_key.encode().hex()
        )
        mediator_process = start("mediator", mediator_command, mediator_environment)
        ready(proxy, "/chio/health")
        issuance = {
            "subjectPublicKey": caller.verify_key.encode().hex(),
            "ttlSeconds": 300,
            "scope": {
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
        }
        status, _, issued = http(control, "/v1/capabilities/issue", issuance, bearer=operator_token)
        if status != 200:
            raise RuntimeError(f"Capability issuance failed: {status}: {issued}")
        capability = issued["capability"]
        if capability["subject"] != issuance["subjectPublicKey"]:
            raise ValueError("Issued capability has the wrong subject")
        (run / "capability.json").write_text(json.dumps(capability, indent=2))
        (run / "capability.json").chmod(0o600)
        before_payload = http(proxy, "/notes")[2]
        body = {"text": args.text}
        status, allowed_id, saved = http(proxy, "/notes", body, capability=capability)
        if status != 201 or not allowed_id:
            raise ValueError(f"Authorized write failed: {status}: {saved}")
        after = http(proxy, "/notes")[2]["notes"]
        if http(proxy, "/notes")[2]["total"] != before_payload["total"] + 1 or saved not in after:
            raise ValueError("The allowed note was not persisted")
        status, _, revocation = http(
            control, "/v1/revocations", {"capabilityId": capability["id"]}, bearer=operator_token
        )
        if status != 200:
            raise ValueError(f"Revocation failed: {status}: {revocation}")
        status, denied_id, denied = http(proxy, "/notes", body, capability=capability)
        if status != 403 or not denied_id:
            raise ValueError(f"The revoked grant was not refused: {status}: {denied}")
        if http(proxy, "/notes")[2]["notes"] != after:
            raise ValueError("The refused request changed application data")
        associations = [
            ("allowed", allowed_id, "allow", capability["id"]),
            ("revoked", denied_id, "deny", capability["id"]),
        ]
        stop(mediator_process)
        stop(trust_process)
        trust_process = start("trust-restarted", trust_command)
        ready(control, "/health")
        mediator_process = start("mediator-restarted", mediator_command, mediator_environment)
        ready(proxy, "/chio/health")
        restarted_status, restarted_id, _ = http(proxy, "/notes", body, capability=capability)
        if restarted_status != 403 or not restarted_id:
            raise ValueError("Restart lost the revocation")
        associations.append(("after_restart", restarted_id, "deny", capability["id"]))
        live_status, _, live_issued = http(
            control, "/v1/capabilities/issue", issuance, bearer=operator_token
        )
        if live_status != 200:
            raise ValueError("Could not issue the outage-control grant")
        stop(trust_process)
        outage_status, outage_id, _ = http(
            proxy, "/notes", body, capability=live_issued["capability"]
        )
        if outage_status != 503 or not outage_id:
            raise ValueError("Unavailable revocation authority did not fail closed")
        associations.append(
            ("authority_unavailable", outage_id, "deny", live_issued["capability"]["id"])
        )
        if http(api, "/notes")[2]["notes"] != after:
            raise ValueError("Restart or outage caused an unauthorized write")
        connection = sqlite3.connect(
            (state / "receipts.db").resolve().as_uri() + "?mode=ro", uri=True
        )
        verified = []
        try:
            for case, receipt_id, verdict, expected_capability in associations:
                row = connection.execute(
                    "SELECT receipt_json FROM http_receipts WHERE id=?", (receipt_id,)
                ).fetchone()
                if not row:
                    raise ValueError("The operation receipt is missing from its store")
                receipt = json.loads(row[0])
                checks = verify_http_receipt_with_trusted_signers(receipt, [signer])
                if not checks["ok"] or receipt["verdict"]["verdict"] != verdict:
                    raise ValueError("Receipt verification failed")
                if receipt["capability_id"] != expected_capability:
                    raise ValueError("Receipt names a different capability")
                if (
                    receipt["method"] != "POST"
                    or receipt["route_pattern"] != "/notes"
                    or receipt.get("metadata", {}).get("chio_http_status_scope") != "final"
                ):
                    raise ValueError("Receipt does not describe this final HTTP operation")
                binding = {
                    "method": "POST",
                    "route_pattern": "/notes",
                    "path": "/notes",
                    "query": {},
                    "body_hash": hashlib.sha256(json.dumps(body).encode()).hexdigest(),
                }
                if receipt["content_hash"] != sha256_hex_utf8(canonicalize_json(binding)):
                    raise ValueError("Receipt is bound to different request bytes")
                verified.append({"case": case, "receipt": receipt, "verification": checks})
        finally:
            connection.close()
        result = {
            "subject": capability["subject"],
            "capability_id": capability["id"],
            "saved_note": saved,
            "before_count": before_payload["total"],
            "after_count": before_payload["total"] + 1,
            "repeated_request": body,
            "revocation": revocation,
            "restart_refusal_status": restarted_status,
            "outage_refusal_status": outage_status,
            "refusal_status": status,
            "refusal": denied,
            "receipts": verified,
        }
        (run / "verification.json").write_text(json.dumps(result, indent=2))
        print(
            f"Saved note {saved['id']}: {args.text}\nRevoked {capability['id']}\nRepeated write refused: HTTP 403; stored notes unchanged\nRevocation survives restart; unavailable authority refuses a live grant\nFour signed HTTP receipts verified against the operator-selected key\nEvidence: {run.relative_to(ROOT)}/verification.json"
        )
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


if __name__ == "__main__":
    main()
