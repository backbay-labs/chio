#!/usr/bin/env python3
"""Qualify real SQLite write contention only on newly created disposable owners.

This does not mutate rows, schema, clocks, or kernel code. The fault process holds
BEGIN IMMEDIATE until the explicit unlock file appears or its bounded timer ends.
Each named owner is single-use and retains its databases and resource volumes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time


def write(path, value, private=False):
    with path.open("x") as stream:
        if private:
            os.chmod(path, 0o600)
        json.dump(value, stream, indent=2, default=lambda item: {"sqliteBlobHex": item.hex()}
                  if isinstance(item, bytes) else str(item))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run(command, timeout=40):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Commands never carry credentials; private child diagnostics stay private.
        raise RuntimeError(f"subprocess failed with status {result.returncode}: {command[0]}")
    return result.stdout


def paths(args):
    if not re.fullmatch(r"[a-z0-9-]{1,60}", args.name):
        raise ValueError("name must be a short lowercase isolated case name")
    state = args.owner_root.resolve() / args.name
    output = args.output_root.resolve() / args.name
    return state, output


def configuration(state):
    return json.loads((state / "operator.json").read_text())


def observe(state):
    operator = configuration(state)
    command = ["docker", "run", "--rm", "--network", "none", "--read-only",
               "--mount", f"type=volume,src={operator['volume']},dst=/workspace,readonly",
               "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly",
               "--entrypoint", "node", operator["image"], "-e",
               "const f=require('fs');let files={};for(const n of f.readdirSync('/workspace')){"
               "const p='/workspace/'+n;if(f.statSync(p).isFile())files[n]=f.readFileSync(p,'utf8')}"
               "const p='/audit/dispatch.jsonl';console.log(JSON.stringify({files,dispatch:"
               "f.existsSync(p)?f.readFileSync(p,'utf8').trim().split('\\n').filter(Boolean).map(JSON.parse):[]}));"]
    return {"observedAtEpoch": time.time(), **json.loads(run(command))}


def create(args):
    state, output = paths(args)
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    launcher = args.owner_launcher.resolve(strict=True)
    command = [sys.executable, str(launcher), "start", "--state-dir", str(state),
               "--kernel", str(args.kernel.resolve(strict=True)), "--kernel-sha256", args.kernel_sha256,
               "--image", args.image, "--volume", f"chio-required-kernel-store-{args.name}",
               "--port", str(args.port), "--policy", str(args.policy.resolve(strict=True))]
    write(output / "start-command.json", command)
    (output / "start.log").write_text(run(command))
    # This owner has never admitted a session. Stop only its verified PID before
    # inserting the explicitly recorded test-only reply barrier.
    run([sys.executable, str(launcher), "stop", "--state-dir", str(state)])
    operator = configuration(state)
    split = operator["command"].index("--") + 1
    barrier = Path(__file__).resolve().with_name("stdio_response_barrier.py")
    operator["command"][split:split] = [sys.executable, str(barrier), "--directory", str(output), "--"]
    temporary = state / "operator-with-barrier.json"
    write(temporary, operator, True)
    temporary.replace(state / "operator.json")
    (output / "restart.log").write_text(run([sys.executable, str(launcher), "restart", "--state-dir", str(state)]))
    prepare = {"endpoint": f"http://127.0.0.1:{args.port}",
               "bearerToken": operator["agentToken"], "adminToken": operator["adminToken"],
               "credentialTtlSeconds": 3600,
               "trustedSigners": [(state / "sessions.sqlite.admission.kernel.pub").read_text().strip()],
               "serverId": "fs", "sessionId": "storage-fault-" + args.name,
               "journalDir": str(state / "gateway-journal"),
               "allowedTools": ["read_text_file", "write_file", "edit_file", "list_directory"]}
    write(state / "prepare.json", prepare, True)
    bridge = args.bridge.resolve(strict=True)
    (output / "prepare.log").write_text(run(["node", str(bridge / "dist/prepare-gateway.js"),
                                             str(state / "prepare.json"), str(state / "gateway.json")]))
    config = json.loads((state / "gateway.json").read_text())
    manifest = {"owner": str(state), "gatewayConfig": str(state / "gateway.json"),
                "output": str(output), "endpoint": prepare["endpoint"],
                "kernelSha256": operator["kernelSha256"], "image": operator["image"],
                "volume": operator["volume"], "auditVolume": operator["auditVolume"],
                "policySha256": operator["policySha256"], "ownerLauncher": str(launcher),
                "ownerLauncherSha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                "barrierSha256": hashlib.sha256(barrier.read_bytes()).hexdigest(),
                "helperSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "prepareGatewaySha256": hashlib.sha256((bridge / "dist/prepare-gateway.js").read_bytes()).hexdigest(),
                "sessionCredential": config["sessionCredential"], "createdAtEpoch": time.time(),
                "testOnlyTransportCutpoint": "/workspace/uncertain.txt reply held after resource returns"}
    write(output / "manifest.json", manifest)
    write(output / "initial-observer.json", observe(state))
    print(json.dumps(manifest))


def fault(args):
    state, output = paths(args)
    manifest = json.loads((output / "manifest.json").read_text())
    if str(state) != manifest["owner"]:
        raise ValueError("case owner mismatch")
    before = args.cutpoint == "before-admission"
    if not before:
        deadline = time.monotonic() + args.wait_seconds
        while not (output / "resource-replied.json").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("no actual resource reply reached the selected cutpoint")
            time.sleep(0.02)
        observed = observe(state)
        if "uncertain.txt" not in observed["files"] or not any(
                item["path"] == "/workspace/uncertain.txt" and item["tool"] == "write_file"
                for item in observed["dispatch"]):
            raise AssertionError("actual effect and backend dispatch must precede the injected fault")
        write(output / "effect-before-fault.json", observed)
    database = state / ("receipts.sqlite" if args.cutpoint == "after-receipt" else "sessions.sqlite.admission")
    connection = sqlite3.connect(f"file:{database}?mode=rw", uri=True, timeout=10)
    try:
        connection.execute("BEGIN IMMEDIATE")
        write(output / "fault-locked.json", {"database": str(database), "cutpoint": args.cutpoint,
              "lockedAtEpoch": time.time(), "mutation": "none; BEGIN IMMEDIATE held, then ROLLBACK",
              "holdSeconds": args.hold_seconds, "pid": os.getpid()})
        if not before:
            (output / "release").write_text("resource reply released after independent effect observation and SQLite write lock\n")
        deadline = time.monotonic() + args.hold_seconds
        while not (output / "unlock").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        connection.rollback()
        connection.close()
        write(output / "fault-released.json", {"releasedAtEpoch": time.time(), "rowsOrSchemaMutated": False})
    print(json.dumps({"released": str(database)}))


def snapshot(args):
    state, output = paths(args)
    result = {"observation": observe(state), "databases": {}}
    for filename in ["sessions.sqlite", "sessions.sqlite.admission", "receipts.sqlite"]:
        connection = sqlite3.connect(f"file:{state / filename}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        selected = ["remote_session_credential_calls", "remote_session_credential_latches",
                    "admission_operations", "admission_operation_terminal_projections", "tool_outcomes"]
        result["databases"][filename] = {}
        for table in selected:
            if table in tables:
                result["databases"][filename][table] = [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]
        connection.close()
    write(output / args.filename, result)
    print(json.dumps({"snapshot": str(output / args.filename), "dispatchCount": len(result["observation"]["dispatch"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-root", type=Path, default=Path.home() / ".local/share/chio-required-operators/kernel-storage-fault-20260909")
    parser.add_argument("--output-root", type=Path, default=Path("/tmp/chio-kernel-storage-fault-20260909"))
    commands = parser.add_subparsers(dest="action", required=True)
    new = commands.add_parser("create")
    for flag in ["kernel", "policy", "owner-launcher", "bridge"]:
        new.add_argument("--" + flag, type=Path, required=True)
    for flag in ["kernel-sha256", "image"]:
        new.add_argument("--" + flag, required=True)
    new.add_argument("--port", type=int, required=True)
    inject = commands.add_parser("fault")
    inject.add_argument("--cutpoint", choices=["before-admission", "after-admission", "after-receipt"], required=True)
    inject.add_argument("--wait-seconds", type=int, default=180)
    inject.add_argument("--hold-seconds", type=int, default=60)
    take = commands.add_parser("snapshot")
    take.add_argument("--filename", default="snapshot.json")
    commands.add_parser("unlock")
    for child in [new, inject, take, commands.choices["unlock"]]:
        child.add_argument("--name", required=True)
    args = parser.parse_args()
    if args.action == "create":
        create(args)
    elif args.action == "fault":
        fault(args)
    elif args.action == "snapshot":
        if Path(args.filename).name != args.filename:
            raise ValueError("snapshot filename must be a basename")
        snapshot(args)
    else:
        _, output = paths(args)
        (output / "unlock").write_text("operator requested end of bounded SQLite contention\n")


if __name__ == "__main__":
    main()
