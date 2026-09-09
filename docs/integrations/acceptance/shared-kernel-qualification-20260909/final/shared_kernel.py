#!/usr/bin/env python3
"""Qualify a real kernel and isolated Docker resource; never a host acceptance claim."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IMAGE = "chio-required-agent-filesystem:20260909"
PROTOCOL = "2025-11-25"
POLICY = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 0
  durable_admission_mode: all
guards:
  forbidden_path:
    enabled: true
    additional_patterns: ["**/forbidden.txt", "**/secret.txt"]
capabilities:
  default:
    tools:
      - {{server: fs, tool: read_text_file, operations: [invoke], ttl: {ttl}}}
      - {{server: fs, tool: write_file, operations: [invoke], ttl: {ttl}}}
      - {{server: fs, tool: edit_file, operations: [invoke], ttl: {ttl}}}
      - {{server: fs, tool: list_directory, operations: [invoke], ttl: {ttl}}}
"""
APPROVAL_POLICY = """hushspec: "0.1.0"
name: qualification-approval
rules:
  tool_access:
    enabled: true
    default: block
    allow: [read_text_file, write_file]
    require_confirmation: [write_file]
"""
BUDGET_POLICY = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 0
  durable_admission_mode: all
guards:
  tool_access:
    enabled: true
    default_action: block
    allow: [read_text_file, write_file, edit_file, list_directory]
capabilities:
  default:
    tools:
      - server: fs
        tool: '*'
        operations: [invoke]
        ttl: 3600
        max_invocations: 2
"""


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout.strip()


class Runtime:
    def __init__(self, binary, directory, ttl=3600, policy=None, barrier=False):
        self.binary, self.directory = binary, directory
        directory.mkdir(parents=True)
        self.state = directory / "private-state"
        self.state.mkdir(mode=0o700)
        self.policy = directory / "policy.yaml"
        self.policy.write_text(policy or POLICY.format(ttl=ttl))
        self.volume = "chio-qualification-" + secrets.token_hex(6)
        self.agent_token, self.admin_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.log = (directory / "kernel.log").open("a")
        self.evidence = [{"runtime": {"volume": self.volume, "policySha256": hashlib.sha256(self.policy.read_bytes()).hexdigest()}}]
        self.rpc_id = 0
        self.rpc_lock = threading.Lock()
        self.session = None
        self.barrier = barrier
        self.child = None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        run(["docker", "volume", "create", self.volume])
        run(["docker", "run", "--rm", "--network", "none", "--user", "0:0",
             "--mount", f"type=volume,source={self.volume},target=/workspace", "--entrypoint", "sh",
             IMAGE, "-c", "chown 1000:1000 /workspace"])

    def start(self):
        resource = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--mount", f"type=volume,source={self.volume},target=/workspace", IMAGE]
        if self.barrier:
            resource = [sys.executable, str(Path(__file__).with_name("stdio_response_barrier.py")),
                        "--directory", str(self.directory), "--", *resource]
        command = [str(self.binary), "mcp", "serve-http", "--policy", str(self.policy),
                   "--server-id", "fs", "--listen", f"127.0.0.1:{self.port}",
                   "--receipt-db", str(self.state / "receipts.db"),
                   "--session-db", str(self.state / "sessions.db"),
                   "--authority-db", str(self.state / "authority.db"), "--", *resource]
        env = {k: v for k, v in os.environ.items() if not k.startswith("CHIO_")}
        env.update(CHIO_AUTH_TOKEN=self.agent_token, CHIO_ADMIN_TOKEN=self.admin_token)
        self.child = subprocess.Popen(command, env=env, stdout=self.log, stderr=self.log, start_new_session=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                raise RuntimeError("kernel startup failed; see kernel.log")
            try:
                status, _, _ = self.http("/admin/health", token=self.admin_token)
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("kernel startup timed out")

    def stop(self, kill=False):
        if self.child is not None:
            try:
                os.killpg(self.child.pid, signal.SIGKILL if kill else signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.child.wait(timeout=15)
            self.child = None

    def http(self, path, payload=None, token=None, session=None, timeout=20):
        headers = {"Authorization": "Bearer " + (token or self.agent_token),
                   "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": PROTOCOL}
        if session:
            headers["MCP-Session-Id"] = session
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                    data=None if payload is None else json.dumps(payload).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.status
            response_headers = dict(response.headers)
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                data = []
                parsed = None
                for raw in response:
                    line = raw.decode().strip()
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip())
                    elif not line and data:
                        event = json.loads("\n".join(data))
                        data = []
                        if event.get("id") == (payload or {}).get("id"):
                            parsed = event
                            break
            else:
                raw = response.read().decode()
                try:
                    parsed = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    parsed = {"text": raw}
        self.evidence.append({"path": path, "request": payload, "session": session,
                              "status": status, "response": parsed})
        return status, response_headers, parsed

    def rpc(self, method, params=None, session=None):
        with self.rpc_lock:
            self.rpc_id += 1
            request_id = self.rpc_id
        return self.http("/mcp", {"jsonrpc": "2.0", "id": request_id,
                    "method": method, "params": params or {}}, session=session or self.session)

    def initialize(self):
        status, headers, response = self.rpc("initialize", {"protocolVersion": PROTOCOL,
                     "capabilities": {}, "clientInfo": {"name": "shared-kernel-qualification", "version": "1"}})
        assert status == 200, response
        self.session = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
        assert self.session, headers
        self.http("/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, session=self.session)
        return self.rpc("chio/execution-context")[2]["result"]

    def write(self, filename, content, request_id):
        return self.rpc("tools/call", {"name": "write_file", "arguments": {
            "path": "/workspace/" + filename, "content": content}, "_meta": {"chioRequestId": request_id}})[2]

    def observe(self, filename, replace=None):
        script = "const fs=require('fs');const p='/workspace/'+process.argv[1];"
        args = [filename]
        if replace is not None:
            script += "fs.writeFileSync(p,process.argv[2]);"
            args.append(replace)
        script += "console.log(JSON.stringify(fs.existsSync(p)?{exists:true,content:fs.readFileSync(p,'utf8')}:{exists:false}));"
        value = json.loads(run(["docker", "run", "--rm", "--network", "none", "--read-only",
             "--mount", f"type=volume,source={self.volume},target=/workspace" + (",readonly" if replace is None else ""),
             "--entrypoint", "node", IMAGE, "-e", script, *args]))
        self.evidence.append({"observer": filename, "operatorReplacement": replace, "resource": value})
        return value

    def finish(self):
        self.stop()
        (self.directory / "raw.json").write_text(json.dumps(self.evidence, indent=2) + "\n")
        self.log.close()
        # Only this run's randomly named disposable volume is removed.
        containers = run(["docker", "ps", "-aq", "--filter", f"volume={self.volume}"]).splitlines()
        if containers:
            subprocess.run(["docker", "rm", "-f", *containers], capture_output=True)
        for attempt in range(30):
            result = subprocess.run(["docker", "volume", "rm", self.volume], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("owned disposable volume cleanup failed: " + result.stderr.decode())


def outcome(response):
    return response.get("result", {}).get("_meta", {}).get("chioEvidence", {})


def basic_cases(runtime):
    runtime.start()
    context = runtime.initialize()
    first = runtime.write("useful.txt", "useful-work", "first-operation")
    assert outcome(first).get("outputKind") == "value", first
    assert runtime.observe("useful.txt")["content"] == "useful-work"
    runtime.observe("useful.txt", "independent-sentinel")
    retry = runtime.write("useful.txt", "useful-work", "first-operation")
    if outcome(retry).get("receipt"):
        assert outcome(first)["receipt"]["id"] == outcome(retry)["receipt"]["id"], retry
    else:
        assert retry.get("result", {}).get("isError"), retry
        assert "already has authoritative lineage" in json.dumps(retry), retry
        runtime.evidence.append({"limitation": "completed duplicate is rejected without replaying its receipt in the same live session"})
    assert runtime.observe("useful.txt")["content"] == "independent-sentinel"
    conflict = runtime.write("conflict.txt", "must-not-write", "first-operation")
    assert conflict.get("error") or conflict.get("result", {}).get("isError"), conflict
    assert runtime.observe("conflict.txt")["exists"] is False
    denied = runtime.write("forbidden.txt", "must-not-write", "denied-operation")
    assert denied.get("error") or denied.get("result", {}).get("isError"), denied
    assert runtime.observe("forbidden.txt")["exists"] is False
    alternate = runtime.rpc("tools/call", {"name": "move_file", "arguments": {
        "source": "/workspace/useful.txt", "destination": "/workspace/escalated.txt"},
        "_meta": {"chioRequestId": "scope-escalation"}})[2]
    assert alternate.get("error") or alternate.get("result", {}).get("isError"), alternate
    assert runtime.observe("escalated.txt")["exists"] is False
    assert runtime.observe("useful.txt")["content"] == "independent-sentinel"
    assert runtime.http("/admin/authority")[0] == 401
    assert runtime.http("/mcp", {"jsonrpc":"2.0","id":91,"method":"tools/list","params":{}}, token="invalid-principal", session=runtime.session)[0] == 401
    assert runtime.http("/mcp", {"jsonrpc":"2.0","id":92,"method":"tools/list","params":{}}, session="invalid-session")[0] != 200
    # Restart while retaining the same session and authority, then prove replay
    # returns the original receipt without overwriting the observer's sentinel.
    runtime.stop()
    runtime.start()
    resumed_context = runtime.rpc("chio/execution-context")[2]
    assert resumed_context.get("result") == context, resumed_context
    resumed = runtime.write("useful.txt", "useful-work", "first-operation")
    assert outcome(resumed).get("receipt", {}).get("id") == outcome(first)["receipt"]["id"], resumed
    assert runtime.observe("useful.txt")["content"] == "independent-sentinel"
    trust = runtime.http(f"/admin/sessions/{runtime.session}/trust", token=runtime.admin_token)[2]
    capability_id = trust["capabilities"][0]["capabilityId"]
    revoked = runtime.http("/admin/revocations", {"capability_id": capability_id}, token=runtime.admin_token)
    assert revoked[0] == 200, revoked
    blocked = runtime.write("revoked.txt", "must-not-write", "revoked-operation")
    assert blocked.get("error") or blocked.get("result", {}).get("isError"), blocked
    assert runtime.observe("revoked.txt")["exists"] is False
    runtime.stop()
    runtime.start()
    blocked = runtime.write("revoked-after-restart.txt", "must-not-write", "revoked-restarted-operation")
    assert blocked.get("error") or blocked.get("result", {}).get("isError"), blocked
    assert runtime.observe("revoked-after-restart.txt")["exists"] is False
    runtime.session = None
    runtime.initialize()
    fresh = runtime.write("fresh.txt", "fresh-authority", "fresh-operation")
    assert outcome(fresh).get("outputKind") == "value", fresh
    assert runtime.observe("fresh.txt")["content"] == "fresh-authority"


def expiration_case(runtime):
    runtime.start()
    runtime.initialize()
    first = runtime.write("before-expiry.txt", "valid-authority", "before-expiry")
    assert outcome(first).get("outputKind") == "value", first
    assert runtime.observe("before-expiry.txt")["content"] == "valid-authority"
    time.sleep(5)
    blocked = runtime.write("expired.txt", "must-not-write", "expired-operation")
    assert blocked.get("error") or blocked.get("result", {}).get("isError"), blocked
    assert runtime.observe("expired.txt")["exists"] is False


def unknown_case(runtime):
    runtime.start()
    context = runtime.initialize()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        pending = executor.submit(runtime.write, "uncertain.txt", "effect-before-crash", "uncertain-operation")
        deadline = time.monotonic() + 20
        marker = runtime.directory / "resource-replied.json"
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "resource did not reach response barrier"
        assert runtime.observe("uncertain.txt")["content"] == "effect-before-crash"
        # The actual Docker resource has committed. Its reply is held outside
        # the kernel, so no durable successful outcome has reached the kernel.
        runtime.stop(kill=True)
        try:
            lost = pending.result(timeout=10)
            runtime.evidence.append({"lostResponse": lost})
        except Exception as error:
            runtime.evidence.append({"lostResponseError": type(error).__name__})
    runtime.observe("uncertain.txt", "independent-after-crash")
    (runtime.directory / "release").touch()
    runtime.start()
    restored = runtime.rpc("chio/execution-context")[2]
    assert restored.get("result") == context, restored
    retry = runtime.write("uncertain.txt", "effect-before-crash", "uncertain-operation")
    assert retry.get("error") or retry.get("result", {}).get("isError"), retry
    assert outcome(retry).get("outputKind") != "value", retry
    assert runtime.observe("uncertain.txt")["content"] == "independent-after-crash"


def approval_case(runtime):
    runtime.observe("readable.txt", "legitimate-approved-scope")
    runtime.start()
    runtime.initialize()
    readable = runtime.rpc("tools/call", {"name": "read_text_file", "arguments": {
        "path": "/workspace/readable.txt"}, "_meta": {"chioRequestId": "approval-read"}})[2]
    assert outcome(readable).get("outputKind") == "value", readable
    missing = runtime.write("approval-missing.txt", "must-not-write", "approval-missing")
    assert missing.get("error") or missing.get("result", {}).get("isError"), missing
    assert runtime.observe("approval-missing.txt")["exists"] is False
    forged = runtime.rpc("tools/call", {"name": "write_file", "arguments": {
        "path": "/workspace/approval-forged.txt", "content": "must-not-write"}, "_meta": {
            "chioRequestId": "approval-forged", "chioApprovalToken": {"approved": True}}})[2]
    assert forged.get("error") or forged.get("result", {}).get("isError"), forged
    assert runtime.observe("approval-forged.txt")["exists"] is False
    runtime.evidence.append({"unresolved": "No real pending/rejected/approved operator workflow is exercised. This case proves only missing and malformed approval artifacts cannot authorize writes."})


def cancellation_case(runtime):
    runtime.start()
    runtime.initialize()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        request_id = runtime.rpc_id + 1
        pending = executor.submit(runtime.write, "uncertain.txt", "effect-before-cancel", "cancelled-operation")
        marker = runtime.directory / "resource-replied.json"
        deadline = time.monotonic() + 20
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "resource did not reach cancellation cutpoint"
        assert runtime.observe("uncertain.txt")["content"] == "effect-before-cancel"
        cancel = runtime.http("/mcp", {"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": request_id, "reason": "qualification cancellation"}}, session=runtime.session)
        assert cancel[0] in [200, 202, 204], cancel
        try:
            cancelled = pending.result(timeout=10)
        except concurrent.futures.TimeoutError:
            runtime.stop(kill=True)
            raise AssertionError("kernel did not finish cancellation while upstream result remained held")
        finally:
            (runtime.directory / "release").touch()
        assert cancelled.get("error") or cancelled.get("result", {}).get("isError"), cancelled
        assert outcome(cancelled).get("outputKind") != "value", cancelled
    runtime.observe("uncertain.txt", "independent-after-cancel")
    runtime.stop()
    runtime.start()
    retry = runtime.write("uncertain.txt", "effect-before-cancel", "cancelled-operation")
    assert retry.get("error") or retry.get("result", {}).get("isError"), retry
    assert outcome(retry).get("outputKind") != "value", retry
    assert runtime.observe("uncertain.txt")["content"] == "independent-after-cancel"


def budget_case(runtime):
    runtime.start()
    original_context = runtime.initialize()
    first = runtime.write("budget-first.txt", "first-call", "budget-first")
    assert outcome(first).get("outputKind") == "value", first
    assert runtime.observe("budget-first.txt")["content"] == "first-call"
    second = runtime.rpc("tools/call", {"name": "read_text_file", "arguments": {
        "path": "/workspace/budget-first.txt"}, "_meta": {"chioRequestId": "budget-second"}})[2]
    assert outcome(second).get("outputKind") == "value", second
    third = runtime.write("budget-third.txt", "must-not-write", "budget-third")
    assert third.get("error") or third.get("result", {}).get("isError"), third
    assert runtime.observe("budget-third.txt")["exists"] is False
    usage = runtime.http("/admin/budgets", token=runtime.admin_token)
    assert usage[0] == 200, usage
    runtime.stop()
    runtime.start()
    after_restart = runtime.write("budget-after-restart.txt", "must-not-write", "budget-after-restart")
    assert after_restart.get("error") or after_restart.get("result", {}).get("isError"), after_restart
    assert runtime.observe("budget-after-restart.txt")["exists"] is False
    # Explicitly test the external authority boundary. A new session currently
    # issues a different capability and resets its grant quota. The agent must
    # not hold the credential that admits arbitrary fresh sessions.
    runtime.session = None
    new_context = runtime.initialize()
    fresh = runtime.write("budget-new-session.txt", "fresh-session-reset", "budget-new-session")
    assert outcome(fresh).get("outputKind") == "value", fresh
    assert runtime.observe("budget-new-session.txt")["content"] == "fresh-session-reset"
    runtime.evidence.append({"boundaryLimitation": "Fresh session issuance resets grant quota; session admission credential must remain with trusted operator or pinned gateway.",
        "originalContext": original_context, "newContext": new_context})


def parallel_budget_case(runtime):
    runtime.start()
    runtime.initialize()
    # A single wildcard grant shares one durable quota across these calls.
    # Unique operation identities distinguish concurrency from duplicate retry.
    def write(index):
        return runtime.rpc("tools/call", {"name": "write_file", "arguments": {
            "path": f"/workspace/parallel-{index}.txt", "content": str(index)},
            "_meta": {"chioRequestId": f"parallel-{index}"}})[2]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(write, range(4)))
    observed = [runtime.observe(f"parallel-{index}.txt") for index in range(4)]
    assert sum(item["exists"] for item in observed) == 2, observed
    assert all(not item["exists"] or item["content"] == str(index)
               for index, item in enumerate(observed)), observed
    assert sum(outcome(response).get("outputKind") == "value" for response in responses) == 2, responses
    runtime.stop()
    runtime.start()
    denied = runtime.write("parallel-after-restart.txt", "must-not-write", "parallel-restarted")
    assert denied.get("error") or denied.get("result", {}).get("isError"), denied
    assert runtime.observe("parallel-after-restart.txt")["exists"] is False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", help="Comma-separated case names; omitted runs all cases")
    parser.add_argument("--source-revision", help="Operator-pinned source revision of the tested binary")
    args = parser.parse_args()
    cases = [("authority-replay", basic_cases, {}),
             ("capability-expiration", expiration_case, {"ttl": 4}),
             ("unknown-after-dispatch", unknown_case, {"barrier": True}),
             ("cancellation-after-dispatch", cancellation_case, {"barrier": True}),
             ("approval-artifact-rejection", approval_case, {"policy": APPROVAL_POLICY}),
             ("grant-budget", budget_case, {"policy": BUDGET_POLICY}),
             ("parallel-grant-budget", parallel_budget_case, {"policy": BUDGET_POLICY})]
    selected = set(args.cases.split(",")) if args.cases else {case[0] for case in cases}
    unknown = selected - {case[0] for case in cases}
    if unknown:
        parser.error("unknown qualification cases: " + ", ".join(sorted(unknown)))
    args.output.mkdir(parents=True, exist_ok=False)
    # Retain the exact tested driver source beside its hashes, so later
    # qualification-runner improvements cannot obscure historical evidence.
    for source in [Path(__file__), Path(__file__).with_name("stdio_response_barrier.py")]:
        (args.output / source.name).write_bytes(source.read_bytes())
    manifest = {"startedAt": datetime.now(timezone.utc).isoformat(),
                "sourceRevision": args.source_revision,
                "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "barrierSha256": hashlib.sha256(Path(__file__).with_name("stdio_response_barrier.py").read_bytes()).hexdigest(),
                "binary": str(args.binary), "binarySha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                "kernelVersion": run([str(args.binary), "--version"]),
                "image": run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE]),
                "os": run(["sw_vers"]), "docker": run(["docker", "version", "--format", "{{.Client.Version}}"]),
                "claim": "shared kernel qualification only, no host acceptance", "cases": []}
    for name, function, options in cases:
        if name not in selected:
            continue
        runtime = None
        result = {"case": name, "status": "failed"}
        try:
            runtime = Runtime(args.binary, args.output / name, **options)
            function(runtime)
            result["status"] = "passed"
        except Exception as error:
            result["error"] = f"{type(error).__name__}: {error}"
        finally:
            if runtime:
                try:
                    runtime.finish()
                except Exception as error:
                    result["cleanupError"] = str(error)
        manifest["cases"].append(result)
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    manifest["binaryChangedDuringRun"] = hashlib.sha256(args.binary.read_bytes()).hexdigest() != manifest["binarySha256"]
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return int(manifest["binaryChangedDuringRun"] or any(
        result["status"] != "passed" or "cleanupError" in result for result in manifest["cases"]))


if __name__ == "__main__":
    sys.exit(main())
