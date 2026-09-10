#!/usr/bin/env python3
"""Exercise scoped operator transport/journal faults through real Hermes inference."""
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
import time
import uuid
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["operator-state", "bridge", "launcher-python", "host-python", "host-root", "model-auth-file", "fault-injector", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=["cancel-before-dispatch", "kernel-network-refused", "journal-before-dispatch", "journal-after-effect"],
                        default=["cancel-before-dispatch", "kernel-network-refused", "journal-before-dispatch", "journal-after-effect"])
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    operator = json.loads((args.operator_state / "operator.json").read_text())
    results = []

    def save(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    def observe():
        code = "const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
        return json.loads(subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", f"type=volume,src={operator['volume']},dst=/observe,readonly", "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly", "--entrypoint", "node", operator["image"], "-e", code], text=True))

    for case in args.cases:
        folder = args.output / case
        folder.mkdir(mode=0o700)
        private = args.operator_state / ("hermes-cutpoint-" + uuid.uuid4().hex)
        private.mkdir(mode=0o700)
        config = private / "gateway.json"
        request = private / "prepare.json"
        save(request, {"endpoint": f"http://127.0.0.1:{operator['port']}", "bearerToken": operator["agentToken"], "adminToken": operator["adminToken"], "credentialTtlSeconds": 900,
            "trustedSigners": [(args.operator_state / "sessions.sqlite.admission.kernel.pub").read_text().strip()], "serverId": "fs", "sessionId": str(uuid.uuid4()),
            "journalDir": str(private / "journal"), "allowedTools": ["read_text_file", "write_file", "edit_file", "list_directory"]})
        request.chmod(0o600)
        subprocess.run(["node", str(args.bridge / "dist/prepare-gateway.js"), str(request), str(config)], capture_output=True, check=True)
        name = "hermes-cutpoint-" + private.name[-12:] + ".txt"
        content = "original Hermes cutpoint effect"
        prompt = f'Call mcp__chio__write_file exactly once to write /workspace/{name} with content "{content}". Stop on any unsuccessful or uncertain result. Never retry.'
        env = os.environ.copy()
        env.update(NODE_OPTIONS="--import=" + str(args.fault_injector.resolve()),
            CHIO_SUBSCRIPTION_FAULT="hold-before-dispatch" if case == "cancel-before-dispatch" else case,
            CHIO_SUBSCRIPTION_FAULT_LOG=str((folder / "fault.jsonl").resolve()),
            CHIO_SUBSCRIPTION_KERNEL_ENDPOINT=f"http://127.0.0.1:{operator['port']}/mcp",
            CHIO_SUBSCRIPTION_JOURNAL=str((private / "journal").resolve()))
        refused = None
        if case == "kernel-network-refused":
            refused = socket.socket()
            refused.bind(("127.0.0.1", 0))
            env["CHIO_SUBSCRIPTION_REFUSED_ENDPOINT"] = f"http://127.0.0.1:{refused.getsockname()[1]}/mcp"
            prompt += ' After a successful first result, call the same tool exactly once to replace the same file with "must not dispatch through refused route". Stop immediately on an unsuccessful result.'
            with socket.create_connection(("127.0.0.1", operator["port"]), timeout=3):
                pass
            save(folder / "kernel-live-before.json", {"pid": int((args.operator_state / "kernel.pid").read_text()), "connectionSucceeded": True})

        def run(label, query_text, environment, *, folder=folder, private=private, config=config, case=case):
            state = Path("/tmp") / ("chio-hermes-cutpoint-" + uuid.uuid4().hex)
            query = private / (label + ".txt")
            query.write_text(query_text)
            command = [str(args.launcher_python), "-m", "chio_hermes.restricted", "--host-python", str(args.host_python), "--host-root", str(args.host_root), "--node", shutil.which("node"), "--gateway-script", str(args.bridge / "dist/gateway-http.js"), "--gateway-config", str(config), "--state-dir", str(state), "--query-file", str(query), "--model", "gpt-5.5", "--model-auth", "codex-subscription", "--codex-auth-file", str(args.model_auth_file), "--max-turns", "5"]
            target = folder / label
            target.mkdir(mode=0o700)
            save(target / "command.json", command)
            started = time.monotonic()
            with (target / "host.stdout.txt").open("w") as stdout, (target / "host.stderr.txt").open("w") as stderr:
                child = subprocess.Popen(command, env=environment, stdout=stdout, stderr=stderr)
                if label == "initial" and case == "cancel-before-dispatch":
                    deadline = time.monotonic() + 130
                    while not (folder / "fault.jsonl").exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.1)
                    if not (folder / "fault.jsonl").exists():
                        child.terminate()
                        child.wait(timeout=55)
                        raise RuntimeError("native before-dispatch barrier not reached")
                    save(folder / "at-cancellation.json", observe())
                    child.send_signal(signal.SIGTERM)
                    save(folder / "cancellation.json", {"launcherPid": child.pid, "signal": "SIGTERM", "afterRecordedBeforeDispatchBarrier": True})
                code = child.wait(timeout=220)
            for filename in ["launch.json", "terminal.json", "model-relay.json", "host-delivery.json", "host.sb"]:
                if (state / filename).is_file():
                    shutil.copy2(state / filename, target / filename)
            database = state / "profile/state.db"
            if database.exists():
                with sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True) as db:
                    rows = [{"role": row[0], "content": row[1], "tool_calls": json.loads(row[2]) if row[2] else None} for row in db.execute("select role, content, tool_calls from messages order by id")]
                save(target / "native-history.json", rows)
            save(target / "process-result.json", {"exitCode": code, "elapsedSecondsIncludingProviderAndStartup": time.monotonic() - started})
            return code, json.loads((target / "terminal.json").read_text()) if (target / "terminal.json").exists() else None

        before = observe()
        save(folder / "before.json", before)
        code, terminal = run("initial", prompt, env)
        after = observe()
        save(folder / "after.json", after)
        journal = [json.loads(p.read_text()) for p in (private / "journal").glob("*.json")]
        save(folder / "journal-summary.json", [{"requestId": r["requestId"], "state": r["state"], "acknowledged": r.get("acknowledged"), "hostDeliveryConfirmed": r.get("hostDeliveryConfirmed")} for r in journal])
        expected = 0 if case in ["cancel-before-dispatch", "journal-before-dispatch"] else 1
        assert code != 0 and (folder / "fault.jsonl").exists()
        assert len(after["dispatch"]) - len(before["dispatch"]) == expected
        assert after["files"].get(name) == content if expected else name not in after["files"]
        assert terminal and terminal["confirmedDeliveries"] == (1 if case == "kernel-network-refused" else 0)
        if case == "kernel-network-refused":
            with socket.create_connection(("127.0.0.1", operator["port"]), timeout=3):
                pass
            live = {"pid": int((args.operator_state / "kernel.pid").read_text()), "connectionSucceeded": True}
            save(folder / "kernel-live-after.json", live)
            assert live == json.loads((folder / "kernel-live-before.json").read_text())
            refused.close()
        retry_env = os.environ.copy()
        retry_env.pop("NODE_OPTIONS", None)
        if case == "journal-before-dispatch":
            retry_code, retry_terminal = run("restored-before-any-dispatch", f'Call mcp__chio__write_file exactly once for /workspace/{name} with content "{content}". Stop on refusal.', retry_env)
            restored = observe()
            save(folder / "after-restored.json", restored)
            assert retry_code == 0 and retry_terminal["confirmedDeliveries"] == 1
            assert len(restored["dispatch"]) == len(after["dispatch"]) + 1 and restored["files"][name] == content
        else:
            retry_code, retry_terminal = run("restart-fenced", f'Call mcp__chio__write_file exactly once for /workspace/{name} with content "must not redispatch". Stop on refusal.', retry_env)
            save(folder / "after-restart.json", observe())
            assert retry_code != 0 and observe() == after
        result = {"case": case, "passed": True, "initialExitCode": code, "initialNewDispatchRows": expected, "terminal": terminal, "privateConfiguration": str(config),
                  "configurationSha256": hashlib.sha256(config.read_bytes()).hexdigest(), "faultInjectorSha256": hashlib.sha256(args.fault_injector.read_bytes()).hexdigest(),
                  "scope": "actual pinned Hermes and live subscription inference; operator-only narrow transport or journal fault"}
        results.append(result)
        save(args.output / "results.json", results)
        print(json.dumps({"case": case, "passed": True, "initialNewDispatchRows": expected}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
