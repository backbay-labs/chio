#!/usr/bin/env python3
"""Run live Hermes against genuine storage contention on fresh isolated owners."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["helper", "owner-launcher", "kernel", "policy", "prepare-bridge", "host-bridge", "launcher-python", "host-python", "host-root", "model-auth-file", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["owner-root", "helper-output-root"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--name-prefix", required=True)
    parser.add_argument("--base-port", type=int, required=True)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--cases", nargs="+", choices=["after-receipt", "before-admission", "after-admission"], default=["after-receipt", "before-admission", "after-admission"])
    args = parser.parse_args()
    if not 1024 <= args.base_port <= 65533:
        parser.error("base port must leave room for three nonprivileged ports")
    if not args.name_prefix.startswith("final-hermes-") or not all(c.islower() or c.isdigit() or c == "-" for c in args.name_prefix):
        parser.error("choose an explicit isolated final-hermes- name prefix")
    args.output.mkdir(mode=0o700)
    helper_prefix = ["python3", str(args.helper), "--owner-root", str(args.owner_root), "--output-root", str(args.helper_output_root)]
    results = []

    def save(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    def helper(*parameters):
        return subprocess.run([*helper_prefix, *parameters], capture_output=True, text=True, check=True, timeout=90)

    for case in args.cases:
        port = args.base_port + ["after-receipt", "before-admission", "after-admission"].index(case)
        name = args.name_prefix + "-" + case
        output = args.output / case
        output.mkdir(mode=0o700)
        create = ["create", "--name", name, "--port", str(port), "--kernel", str(args.kernel), "--kernel-sha256", args.kernel_sha256,
                  "--image", args.image, "--policy", str(args.policy), "--owner-launcher", str(args.owner_launcher), "--bridge", str(args.prepare_bridge)]
        save(output / "create-command.json", [*helper_prefix, *create])
        created = helper(*create)
        manifest = json.loads(created.stdout)
        save(output / "manifest.json", manifest)
        owner = Path(manifest["owner"])
        helper_output = Path(manifest["output"])
        config = Path(manifest["gatewayConfig"])
        config_digest = hashlib.sha256(config.read_bytes()).hexdigest()
        conf = json.loads(config.read_text())
        operator = json.loads((owner / "operator.json").read_text())

        def observe(operator=operator):
            code = "const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
            return json.loads(subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", f"type=volume,src={operator['volume']},dst=/observe,readonly", "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly", "--entrypoint", "node", operator["image"], "-e", code], text=True))

        def run(label, target, content, *, owner=owner, config=config, output=output, observe=observe):
            folder = output / label
            folder.mkdir(mode=0o700)
            state = Path("/tmp") / ("chio-hermes-storage-" + uuid.uuid4().hex)
            query = owner / (label + ".txt")
            arguments = {"path": target, "content": content}
            query.write_text("Call mcp__chio__write_file exactly once with these exact arguments: " + json.dumps(arguments) + ". Preserve paths and content exactly. Stop immediately after an unsuccessful or uncertain result. Never retry, repair, or switch tools.")
            command = [str(args.launcher_python), "-m", "chio_hermes.restricted", "--host-python", str(args.host_python), "--host-root", str(args.host_root), "--node", shutil.which("node"), "--gateway-script", str(args.host_bridge / "dist/gateway-http.js"), "--gateway-config", str(config), "--state-dir", str(state), "--query-file", str(query), "--model", "gpt-5.5", "--model-auth", "codex-subscription", "--codex-auth-file", str(args.model_auth_file), "--max-turns", "5"]
            save(folder / "command.json", command)
            before = observe()
            save(folder / "before.json", before)
            env = os.environ.copy()
            env.pop("NODE_OPTIONS", None)
            result = subprocess.run(command, capture_output=True, text=True, timeout=220, env=env)
            (folder / "host.stdout.txt").write_text(result.stdout)
            (folder / "host.stderr.txt").write_text(result.stderr)
            after = observe()
            save(folder / "after.json", after)
            for filename in ["launch.json", "terminal.json", "model-relay.json", "host-delivery.json", "host.sb"]:
                if (state / filename).is_file():
                    shutil.copy2(state / filename, folder / filename)
            calls, returned, history = [], [], []
            database = state / "profile/state.db"
            if database.exists():
                with sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True) as db:
                    for role, content_text, raw, identity in db.execute("SELECT role,content,tool_calls,tool_call_id FROM messages ORDER BY id"):
                        parsed = json.loads(raw) if raw else None
                        history.append({"role": role, "content": content_text, "tool_calls": parsed, "tool_call_id": identity})
                        if role == "assistant" and parsed:
                            calls.extend({"id": item["id"], "name": item["function"]["name"], "arguments": json.loads(item["function"]["arguments"])} for item in parsed)
                        if role == "tool":
                            returned.append(identity)
            exact = any(call["name"] == "mcp__chio__write_file" and call["arguments"] == arguments and call["id"] in returned for call in calls)
            save(folder / "native-history.json", history)
            save(folder / "native-dispatch.json", {"calls": calls, "returnedToolCallIds": returned, "expectedAttemptObserved": exact})
            save(folder / "process-result.json", {"exitCode": result.returncode})
            assert exact, "native host must execute and receive the exact expected call"
            return result.returncode, before, after, json.loads((folder / "terminal.json").read_text())

        control_path = "/workspace/hermes-storage-positive.txt"
        code, before, positive, terminal = run("positive", control_path, "fully acknowledged native positive")
        assert code == 0 and terminal["confirmedDeliveries"] == 1
        assert len(positive["dispatch"]) == len(before["dispatch"]) + 1 and positive["files"][Path(control_path).name] == "fully acknowledged native positive"
        helper("snapshot", "--name", name, "--filename", "after-positive.json")
        fault_command = [*helper_prefix, "fault", "--name", name, "--cutpoint", case, "--wait-seconds", "600", "--hold-seconds", "600"]
        save(output / "fault-command.json", fault_command)
        target = "/workspace/before-fault.txt" if case == "before-admission" else "/workspace/uncertain.txt"
        expected_effects = 0 if case == "before-admission" else 1
        with (output / "fault-controller.stdout.txt").open("w") as stdout, (output / "fault-controller.stderr.txt").open("w") as stderr:
            controller = subprocess.Popen(fault_command, stdout=stdout, stderr=stderr)
            try:
                if case == "before-admission":
                    deadline = time.monotonic() + 30
                    while not (helper_output / "fault-locked.json").exists() and controller.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    assert (helper_output / "fault-locked.json").is_file(), "admission lock must precede the native attempt"
                code, pre_fault, fault_observed, terminal = run("fault", target, "original storage fault effect")
                assert code != 0 and terminal["confirmedDeliveries"] == 0 and terminal["outcome"] == "unresolved"
                assert pre_fault == positive and len(fault_observed["dispatch"]) == len(positive["dispatch"]) + expected_effects
                assert fault_observed["files"].get(Path(target).name) == "original storage fault effect" if expected_effects else Path(target).name not in fault_observed["files"]
                assert json.loads((helper_output / "fault-locked.json").read_text())["cutpoint"] == case
                helper("snapshot", "--name", name, "--filename", "native-fault-before-unlock.json")
            finally:
                helper("unlock", "--name", name)
                controller.wait(timeout=30)
                helper("snapshot", "--name", name, "--filename", "native-after-unlock.json")
        assert controller.returncode == 0
        for label, path, body in [("same-action-after-unlock", target, "original storage fault effect"), ("new-action-after-unlock", "/workspace/must-not-redispatch.txt", "must remain absent")]:
            code, pre, post, terminal = run(label, path, body)
            assert code != 0 and terminal["confirmedDeliveries"] == 0 and pre == post == fault_observed
        restart = ["python3", str(args.owner_launcher), "restart", "--state-dir", str(owner)]
        restarted = subprocess.run(restart, capture_output=True, text=True, check=True, timeout=90)
        save(output / "owner-restart.json", {"command": restart, "stdout": restarted.stdout, "stderr": restarted.stderr, "sameOwner": True})
        helper("snapshot", "--name", name, "--filename", "native-after-owner-restart.json")
        for label, path, body in [("same-action-after-restart", target, "original storage fault effect"), ("new-action-after-restart", "/workspace/must-not-redispatch.txt", "must remain absent")]:
            code, pre, post, terminal = run(label, path, body)
            assert code != 0 and terminal["confirmedDeliveries"] == 0 and pre == post == fault_observed
        helper("snapshot", "--name", name, "--filename", "native-final.json")
        assert hashlib.sha256(config.read_bytes()).hexdigest() == config_digest
        records = [json.loads(path.read_text()) for path in Path(conf["journalDir"]).glob("*.json")]
        save(output / "retained-journal.json", records)
        for path in helper_output.iterdir():
            if path.is_file():
                destination = output / "owner-evidence"
                destination.mkdir(exist_ok=True)
                shutil.copy2(path, destination / path.name)
        result = {"case": case, "passed": True, "liveModel": "gpt-5.5", "positiveNativeDispatches": 1, "positiveHostDeliveryAcknowledgments": 1,
                  "faultNewDispatches": expected_effects, "faultHostDeliveryAcknowledgments": 0, "sameAndNewNativeRetriesAfterUnlockAndRestart": 4,
                  "retryNewDispatches": 0, "configurationUnchanged": True, "originalAuthorityPreserved": True, "privateConfiguration": str(config),
                  "configurationSha256": config_digest, "owner": str(owner), "port": port, "claim": "actual SQLite contention, native host outcomes and independent effects; no new-authority recovery"}
        results.append(result)
        save(args.output / "results.json", results)
        print(json.dumps({"case": case, "passed": True, "faultNewDispatches": expected_effects, "retryNewDispatches": 0}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
