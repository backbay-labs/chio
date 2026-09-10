#!/usr/bin/env python3
"""Deliver two function calls in one fixture response to the actual pinned Hermes.

Only parent-side provider responses are replaced. This is supplemental native
batch evidence, not live inference acceptance. Kernel/resource execution is real.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

from chio_hermes import restricted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["operator-state", "bridge", "host-python", "host-root", "model-auth-file", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    operator = json.loads((args.operator_state / "operator.json").read_text())
    private = args.operator_state / ("hermes-parallel-" + uuid.uuid4().hex)
    private.mkdir(mode=0o700)
    config, preparation = private / "gateway.json", private / "prepare.json"
    preparation.write_text(json.dumps({"endpoint": f"http://127.0.0.1:{operator['port']}", "bearerToken": operator["agentToken"], "adminToken": operator["adminToken"], "credentialTtlSeconds": 900,
        "trustedSigners": [(args.operator_state / "sessions.sqlite.admission.kernel.pub").read_text().strip()], "serverId": "fs", "sessionId": str(uuid.uuid4()),
        "journalDir": str(private / "journal"), "allowedTools": ["read_text_file", "write_file", "edit_file", "list_directory"]}))
    preparation.chmod(0o600)
    subprocess.run(["node", str(args.bridge / "dist/prepare-gateway.js"), str(preparation), str(config)], capture_output=True, check=True)
    calls = [{"path": "/workspace/hermes-parallel-" + private.name[-12:] + "-" + letter + ".txt", "content": "native batch " + letter} for letter in ["a", "b"]]
    state = Path("/tmp") / ("chio-hermes-parallel-" + uuid.uuid4().hex)
    prompt = private / "query.txt"
    prompt.write_text("Use the designated Chio file tools for the controlled parallel batch. Stop after both outcomes. Never retry uncertain work.")

    def save(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + "\n")

    def observe():
        code = "const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"
        return json.loads(subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", f"type=volume,src={operator['volume']},dst=/observe,readonly", "--mount", f"type=volume,src={operator['auditVolume']},dst=/audit,readonly", "--entrypoint", "node", operator["image"], "-e", code], text=True))

    events = []
    batch_delivered = False

    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Type": "text/event-stream"}

    class FixtureOpener:
        def open(self, request, timeout):
            nonlocal batch_delivered
            assert request.full_url == "https://chatgpt.com/backend-api/codex/responses" and timeout == 60
            body = json.loads(request.data)
            assert body["model"] == "gpt-5.5" and body["parallel_tool_calls"] is False
            names = [tool["name"] for tool in body.get("tools", [])]
            events.append({"phase": "provider-request", "toolNames": names, "parallel_tool_calls": False,
                           "functionOutputs": [item for item in body.get("input", []) if item.get("type") == "function_call_output"]})
            if names and not batch_delivered:
                assert "mcp__chio__write_file" in names and len(names) == 4
                items = [{"type": "function_call", "id": "fc_parallel_" + str(index), "call_id": "call_parallel_" + str(index), "name": "mcp__chio__write_file", "arguments": json.dumps(call), "status": "completed"} for index, call in enumerate(calls)]
                batch_delivered = True
                events.append({"phase": "two-native-calls-one-response", "items": items})
            else:
                items = [{"type": "message", "id": "msg_done", "role": "assistant", "content": [{"type": "output_text", "text": "Fixture complete. Recorded tool outcomes determine success."}]}]
            response_id = "resp_parallel_" + str(len(events))
            response = {"id": response_id, "object": "response", "status": "completed", "output": items, "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            frames = [{"type": "response.created", "response": {"id": response_id, "status": "in_progress", "output": []}}]
            frames.extend({"type": "response.output_item.done", "output_index": index, "item": item} for index, item in enumerate(items))
            frames.append({"type": "response.completed", "response": response})
            save("fixture.json", {"liveInference": False, "upstreamNetworkUsed": False, "events": events})
            return Response("".join("data: " + json.dumps(frame) + "\n\n" for frame in frames).encode())

    before = observe()
    assert all(Path(call["path"]).name not in before["files"] for call in calls)
    save("before.json", before)
    command = ["chio-hermes-restricted", "--host-python", str(args.host_python), "--host-root", str(args.host_root), "--node", shutil.which("node"), "--gateway-script", str(args.bridge / "dist/gateway-http.js"), "--gateway-config", str(config), "--state-dir", str(state), "--query-file", str(prompt), "--model", "gpt-5.5", "--model-auth", "codex-subscription", "--codex-auth-file", str(args.model_auth_file), "--max-turns", "4"]
    save("identity.json", {"claim": "supplemental actual native batch with local provider response fixture; not live inference acceptance", "liveInference": False,
        "installedLauncher": restricted.__file__, "launcherSha256": hashlib.sha256(Path(restricted.__file__).read_bytes()).hexdigest(),
        "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "preparedConfigurationSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "privateConfiguration": str(config), "kernelSha256": operator["kernelSha256"], "image": operator["image"], "calls": calls, "command": command})
    original_opener = urllib.request.build_opener
    urllib.request.build_opener = lambda *_args, **_kwargs: FixtureOpener()
    sys.argv = command
    try:
        code = restricted.main()
    finally:
        urllib.request.build_opener = original_opener
        save("after.json", observe())
        for name in ["launch.json", "terminal.json", "model-relay.json", "host-delivery.json", "host.sb"]:
            if (state / name).is_file():
                shutil.copy2(state / name, args.output / name)
        if (state / "profile/logs/agent.log").is_file():
            shutil.copy2(state / "profile/logs/agent.log", args.output / "agent.log")
    with sqlite3.connect("file:" + str(state / "profile/state.db") + "?mode=ro", uri=True) as db:
        rows = [{"role": row[0], "content": row[1], "tool_calls": json.loads(row[2]) if row[2] else None} for row in db.execute("select role, content, tool_calls from messages order by id")]
    save("native-history.json", rows)
    after = json.loads((args.output / "after.json").read_text())
    native_batch = [row for row in rows if row["role"] == "assistant" and len(row.get("tool_calls") or []) == 2]
    tool_rows = [row for row in rows if row["role"] == "tool"]
    records = [json.loads(path.read_text()) for path in (private / "journal").glob("*.json")]
    save("journal-summary.json", [{"requestId": row["requestId"], "state": row["state"], "acknowledged": row.get("acknowledged"), "hostDeliveryConfirmed": row.get("hostDeliveryConfirmed")} for row in records])
    assert batch_delivered and len(native_batch) == 1 and len(tool_rows) == 2
    assert len(after["dispatch"]) == len(before["dispatch"]) + 1
    present = [Path(call["path"]).name in after["files"] for call in calls]
    assert sum(present) == 1
    for call, exists in zip(calls, present, strict=True):
        if exists:
            assert after["files"][Path(call["path"]).name] == call["content"]
    assert sum(row["state"] == "completed" and row.get("acknowledged") and row.get("hostDeliveryConfirmed") for row in records) == 1
    assert any("not_dispatched" in row["content"] for row in tool_rows) and code == 3
    save("result.json", {"passed": True, "liveInference": False, "nativeToolCallsInOneAssistantMessage": 2, "nativeToolResults": 2,
        "newResourceDispatchRows": 1, "oneTargetAbsent": True, "completedVerifiedAndAcknowledged": 1, "secondNotDispatched": True, "launcherExitCode": code,
        "claim": "real native host processes an injected two-call batch; delivery fence permits only one effect"})
    print("actual native two-call batch: one verified effect, second not dispatched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
