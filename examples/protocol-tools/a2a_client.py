# /// script
# requires-python = ">=3.11"
# dependencies = ["a2a-sdk==1.1.2", "chio-sdk"]
# [tool.uv.sources]
# chio-sdk = { path = "../../sdks/python/chio-py" }
# ///
"""Call a real Chio HTTP agent with the official A2A Python client."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import httpx
from a2a.client import A2ACardResolver
from a2a.client.transports.jsonrpc import JsonRpcTransport
from a2a.types import GetTaskRequest, Message, Part, Role, SendMessageRequest
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.struct_pb2 import Value as ProtobufValue
from chio.invariants import canonicalize_json, sha256_hex_utf8, verify_receipt_with_trusted_signers

ROOT = Path(__file__).resolve().parent


def projected_parts(value):
    if isinstance(value, str):
        return [{"text": value}]
    if isinstance(value, dict) and isinstance(value.get("content"), list):
        return [{"text": part["text"]} for part in value["content"] if isinstance(part.get("text"), str)]
    if isinstance(value, (dict, list)):
        return [{"data": value}]
    return [{"text": json.dumps(value, separators=(",", ":"))}]


def verify_task(task, text, key):
    receipt = task["metadata"]["chio"]["receipt"]
    if not verify_receipt_with_trusted_signers(receipt, [key])["ok"]:
        raise ValueError("Invalid receipt or untrusted kernel")
    if task["metadata"]["chio"]["receiptId"] != receipt["id"]:
        raise ValueError("Task references another receipt")
    if receipt["action"]["parameters"] != {"text": text}:
        raise ValueError("Receipt binds different tool input")
    if sha256_hex_utf8(canonicalize_json({"text": text})) != receipt["action"]["parameter_hash"]:
        raise ValueError("Input hash differs")
    allowed = receipt["decision"]["verdict"] == "allow"
    if allowed != (task["status"]["state"] == "TASK_STATE_COMPLETED"):
        raise ValueError("Task status differs from the signed decision")
    if allowed:
        output = task["artifacts"][0]["parts"][0]["data"]
        if output != {"words": len(text.split()), "bytes": len(text.encode())}:
            raise ValueError("The agent did not return the actual document count")
        retained = task["metadata"]["chio"]["retainedOutput"]
        if retained["kind"] == "stream":
            hashes = [sha256_hex_utf8(canonicalize_json(chunk)) for chunk in retained["chunks"]]
            if hashes != receipt["metadata"]["stream"]["chunk_hashes"]:
                raise ValueError("A retained stream chunk differs from its signed hash")
            content_hash = sha256_hex_utf8("".join(hashes))
            expected_parts = [part for chunk in retained["chunks"] for part in projected_parts(chunk)]
            if retained["chunks"][0] != output:
                raise ValueError("A2A projected another document count")
        else:
            content_hash = sha256_hex_utf8(canonicalize_json(retained["value"]))
            expected_parts = projected_parts(retained["value"])
            if retained["value"] != output:
                raise ValueError("A2A projected another tool output")
        if task["artifacts"][0]["parts"] != expected_parts:
            raise ValueError("A projected artifact changed after the kernel signed its output")
        if content_hash != receipt["content_hash"]:
            raise ValueError("Tool output differs from its signed hash")
    return receipt


async def exercise(endpoint, token, key, capability, text, directory):
    async with httpx.AsyncClient(timeout=30) as public:
        refused = await public.post(endpoint, json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {}})
        if refused.status_code != 401:
            raise ValueError("Missing application credential was not refused")
    wire = []
    async def capture(response):
        await response.aread()
        if response.request.method == "POST":
            wire.append({"request": json.loads(response.request.content), "response": response.json()})
            (directory / "wire.json").write_text(json.dumps(wire, indent=2) + "\n")
    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=30,
                                 event_hooks={"response": [capture]}) as http:
        card = await A2ACardResolver(http, endpoint).get_agent_card()
        client = JsonRpcTransport(http, card, endpoint)
        records = []
        for number in range(3):
            message_id = str(uuid.uuid4())
            request = SendMessageRequest(message=Message(message_id=message_id, role=Role.ROLE_USER,
                parts=[Part(data=ParseDict({"text": text}, ProtobufValue()))]), metadata={"chio": {"targetSkillId": "count_words"}})
            response = await client.send_message(request)
            task = MessageToDict(response)["task"]
            receipt = verify_task(task, text, key)
            if receipt["decision"]["verdict"] != ("allow" if number < 2 else "deny"):
                raise ValueError("The third call must hit the two-invocation grant")
            expected_request = "a2a-message:" + capability["subject"] + ":" + message_id
            if receipt["capability_id"] != capability["id"]:
                raise ValueError("Receipt belongs to another capability")
            if receipt["metadata"]["receipt_context"]["request_id"] != expected_request:
                raise ValueError("Receipt belongs to another protocol message")
            lookup = MessageToDict(await client.get_task(GetTaskRequest(id=task["id"])))
            if lookup != task:
                raise ValueError("GetTask returned another task or changed its evidence")
            if number == 0:
                retry = MessageToDict(await client.send_message(request))["task"]
                if retry != task:
                    raise ValueError("An identical retry did not retain the original result")
            records.append({"message_id": message_id, "task": task, "verified": True})
            print(task["status"]["state"] + ": " + receipt["id"])
        capture_record = {"client": {"package": "a2a-sdk", "version": "1.1.2", "transport": "JsonRpcTransport"},
            "trusted_kernel_key": key, "agent_card": MessageToDict(card), "runs": records,
            "wire": wire, "verification": {"ok": True, "missing_credential_refused": True,
                "identical_retry_retained": True, "task_lookup_bound": True, "quota_refused": True}}
        (directory / "a2a-capture.json").write_text(json.dumps(capture_record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="?", default="Chio gives agent operations explicit authority and evidence")
    args = parser.parse_args()
    if not 0 < len(args.text.encode()) <= 60_000:
        parser.error("text must contain 1 to 60000 UTF-8 bytes")
    subprocess.run(["cargo", "build", "--locked", "--bin", "a2a-host"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    os.umask(0o077)
    (ROOT / ".state").mkdir(exist_ok=True)
    directory = ROOT / ".state" / ("a2a-" + str(uuid.uuid4()))
    with (ROOT / ".state" / (directory.name + ".log")).open("w") as log:
        process = subprocess.Popen([str(target / "debug/a2a-host"), str(directory)], cwd=ROOT,
                                   stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 30
            while not (directory / "server.json").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("A2A host did not become ready; inspect its .state log")
                time.sleep(.1)
            endpoint = json.loads((directory / "server.json").read_text())["endpoint"]
            token = (directory / "client-token.txt").read_text().strip()
            key = (directory / "kernel-public-key.txt").read_text().strip()
            capability = json.loads((directory / "capability.json").read_text())
            asyncio.run(exercise(endpoint, token, key, capability, args.text, directory))
            print("Evidence:", directory.relative_to(ROOT) / "a2a-capture.json")
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
