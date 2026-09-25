# /// script
# requires-python = ">=3.11,<3.15"
# dependencies = ["agent-client-protocol==0.12.1", "chio-sdk"]
# [tool.uv.sources]
# chio-sdk = { path = "../../sdks/python/chio-py" }
# ///
"""Use the official ACP client to initialize an agent, open a session and run governed tools."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import uuid

from acp import Client, PROTOCOL_VERSION, RequestError, connect_to_agent
from acp.schema import ClientCapabilities, Implementation, TextContentBlock
from chio.invariants import canonicalize_json, sha256_hex_utf8, verify_receipt_with_trusted_signers

ROOT = Path(__file__).resolve().parent


class Reviewer(Client):
    def __init__(self):
        self.updates = []

    async def session_update(self, session_id, update, **kwargs):
        self.updates.append({"session_id": session_id, "update": update.model_dump(by_alias=True, exclude_none=True)})

    async def request_permission(self, **kwargs):
        raise RequestError.method_not_found("No client-side permissions are exposed by this example")


class RecordedStdio:
    """ACP's message transport, with the actual newline frames retained."""
    def __init__(self, process, wire):
        self.process, self.wire = process, wire

    async def send(self, message):
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        await self.process.stdin.drain()
        self.wire.append({"direction": "client", "message": message})

    async def receive(self):
        line = await self.process.stdout.readline()
        if not line:
            return None
        message = json.loads(line)
        self.wire.append({"direction": "server", "message": message})
        return message

    async def close(self):
        self.process.stdin.close()
        await self.process.stdin.wait_closed()


def verify(result, update, text, key, capability, session_id):
    chio = result["_meta"]["chio"]
    receipt = chio["receipt"]
    if not verify_receipt_with_trusted_signers(receipt, [key])["ok"]:
        raise ValueError("Invalid receipt or untrusted kernel")
    if receipt["capability_id"] != capability["id"] or chio["receiptId"] != receipt["id"]:
        raise ValueError("Result belongs to another grant or receipt")
    if update["_meta"]["chio"] != chio:
        raise ValueError("Tool update and terminal result name different evidence")
    request_id = receipt["metadata"]["receipt_context"]["request_id"]
    if update["toolCallId"] != request_id or not request_id.startswith("acp-prompt:" + session_id + ":"):
        raise ValueError("The tool update is not associated with this signed operation")
    arguments = {"text": text}
    if receipt["action"]["parameters"] != arguments or update["rawInput"] != arguments:
        raise ValueError("Receipt binds different text")
    if receipt["action"]["parameter_hash"] != sha256_hex_utf8(canonicalize_json(arguments)):
        raise ValueError("Input hash differs")
    allowed = receipt["decision"]["verdict"] == "allow"
    if (update["status"] == "completed") != allowed:
        raise ValueError("Tool status differs from the signed decision")
    if allowed:
        output = update["rawOutput"]
        chunks = output.get("stream") if isinstance(output, dict) else None
        if chunks is not None:
            hashes = [sha256_hex_utf8(canonicalize_json(chunk)) for chunk in chunks]
            if hashes != receipt["metadata"]["stream"]["chunk_hashes"]:
                raise ValueError("Stream chunk differs from its signed hash")
            digest = sha256_hex_utf8("".join(hashes))
            count = chunks[0]
        else:
            digest, count = sha256_hex_utf8(canonicalize_json(output)), output
        if digest != receipt["content_hash"]:
            raise ValueError("The tool output differs from its signed hash")
        if count != {"words": len(text.split()), "bytes": len(text.encode())}:
            raise ValueError("The tool did not count the supplied document")
    return receipt


async def exercise(binary, directory, text):
    wire = []
    with (directory.parent / (directory.name + ".log")).open("w") as log:
        process = await asyncio.create_subprocess_exec(str(binary), str(directory), cwd=ROOT,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=log, limit=4_194_304)
        try:
            reviewer = Reviewer()
            client = connect_to_agent(reviewer, RecordedStdio(process, wire))
            initialized = await client.initialize(protocol_version=PROTOCOL_VERSION,
                client_capabilities=ClientCapabilities(), client_info=Implementation(name="chio-docs-client", version="1.0.0"))
            if initialized.protocol_version != PROTOCOL_VERSION:
                raise ValueError("Client and agent did not negotiate the same ACP version")
            session = await client.new_session(cwd=str(ROOT), mcp_servers=[])
            # The operator selects its own host's public key before any tool prompt.
            key = (directory / "kernel-public-key.txt").read_text().strip()
            capability = json.loads((directory / "capability.json").read_text())
            records = []
            for number in range(3):
                offset = len(reviewer.updates)
                result = (await client.prompt(session_id=session.session_id,
                    prompt=[TextContentBlock(type="text", text=text)])).model_dump(by_alias=True, exclude_none=True)
                updates = reviewer.updates[offset:]
                calls = [entry["update"] for entry in updates if entry["update"]["sessionUpdate"] == "tool_call"]
                if len(calls) != 1:
                    raise ValueError("Each prompt must return one associated tool update")
                receipt = verify(result, calls[0], text, key, capability, session.session_id)
                if receipt["decision"]["verdict"] != ("allow" if number < 2 else "deny"):
                    raise ValueError("The third prompt must exhaust the two-invocation grant")
                records.append({"result": result, "updates": updates, "verified": True})
                print(calls[0]["status"] + ": " + receipt["id"])
            try:
                await client.prompt(session_id="not-an-owned-session", prompt=[TextContentBlock(type="text", text=text)])
            except RequestError:
                unknown_refused = True
            else:
                raise ValueError("An unknown session was accepted")
            (directory / "acp-capture.json").write_text(json.dumps({
                "client": {"package": "agent-client-protocol", "version": "0.12.1"},
                "protocol_version": initialized.protocol_version, "session_id": session.session_id,
                "trusted_kernel_key": key, "runs": records, "wire": wire,
                "verification": {"ok": True, "unknown_session_refused": unknown_refused, "quota_refused": True}
            }, indent=2) + "\n")
            print("Evidence:", directory.relative_to(ROOT) / "acp-capture.json")
        finally:
            if process.returncode is None:
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=10)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
            if directory.exists():
                (directory / "wire.json").write_text(json.dumps(wire, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="?", default="Chio governs the tools behind an ACP agent")
    args = parser.parse_args()
    if not 0 < len(args.text.encode()) <= 60_000:
        parser.error("text must contain 1 to 60000 UTF-8 bytes")
    subprocess.run(["cargo", "build", "--locked", "--bin", "acp-host"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    os.umask(0o077)
    (ROOT / ".state").mkdir(exist_ok=True)
    directory = ROOT / ".state" / ("acp-" + str(uuid.uuid4()))
    asyncio.run(asyncio.wait_for(exercise(target / "debug/acp-host", directory, args.text), timeout=90))


if __name__ == "__main__":
    main()
