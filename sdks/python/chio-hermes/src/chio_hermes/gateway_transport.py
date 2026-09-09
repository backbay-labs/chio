"""Private launcher transport. Guest processes receive no kernel or journal authority."""
from __future__ import annotations

import hashlib
import json
import re
import select
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any


class GatewayTransport:
    def __init__(self, node: Path, module: Path, config: Path) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._confirmed: set[str] = set()
        self.events: list[dict[str, Any]] = []
        self.outcomes: dict[str, str] = {}
        self.control = Path(tempfile.mkdtemp(prefix="chio-hermes-operator-"))
        self._errors = (self.control / "gateway.stderr").open("wb")
        self.process = subprocess.Popen([str(node), str(Path(__file__).with_name("gateway_runner.mjs")), str(module), str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._errors, text=True, bufsize=1)
        try:
            ready = self._read()
            if ready.get("schema") != "chio.hermes.launcher-transport.v1":
                raise ValueError("gateway does not expose the host delivery transport")
            self.url, self.token = ready["url"], ready["token"]
        except BaseException:
            self.close()
            raise

    def _read(self) -> dict[str, Any]:
        if not select.select([self.process.stdout], [], [], 40)[0]:
            raise ValueError("private gateway transport timed out; preserve original operation")
        line = self.process.stdout.readline(1024 * 1024)
        if not line.endswith("\n"):
            raise ValueError("private gateway closed or exceeded response limit")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("invalid private gateway response")
        return value

    def receive_host_results(self, messages: list[dict[str, Any]]) -> None:
        # Only actual model requests from the sandboxed host reach this method.
        # Receipt validation and exact proof matching remain in the gateway.
        for message in messages:
            if message.get("role") != "tool":
                continue
            content = message.get("content")
            if isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text":
                content = content[0].get("text")
            if isinstance(content, str) and content.startswith('<untrusted_tool_result source="mcp__chio__'):
                wrapped = re.fullmatch(r'<untrusted_tool_result source="mcp__chio__[A-Za-z0-9_.-]+">\n[^\n]+\n\n(.*)\n</untrusted_tool_result>', content, re.DOTALL)
                if not wrapped:
                    continue
                content = wrapped.group(1)
            try:
                outcome = json.loads(content)
            except (TypeError, ValueError):
                continue
            # The pinned Hermes MCP adapter wraps text in {"result": text}.
            if isinstance(outcome, dict) and "state" not in outcome:
                envelope = outcome
                raw = envelope.get("result", envelope.get("error"))
                if isinstance(raw, str):
                    try:
                        outcome = json.loads(raw)
                    except (TypeError, ValueError):
                        if "error" in envelope:
                            self.outcomes[str(message.get("tool_call_id"))] = "unknown"
                        continue
            # Hermes can serialize MCP text blocks in a content envelope.
            if isinstance(outcome, dict) and isinstance(outcome.get("content"), list):
                blocks = outcome["content"]
                if len(blocks) == 1 and blocks[0].get("type") == "text":
                    try:
                        outcome = json.loads(blocks[0]["text"])
                    except (TypeError, ValueError, KeyError):
                        continue
            if not isinstance(outcome, dict):
                continue
            state = outcome.get("state")
            if state in ["completed", "denied", "not_dispatched", "unknown", "awaiting_approval"]:
                self.outcomes[str(outcome.get("requestId", message.get("tool_call_id")))] = state
            if state != "completed" or outcome.get("evidence") != "verified":
                continue
            proof = outcome.get("delivery")
            identity = hashlib.sha256(json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with self._lock:
                if identity in self._confirmed:
                    continue
                self._counter += 1
                self.process.stdin.write(json.dumps({"id": self._counter, "method": "acknowledge", "proof": proof, "outcome": outcome}) + "\n")
                self.process.stdin.flush()
                response = self._read()
                if response.get("id") != self._counter or response.get("result", {}).get("acknowledged") is not True:
                    raise ValueError("host delivery proof unresolved; no new model turn")
                self._confirmed.add(identity)
                self.events.append({"requestId": outcome["requestId"], "acknowledged": True})

    def close(self) -> None:
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self._errors.close()

    def __enter__(self) -> GatewayTransport:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
