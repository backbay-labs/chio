#!/usr/bin/env python3
"""Run a real Hermes session with a bounded, per-client kernel fault.

Use a fresh operator-prepared gateway configuration for each case. This never
stops the shared kernel. It preserves private configs locally and emits only
request method names/counts in the proxy trace, never authentication headers.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def corrupt_output(payload: bytes, content_type: str) -> bytes:
    """Substitute evidence output in JSON or the kernel's SSE result frame."""
    def substitute(raw: str) -> str:
        response = json.loads(raw)
        evidence = response.get("result", {}).get("_meta", {}).get("chioEvidence")
        if not isinstance(evidence, dict):
            raise ValueError("fault injection requires an actual execution evidence envelope")
        evidence["output"] = {"substituted": "untrusted result body"}
        return json.dumps(response)

    if "text/event-stream" not in content_type:
        return substitute(payload.decode()).encode()
    blocks = payload.decode().replace("\r\n", "\n").split("\n\n")
    changed = False
    for index, block in enumerate(blocks):
        lines = block.splitlines()
        data = [line[5:].lstrip() for line in lines if line.startswith("data:")]
        if not data:
            continue
        blocks[index] = "\n".join([line for line in lines if not line.startswith("data:")]
                                  + ["data: " + substitute("\n".join(data))])
        changed = True
    if not changed:
        raise ValueError("fault injection found no SSE result frame")
    return "\n\n".join(blocks).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fault", required=True, choices=[
        "malformed-context", "timeout-context", "corrupt-result",
        "wrong-subject", "wrong-capability", "missing-session", "gateway-crash",
    ])
    for name in ["gateway-config", "gateway-script", "host-python", "host-root", "query-file", "output"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path("/opt/homebrew/bin/node"))
    parser.add_argument("--launcher-python", type=Path, required=True)
    parser.add_argument("--restart", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = json.loads(args.gateway_config.read_text())
    original_endpoint = config["execution"]["endpoint"]
    trace: list[dict] = []

    class FaultProxy(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(raw)
            method = request.get("method")
            entry = {"method": method, "path": self.path, "forwarded": False}
            trace.append(entry)
            if args.fault == "timeout-context" and method == "chio/execution-context":
                time.sleep(1)
                payload = b"{}"
                status = 200
                headers = {"Content-Type": "application/json"}
            elif args.fault == "malformed-context" and method == "chio/execution-context":
                payload = b"not JSON"
                status = 200
                headers = {"Content-Type": "application/json"}
            else:
                entry["forwarded"] = True
                # The SDK takes an origin and appends /mcp. Preserve its actual
                # request path; posting to the bare origin returns HTTP 404.
                outbound = urllib.request.Request(original_endpoint.rstrip("/") + self.path, data=raw, method="POST",
                    headers={**{key: value for key, value in self.headers.items()
                                if key.lower() not in {"host", "content-length", "connection", "accept-encoding"}},
                             "Accept-Encoding": "identity"})
                try:
                    upstream = urllib.request.urlopen(outbound, timeout=15)
                except urllib.error.HTTPError as exc:
                    upstream = exc
                with upstream:
                    payload = upstream.read()
                    status = upstream.status
                    headers = {key: value for key, value in upstream.headers.items()
                               if key.lower() in {"content-type", "mcp-session-id"}}
                    content_type = upstream.headers.get("Content-Type", "")
                if args.fault == "corrupt-result" and method == "tools/call" and status == 200:
                    entry["http_status"] = status
                    entry["response_content_type"] = content_type
                    payload = corrupt_output(payload, content_type)
                    entry["result_corrupted"] = True
            entry["http_status"] = status
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), FaultProxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.fault in {"malformed-context", "timeout-context", "corrupt-result"}:
        config["execution"]["endpoint"] = f"http://127.0.0.1:{server.server_port}"
    if args.fault == "timeout-context":
        config["execution"]["timeoutMs"] = 100
    if args.fault == "wrong-subject":
        config["execution"]["subjectKey"] = "ab" * 32
    if args.fault == "wrong-capability":
        config["execution"]["capabilityId"] = "00000000-0000-0000-0000-000000000000"
    if args.fault == "missing-session":
        config["execution"]["sessionId"] = "00000000-0000-0000-0000-000000000000"
    private_config = args.output.resolve() / "private-gateway.json"
    with open(os.open(private_config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as handle:
        json.dump(config, handle)
    gateway_script = args.gateway_script
    if args.fault == "gateway-crash":
        gateway_script = args.output.resolve() / "crashed-gateway.js"
        gateway_script.write_text("throw new Error('injected gateway startup failure');\n")
    runs = []
    try:
        for run_number in range(2 if args.restart else 1):
            command = [str(args.launcher_python.absolute()), "-m", "chio_hermes.restricted",
                       "--host-python", str(args.host_python.absolute()),
                       "--host-root", str(args.host_root.resolve()), "--node", str(args.node.absolute()),
                       "--gateway-script", str(gateway_script.resolve()),
                       "--gateway-config", str(private_config),
                       "--state-dir", str(args.output.resolve() / f"run-{run_number}"),
                       "--query-file", str(args.query_file.resolve()), "--model", "gpt-4.1",
                       "--model-base-url", "https://api.openai.com/v1", "--max-turns", "6"]
            started = time.monotonic()
            with (args.output / f"stdout-{run_number}.txt").open("w") as stdout, (args.output / f"stderr-{run_number}.txt").open("w") as stderr:
                result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=100)
            runs.append({"run": run_number, "exit": result.returncode,
                         "elapsed_s": round(time.monotonic() - started, 3), "command": command,
                         "forwarded_tool_calls": sum(item["forwarded"] and item["method"] == "tools/call" for item in trace)})
    finally:
        server.shutdown()
        server.server_close()
        (args.output / "proxy-trace.json").write_text(json.dumps(trace, indent=2) + "\n")
        (args.output / "runs.json").write_text(json.dumps(runs, indent=2) + "\n")
    print(json.dumps({"fault": args.fault, "runs": runs}), flush=True)
    return 0 if all(run["exit"] == 0 for run in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
