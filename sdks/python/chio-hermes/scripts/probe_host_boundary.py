#!/usr/bin/env python3
"""Probe a real Hermes CLI with deterministic tool calls and isolated profiles.

The local completion fixture replaces inference only. Hermes itself discovers
plugins, dispatches tools, and performs effects. This diagnoses its enforcement
contract; it is not an I01-I08 acceptance suite or an independent adoption claim.
Pass a tracked-only archive of the pinned host source as --host-root, because
Hermes loads and can sanitize <install>/.env even with an isolated HERMES_HOME.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CASES = {
    "native_control": None,
    "chio_loaded": "chio",
    "hook_raises": "raise RuntimeError('injected policy callback failure')",
    "hook_malformed": "return {'action': 'block'}",
    "plugin_load_failure": "load_failure",
    "restricted_native": None,
}


def sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def run_case(args: argparse.Namespace, name: str, hook: str | None) -> dict:
    root = args.output / name
    root.mkdir(parents=True, exist_ok=False)
    workspace = root / "workspace"
    workspace.mkdir()
    profile = root / "profile"
    profile.mkdir()
    (profile / ".env").write_text("# Isolated diagnostic profile; no credentials.\n")
    marker = workspace / "forbidden.txt"
    content = "Chio Hermes independent effect observer\n"
    tool_args = {"path": str(marker), "content": content}
    if args.probe_tool == "terminal":
        tool_args = {"command": f"/bin/sh -c {shlex.quote('printf forbidden > ' + shlex.quote(str(marker)))}"}
    if args.tool_args_json:
        tool_args = json.loads(args.tool_args_json.replace("{marker}", str(marker)))
    requests: list[dict] = []

    class CompletionFixture(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            tool_results = [
                msg for msg in request.get("messages", []) if msg.get("role") == "tool"
            ]
            requests.append({
                "path": self.path,
                "tools": [t.get("function", {}).get("name") for t in request.get("tools", [])],
                "tool_results": tool_results,
                "stream": request.get("stream", False),
            })
            message = {"role": "assistant", "content": "Probe finished."}
            finish_reason = "stop"
            if not tool_results:
                message = {
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": "call_boundary_probe", "type": "function",
                        "function": {
                            "name": args.probe_tool,
                            "arguments": json.dumps(tool_args),
                        },
                    }],
                }
                finish_reason = "tool_calls"
            completion = {
                "id": "chatcmpl-boundary-probe", "object": "chat.completion",
                "created": int(time.time()), "model": "boundary-probe",
                "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130},
            }
            if request.get("stream"):
                delta = dict(message)
                if "tool_calls" in delta:
                    delta["tool_calls"] = [{"index": 0, **delta["tool_calls"][0]}]
                chunk = {**completion, "object": "chat.completion.chunk"}
                chunk["choices"] = [{"index": 0, "delta": delta, "finish_reason": None}]
                final = {**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}]}
                body = ("data: " + json.dumps(chunk) + "\n\ndata: " + json.dumps(final)
                        + "\n\ndata: [DONE]\n\n").encode()
                mimetype = "text/event-stream"
            else:
                body = json.dumps(completion).encode()
                mimetype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", mimetype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), CompletionFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    enabled = []
    if hook == "chio":
        enabled = ["chio"]
    elif hook:
        enabled = ["boundary-probe"]
        plugin = profile / "plugins" / "boundary-probe"
        plugin.mkdir(parents=True)
        (plugin / "plugin.yaml").write_text(
            "name: boundary-probe\nversion: 0.0.0\ndescription: Boundary fault injection\n"
        )
        code = "raise RuntimeError('injected plugin load failure')\n"
        if hook != "load_failure":
            code = (
                "def register(ctx):\n"
                "    def pre_tool_call(**kwargs):\n"
                f"        {hook}\n"
                "    ctx.register_hook('pre_tool_call', pre_tool_call)\n"
            )
        (plugin / "__init__.py").write_text(code)
    config = {
        "model": {"provider": "custom", "default": "boundary-probe", "api_mode": "chat_completions",
                  "base_url": f"http://127.0.0.1:{server.server_port}/v1"},
        "terminal": {"backend": "local", "cwd": str(workspace)},
        "plugins": {"enabled": enabled},
        "display": {"interface": "cli"},
        "compression": {"enabled": False},
        "agent": {"max_turns": 3},
    }
    if args.gateway_script and args.gateway_config:
        gateway_config = json.loads(args.gateway_config.read_text())
        config["mcp_servers"] = {"chio": {
            "command": str(args.node),
            "args": [str(args.gateway_script.resolve()), str(args.gateway_config.resolve())],
            "tools": {"include": [tool["name"] for tool in gateway_config["tools"]]},
            "timeout": 45, "connect_timeout": 15, "lazy": False,
        }}
        config["tools"] = {"tool_search": {"enabled": "off"}}
    # JSON is a YAML subset and avoids a dependency in the diagnostic runner.
    (profile / "config.yaml").write_text(json.dumps(config, indent=2) + "\n")
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR", "HOME"}}
    env.update({
        "HERMES_HOME": str(profile),
        "HERMES_ENABLE_PROJECT_PLUGINS": "false",
        "HERMES_SKIP_NODE_BOOTSTRAP": "1",
        "PYTHONPATH": str(args.plugin_target),
        "CHIO_WORKSPACE_ROOT": str(workspace),
        "CHIO_SIDECAR_URL": "http://127.0.0.1:1",
        "CHIO_CAPABILITY_ID": "diagnostic-invalid-capability",
        "CUSTOM_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
        "CUSTOM_API_KEY": "local-fixture-no-secret",
        "OPENAI_API_KEY": "local-fixture-no-secret",
        "NO_COLOR": "1",
    })
    command = [str(args.host_python), str(args.host_root / "hermes"), "chat", "--cli",
               "--ignore-rules", "--provider", "custom", "-m", "boundary-probe",
               "-t", args.toolsets, "--max-turns", "3", "--run-budget", "45", "-Q",
               "-q", "Use write_file once for the requested diagnostic file, then stop."]
    if args.restricted_launcher_python:
        query = root / "query.txt"
        query.write_text("Perform the requested boundary diagnostic, then stop.\n")
        command = [str(args.restricted_launcher_python.absolute()), "-m", "chio_hermes.restricted",
                   "--host-python", str(args.host_python), "--host-root", str(args.host_root),
                   "--node", str(args.node), "--gateway-script", str(args.gateway_script.resolve()),
                   "--gateway-config", str(args.gateway_config.resolve()),
                   "--state-dir", str(root / "restricted-run"), "--query-file", str(query),
                   "--model", "boundary-probe", "--model-base-url", f"http://127.0.0.1:{server.server_port}/v1",
                   "--model-key-env", "CUSTOM_API_KEY", "--max-turns", "3"]
        env.pop("PYTHONPATH", None)
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=workspace, env=env, capture_output=True,
                                text=True, timeout=60)
        (root / "stdout.txt").write_text(result.stdout)
        (root / "stderr.txt").write_text(result.stderr)
        returncode = result.returncode
    except subprocess.TimeoutExpired as exc:
        (root / "stdout.txt").write_bytes(exc.stdout or b"")
        (root / "stderr.txt").write_bytes(exc.stderr or b"")
        returncode = "timeout"
    finally:
        server.shutdown()
        server.server_close()
    (root / "requests.json").write_text(json.dumps(requests, indent=2) + "\n")
    observation = {
        "case": name, "probe_tool": args.probe_tool, "toolsets": args.toolsets,
        "host_exit": returncode, "elapsed_s": round(time.monotonic() - started, 3),
        "effect_exists": marker.exists(), "effect_matches": marker.read_text() == content if marker.exists() else False,
        "effect_sha256": sha256(marker), "completion_requests": len(requests),
        "command": command, "config_sha256": sha256(profile / "config.yaml"),
    }
    (root / "observation.json").write_text(json.dumps(observation, indent=2) + "\n")
    print(json.dumps(observation), flush=True)
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-python", type=Path, required=True)
    parser.add_argument("--host-root", type=Path, required=True)
    parser.add_argument("--plugin-target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=list(CASES), default=list(CASES))
    parser.add_argument("--toolsets", default="file")
    parser.add_argument("--probe-tool", default="write_file")
    parser.add_argument("--tool-args-json", help="Exact diagnostic arguments; {marker} is the disposable observer path")
    parser.add_argument("--restricted-launcher-python", type=Path,
                        help="Use the installed restricted launcher rather than the legacy host command")
    parser.add_argument("--gateway-script", type=Path)
    parser.add_argument("--gateway-config", type=Path)
    parser.add_argument("--node", type=Path, default=Path("/opt/homebrew/bin/node"))
    args = parser.parse_args()
    if args.restricted_launcher_python and (
        not args.gateway_script or not args.gateway_config or args.cases != ["restricted_native"]
    ):
        parser.error("restricted launcher requires gateway paths and only restricted_native case")
    # Resolving a venv interpreter symlink would escape its installed packages.
    args.host_python = args.host_python.absolute()
    for name in ("host_root", "plugin_target", "output"):
        setattr(args, name, getattr(args, name).resolve())
    if (args.host_root / ".env").exists():
        parser.error("--host-root must be a tracked-only archive without an install .env")
    args.output.mkdir(parents=True, exist_ok=False)
    results = [run_case(args, name, CASES[name]) for name in args.cases]
    summary = {"host_root": str(args.host_root), "platform": platform.platform(),
               "inference": "local deterministic fixture", "acceptance": "not accepted",
               "results": results}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    # Success means every CLI actually ran, not that a security gate passed.
    return 0 if all(r["host_exit"] == 0 and r["completion_requests"] >= 2 for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
