"""Launch the pinned Hermes CLI with only the Chio execution gateway.

This candidate mode uses static host tool restrictions, independent of the
legacy Python plugin's hook. Resource isolation and the kernel gateway remain
separate required boundaries; this launcher is not an operating-system sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

HOST_REVISION = "175054c14b54404663d8614a178280cffe6062eb"
# Compatibility checks on the inspected dispatch/configuration contract. The
# operator must still install the complete pinned upstream revision.
HOST_CONTRACT_HASHES = {
    "hermes": "6e1adae1e73ce67121d4ec380a5b66b8fb84f02dd8004b3a9988c39660139417",
    "hermes_cli/main.py": "2fc800dde92f7fccd08b545d29290d0b8425e6ab748e6c7cd2ab35f5461406d8",
    "hermes_cli/plugins.py": "4bdca832fa1369490db5b70cf068633f32e6d5628e2e817c4f8c2d7b3536cb9b",
    "hermes_cli/config.py": "4c918464bd678adc91f5f879835757ffeb65e0d273dcee0cf4baa1c7fc79cb09",
    "hermes_cli/env_loader.py": "26712ba3e020b5c306cd456e8d2cc96084fd2295f7ec4104466fffd0adeab87d",
    "hermes_cli/managed_scope.py": "6b542220964ddaebc176ddbccb833174ab309cde97e0e2ba7a309c7b98ce26f9",
    "agent/conversation_loop.py": "9dbde98ce88e9b393cf220457f4358b4e9023b697873aec59fb688c7d8fe14fa",
    "agent/agent_runtime_helpers.py": "cf860e203b2311fa473d861ae21084d72bbcee5d803e48e3f58dc1c9df4245b9",
    "model_tools.py": "32a106d66835dc9f88f15624076086a53cbd4bb7ed80889228d0e53f62d4cfac",
    "tools/mcp_tool.py": "1ed7ba9edd353ff6c1351efd8d766bf814cb1e6505926c01d50ef029008e04f8",
}


def _private_json(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 1024 * 1024:
        raise ValueError("gateway config must be a private regular file of at most 1 MiB")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("gateway config must be an object")
    return value


def validate_host(root: Path) -> None:
    # Hermes loads and can sanitize install/.env despite HERMES_HOME isolation.
    if (root / ".env").exists():
        raise ValueError("use a dedicated pinned host install without install/.env")
    for name, expected in HOST_CONTRACT_HASHES.items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Hermes contract mismatch: {name}; expected revision {HOST_REVISION}")


def gateway_tool_names(config: dict[str, Any]) -> list[str]:
    execution = config.get("execution")
    if not isinstance(execution, dict) or not execution.get("sessionId"):
        raise ValueError("gateway must retain an operator-prepared kernel session")
    if not config.get("sessionId") or not config.get("journalDir"):
        raise ValueError("gateway must include a persistent operation journal and identity")
    tools = config.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ValueError("gateway must expose a nonempty explicit tool allowlist")
    names = []
    for tool in tools:
        name = tool.get("name") if isinstance(tool, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            raise ValueError("gateway tool names must be exact names, without wildcards")
        if name in names:
            raise ValueError("duplicate gateway tool")
        names.append(name)
    return names


def prepare(args: argparse.Namespace) -> tuple[list[str], dict[str, str], Path]:
    host_root = args.host_root.resolve()
    validate_host(host_root)
    if Path("/etc/hermes").exists() or os.environ.get("HERMES_MANAGED_DIR"):
        raise ValueError("machine-managed Hermes configuration needs separate qualification")
    config_path = args.gateway_config.absolute()
    gateway = _private_json(config_path)
    names = gateway_tool_names(gateway)
    if not args.node.is_file() or not args.gateway_script.is_file():
        raise ValueError("install the pinned Node runtime and Chio gateway artifact first")
    state = args.state_dir.absolute()
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = state / "profile"
    workspace = state / "empty-workspace"
    profile.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    (profile / ".env").write_text("# No stored credentials in the agent profile.\n")
    config = {
        "model": {"provider": "chio-model", "default": args.model, "max_tokens": 4096},
        "providers": {"chio-model": {
            "base_url": args.model_base_url,
            "api_key": "${CHIO_HERMES_MODEL_API_KEY}",
            "api_mode": "chat_completions",
        }},
        "plugins": {"enabled": [], "disabled": ["chio"]},
        "hooks": {},
        "tools": {"tool_search": {"enabled": "off"}},
        "mcp_servers": {"chio": {
            "command": str(args.node.absolute()),
            "args": [str(args.gateway_script.resolve()), str(config_path)],
            "tools": {"include": names},
            "timeout": 45, "connect_timeout": 15,
            "lazy": False, "trust": "full",
        }},
        "terminal": {"backend": "local", "cwd": str(workspace)},
        "display": {"interface": "cli"},
        "compression": {"enabled": False},
        "agent": {"max_turns": args.max_turns},
    }
    (profile / "config.yaml").write_text(json.dumps(config, indent=2) + "\n")
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "LANG", "LC_ALL", "TERM", "USER", "TMPDIR", "HOME"}}
    model_key = os.environ.get(args.model_key_env, "")
    if not model_key:
        raise ValueError(f"model credential environment variable {args.model_key_env} is unset")
    env.update({
        "HERMES_HOME": str(profile),
        "HERMES_ENABLE_PROJECT_PLUGINS": "false",
        "HERMES_SKIP_NODE_BOOTSTRAP": "1",
        "CHIO_HERMES_MODEL_API_KEY": model_key,
        "NO_COLOR": "1",
    })
    command = [str(args.host_python.absolute()), str(host_root / "hermes"), "chat", "--cli",
               "--ignore-rules", "--provider", "chio-model", "-m", args.model,
               "-t", "mcp-chio", "--max-turns", str(args.max_turns), "-Q",
               "--query-file", str(args.query_file.resolve())]
    manifest = {
        "schema": "chio.hermes.restricted-run.v1", "hostRevision": HOST_REVISION,
        "gatewayConfigSha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "gatewayScriptSha256": hashlib.sha256(args.gateway_script.read_bytes()).hexdigest(),
        "configSha256": hashlib.sha256((profile / "config.yaml").read_bytes()).hexdigest(),
        "tools": names, "command": command,
        "supportedMode": "one-shot external resource tools only",
        "acceptance": "candidate; see ACCEPTANCE.md",
    }
    (state / "launch.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return command, env, workspace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host-python", "host-root", "node", "gateway-script", "gateway-config",
                 "state-dir", "query-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-base-url", required=True)
    parser.add_argument("--model-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--max-turns", type=int, default=20, choices=range(1, 101), metavar="1..100")
    args = parser.parse_args()
    try:
        command, env, workspace = prepare(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Hermes restricted launch refused: {exc}\n")
    return subprocess.call(command, env=env, cwd=workspace)


if __name__ == "__main__":
    raise SystemExit(main())
