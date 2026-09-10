"""Launch the pinned Hermes CLI with only the Chio execution gateway.

This candidate mode uses static host tool restrictions, independent of the
legacy Python plugin's hook. Resource isolation and the kernel gateway remain
separate required boundaries. The qualified mode adds a default-deny macOS
profile and an operator-owned model relay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .gateway_transport import GatewayTransport
from .model_relay import CodexSubscription, ModelRelay

HOST_REVISION = "175054c14b54404663d8614a178280cffe6062eb"
# Compatibility checks on the inspected dispatch/configuration contract. The
# operator must still install the complete pinned upstream revision.
HOST_CONTRACT_HASHES = {
    "hermes_cli/runtime_provider.py": "1d8651d7339692e9a1b141049c1cde0713d11f0488bee57c1da423db2701e1bd",
    "hermes_cli/auth.py": "30320e54d91f06f530e4784bdcda78db9ddf96ea76335de2c2bdda80d29fa3f4",
    "agent/transports/codex.py": "f9c87b38c6a97f57d11e385bb4d2e8ba88bffd3dbc1713b2504715f477f615ee",
    "agent/codex_responses_adapter.py": "d47aa67bffc2f7175b4f0b75e1e436e24de7ebaeeea1097c7d8fd649cd1559c7",
    "agent/codex_runtime.py": "cae3abcfd43a833f1ee469270b107ce0149552e8fddfae304a601596fa8dbf79",
    "agent/tool_dispatch_helpers.py": "5745840851e82e4277a85d4987f9c879978b7abe2f50e9b15f9aaf8139fcb6b0",
    "cli.py": "6d343fef18bf359c0b7c72345a801cf99d5f82d30d5b861f47c1fab6e5da60ac",
    "hermes": "6e1adae1e73ce67121d4ec380a5b66b8fb84f02dd8004b3a9988c39660139417",
    "hermes_cli/main.py": "2fc800dde92f7fccd08b545d29290d0b8425e6ab748e6c7cd2ab35f5461406d8",
    "hermes_cli/plugins.py": "4bdca832fa1369490db5b70cf068633f32e6d5628e2e817c4f8c2d7b3536cb9b",
    "hermes_cli/config.py": "4c918464bd678adc91f5f879835757ffeb65e0d273dcee0cf4baa1c7fc79cb09",
    "hermes_cli/env_loader.py": "26712ba3e020b5c306cd456e8d2cc96084fd2295f7ec4104466fffd0adeab87d",
    "hermes_cli/managed_scope.py": "6b542220964ddaebc176ddbccb833174ab309cde97e0e2ba7a309c7b98ce26f9",
    "hermes_cli/banner.py": "6e54a6cefb291ddf41b4772583d8535c30c012669ebd41753017e2bd4d3c1261",
    "agent/conversation_loop.py": "9dbde98ce88e9b393cf220457f4358b4e9023b697873aec59fb688c7d8fe14fa",
    "agent/agent_runtime_helpers.py": "cf860e203b2311fa473d861ae21084d72bbcee5d803e48e3f58dc1c9df4245b9",
    "model_tools.py": "32a106d66835dc9f88f15624076086a53cbd4bb7ed80889228d0e53f62d4cfac",
    "tools/mcp_tool.py": "1ed7ba9edd353ff6c1351efd8d766bf814cb1e6505926c01d50ef029008e04f8",
    "tools/tirith_security.py": "c05699cb7bad7347f0370cc7838a44c2a3b0229f23e73120ab1c70812722fb64",
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
    credential = config.get("sessionCredential")
    if not isinstance(credential, dict) or credential.get("schema") != "chio.mcp.session-credential.v1":
        raise ValueError("prepare a kernel-scoped session credential; bootstrap bearer configs are unsupported")
    scope = credential.get("allowedTools")
    issued, expires = credential.get("issuedAt"), credential.get("expiresAt")
    now = time.time()
    if (
        credential.get("sessionId") != execution["sessionId"]
        or not execution.get("subjectKey") or credential.get("subjectKey") != execution["subjectKey"]
        or not execution.get("capabilityId") or credential.get("capabilityIds") != [execution["capabilityId"]]
        or not execution.get("serverId") or credential.get("serverId") != execution["serverId"]
        or credential.get("endpointPath") != "/mcp"
        or not isinstance(scope, list) or not all(isinstance(name, str) for name in scope)
        or sorted(scope) != sorted(names)
        or type(issued) is not int or type(expires) is not int
        or not 0 < expires - issued <= 3600 or issued > now + 5 or expires <= now
    ):
        raise ValueError("session credential metadata must match live identity, scope and bounded lifetime")
    # Metadata is a compatibility check. The kernel and gateway must enforce
    # the actual bearer scope and confirm it in the live execution context.
    # Resume is a gateway control tool, not an additional kernel capability.
    # Expose it only after checking the issued four-tool credential unchanged.
    return names + (["chio_resume"] if config.get("approval") is not None else [])


def macos_profile(*, home: Path, read_paths: list[Path], write_paths: list[Path],
                  network_ports: list[int] | None = None,
                  executables: list[Path] | None = None, bootstrap_fork: bool = False) -> str:
    """Restrict file contents/mutations and network in the host and children.

    This candidate adds explicit OS controls to the static tool boundary.
    Qualification must still test the complete pinned host and kernel contract.
    """
    def quoted(path: Path) -> str:
        value = str(path.resolve())
        if any(ord(char) < 32 for char in value):
            raise ValueError("sandbox paths cannot contain control characters")
        return json.dumps(value, ensure_ascii=False)

    quoted(home)  # Validate all supplied paths, including the operator home.
    ports = network_ports or []
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("network ports must be explicit localhost TCP ports")
    lines = ["(version 1)", "(deny default)", "(deny file-link)",
             "(allow file-read-metadata)", '(allow file-read-data (literal "/"))',
             '(allow sysctl-read (sysctl-name-prefix "hw.") (sysctl-name "kern.hostname") '
             '(sysctl-name "kern.ostype") (sysctl-name "kern.osrelease") (sysctl-name "kern.osversion") '
             '(sysctl-name "kern.osproductversion") (sysctl-name "kern.version") (sysctl-name "kern.maxfilesperproc") '
             '(sysctl-name "kern.tcsm_available") (sysctl-name "kern.tcsm_enable") (sysctl-name "machdep.cpu.brand_string"))',
             '(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.opendirectoryd.libinfo"))',
             "(allow process-info* (target self))", "(allow signal (target children) (target self))"]
    if bootstrap_fork:
        lines.append("(allow process-fork)")
    if ports:
        lines.append("(allow network-outbound " + " ".join(f'(remote tcp "localhost:{port}")' for port in ports) + ")")
    if executables:
        lines.append("(allow process-exec " + " ".join(f"(literal {quoted(path)})" for path in executables) + ")")
    system_reads = [Path(path) for path in [
        "/System/Library", "/System/Volumes/Preboot/Cryptexes/OS", "/usr/lib",
        "/Library/Apple/System", "/private/var/db/dyld",
        "/private/etc/localtime", "/private/etc/hosts",
        "/private/etc/resolv.conf", "/private/etc/services", "/private/etc/ssl/cert.pem",
        "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty",
    ]]
    reads = [
        f"({'subpath' if path.is_dir() else 'literal'} {quoted(path)})"
        for path in read_paths + system_reads
    ]
    writes = [f"(subpath {quoted(path)})" for path in write_paths]
    writes += [f"(literal {quoted(Path(path))})" for path in ["/dev/null", "/dev/tty"]]
    lines.append(f"(allow file-read* {' '.join(reads)})")
    lines.append(f"(allow file-read* file-write* {' '.join(writes)})")
    return "\n".join(lines) + "\n"


def runtime_libraries(executable: Path) -> list[Path]:
    """Resolve the pinned executable's Mach-O dependencies without broad Cellar access."""
    root = executable.resolve()
    pending = [root]
    files: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in files:
            continue
        if len(files) >= 128:
            raise ValueError("runtime dependency graph exceeds qualified limit")
        files.add(path)
        output = subprocess.check_output(["/usr/bin/otool", "-L", str(path)], text=True, timeout=5)
        for line in output.splitlines()[1:]:
            if not line.startswith("\t"):
                continue
            name = line.strip().split(" (compatibility", 1)[0]
            if not name or name.startswith(("/usr/lib/", "/System/")):
                continue
            if name.startswith("@rpath/"):
                candidate = path.parent / name[7:]
                if not candidate.exists():
                    candidate = root.parent.parent / "lib" / name[7:]
            elif name.startswith("@loader_path/"):
                candidate = path.parent / name[13:]
            elif name.startswith("@executable_path/"):
                candidate = root.parent / name[17:]
            else:
                candidate = Path(name)
            if not candidate.is_absolute() or not candidate.is_file():
                raise ValueError("runtime library resolution requires a qualified absolute file")
            pending.append(candidate.resolve())
    return sorted(files)


def python_runtime_root(executable: Path) -> Path:
    value = subprocess.check_output([str(executable.absolute()), "-I", "-c", "import sys; print(sys.base_prefix)"],
                                   text=True, timeout=10, env={"PATH": os.defpath})
    path = Path(value.strip())
    if not path.is_absolute() or not path.is_dir():
        raise ValueError("the pinned Python runtime root must be an existing absolute directory")
    return path.resolve()


def sandbox_executable() -> Path:
    executable = Path("/usr/bin/sandbox-exec")
    if sys.platform != "darwin" or not executable.is_file():
        raise ValueError("this candidate requires the qualified macOS sandbox-exec boundary")
    return executable


def prepare(args: argparse.Namespace) -> tuple[list[str], dict[str, str], Path]:
    host_root = args.host_root.resolve()
    validate_host(host_root)
    sandbox = sandbox_executable()
    if Path("/etc/hermes").exists() or os.environ.get("HERMES_MANAGED_DIR"):
        raise ValueError("machine-managed Hermes configuration needs separate qualification")
    config_path = args.gateway_config.absolute()
    gateway = _private_json(config_path)
    names = gateway_tool_names(gateway)
    transport_url = getattr(args, "model_relay_url", None)
    transport_token = getattr(args, "model_relay_token", None)
    gateway_url = getattr(args, "gateway_transport_url", None)
    gateway_token = getattr(args, "gateway_transport_token", None)
    endpoints = [urlsplit(gateway_url or ""), urlsplit(transport_url or "")]
    if (not transport_token or not gateway_token or any(url.scheme != "http" or url.hostname != "127.0.0.1"
                                  or not url.port or url.username or url.password for url in endpoints)):
        raise ValueError("qualified mode requires launcher-owned HTTP gateway and model relay")
    if not args.node.is_file() or not args.gateway_script.is_file():
        raise ValueError("install the pinned Node runtime and Chio gateway artifact first")
    state = args.state_dir.absolute()
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = state / "profile"
    workspace = state / "empty-workspace"
    profile.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    (profile / ".env").write_text("# No stored credentials in the agent profile.\n")
    private_paths = [config_path.resolve(), Path(gateway["journalDir"]).resolve()]
    if getattr(args, "codex_auth_file", None):
        private_paths.append(args.codex_auth_file.resolve())
    readable_roots = [state.resolve(), host_root, args.host_python.absolute().parent.parent.resolve(), python_runtime_root(args.host_python), args.query_file.resolve()]
    if any(secret == root or root in secret.parents for secret in private_paths for root in readable_roots):
        raise ValueError("kernel credentials and journal must stay outside host-readable paths")
    config = {
        "model": {"provider": "chio-model", "default": args.model, "max_tokens": 4096},
        "providers": {"chio-model": {
            "base_url": transport_url,
            "api_key": "${CHIO_HERMES_MODEL_API_KEY}",
            "api_mode": getattr(args, "model_api_mode", "chat_completions"),
        }},
        "plugins": {"enabled": [], "disabled": ["chio"]},
        "hooks": {},
        # No native terminal is exposed. Prevent its eager scanner bootstrap
        # from downloading another executable during an unrelated MCP run.
        "security": {"tirith_enabled": False},
        "tools": {"tool_search": {"enabled": "off"}},
        "mcp_servers": {"chio": {
            "url": gateway_url,
            "headers": {"Authorization": "Bearer " + gateway_token},
            "skip_preflight": True,
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
    env.update({
        "HERMES_HOME": str(profile),
        "HERMES_ENABLE_PROJECT_PLUGINS": "false",
        "HERMES_SKIP_NODE_BOOTSTRAP": "1",
        "TIRITH_ENABLED": "false",
        "CHIO_HERMES_MODEL_API_KEY": transport_token,
        "NO_COLOR": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "OPENSSL_CONF": "/dev/null",
    })
    command = [str(args.host_python.absolute()), str(host_root / "hermes"), "chat", "--cli",
               "--ignore-rules", "--provider", "chio-model", "-m", args.model,
               "-t", "mcp-chio", "--max-turns", str(args.max_turns), "-Q",
               "--query-file", str(args.query_file.resolve())]
    sandbox_path = state / "host.sb"
    python_execs = [args.host_python]
    framework_app = python_runtime_root(args.host_python) / "Resources/Python.app/Contents/MacOS/Python"
    if framework_app.is_file():
        # python.org macOS launchers posix_spawn this exact runtime binary.
        # Any descendant retains the same file and network resource boundary.
        python_execs.append(framework_app)
    # The resource service must not be among these trusted runtime paths.
    sandbox_path.write_text(macos_profile(
        home=Path.home(),
        read_paths=[host_root, args.host_python.absolute().parent.parent,
                    python_runtime_root(args.host_python),
                    args.query_file.resolve()],
        write_paths=[state],
        network_ports=[url.port for url in endpoints],
        executables=python_execs, bootstrap_fork=len(python_execs)>1,
    ))
    command = [str(sandbox), "-f", str(sandbox_path), *command]
    manifest = {
        "schema": "chio.hermes.restricted-run.v1", "hostRevision": HOST_REVISION,
        "gatewayConfigSha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "gatewayScriptSha256": hashlib.sha256(args.gateway_script.read_bytes()).hexdigest(),
        "configSha256": hashlib.sha256((profile / "config.yaml").read_bytes()).hexdigest(),
        "sandboxSha256": hashlib.sha256(sandbox_path.read_bytes()).hexdigest(),
        "tools": names, "command": command,
        "supportedMode": "one-shot external resource tools only",
        "acceptance": "candidate; see ACCEPTANCE.md",
    }
    (state / "launch.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return command, env, workspace


def run_host(command: list[str], env: dict[str, str], workspace: Path) -> tuple[int, int | None]:
    """Supervise the isolated group through a private parent-liveness pipe."""
    child: subprocess.Popen[bytes] | None = None
    interrupted: int | None = None
    deadline: float | None = None

    def forward(signum: int, _frame: Any) -> None:
        nonlocal interrupted, deadline
        interrupted = interrupted or signum
        # The supervisor gets five seconds to stop its native group. The outer
        # deadline is longer so it cannot kill cleanup before that grace ends.
        deadline = deadline or time.monotonic() + 10
        if child is not None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        for signum in previous:
            signal.signal(signum, forward)
        child = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).with_name("host_supervisor.py"))],
            stdin=subprocess.PIPE, start_new_session=True,
        )
        if child.stdin is None:
            raise ValueError("private host lifeline unavailable")
        child.stdin.write(json.dumps({"command": command, "env": env, "cwd": str(workspace)}).encode() + b"\n")
        child.stdin.flush()
        if interrupted is not None:
            forward(interrupted, None)
        while True:
            try:
                return child.wait(timeout=0.1), interrupted
            except subprocess.TimeoutExpired:
                if deadline is not None and time.monotonic() >= deadline:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = None
    finally:
        if child is not None and child.stdin is not None:
            child.stdin.close()
        if interrupted is not None and child is not None:
            # The supervisor owns native descendant cleanup before it exits.
            # The launcher separately reaps its own supervisor process group.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if child is not None and child.poll() is None:
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host-python", "host-root", "node", "gateway-script", "gateway-config",
                 "state-dir", "query-file"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-base-url")
    parser.add_argument("--model-auth", choices=["api-key", "codex-subscription"], default="api-key")
    parser.add_argument("--codex-auth-file", type=Path)
    parser.add_argument("--model-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--max-turns", type=int, default=20, choices=range(1, 101), metavar="1..100")
    args = parser.parse_args()
    try:
        if args.model_auth == "codex-subscription":
            if not args.codex_auth_file:
                raise ValueError("subscription mode requires an explicit operator-owned native Codex auth cache")
            if args.model_base_url and args.model_base_url.rstrip("/") != "https://chatgpt.com/backend-api/codex":
                raise ValueError("subscription mode requires the fixed ChatGPT Codex route")
            model_key = CodexSubscription.from_cache(_private_json(args.codex_auth_file.absolute()))
        else:
            if args.codex_auth_file or args.model_base_url and args.model_base_url.rstrip("/") != "https://api.openai.com/v1":
                raise ValueError("API mode requires the fixed OpenAI chat-completions route")
            model_key = os.environ.get(args.model_key_env, "")
            if not model_key:
                raise ValueError(f"model credential environment variable {args.model_key_env} is unset")
        names = gateway_tool_names(_private_json(args.gateway_config.absolute()))
        with GatewayTransport(args.node.resolve(), args.gateway_script.resolve(), args.gateway_config.resolve()) as gateway:
            args.gateway_transport_url, args.gateway_transport_token = gateway.url, gateway.token
            with ModelRelay(model_key, args.model, {"mcp__chio__" + name for name in names}, args.max_turns + 4, gateway.receive_host_results) as relay:
                args.model_relay_url, args.model_relay_token = relay.base_url, relay.token
                args.model_api_mode = relay.api_mode
                command, env, workspace = prepare(args)
                try:
                    host_code, interrupted = run_host(command, env, workspace)
                    private = _private_json(args.gateway_config.absolute())
                    records = [_private_json(path) for path in Path(private["journalDir"]).glob("*.json")]
                    unresolved = any(record.get("state") in ["pending", "unknown"] or record.get("state") == "completed" and (not record.get("acknowledged") or not record.get("hostDeliveryConfirmed")) for record in records)
                    pending = any(record.get("state") == "awaiting_approval" for record in records)
                    unsuccessful = any(record.get("state") in ["denied", "not_dispatched"] or record.get("outcome", {}).get("result", {}).get("isError") is True for record in records)
                    unresolved |= "unknown" in gateway.outcomes.values()
                    pending |= "awaiting_approval" in gateway.outcomes.values()
                    unsuccessful |= any(value in ["denied", "not_dispatched"] for value in gateway.outcomes.values())
                    outcome = "unresolved" if unresolved else "awaiting_approval" if pending else "protected_work_incomplete" if unsuccessful else "cancelled" if interrupted else "completed" if host_code == 0 else "host_failed"
                    exit_code = 2 if unresolved else 4 if pending else 3 if unsuccessful else 128 + interrupted if interrupted else host_code
                    (args.state_dir / "terminal.json").write_text(json.dumps({"hostExitCode": host_code, "exitCode": exit_code, "outcome": outcome, "operatorInterrupt": signal.Signals(interrupted).name if interrupted else None, "confirmedDeliveries": len(gateway.events)}) + "\n")
                    return exit_code
                finally:
                    (args.state_dir / "model-relay.json").write_text(json.dumps(relay.events, indent=2) + "\n")
                    (args.state_dir / "host-delivery.json").write_text(json.dumps(gateway.events, indent=2) + "\n")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Hermes restricted launch refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
