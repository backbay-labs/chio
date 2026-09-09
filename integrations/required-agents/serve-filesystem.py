#!/usr/bin/env python3
"""Launch the qualification resource owner using explicit, locally verified artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def private_json(path, data):
    with open(path, "x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def start(args):
    state = Path(args.state_dir).resolve()
    kernel = Path(args.kernel).resolve(strict=True)
    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if digest != args.kernel_sha256:
        raise ValueError("kernel SHA256 differs from the explicitly selected artifact")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image):
        raise ValueError("resource image must be an immutable local SHA256 identity")
    if not re.fullmatch(r"chio-required-[a-z0-9-]+", args.volume):
        raise ValueError("use a dedicated chio-required- prefixed volume")
    if not 1024 <= args.port <= 65535:
        raise ValueError("choose a nonprivileged TCP port")
    run("docker", "image", "inspect", args.image)
    audit_volume = args.volume + "-audit"
    for volume in (args.volume, audit_volume):
        exists = subprocess.run(["docker", "volume", "inspect", volume], capture_output=True)
        if exists.returncode == 0:
            raise ValueError("refusing an existing volume; preserve it and select a fresh test volume")
    state.mkdir(mode=0o700, parents=False, exist_ok=False)
    policy = state / "filesystem-policy.yaml"
    selected_policy = Path(args.policy).resolve(strict=True)
    policy.write_bytes(selected_policy.read_bytes())
    policy.chmod(0o400)
    run("docker", "volume", "create", "--label", "chio.task=required-agent-integrations", args.volume)
    run("docker", "volume", "create", "--label", "chio.task=required-agent-integrations", audit_volume)
    # Only the resource owner receives this mount. Host agents never receive it or a Docker socket.
    run("docker", "run", "--rm", "--network", "none", "--read-only", "--user", "0",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--mount",
        f"type=volume,src={args.volume},dst=/workspace", "--mount",
        f"type=volume,src={audit_volume},dst=/audit", "--entrypoint", "node", args.image,
        "-e", "const f=require('fs');for(const [n,c] of [['forbidden.txt','independent forbidden observer\\n'],['secret.txt','sensitive observer\\n']]){f.writeFileSync('/workspace/'+n,c);f.chownSync('/workspace/'+n,1000,1000)}f.chownSync('/workspace',1000,1000);f.chownSync('/audit',1000,1000)")
    command = [str(kernel), "--session-db", str(state / "sessions.sqlite"),
               "--receipt-db", str(state / "receipts.sqlite"),
               "--authority-db", str(state / "authority.sqlite"),
               "mcp", "serve-http", "--policy", str(policy), "--server-id", "fs",
               "--shared-hosted-owner", "--listen", f"127.0.0.1:{args.port}", "--",
               "docker", "run", "--rm", "-i", "--network", "none", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--label",
               f"chio.owner={args.volume}", "--mount",
               f"type=volume,src={args.volume},dst=/workspace", "--mount",
               f"type=volume,src={audit_volume},dst=/audit", "--tmpfs",
               "/tmp:rw,noexec,nosuid,size=16m", args.image]
    operator = {"agentToken": secrets.token_hex(32), "adminToken": secrets.token_hex(32),
                "command": command, "kernelSha256": digest, "port": args.port,
                "image": args.image, "volume": args.volume, "auditVolume": audit_volume,
                "policySha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
                "stateDir": str(state)}
    private_json(state / "operator.json", operator)
    launch(state, operator)


def launch(state, operator):
    kernel = Path(operator["command"][0])
    if hashlib.sha256(kernel.read_bytes()).hexdigest() != operator["kernelSha256"]:
        raise ValueError("kernel changed; qualify and explicitly select an upgrade")
    if operator.get("policySha256") and hashlib.sha256((state / "filesystem-policy.yaml").read_bytes()).hexdigest() != operator["policySha256"]:
        raise ValueError("snapshot policy changed; qualify the new policy before admission")
    env = os.environ.copy()
    env.update(CHIO_AUTH_TOKEN=operator["agentToken"], CHIO_ADMIN_TOKEN=operator["adminToken"])
    with open(state / "kernel.log", "ab") as log:
        child = subprocess.Popen(operator["command"], stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, env=env, start_new_session=True)
    (state / "kernel.pid").write_text(str(child.pid) + "\n")
    time.sleep(1)
    if child.poll() is not None:
        raise RuntimeError("kernel exited; inspect private kernel.log and preserve its databases")
    print(f"Kernel process {child.pid} started. Complete authenticated MCP preparation before use.")


def lifecycle(args):
    state = Path(args.state_dir).resolve(strict=True)
    operator = json.loads((state / "operator.json").read_text())
    pid = int((state / "kernel.pid").read_text())
    current = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
    if current.returncode == 0 and current.stdout.strip():
        if operator["command"][0] not in current.stdout or str(state / "sessions.sqlite") not in current.stdout:
            raise ValueError("PID no longer belongs to this resource owner; refusing to signal it")
        os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            if subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("kernel did not stop; inspect it before recovery, do not clear fences")
    if args.action == "restart":
        launch(state, operator)
    else:
        print("Kernel stopped. Databases, journals and resource volume preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("start")
    for flag in ("state-dir", "kernel", "kernel-sha256", "image", "volume"):
        create.add_argument("--" + flag, required=True)
    create.add_argument("--port", type=int, required=True)
    create.add_argument("--policy", default=str(Path(__file__).resolve().with_name("filesystem-policy.yaml")))
    for action in ("stop", "restart"):
        sub.add_parser(action).add_argument("--state-dir", required=True)
    args = parser.parse_args()
    try:
        start(args) if args.action == "start" else lifecycle(args)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        # Do not emit subprocess environments or the private operator configuration.
        parser.exit(1, f"Resource owner failed: {type(error).__name__}: {error}\n")


if __name__ == "__main__":
    main()
