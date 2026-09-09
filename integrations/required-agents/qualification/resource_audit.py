#!/usr/bin/env python3
"""Observe actual resource dispatch and fail-before-forward audit faults."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs)


def qualify(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    image = run(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"]).stdout.strip()
    if not image.startswith("sha256:"):
        raise ValueError("missing immutable image identity")
    cases = []
    for label in ("normal", "audit-full", "malformed", "symlink", "hardlink"):
        volume = f"chio-required-audit-{args.run_id}-{label}"
        if subprocess.run(["docker", "volume", "inspect", volume], capture_output=True).returncode == 0:
            raise ValueError("refusing existing disposable volume")
        run(["docker", "volume", "create", volume])
        setup = "const f=require('fs');f.mkdirSync('/data/workspace');f.mkdirSync('/data/audit');f.chownSync('/data/workspace',1000,1000);f.chownSync('/data/audit',1000,1000);"
        if label == "audit-full":
            setup += "f.symlinkSync('/dev/full','/data/audit/dispatch.jsonl');"
        if label in ("symlink", "hardlink"):
            setup += "f.writeFileSync('/data/workspace/secret.txt','protected alias sentinel');"
            setup += ("f.symlinkSync('secret.txt','/data/workspace/alias.txt');" if label == "symlink" else
                      "f.linkSync('/data/workspace/secret.txt','/data/workspace/alias.txt');")
            control = run(["docker", "run", "--rm", "--network", "none", "--user", "0", "--mount",
                           f"type=volume,src={volume},dst=/data", "--entrypoint", "node", image, "-e", setup +
                           "console.log(require('fs').readFileSync('/data/workspace/alias.txt','utf8'));"])
            assert control.stdout.strip() == "protected alias sentinel"
            setup = ""  # The independent alias-read control also initialized this case.
        run(["docker", "run", "--rm", "--network", "none", "--user", "0", "--mount",
             f"type=volume,src={volume},dst=/data", "--entrypoint", "node", image, "-e", setup])
        command = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--mount",
                   f"type=volume,src={volume},dst=/workspace,volume-subpath=workspace", "--mount",
                   f"type=volume,src={volume},dst=/audit,volume-subpath=audit", image]
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "resource-audit-qualification", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "write_file", "arguments": {"path": "/workspace/observed.txt", "content": "independent dispatch observation\n"}}},
        ]
        wire = "\n".join(map(json.dumps, frames)) + "\n"
        if label == "malformed":
            wire = "invalid-json\n" + wire
        # Keep stdin open until the official MCP server answers the write or exits.
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        import threading
        lines = []
        def collect():
            for line in child.stdout:
                lines.append(line)
                try:
                    if json.loads(line).get("id") == 2:
                        child.stdin.close()
                except ValueError:
                    pass
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            child.stdin.write(wire)
            child.stdin.flush()
        except BrokenPipeError:
            pass  # Invalid resource trees exit before opening the MCP transport.
        try:
            child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            child.terminate()
            child.wait(timeout=10)
            raise RuntimeError(f"resource probe timed out: {label}")
        reader.join(timeout=2)
        stderr = child.stderr.read()
        (output / f"{label}.stdout.jsonl").write_text("".join(lines))
        (output / f"{label}.stderr.txt").write_text(stderr)
        observer = "const f=require('fs');const p='/observe/workspace/observed.txt';const a='/observe/audit/dispatch.jsonl';let audit=null;if(f.existsSync(a)&&!f.lstatSync(a).isSymbolicLink())audit=f.readFileSync(a,'utf8');console.log(JSON.stringify({exists:f.existsSync(p),content:f.existsSync(p)?f.readFileSync(p,'utf8'):null,audit}));"
        effect = json.loads(run(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount",
                                f"type=volume,src={volume},dst=/observe,readonly", "--entrypoint", "node", image, "-e", observer]).stdout)
        if label == "normal":
            assert child.returncode == 0 and effect["content"] == "independent dispatch observation\n", effect
            records = [json.loads(line) for line in effect["audit"].splitlines()]
            assert len(records) == 1 and records[0]["tool"] == "write_file", records
            assert records[0]["path"] == "/workspace/observed.txt", records
        else:
            assert child.returncode != 0 and effect["exists"] is False, effect
        cases.append({"case": label, "passed": True, "exitCode": child.returncode,
                      "volume": volume, "independentObservation": effect})
    result = {"schema": "chio.resource-audit-qualification.v1", "image": image,
              "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": cases}
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": len(cases), "failed": 0, "skipped": 0, "image": image}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    qualify(parser.parse_args())
