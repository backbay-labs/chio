#!/usr/bin/env python3
"""Independently observe inherited home-data/write and Unix-socket denials."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_hermes.restricted import macos_profile, python_runtime_root

CHILD = """
import json,os,socket,subprocess,sys
from pathlib import Path
checks={}
extra=json.loads(sys.argv[4])
def connect(port):
    with socket.create_connection(("127.0.0.1",port),timeout=2):pass
for name,action in [
    ("home_read",lambda:Path(sys.argv[1]).read_text()),
    ("home_write",lambda:Path(sys.argv[2]).write_text("forbidden")),
    ("unix_connect",lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM).connect(sys.argv[3])),
    ("other_profile_read",lambda:Path(extra["other_read"]).read_text()),
    ("other_profile_write",lambda:Path(extra["other_write"]).write_text("forbidden")),
    ("data_alias_read",lambda:Path(extra["alias_read"]).read_text()),
    ("symlink_read",lambda:Path(extra["symlink_read"]).read_text()),
    ("hardlink",lambda:os.link(extra["other_read"],extra["hardlink"])),
    ("shell_spawn",lambda:subprocess.run(["/bin/sh","-c","exit 0"],check=True)),
    ("unrelated_tcp",lambda:connect(extra["denied_port"]))]:
    try:action();checks[name]="BYPASS"
    except PermissionError:checks[name]="denied"
connect(extra["allowed_port"])
checks["selected_tcp"]="allowed"
print(json.dumps(checks))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=".chio-hermes-canary-", dir=Path.home()) as raw, tempfile.TemporaryDirectory(prefix="chio-hermes-other-", dir="/tmp") as other_raw:
        canary = Path(raw)
        readable = canary / "read.txt"
        readable.write_text("disposable-public-canary")
        forbidden = canary / "denied-write.txt"
        socket_path = output / "observer.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(8)
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control.connect(str(socket_path))
        peer, _ = server.accept()
        peer.close()
        control.close()
        other = Path(other_raw).resolve()
        other_read = other / "operator-canary.txt"
        other_read.write_text("disposable-public-operator-canary")
        other_write = other / "denied-write.txt"
        link = output / "untrusted-alias"
        link.symlink_to(other_read)
        listeners = []
        for _ in range(2):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            with socket.create_connection(listener.getsockname(), timeout=2):
                peer, _ = listener.accept()
                peer.close()
            listeners.append(listener)
        extra = {"other_read": str(other_read), "other_write": str(other_write),
                 "alias_read": "/System/Volumes/Data" + str(other_read),
                 "symlink_read": str(link), "hardlink": str(output / "forbidden-hardlink"),
                 "denied_port": listeners[0].getsockname()[1], "allowed_port": listeners[1].getsockname()[1]}
        profile = output / "profile.sb"
        interpreter = Path(sys.executable)
        runtime = python_runtime_root(interpreter)
        executables = [interpreter]
        framework_app = runtime / "Resources/Python.app/Contents/MacOS/Python"
        if framework_app.is_file():
            executables.append(framework_app)
        profile.write_text(macos_profile(home=Path.home(), read_paths=[
            interpreter.absolute().parent.parent, runtime,
        ], write_paths=[output], executables=executables, bootstrap_fork=len(executables)>1,
            network_ports=[extra["allowed_port"]]))
        results = []
        for descendant in [False, True]:
            code = CHILD
            if descendant:
                code = "import subprocess,sys;raise SystemExit(subprocess.call([sys.executable,'-c'," + repr(CHILD) + ",*sys.argv[1:]]))"
            command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(interpreter), "-c", code,
                       str(readable), str(forbidden), str(socket_path), json.dumps(extra)]
            run = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=10)
            (output / f"stdout-{int(descendant)}.txt").write_text(run.stdout)
            (output / f"stderr-{int(descendant)}.txt").write_text(run.stderr)
            results.append({"descendant": descendant, "exit": run.returncode,
                            "checks": json.loads(run.stdout) if run.returncode == 0 else None})
        server.settimeout(0.2)
        try:
            peer, _ = server.accept()
            peer.close()
            extra_connection = True
        except TimeoutError:
            extra_connection = False
        server.close()
        socket_path.unlink()
        connections = []
        for listener in listeners:
            count = 0
            listener.settimeout(0.2)
            try:
                while True:
                    peer, _ = listener.accept()
                    peer.close()
                    count += 1
            except TimeoutError:
                pass
            listener.close()
            connections.append(count)
        observation = {
            "positive_read_matches": readable.read_text() == "disposable-public-canary",
            "positive_unix_connect": True, "runs": results,
            "forbidden_write_exists": forbidden.exists(), "forbidden_unix_observed": extra_connection,
            "profileSha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
            "positive_tcp_controls": True, "unrelated_tcp_observed": connections[0],
            "selected_tcp_observed": connections[1], "other_write_exists": other_write.exists(),
            "hardlink_exists": Path(extra["hardlink"]).exists(),
        }
        (output / "observation.json").write_text(json.dumps(observation, indent=2) + "\n")
        print(json.dumps(observation))
    return 0 if not observation["forbidden_write_exists"] and not extra_connection and not observation["other_write_exists"] and not observation["hardlink_exists"] and connections == [0, 2] and all(
        run["exit"] == 0 and run["checks"].get("selected_tcp") == "allowed"
        and all(value == "denied" for key, value in run["checks"].items() if key != "selected_tcp") for run in results
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
