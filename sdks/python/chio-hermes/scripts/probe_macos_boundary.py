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

from chio_hermes.restricted import macos_profile

CHILD = """
import json,socket,sys
from pathlib import Path
checks={}
for name,action in [
    ("home_read",lambda:Path(sys.argv[1]).read_text()),
    ("home_write",lambda:Path(sys.argv[2]).write_text("forbidden")),
    ("unix_connect",lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM).connect(sys.argv[3]))]:
    try:action();checks[name]="BYPASS"
    except PermissionError:checks[name]="denied"
print(json.dumps(checks))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=".chio-hermes-canary-", dir=Path.home()) as raw:
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
        profile = output / "profile.sb"
        interpreter = Path(sys.executable)
        profile.write_text(macos_profile(home=Path.home(), read_paths=[
            interpreter.absolute().parent.parent, interpreter.resolve().parent.parent,
        ], write_paths=[output]))
        results = []
        for descendant in [False, True]:
            code = CHILD
            if descendant:
                code = "import subprocess,sys;raise SystemExit(subprocess.call([sys.executable,'-c'," + repr(CHILD) + ",*sys.argv[1:]]))"
            command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(interpreter), "-c", code,
                       str(readable), str(forbidden), str(socket_path)]
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
        observation = {
            "positive_read_matches": readable.read_text() == "disposable-public-canary",
            "positive_unix_connect": True, "runs": results,
            "forbidden_write_exists": forbidden.exists(), "forbidden_unix_observed": extra_connection,
            "profileSha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        }
        (output / "observation.json").write_text(json.dumps(observation, indent=2) + "\n")
        print(json.dumps(observation))
    return 0 if not observation["forbidden_write_exists"] and not extra_connection and all(
        run["exit"] == 0 and set(run["checks"].values()) == {"denied"} for run in results
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
