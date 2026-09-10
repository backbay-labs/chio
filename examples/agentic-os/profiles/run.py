#!/usr/bin/env python3
"""Verified prebuilt entrypoint; run configuration is generated with the release."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def fetch_runtime(config):
    destination = ROOT / ".runtime"
    marker = destination / "runtime.json"
    if marker.is_file() and json.loads(marker.read_text()) == config:
        for name, expected in config["files"].items():
            path = destination / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise RuntimeError("The installed runtime changed. Remove .runtime and launch again to restore the verified files.")
        return destination
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise RuntimeError("This prebuilt runtime requires Ubuntu 26.04 on x86_64. Use the documented Linux VM or build the source on a supported host.")
    with tempfile.TemporaryDirectory(prefix=".chio-runtime-", dir=ROOT) as temporary:
        stage = Path(temporary)
        archive = stage / "runtime.tar.gz"
        print("Downloading the verified Chio application runtime…", flush=True)
        with urllib.request.urlopen(config["url"], timeout=120) as response, archive.open("wb") as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 200_000_000:
                    raise RuntimeError("Runtime archive exceeds the release size bound")
                output.write(chunk)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != config["sha256"]:
            raise RuntimeError("Runtime checksum does not match this project release")
        extracted = stage / "files"
        extracted.mkdir()
        with tarfile.open(archive) as package:
            for member in package.getmembers():
                if member.name not in config["files"] or not member.isfile() or member.size > 300_000_000:
                    raise RuntimeError("Runtime archive contains an unexpected entry")
            package.extractall(extracted, filter="data")
        for name, expected in config["files"].items():
            path = extracted / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise RuntimeError("A runtime executable failed verification")
            path.chmod(0o755)
        (extracted / "runtime.json").write_text(json.dumps(config))
        if destination.exists():
            raise RuntimeError("An earlier runtime directory exists. Inspect it before removing .runtime and trying again.")
        extracted.rename(destination)
    return destination


def market_profile():
    if os.environ.get("CHIO_SANDBOX_CGROUP_PARENT"):
        return
    relative = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")), None)
    if relative is None:
        raise RuntimeError("The marketplace operator requires a host with cgroup v2")
    current = Path("/sys/fs/cgroup") / relative.lstrip("/")
    if os.environ.get("CHIO_AGENT_OS_DELEGATED") != "1":
        if not shutil.which("systemd-run"):
            raise RuntimeError("The marketplace needs a delegated cgroup v2 scope. See profiles/README.md for the operator host requirements.")
        os.execvp("systemd-run", ["systemd-run", "--user", "--scope", "--property=Delegate=yes", "env", "CHIO_AGENT_OS_DELEGATED=1", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    # This application owns the delegated scope. Move only its own process to
    # a leaf before enabling controllers on the empty parent.
    host = current / "chio-host"
    jobs = current / "chio-jobs"
    host.mkdir(exist_ok=True)
    jobs.mkdir(exist_ok=True)
    (host / "cgroup.procs").write_text(str(os.getpid()))
    (current / "cgroup.subtree_control").write_text("+memory +pids")
    (jobs / "cgroup.subtree_control").write_text("+memory +pids")
    os.environ["CHIO_SANDBOX_CGROUP_PARENT"] = str(jobs)


def main():
    os.chdir(ROOT)
    config = json.loads((ROOT / "release.json").read_text())
    runtime = fetch_runtime(config["runtime"])
    app = config["application"]
    os.environ["CHIO_APPLICATION"] = app
    os.environ["CHIO_BINARY"] = str(runtime / "chio")
    os.environ.setdefault("CHIO_RUNS", str(ROOT / "runs"))
    if app == "cognition-marketplace":
        if not shutil.which("uv"):
            raise RuntimeError("Install uv as described in README.md; the buyer uses the supported Python SDK")
        subprocess.run(["uv", "sync", "--locked", "--project", str(ROOT / "cognition-marketplace")], check=True)
        os.environ["CHIO_MARKET_PYTHON"] = str(ROOT / "cognition-marketplace/.venv/bin/python")
        market_profile()
    os.execv(runtime / "chio-agent-os", [str(runtime / "chio-agent-os"), *sys.argv[1:]])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Cannot start this project: {error}", file=sys.stderr)
        sys.exit(1)
