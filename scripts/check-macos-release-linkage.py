#!/usr/bin/env python3
"""Refuse macOS release binaries that depend on non-system dynamic libraries."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import subprocess
import tempfile


ARCHITECTURES = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}
DENY_LOCAL_LIBRARIES = """(version 1)
(allow default)
(deny file-read*
  (subpath "/opt/homebrew")
  (subpath "/usr/local")
  (subpath "/opt/local")
  (subpath "/opt/pkg"))
"""


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def dependencies(text: str) -> list[str]:
    lines = text.splitlines()
    if len(lines) < 2 or not lines[0].endswith(":"):
        raise ValueError("unrecognized or empty otool dependency output")
    paths = []
    for line in lines[1:]:
        match = re.fullmatch(
            r"\s+(.+) \(compatibility version [0-9.]+, current version [0-9.]+\)", line
        )
        if match is None:
            raise ValueError("unrecognized otool dependency entry")
        path = match.group(1)
        if ".." in PurePosixPath(path).parts or not path.startswith(
            ("/System/Library/", "/usr/lib/")
        ):
            raise ValueError(f"non-system dynamic library: {path}")
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=ARCHITECTURES, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise ValueError("macOS release linkage requires the real macOS loader")
    binary = args.binary.resolve(strict=True)
    original_hash = digest(binary)
    report = {"binary": str(binary), "sha256": original_hash,
              "target": args.target, "expected_version": args.expected_version,
              "sandbox_profile": DENY_LOCAL_LIBRARIES, "commands": [], "passed": False}

    def run(command: list[str]) -> str:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        report["commands"].append({"argv": command, "exit": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise ValueError("macOS release linkage command failed")
        return result.stdout

    try:
        architecture = run(["/usr/bin/lipo", "-archs", str(binary)]).strip()
        if architecture != ARCHITECTURES[args.target]:
            raise ValueError("release binary architecture mismatch")
        report["dependencies"] = dependencies(run(["/usr/bin/otool", "-L", str(binary)]))
        # Disallow core dumps from a failing dyld negative control. No installed
        # library is renamed, uninstalled or otherwise modified by this check.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        with tempfile.TemporaryDirectory(prefix="chio-release-linkage-") as directory:
            profile = Path(directory) / "without-local-libraries.sb"
            profile.write_text(DENY_LOCAL_LIBRARIES)
            version = run(["/usr/bin/sandbox-exec", "-f", str(profile), str(binary), "--version"])
        if version.strip() != f"chio-cli {args.expected_version}":
            raise ValueError("release binary version mismatch")
        if digest(binary) != original_hash:
            raise ValueError("release binary changed during linkage qualification")
        report["passed"] = True
        print(f"PASS: {args.target} system-library linkage and isolated version startup")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
