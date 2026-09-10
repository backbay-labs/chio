#!/usr/bin/env python3
"""Build checksum-pinned native OpenSSL in a fresh, isolated release directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tarfile


VERSION = "3.6.4"
SOURCE_URL = (
    "https://github.com/openssl/openssl/releases/download/"
    f"openssl-{VERSION}/openssl-{VERSION}.tar.gz"
)
SOURCE_SHA256 = "9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef"
TARGETS = {
    "aarch64-apple-darwin": ("arm64", "darwin64-arm64-cc"),
    "x86_64-apple-darwin": ("x86_64", "darwin64-x86_64-cc"),
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_environment(target: str, prefix: Path) -> dict[str, str]:
    # openssl-sys checks these target-specific values before generic variables.
    key = target.upper().replace("-", "_")
    return {
        f"{key}_OPENSSL_STATIC": "1",
        f"{key}_OPENSSL_DIR": str(prefix),
        f"{key}_OPENSSL_LIB_DIR": str(prefix / "lib"),
        f"{key}_OPENSSL_INCLUDE_DIR": str(prefix / "include"),
        f"{key}_OPENSSL_LIBS": "ssl:crypto",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh directory; existing paths are refused")
    parser.add_argument("--archive", type=Path,
                        help="Optional existing source archive, verified against the same pin")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    arch, configure_target = TARGETS[args.target]
    if platform.system() != "Darwin" or platform.machine() != arch:
        raise ValueError("requires a native macOS runner matching the requested target")
    if not 1 <= args.jobs <= 16:
        raise ValueError("jobs must be between 1 and 16")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prefix = output / "install"
    archive = args.archive.resolve() if args.archive else output / f"openssl-{VERSION}.tar.gz"
    records = []
    # Do not inherit compiler flags, OpenSSL options or module/config paths from
    # the operator's shell. All build dependencies come from the macOS toolchain.
    env = {k: os.environ[k] for k in ("HOME", "TMPDIR") if k in os.environ}
    env.update({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
                "MACOSX_DEPLOYMENT_TARGET": "11.0"})

    def run(label: str, command: list[str], cwd: Path | None = None) -> None:
        log = output / f"{label}.log"
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
        records.append({"label": label, "argv": command,
                        "cwd": str(cwd) if cwd else None,
                        "exit": result.returncode, "log_sha256": digest(log)})
        (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{label} failed; inspect {log}")

    if not args.archive:
        run("download", ["/usr/bin/curl", "--fail", "--location", "--retry", "2",
                         "--proto", "=https", "--tlsv1.2", "--output", str(archive), SOURCE_URL])
    if digest(archive) != SOURCE_SHA256:
        raise ValueError("OpenSSL source checksum mismatch")
    source_parent = output / "source"
    source_parent.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        if any(Path(member.name).parts[0] != f"openssl-{VERSION}" for member in source):
            raise ValueError("unexpected OpenSSL source archive root")
        source.extractall(source_parent, filter="data")
    source_root = source_parent / f"openssl-{VERSION}"
    # no-shared/no-module/no-dso prevent a runtime dependency on build-machine
    # libraries and dynamically loaded providers. Built-in crypto remains enabled.
    configure = ["/usr/bin/perl", "Configure", configure_target, "no-shared",
                 "no-module", "no-dso", f"--prefix={prefix}", "--libdir=lib",
                 "--openssldir=/etc/ssl", "-mmacosx-version-min=11.0"]
    run("toolchain", ["/usr/bin/xcrun", "clang", "--version"])
    run("configure", configure, source_root)
    run("build", ["/usr/bin/make", f"-j{args.jobs}"], source_root)
    run("test", ["/usr/bin/make", f"-j{args.jobs}", "test"], source_root)
    run("install", ["/usr/bin/make", "install_sw"], source_root)
    run("version", [str(prefix / "bin/openssl"), "version", "-a"])
    version_output = (output / "version.log").read_text()
    if not version_output.startswith(f"OpenSSL {VERSION} "):
        raise ValueError("built OpenSSL version mismatch")
    files = [prefix / "lib/libssl.a", prefix / "lib/libcrypto.a"]
    if any(not p.is_file() or p.is_symlink() for p in files):
        raise ValueError("static OpenSSL archives missing")
    if list(prefix.rglob("*.dylib")) or list(prefix.rglob("*.so")):
        raise ValueError("unexpected dynamic OpenSSL library")
    headers = sorted((prefix / "include").rglob("*.h"))
    if not headers:
        raise ValueError("OpenSSL headers missing")
    cargo_env = build_environment(args.target, prefix)
    (output / "cargo-env.sh").write_text("".join(
        f"export {key}={shlex.quote(value)}\n" for key, value in cargo_env.items()
    ))
    (output / "cargo-env.json").write_text(json.dumps(cargo_env, indent=2) + "\n")
    manifest = {
        "name": "openssl", "version": VERSION, "license": "Apache-2.0",
        "purl": f"pkg:generic/openssl@{VERSION}",
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
        "source_checksum_url": SOURCE_URL + ".sha256", "target": args.target,
        "configure": configure, "test_command_exit": 0,
        "files": {str(p.relative_to(prefix)): digest(p) for p in files + headers},
        "license_sha256": digest(source_root / "LICENSE.txt"),
        "commands_sha256": digest(output / "commands.json"),
        "recipe_sha256": digest(Path(__file__)),
        "coverage": "Native source/build identity; not a cargo-vet audit or host acceptance.",
    }
    (output / "native-openssl.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "manifest": str(output / "native-openssl.json"),
                      "cargo_env": str(output / "cargo-env.sh")}, indent=2))


if __name__ == "__main__":
    main()
