#!/usr/bin/env python3
"""Install the pinned Aeneas release toolchain for the current architecture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO / "formal/aeneas/production.toml"
BINARY_NAMES = ("aeneas", "charon", "charon-driver")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def host_architecture() -> str:
    architecture = platform.machine().lower()
    aliases = {"amd64": "x86_64", "arm64": "aarch64"}
    architecture = aliases.get(architecture, architecture)
    if architecture not in {"x86_64", "aarch64"}:
        raise SystemExit(f"unsupported Aeneas host architecture: {architecture}")
    return architecture


def selected_toolchain(registry: dict[str, object], architecture: str) -> dict[str, str]:
    rows = registry.get("toolchains")
    if not isinstance(rows, list):
        raise SystemExit("Aeneas production registry has no toolchain table")
    matches = [row for row in rows if row.get("architecture") == architecture]
    if len(matches) != 1:
        raise SystemExit(
            f"Aeneas production registry must have one {architecture} toolchain row"
        )
    return matches[0]


def download_archive(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "chio-formal-gate"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)


def extract_binaries(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as release:
        for name in BINARY_NAMES:
            try:
                member = release.getmember(name)
            except KeyError as error:
                raise SystemExit(f"Aeneas release archive is missing {name}") from error
            if not member.isfile() or member.issym() or member.islnk():
                raise SystemExit(f"Aeneas release member is not a regular file: {name}")
            source = release.extractfile(member)
            if source is None:
                raise SystemExit(f"Aeneas release member could not be read: {name}")
            target = destination / name
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755)


def verify_hashes(directory: Path, toolchain: dict[str, str], phase: str) -> None:
    for name in BINARY_NAMES:
        key_name = name.replace("-", "_")
        expected = toolchain[f"{key_name}_{phase}_sha256"]
        actual = sha256(directory / name)
        if actual != expected:
            raise SystemExit(
                f"Aeneas {phase} binary hash mismatch for {name}: "
                f"expected={expected} actual={actual}"
            )


def apply_interpreter_repair(directory: Path, toolchain: dict[str, str]) -> None:
    policy = toolchain["interpreter_repair"]
    if policy == "none":
        return
    if policy != "replace_exact_bytes_v1":
        raise SystemExit(f"unsupported Aeneas interpreter repair policy: {policy}")

    before = toolchain["interpreter_before"].encode("ascii") + b"\0"
    after = toolchain["interpreter_after"].encode("ascii") + b"\0"
    if len(after) > len(before):
        raise SystemExit("Aeneas interpreter repair replacement does not fit")
    replacement = after + b"\0" * (len(before) - len(after))

    for name in ("charon", "charon-driver"):
        path = directory / name
        contents = path.read_bytes()
        if contents.count(before) != 1:
            raise SystemExit(
                f"Aeneas interpreter repair expected one loader marker in {name}"
            )
        path.write_bytes(contents.replace(before, replacement))
        path.chmod(0o755)


def verify_executables(directory: Path) -> None:
    environment = os.environ.copy()
    environment["PATH"] = f"{directory}:{environment.get('PATH', '')}"
    for command in (("aeneas", "--help"), ("charon", "--help")):
        completed = subprocess.run(
            [str(directory / command[0]), command[1]],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"installed {command[0]} is not executable: {completed.stderr.strip()}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--archive",
        type=Path,
        help="Use a local release archive after verifying its registered digest.",
    )
    args = parser.parse_args()

    registry_bytes = REGISTRY_PATH.read_bytes()
    registry = tomllib.loads(registry_bytes.decode("utf-8"))
    if registry.get("schema") != "chio.aeneas-production.v1":
        raise SystemExit("Aeneas production registry schema mismatch")

    architecture = host_architecture()
    toolchain = selected_toolchain(registry, architecture)
    release_tag = registry["vendor_release_tag"]
    release_url = (
        "https://github.com/AeneasVerif/aeneas/releases/download/"
        f"{release_tag}/{toolchain['archive_asset']}"
    )
    destination = REPO / "target/formal/aeneas-toolchain" / architecture
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f".{architecture}-", dir=destination.parent
    ) as temporary:
        temporary_path = Path(temporary)
        archive = temporary_path / toolchain["archive_asset"]
        if args.archive is None:
            download_archive(release_url, archive)
        else:
            if not args.archive.is_file() or args.archive.is_symlink():
                raise SystemExit(f"Aeneas release archive is not a regular file: {args.archive}")
            shutil.copyfile(args.archive, archive)

        archive_digest = sha256(archive)
        if archive_digest != toolchain["archive_sha256"]:
            raise SystemExit(
                "Aeneas release archive hash mismatch: "
                f"expected={toolchain['archive_sha256']} actual={archive_digest}"
            )

        staging = temporary_path / "install"
        binary_dir = staging / "bin"
        binary_dir.mkdir(parents=True)
        extract_binaries(archive, binary_dir)
        verify_hashes(binary_dir, toolchain, "official")
        apply_interpreter_repair(binary_dir, toolchain)
        verify_hashes(binary_dir, toolchain, "runtime")
        verify_executables(binary_dir)

        receipt = {
            "schema": "chio.aeneas-toolchain-install.v1",
            "architecture": architecture,
            "releaseTag": release_tag,
            "releaseUrl": release_url,
            "archiveAsset": toolchain["archive_asset"],
            "archiveSha256": archive_digest,
            "interpreterRepair": toolchain["interpreter_repair"],
            "registrySha256": hashlib.sha256(registry_bytes).hexdigest(),
            "runtimeSha256": {
                name: sha256(binary_dir / name) for name in BINARY_NAMES
            },
        }
        (staging / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise SystemExit(f"refusing to replace invalid toolchain path: {destination}")
            shutil.rmtree(destination)
        os.replace(staging, destination)

    print(f"Installed authenticated Aeneas toolchain at {destination}")


if __name__ == "__main__":
    main()
