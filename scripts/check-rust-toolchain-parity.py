#!/usr/bin/env python3
"""Fail when production Rust builders drift from the workspace toolchain."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


PRODUCTION_DOCKERFILES = (
    Path("deploy/docker/Dockerfile"),
    Path("deploy/docker/Dockerfile.sidecar"),
    Path("deploy/docker/Dockerfile.tee"),
    Path("deploy/sidecar/Dockerfile"),
)
ALPINE_DOCKERFILES = PRODUCTION_DOCKERFILES[:3]
GENERATED_MANIFEST = Path("deploy/docker/chio-workspace/Cargo.toml")
RUST_VERSION_RE = re.compile(r"(?m)^ARG RUST_VERSION=([^\s#]+)\s*$")
RUST_FROM_RE = re.compile(r"(?m)^FROM rust:[^\s]+(?:\s+AS\s+\S+)?\s*$")
DIGEST_RE = re.compile(r"@sha256:([0-9a-f]{64})(?=\s|$)")


def read_toml(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read valid TOML from {path}: {error}") from error


def nested_string(document: dict[str, object], path: tuple[str, ...], source: Path) -> str:
    value: object = document
    for component in path:
        if not isinstance(value, dict) or component not in value:
            joined = ".".join(path)
            raise ValueError(f"{source} is missing {joined}")
        value = value[component]
    if not isinstance(value, str) or not value:
        joined = ".".join(path)
        raise ValueError(f"{source} must define non-empty string {joined}")
    return value


def release_prefix(version: str) -> str:
    parts = version.split(".")
    if len(parts) < 2 or any(not part.isdigit() for part in parts):
        raise ValueError(f"unsupported Rust release version: {version!r}")
    return ".".join(parts[:2])


def check(repo_root: Path) -> list[str]:
    errors: list[str] = []
    toolchain_path = repo_root / "rust-toolchain.toml"
    root_manifest_path = repo_root / "Cargo.toml"
    generated_manifest_path = repo_root / GENERATED_MANIFEST

    try:
        toolchain = nested_string(
            read_toml(toolchain_path), ("toolchain", "channel"), toolchain_path
        )
        workspace_msrv = nested_string(
            read_toml(root_manifest_path),
            ("workspace", "package", "rust-version"),
            root_manifest_path,
        )
        generated_msrv = nested_string(
            read_toml(generated_manifest_path),
            ("workspace", "package", "rust-version"),
            generated_manifest_path,
        )
        if release_prefix(toolchain) != workspace_msrv:
            errors.append(
                f"workspace rust-version {workspace_msrv!r} must match the "
                f"toolchain release {release_prefix(toolchain)!r}"
            )
        if generated_msrv != workspace_msrv:
            errors.append(
                f"{GENERATED_MANIFEST} rust-version {generated_msrv!r} must "
                f"match workspace rust-version {workspace_msrv!r}"
            )
    except ValueError as error:
        return [str(error)]

    alpine_digests: set[str] = set()
    for relative_path in PRODUCTION_DOCKERFILES:
        path = repo_root / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"cannot read {relative_path}: {error}")
            continue

        pins = RUST_VERSION_RE.findall(text)
        if pins != [toolchain]:
            actual = pins[0] if len(pins) == 1 else pins
            errors.append(
                f"{relative_path} must have exactly one ARG RUST_VERSION={toolchain}; "
                f"found {actual!r}"
            )

        rust_from_lines = RUST_FROM_RE.findall(text)
        if not rust_from_lines:
            errors.append(f"{relative_path} has no Rust builder FROM line")
            continue
        for from_line in rust_from_lines:
            if "${RUST_VERSION}" not in from_line:
                errors.append(
                    f"{relative_path} Rust builder must use the RUST_VERSION argument: "
                    f"{from_line}"
                )
            digests = DIGEST_RE.findall(from_line)
            if len(digests) != 1:
                errors.append(
                    f"{relative_path} Rust builder must have exactly one sha256 digest: "
                    f"{from_line}"
                )
            elif relative_path in ALPINE_DOCKERFILES:
                alpine_digests.add(digests[0])

    if len(alpine_digests) != 1:
        errors.append(
            "Alpine production Rust builders must use one lockstep image digest; "
            f"found {sorted(alpine_digests)!r}"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()
    errors = check(args.repo_root.resolve())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("Rust toolchain, workspace manifests, and production builders are aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
