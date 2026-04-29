#!/usr/bin/env python3
"""Fail on wildcard registry dependencies while allowing local path deps."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
SKIP_DIRS = {".git", "target", ".planning"}


def cargo_manifests() -> list[Path]:
    manifests: list[Path] = []
    for path in ROOT.rglob("Cargo.toml"):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        manifests.append(path)
    return sorted(manifests)


def dependency_tables(node: dict[str, Any], prefix: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    tables: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    for key, value in node.items():
        path = (*prefix, key)
        if key in DEPENDENCY_TABLES and isinstance(value, dict):
            tables.append((path, value))
            continue
        if isinstance(value, dict):
            tables.extend(dependency_tables(value, path))
    return tables


def version_is_wildcard(version: str) -> bool:
    return "*" in version.strip()


def check_dependency(manifest: Path, table_path: tuple[str, ...], name: str, spec: Any) -> list[str]:
    location = f"{manifest.relative_to(ROOT)} [{'.'.join(table_path)}] {name}"
    if isinstance(spec, str):
        if version_is_wildcard(spec):
            return [f"{location}: wildcard registry dependency version {spec!r}"]
        return []

    if not isinstance(spec, dict):
        return [f"{location}: unsupported dependency specification"]

    if spec.get("workspace") is True or "path" in spec:
        return []

    version = spec.get("version")
    if version is None:
        if "git" in spec:
            return []
        return [f"{location}: registry dependency is missing an explicit version"]
    if not isinstance(version, str):
        return [f"{location}: dependency version must be a string"]
    if version_is_wildcard(version):
        return [f"{location}: wildcard registry dependency version {version!r}"]
    return []


def main() -> int:
    violations: list[str] = []
    for manifest in cargo_manifests():
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for table_path, table in dependency_tables(data):
            for name, spec in table.items():
                violations.extend(check_dependency(manifest, table_path, name, spec))

    if violations:
        print("External wildcard dependency check failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print("external wildcard dependency check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
