#!/usr/bin/env python3
"""Fail when Cargo.lock duplicate versions drift from the reviewed baseline."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "cargo-deny-duplicate-baseline.txt"
LOCKFILE = ROOT / "Cargo.lock"


def version_key(version: str) -> tuple[object, ...]:
    normalized = version.replace("+", ".").replace("-", ".")
    key: list[object] = []
    for part in normalized.split("."):
        key.append(int(part) if part.isdigit() else part)
    return tuple(key)


def duplicate_inventory() -> list[str]:
    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    versions: defaultdict[str, set[str]] = defaultdict(set)
    for package in lock.get("package", []):
        versions[package["name"]].add(package["version"])
    lines = []
    for name in sorted(versions):
        if len(versions[name]) > 1:
            ordered = sorted(versions[name], key=version_key)
            lines.append(f"{name} {' '.join(ordered)}")
    return lines


def main() -> int:
    expected = BASELINE.read_text(encoding="utf-8").splitlines()
    actual = duplicate_inventory()
    if actual == expected:
        print("cargo-deny duplicate baseline matches Cargo.lock")
        return 0

    print("Cargo.lock duplicate-version inventory drifted from baseline.", file=sys.stderr)
    print("Refresh scripts/cargo-deny-duplicate-baseline.txt only after review.", file=sys.stderr)
    expected_set = set(expected)
    actual_set = set(actual)
    for line in sorted(actual_set - expected_set):
        print(f"+ {line}", file=sys.stderr)
    for line in sorted(expected_set - actual_set):
        print(f"- {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
