#!/usr/bin/env python3
"""Fail when a cargo-vet config adds net-new exemption blocks."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

EXEMPTION_HEADER = re.compile(r"^\s*\[\[exemptions\.([^\]]+)\]\]\s*$")


def exemption_names(path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = EXEMPTION_HEADER.match(line)
        if match:
            names.add(match.group(1).strip().strip('"'))
    return names


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare cargo-vet exemption counts between two config files."
    )
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--head", required=True, type=pathlib.Path)
    args = parser.parse_args()

    base_exemptions = exemption_names(args.base)
    head_exemptions = exemption_names(args.head)
    base_count = len(base_exemptions)
    head_count = len(head_exemptions)
    added = sorted(head_exemptions - base_exemptions)
    print(f"cargo-vet exemption count: base={base_count} head={head_count}")

    if added:
        print(
            "net-new cargo-vet exemptions are blocked: " + ", ".join(added),
            file=sys.stderr,
        )
        print(
            "add real audits or get an "
            "explicit cargo-vet-exemption-justification PR comment",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
