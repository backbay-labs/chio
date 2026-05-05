#!/usr/bin/env python3
"""Fail when a cargo-vet config adds net-new exemption blocks."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

EXEMPTION_HEADER = re.compile(r"^\s*\[\[exemptions\.[^\]]+\]\]\s*$")


def exemption_count(path: pathlib.Path) -> int:
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if EXEMPTION_HEADER.match(line)
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare cargo-vet exemption counts between two config files."
    )
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--head", required=True, type=pathlib.Path)
    args = parser.parse_args()

    base_count = exemption_count(args.base)
    head_count = exemption_count(args.head)
    print(f"cargo-vet exemption count: base={base_count} head={head_count}")

    if head_count > base_count:
        print(
            "net-new cargo-vet exemptions are blocked; add real audits or get an "
            "explicit cargo-vet-exemption-justification PR comment",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
