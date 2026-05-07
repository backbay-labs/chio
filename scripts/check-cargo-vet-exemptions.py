#!/usr/bin/env python3
"""Fail when a cargo-vet config adds net-new exemption blocks.

Each exemption block is keyed on (name, version, criteria). Adding a row for
an already-exempt name, escalating criteria from `safe-to-run` to
`safe-to-deploy`, or repeating a name@version with a different criteria all
count as net-new exemptions.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

EXEMPTION_HEADER = re.compile(r"^\s*\[\[exemptions\.([^\]]+)\]\]\s*$")
VERSION_LINE = re.compile(r"^\s*version\s*=\s*[\"']([^\"']+)[\"']\s*$")
CRITERIA_LINE_STRING = re.compile(r"^\s*criteria\s*=\s*[\"']([^\"']+)[\"']\s*$")
CRITERIA_LINE_LIST = re.compile(r"^\s*criteria\s*=\s*\[(.+)\]\s*$")


def _parse_criteria_list(payload: str) -> str:
    items = [
        item.strip().strip("\"'")
        for item in payload.split(",")
        if item.strip()
    ]
    return ",".join(sorted(items))


def exemption_entries(path: pathlib.Path) -> set[str]:
    entries: set[str] = set()
    current_name: str | None = None
    current_version: str | None = None
    current_criteria: str | None = None

    def flush_current() -> None:
        nonlocal current_name, current_version, current_criteria
        if current_name is not None:
            version = current_version or "<missing-version>"
            criteria = current_criteria or "<missing-criteria>"
            entries.add(f"{current_name}@{version}#{criteria}")
        current_name = None
        current_version = None
        current_criteria = None

    for line in path.read_text(encoding="utf-8").splitlines():
        match = EXEMPTION_HEADER.match(line)
        if match:
            flush_current()
            current_name = match.group(1).strip().strip('"')
            continue
        if current_name is None:
            continue
        version_match = VERSION_LINE.match(line)
        if version_match:
            current_version = version_match.group(1).strip()
            continue
        criteria_string_match = CRITERIA_LINE_STRING.match(line)
        if criteria_string_match:
            current_criteria = criteria_string_match.group(1).strip()
            continue
        criteria_list_match = CRITERIA_LINE_LIST.match(line)
        if criteria_list_match:
            current_criteria = _parse_criteria_list(
                criteria_list_match.group(1)
            )
            continue
    flush_current()
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare cargo-vet exemption counts between two config files."
    )
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--head", required=True, type=pathlib.Path)
    args = parser.parse_args()

    base_exemptions = exemption_entries(args.base)
    head_exemptions = exemption_entries(args.head)
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
