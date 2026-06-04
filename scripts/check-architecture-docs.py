#!/usr/bin/env python3
"""Check changed ARCHITECTURE.md files for minimum review value."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

BOUNDARY_RE = re.compile(r"\b(boundary|public surface|scope|owns|does not own)\b", re.I)
TRUST_RE = re.compile(
    r"\b(trust|security|invariant|fail-closed|authority|signed|canonical)\b",
    re.I,
)
VERIFY_RE = re.compile(
    r"\b(verification|test|tests|testing|coverage|regression|conformance|gate|smoke)\b",
    re.I,
)
WORD_RE = re.compile(r"[A-Za-z0-9_'-]+")
H2_RE = re.compile(r"^##\s+\S+", re.M)
MIN_NONBLANK_LINES = 10
MIN_WORDS = 180
MIN_H2_SECTIONS = 3


def changed_architecture_docs(base_ref: str) -> list[Path]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [
        REPO_ROOT / line
        for line in result.stdout.splitlines()
        if line.endswith("ARCHITECTURE.md")
    ]


def check_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    words = WORD_RE.findall(text)
    errors: list[str] = []
    if len(lines) < MIN_NONBLANK_LINES:
        errors.append(
            f"has {len(lines)} nonblank lines, expected at least {MIN_NONBLANK_LINES}"
        )
    if len(words) < MIN_WORDS:
        errors.append(f"has {len(words)} words, expected at least {MIN_WORDS}")
    if not BOUNDARY_RE.search(text):
        errors.append("does not describe a boundary, scope, or public surface")
    if not TRUST_RE.search(text):
        errors.append("does not describe trust, security, or canonical invariants")
    if not VERIFY_RE.search(text):
        errors.append("does not describe verification or test focus")
    h2_count = len(H2_RE.findall(text))
    if h2_count < MIN_H2_SECTIONS:
        errors.append(
            f"has {h2_count} second-level sections, expected at least {MIN_H2_SECTIONS}"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check changed ARCHITECTURE.md files for a useful boundary, "
            "trust, and verification baseline."
        )
    )
    parser.add_argument(
        "--base-ref",
        default="origin/main",
        help="base ref used when no file paths are supplied",
    )
    parser.add_argument("paths", nargs="*", help="specific ARCHITECTURE.md files to check")
    args = parser.parse_args()

    if args.paths:
        docs = [Path(path) for path in args.paths if path.endswith("ARCHITECTURE.md")]
    else:
        docs = changed_architecture_docs(args.base_ref)

    failures: list[str] = []
    for path in docs:
        absolute = path if path.is_absolute() else REPO_ROOT / path
        errors = check_file(absolute)
        if errors:
            display = absolute.relative_to(REPO_ROOT)
            for error in errors:
                failures.append(f"{display}: {error}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"architecture docs check passed ({len(docs)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
