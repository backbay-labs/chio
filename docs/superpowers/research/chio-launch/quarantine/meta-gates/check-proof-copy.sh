#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 2
fi

python3 - <<'PY'
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
DEFAULT_ROOTS = (
    "docs/start-here",
    "docs/release",
)

MARKDOWN_SUFFIXES = {".md", ".mdx"}
BARE_ACP_RE = re.compile(r"(?<![A-Za-z0-9-])ACP(?!-[A-Za-z])(?![A-Za-z0-9-])")
ALLOW_CONTEXT_RE = re.compile(
    r"\b("
    r"ban(?:ned|s)?|block(?:ed|s)?|copy lint|do not|does not|must not|should not|never|"
    r"reject(?:ed|s)?|rejected|unsupported|without qualifier|fail(?:s|ed)?|"
    r"ambiguous|not imply|not a|not claim|historical|instead of|rather than|"
    r"without qualifying|too broad for proof|cannot|no "
    r")\b",
    re.IGNORECASE,
)

RULES = (
    (
        "standards.copy.ambiguous-acp",
        BARE_ACP_RE,
        "qualify ACP as ACP-Client, ACP-Commerce, or AGNTCY-ACP",
    ),
    (
        "copy.agent-web.universal-protocol",
        re.compile(r"\bChio is the universal agent protocol\b", re.IGNORECASE),
        "do not claim Chio replaces external agent protocols",
    ),
    (
        "copy.agent-web.native-authority-overclaim",
        re.compile(
            r"\bEvery external agent protocol natively verifies Chio authority\b",
            re.IGNORECASE,
        ),
        "external protocols are projection surfaces unless Chio mediates authority",
    ),
    (
        "copy.market.permissionless-marketplace",
        re.compile(
            r"\bChio (?:operates|runs) a permissionless provider marketplace\b",
            re.IGNORECASE,
        ),
        "proof evidence shows bounded provider selection context, not a live marketplace",
    ),
    (
        "copy.market.global-trust-score",
        re.compile(r"\bChio publishes a global trust score\b", re.IGNORECASE),
        "proof evidence supports local-policy scorecards, not global scores",
    ),
    (
        "copy.market.liquidity-pool",
        re.compile(r"\bChio (?:operates|runs) liquidity pools?\b", re.IGNORECASE),
        "proof evidence supports bounded collateral context, not liquidity pools",
    ),
    (
        "copy.market.underwriter-market",
        re.compile(r"\bChio operates an underwriter market\b", re.IGNORECASE),
        "proof evidence does not prove a live underwriter market",
    ),
    (
        "copy.market.slashing-court",
        re.compile(r"\bChio runs slashing courts?\b", re.IGNORECASE),
        "proof evidence shows jurisdiction receipts, not slashing courts",
    ),
)


def configured_roots() -> list[Path]:
    override = os.environ.get("CHIO_PROOF_COPY_ROOTS")
    raw_roots = override.split(os.pathsep) if override else list(DEFAULT_ROOTS)
    roots = []
    for raw in raw_roots:
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = ROOT / path
        roots.append(path)
    return roots


def iter_markdown(paths: list[Path]):
    for path in paths:
        if path.is_file() and path.suffix in MARKDOWN_SUFFIXES:
            yield path
            continue
        if not path.exists():
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix in MARKDOWN_SUFFIXES:
                yield child


def section_allows(stripped_line: str, current: bool) -> bool:
    lowered = stripped_line.lstrip("#").strip().lower().rstrip(":")
    if "copy lint should reject" in lowered:
        return True
    if lowered in {
        "disallowed",
        "rejected",
        "blocked",
        "do not use",
        "negative cases",
        "public claim blocks",
    }:
        return True
    if stripped_line.startswith("#"):
        return False
    if lowered in {"allowed", "use"}:
        return False
    return current


def context_allows(line: str, blocked_section: bool) -> bool:
    return blocked_section or ALLOW_CONTEXT_RE.search(line) is not None


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


failures: list[str] = []
for path in iter_markdown(configured_roots()):
    blocked_section = False
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        blocked_section = section_allows(line.strip(), blocked_section)
        for code, pattern, guidance in RULES:
            if not pattern.search(line):
                continue
            if context_allows(line, blocked_section):
                continue
            failures.append(f"{relative(path)}:{line_no}: {code}: {guidance}")

if failures:
    print("\\n".join(failures), file=sys.stderr)
    raise SystemExit(1)

print("OK proof copy boundary")
PY
