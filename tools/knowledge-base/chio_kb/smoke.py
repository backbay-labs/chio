"""Smoke checks for the local Chio knowledge-base stack."""

from __future__ import annotations

import argparse
import asyncio
import json
import urllib.request

from chio_kb import query


def _http_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


async def _run(skip_services: bool) -> int:
    if not skip_services:
        health = await query.health()
        print(json.dumps({"database_health": health}, indent=2, sort_keys=True))
    tools = _http_json("http://localhost:8111/tools")
    tool_names = {tool["name"] for tool in tools["tools"]}
    expected = {
        "kb_search_code",
        "kb_search_docs",
        "kb_find_tests",
        "kb_find_docs",
        "kb_neighbors",
        "kb_context",
        "kb_impact",
        "kb_brief_feature",
        "kb_eval",
        "kb_add_episode",
    }
    missing = sorted(expected - tool_names)
    print(json.dumps({"tools": sorted(tool_names), "missing": missing}, indent=2))
    if missing:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-services", action="store_true")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args.skip_services)))


if __name__ == "__main__":
    main()
