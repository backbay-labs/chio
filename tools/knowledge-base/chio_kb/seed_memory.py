"""Seed curated Graphiti memory episodes for Chio agents."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
from typing import Any

from chio_kb import query

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_SEED_DIR = ROOT / "seeds" / "graphiti"


def default_seed_dir() -> pathlib.Path:
    repo_seed_dir = pathlib.Path(os.environ.get("CHIO_KB_REPO_ROOT", "/workspace")) / "ops" / "knowledge-base" / "seeds" / "graphiti"
    if repo_seed_dir.exists():
        return repo_seed_dir
    return PACKAGE_SEED_DIR


def _load_episode(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    if not payload.get("name"):
        raise ValueError(f"{path} is missing name.")
    return payload


async def _add_episode(path: pathlib.Path) -> dict[str, Any]:
    episode = _load_episode(path)
    body = json.dumps(episode, sort_keys=True)
    source_description = episode.get("source_description") or f"Curated Chio KB seed: {path.name}"
    try:
        existing = await query.get_episodes(limit=100)
        for item in existing.get("episodes", []):
            if not isinstance(item, dict):
                continue
            if item.get("name") == episode["name"] and item.get("source_description") == source_description:
                uuid = item.get("uuid")
                if uuid:
                    await query.delete_episode(str(uuid))
    except Exception:
        pass
    try:
        result = await query.add_memory(
            str(episode["name"]),
            body,
            source_description=source_description,
            source="json",
        )
        source = "json"
    except Exception:
        result = await query.add_memory(
            str(episode["name"]),
            body,
            source_description=source_description,
            source="text",
        )
        source = "text"
    return {"path": str(path), "name": episode["name"], "source": source, "result": result}


async def seed_graphiti(seed_dir: pathlib.Path | None = None) -> dict[str, Any]:
    seed_dir = seed_dir or default_seed_dir()
    paths = sorted(seed_dir.glob("*.json"))
    results: list[dict[str, Any]] = []
    for path in paths:
        results.append(await _add_episode(path))
    return {"seed_dir": str(seed_dir), "episode_count": len(results), "episodes": results}


async def _main_async(args: argparse.Namespace) -> int:
    result = await seed_graphiti(pathlib.Path(args.seed_dir) if args.seed_dir else None)
    print(json.dumps(result, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Graphiti with curated Chio KB episodes.")
    parser.add_argument("--seed-dir", default=None)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main_async(args)))


if __name__ == "__main__":
    main()
