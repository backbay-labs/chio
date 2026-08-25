#!/usr/bin/env python3
"""Retract one retained Finding through its scoped seller credential."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from chio_sdk import CognitionMarketSeller


async def run(arguments: argparse.Namespace) -> None:
    async with CognitionMarketSeller(arguments.credential) as seller:
        result = await seller.retract(arguments.finding)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential", type=Path, required=True)
    parser.add_argument("--finding", required=True)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
