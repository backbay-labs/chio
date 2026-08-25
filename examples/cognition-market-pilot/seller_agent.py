#!/usr/bin/env python3
"""Package and admit one verified fix through a scoped seller credential."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from chio_sdk import CognitionMarketSeller


async def run(arguments: argparse.Namespace) -> None:
    async with CognitionMarketSeller(arguments.credential) as seller:
        package = await seller.package_verified_fix(
            repository=arguments.repository,
            base=arguments.base,
            candidate=arguments.candidate,
            tests=arguments.test,
            topic=arguments.topic,
            price=arguments.price,
        )
        admitted = await seller.admit(package)
    print(json.dumps(admitted, separators=(",", ":"), sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--test", action="append", required=True)
    parser.add_argument("--topic", required=True)
    parser.add_argument("--price", type=int, default=300)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
