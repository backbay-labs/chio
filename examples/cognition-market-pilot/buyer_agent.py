#!/usr/bin/env python3
"""Verify and purchase one patch through a scoped buyer credential."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from chio_sdk import CognitionMarketBuyer


async def run(arguments: argparse.Namespace) -> None:
    async with CognitionMarketBuyer(
        arguments.credential,
        chio_binary=arguments.chio,
    ) as buyer:
        verified = await buyer.verified_proof(arguments.finding)
        purchased = await buyer.purchase_verified_fix(
            verified,
            max_price_units=arguments.max_price,
        )
    arguments.patch.write_text(purchased.patch, encoding="utf-8")
    result = {
        "baseRevision": purchased.base_revision,
        "candidateRevision": purchased.candidate_revision,
        "findingId": purchased.finding_id,
        "patch": str(arguments.patch),
        "settlement": purchased.purchase["settlement"],
        "verdict": purchased.purchase["verdict"],
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential", type=Path, required=True)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--max-price", type=int, default=300)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
