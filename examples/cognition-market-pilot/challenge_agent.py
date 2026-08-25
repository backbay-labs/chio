#!/usr/bin/env python3
"""Purchase and file a controlled evidence-invalid challenge as one buyer."""

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
        purchase = await buyer.purchase(verified, max_price_units=arguments.max_price)
        challenge = await buyer.challenge_evidence_invalid(verified, purchase)
    result = {
        "challengeId": challenge["challengeId"],
        "findingId": arguments.finding,
        "settlement": purchase["settlement"],
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential", type=Path, required=True)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--max-price", type=int, default=300)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
