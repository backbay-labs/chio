"""The supported Python SDK verifies the venue proof and purchase terminal."""
import asyncio
import json
import sys
import sqlite3
import hashlib
from pathlib import Path
from chio_sdk import CognitionMarketBuyer, CognitionMarketSeller, CognitionMarketError


def purchase_state(venue):
    # The owned venue database is the effect authority, independent of SDK output.
    with sqlite3.connect(f"file:{venue / 'operator.db'}?mode=ro", uri=True) as database:
        names = [row[0] for row in database.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE '%purchase%' ORDER BY name")]
        if "chio_finding_operator_purchase_jobs" not in names:
            raise RuntimeError("The venue purchase store is unavailable for the negative control")
        state = {}
        for name in names:
            rows = database.execute('SELECT * FROM "' + name.replace('"', '""') + '"').fetchall()
            encoded = repr(sorted(rows, key=repr)).encode()
            state[name] = {"rows": len(rows), "sha256": hashlib.sha256(encoded).hexdigest()}
        return state

async def main(config):
    venue = Path(config["venue"])
    if config["action"] in {"offer", "nonfix"}:
        async with CognitionMarketSeller(venue / "seller-client.json") as seller:
            try:
                package = await seller.package_verified_fix(
                    repository=config["repository"], base=config["base"], candidate=config["candidate"],
                    tests=["python3 -m unittest -v test_analysis"], topic="coding/sliding-window-analysis", price=config["price"],
                )
                admitted = await seller.admit(package)
            except CognitionMarketError as error:
                if config["action"] == "nonfix":
                    return {"refused": True, "reason": str(error)}
                raise
            if config["action"] == "nonfix":
                raise RuntimeError("A non-fixing candidate was admitted")
        return {"offer": admitted}
    async with CognitionMarketBuyer(venue / "buyer-client.json", chio_binary=Path(config["chio"])) as buyer:
        proof = await buyer.verified_proof(config["finding_id"])
        if config["action"] == "tamper":
            altered = json.loads(proof.proof)
            # Alter signed evidence, preserving JSON readability.
            altered["bundle"]["finding"]["payload_sha256"] = "0" * 64
            try:
                await buyer.verify_proof(json.dumps(altered).encode())
            except CognitionMarketError as error:
                return {"refused": True, "reason": str(error)}
            raise RuntimeError("Changed proof was accepted")
        before = purchase_state(venue)
        try:
            purchased = await buyer.purchase_verified_fix(proof, max_price_units=config["max_price"])
        except CognitionMarketError as error:
            after = purchase_state(venue)
            if before != after:
                raise RuntimeError("Refused purchase advanced venue purchase state") from error
            return {"status": "refused", "reason": str(error), "purchase_state_unchanged": True, "purchase_state": after}
        repeated = await buyer.purchase_verified_fix(proof, max_price_units=config["max_price"])
        if repeated.request != purchased.request or repeated.purchase != purchased.purchase:
            raise RuntimeError("Repeated purchase did not recover the same terminal result")
        Path(config["patch"]).write_text(purchased.patch, encoding="utf-8")
        return {"status": "delivered", "finding_id": purchased.finding_id,
                "base_revision": purchased.base_revision, "candidate_revision": purchased.candidate_revision,
                "patch": purchased.patch, "request": purchased.request, "purchase": purchased.purchase,
                "repeated_purchase": "same request and retained terminal; no second purchase"}

if __name__ == "__main__":
    print(json.dumps(asyncio.run(main(json.loads(Path(sys.argv[1]).read_text())))))
