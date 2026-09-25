"""Export records associated with actual buyer and provider responses."""

import json
import sqlite3
import sys
from pathlib import Path


def export(root, state=None):
    root = Path(root)
    state = Path(state) if state is not None else root / "state"
    run = json.loads((root / "agent-output.json").read_text())
    calls = run["tool_calls"]
    http, tools = {}, {}
    with (
        sqlite3.connect(
            (state / "buyer-receipts.sqlite3").resolve().as_uri() + "?mode=ro", uri=True
        ) as buyer,
        sqlite3.connect(
            (state / "trust-receipts.sqlite3").resolve().as_uri() + "?mode=ro", uri=True
        ) as provider,
    ):
        for call in calls:
            output = call.get("output", {})
            association = output.get("_chio_http")
            if association:
                identity = association["receipt_id"]
                row = buyer.execute(
                    "SELECT receipt_json FROM http_receipts WHERE id=?", (identity,)
                ).fetchone()
                if not row:
                    raise ValueError("Missing HTTP receipt " + identity)
                http[identity] = {"association": association, "receipt": json.loads(row[0])}
            for key in ("provider_trace", "quote_provider_trace", "fulfillment_trace"):
                trace = output.get(key)
                if not trace:
                    continue
                identity = trace["receipt_id"]
                row = provider.execute(
                    "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id=?", (identity,)
                ).fetchone()
                if not row:
                    raise ValueError("Missing provider receipt " + identity)
                tools[identity] = {"association": trace, "receipt": json.loads(row[0])}
    records = {"http": list(http.values()), "mcp": list(tools.values())}
    (root / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
    with sqlite3.connect((state / "buyer.db").resolve().as_uri() + "?mode=ro", uri=True) as db:
        ledger = [
            {"job_id": job, "account": account, "amount_minor": amount}
            for job, account, amount in db.execute(
                "SELECT job_id,account,amount FROM ledger ORDER BY job_id,account"
            )
        ]
    (root / "financial").mkdir(exist_ok=True)
    (root / "financial/book-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    return records


if __name__ == "__main__":
    export(sys.argv[1])
