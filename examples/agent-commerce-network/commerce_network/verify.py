"""Independently verify the live work, signatures and balanced book settlement."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chio.invariants import (
    canonicalize_json,
    sha256_hex_utf8,
    verify_http_receipt_with_trusted_signers,
    verify_receipt_with_trusted_signers,
)


def verify_bundle(bundle_path, *, trusted_signers):
    root = Path(bundle_path)
    errors = []

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    try:
        run = json.loads((root / "agent-output.json").read_text())
        summary = json.loads((root / "summary.json").read_text())
        receipts = json.loads((root / "receipts.json").read_text())
        require(
            run["final_status"] == summary["final_status"] == "fulfilled",
            "The run did not fulfill its job",
        )
        require(receipts["http"] and receipts["mcp"], "Both HTTP and MCP records are required")
        outputs = {}
        ids = set()
        for item in receipts["mcp"]:
            receipt, association = item["receipt"], item["association"]
            require(
                verify_receipt_with_trusted_signers(receipt, trusted_signers)["ok"],
                "Invalid or untrusted provider receipt",
            )
            require(
                receipt["id"] == association["receipt_id"] and receipt["id"] not in ids,
                "Provider receipt association reused or changed",
            )
            ids.add(receipt["id"])
            require(
                receipt["metadata"]["receipt_context"]["request_id"] == association["request_id"],
                "Wrong provider request association",
            )
            require(
                receipt["tool_name"] == association["tool_name"]
                and receipt["action"]["parameters"] == association["arguments"],
                "Wrong provider tool or arguments",
            )
            require(
                receipt["decision"]["verdict"] == "allow", "Provider operation was not authorized"
            )
            require(
                sha256_hex_utf8(canonicalize_json(association["result"]))
                == receipt["content_hash"],
                "Provider output differs from the signed output hash",
            )
            outputs[receipt["tool_name"]] = association["result"]["structuredContent"]
        for item in receipts["http"]:
            receipt, association = item["receipt"], item["association"]
            require(
                verify_http_receipt_with_trusted_signers(receipt, trusted_signers)["ok"],
                "Invalid or untrusted HTTP receipt",
            )
            require(
                receipt["id"] == association["receipt_id"] and receipt["id"] not in ids,
                "HTTP receipt association reused or changed",
            )
            ids.add(receipt["id"])
            require(
                receipt["method"] == association["method"]
                and receipt["response_status"] == association["status"],
                "HTTP method or outcome changed",
            )
            binding = {
                "method": association["method"],
                "route_pattern": receipt["route_pattern"],
                "path": association["path"],
                "query": {},
                "body_hash": association["body_sha256"],
            }
            # HTTPX writes JSON compactly with ensure_ascii=False. Recreate
            # those bytes instead of trusting a supplied body hash alone.
            expected_body_hash = (
                hashlib.sha256(
                    json.dumps(
                        association["body"],
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest()
                if association["body"] is not None
                else None
            )
            require(
                expected_body_hash == association["body_sha256"],
                "HTTP request bytes differ from the retained body",
            )
            require(
                sha256_hex_utf8(canonicalize_json(binding)) == receipt["content_hash"],
                "HTTP receipt belongs to different request content",
            )
            require(
                receipt["capability_id"] == association["capability_id"],
                "HTTP receipt names another grant",
            )
            require(
                receipt["metadata"]["chio_http_status_scope"] == "final",
                "HTTP record is not a final response",
            )
        quote = json.loads((root / "contracts/quote-response.json").read_text())
        fulfillment = json.loads((root / "contracts/fulfillment-package.json").read_text())
        settlement = json.loads((root / "contracts/settlement-reconciliation.json").read_text())
        # approval_required is a buyer decision, so compare the provider's
        # immutable quote identity and price independently of that local field.
        require(
            quote["quote_id"] == outputs["request_quote"]["quote_id"]
            and quote["price_minor"] == outputs["request_quote"]["price_minor"],
            "Quote differs from provider evidence",
        )
        require(
            fulfillment == outputs["execute_review"],
            "Fulfillment differs from signed provider output",
        )
        require(
            fulfillment["job_id"] == settlement["job_id"] == run["job_id"],
            "Work and settlement belong to different jobs",
        )
        require(fulfillment["artifacts"], "No work product was delivered")
        for artifact in fulfillment["artifacts"]:
            require(
                hashlib.sha256(artifact["content"].encode()).hexdigest() == artifact["sha256"],
                "Delivered artifact hash mismatch",
            )
        amount = quote["price_minor"]
        require(
            settlement["status"] == "reconciled"
            and settlement["settlement_kind"] == "internal_book_entry",
            "Missing completed book settlement",
        )
        require(settlement["settled_amount_minor"] == amount, "Settlement price differs from quote")
        entries = settlement["entries"]
        require(
            sorted(entry["amount_minor"] for entry in entries) == [-amount, amount],
            "Settlement entries are not balanced",
        )
        ledger = json.loads((root / "financial/book-ledger.json").read_text())
        stored = [entry for entry in ledger if entry["job_id"] == run["job_id"]]
        require(
            sorted((entry["account"], entry["amount_minor"]) for entry in stored)
            == sorted((entry["account"], entry["amount_minor"]) for entry in entries),
            "Settlement differs from the retained ledger",
        )
        return {
            "ok": True,
            "agent_status": run["final_status"],
            "agent_mode": run["mode"],
            "verified_receipts": len(ids),
            "artifacts": len(fulfillment["artifacts"]),
            "settled_amount_minor": amount,
            "settlement_kind": "internal_book_entry",
            "errors": [],
        }
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(str(error))
    return {"ok": False, "errors": errors}
