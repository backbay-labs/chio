#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from catalog import offer
from review import execute_review, open_dispute

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
APPROVAL_THRESHOLD_MINOR = 100_000


def contract_template(name: str) -> dict[str, Any]:
    return json.loads((CONTRACTS_DIR / name).read_text())


def random_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def respond(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def read_message() -> dict[str, Any]:
    while True:
        line = sys.stdin.readline()
        if not line:
            raise EOFError("stdin closed")
        if line.strip():
            return json.loads(line)


def quote_payload(arguments: dict[str, Any]) -> dict[str, Any]:
    template = deepcopy(contract_template("quote-response.json"))
    scope = arguments["requested_scope"]
    selected = offer(scope)
    price_minor = selected["price_minor"]
    template.update(
        {
            "quote_id": random_id("quote"),
            "provider_id": "vanguard-security",
            "offer_id": scope,
            "checks": selected["checks"],
            "max_files": selected["max_files"],
            "max_bytes": selected["max_bytes"],
            "target": arguments["target"],
            "request_id": arguments["request_id"],
            "service_family": arguments["service_family"],
            "price_minor": price_minor,
            "approval_required": price_minor > APPROVAL_THRESHOLD_MINOR,
            "pricing_basis": f"bounded {scope} for {arguments['target']}",
        }
    )
    return template


def fulfillment_payload(arguments: dict[str, Any]) -> dict[str, Any]:
    return execute_review(arguments)


def dispute_payload(arguments: dict[str, Any]) -> dict[str, Any]:
    return open_dispute(arguments)


TOOLS = [
    {
        "name": "request_quote",
        "title": "Request Quote",
        "description": "Return a governed quote for the security-review service family.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "buyer_id": {"type": "string"},
                "service_family": {"type": "string"},
                "target": {"type": "string"},
                "requested_scope": {"type": "string"},
                "release_window": {"type": ["string", "null"]},
            },
            "required": ["request_id", "buyer_id", "service_family", "target", "requested_scope"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "execute_review",
        "title": "Execute Review",
        "description": "Execute the priced security review and return a fulfillment artifact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "quote_id": {"type": "string"},
                "service_family": {"type": "string"},
                "requested_scope": {"type": "string"},
                "target": {"type": "string"},
                "release_window": {"type": ["string", "null"]},
            },
            "required": ["job_id", "quote_id", "service_family", "requested_scope", "target"],
        },
    },
    {
        "name": "open_dispute",
        "title": "Open Dispute",
        "description": "Record a provider-visible dispute against a fulfilled review.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "reason_code": {"type": "string"},
                "summary": {"type": "string"},
            },
            "required": ["job_id", "reason_code", "summary"],
        },
    },
]


def tool_result(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "request_quote":
        structured = quote_payload(arguments)
        summary = f"quoted {structured['service_family']} at {structured['price_minor']} {structured['currency']}"
    elif name == "execute_review":
        structured = fulfillment_payload(arguments)
        summary = f"completed {structured['service_family']} for job {structured['job_id']}"
    elif name == "open_dispute":
        structured = dispute_payload(arguments)
        summary = f"opened dispute {structured['dispute_id']} for job {structured['job_id']}"
    else:
        raise KeyError(name)
    return {
        "content": [{"type": "text", "text": summary}],
        "structuredContent": structured,
        "isError": False,
    }


while True:
    try:
        message = read_message()
    except EOFError:
        break

    method = message.get("method")

    if method == "initialize":
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "vanguard-security-review",
                        "version": "0.1.0",
                    },
                },
            }
        )
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        continue

    if method == "tools/call":
        name = message.get("params", {}).get("name")
        arguments = message.get("params", {}).get("arguments", {})
        try:
            result = tool_result(name, arguments)
        except KeyError:
            respond(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": f"unsupported tool: {name}"},
                }
            )
            continue
        except (ValueError, OSError, SyntaxError, RecursionError) as error:
            result = {"content": [{"type": "text", "text": str(error)}], "isError": True}
        respond({"jsonrpc": "2.0", "id": message["id"], "result": result})
        continue

    if message.get("id") is not None:
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"unsupported method: {method}"},
            }
        )
