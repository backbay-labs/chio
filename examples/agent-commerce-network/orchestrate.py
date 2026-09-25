#!/usr/bin/env python3
"""Run a governed procurement request and retain the returned work and book settlement."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from commerce_network.agents import run_procurement_agent
from commerce_network.chio import TrustControl
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("commerce-network")


def _now() -> int:
    return int(time.time())


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _usd(cents: int) -> dict:
    return {"units": cents, "currency": "USD"}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    p = argparse.ArgumentParser()
    p.add_argument("--control-url", required=True)
    p.add_argument("--service-token", required=True)
    p.add_argument("--buyer-url", required=True, help="Buyer sidecar URL (chio api protect)")
    p.add_argument("--buyer-auth-token", default="demo-token")
    p.add_argument("--artifact-dir")
    p.add_argument(
        "--scope",
        default="hotfix-review",
        choices=[
            "hotfix-review",
            "release-review",
            "release-plus-cloud-review",
            "full-estate-review",
        ],
    )
    p.add_argument("--target", default="payments-api")
    p.add_argument("--budget-minor", type=int, default=90_000, help="Budget in cents")
    p.add_argument("--release-window", default=None)
    args = p.parse_args(argv)

    out = (
        Path(args.artifact_dir)
        if args.artifact_dir
        else (ROOT / "artifacts" / "live" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    )
    out.mkdir(parents=True, exist_ok=True)

    trust = TrustControl(args.control_url, args.service_token)

    # The HTTP gateway admits only the operator-issued application grant.
    # The buyer owns quoted-price reservations and its persistent book ledger.
    cap = trust.issue_capability(
        subject_pk=SigningKey.generate().verify_key.encode().hex(),
        scope={
            "grants": [
                {
                    "server_id": "chio_http_authority",
                    "tool_name": "authorize_http_request",
                    "operations": ["invoke"],
                    "constraints": [],
                }
            ],
            "resource_grants": [],
            "prompt_grants": [],
        },
        ttl=3600,
    )
    _write(out / "capability.json", cap)

    # -- Run procurement agent --
    agent_out = run_procurement_agent(
        buyer_url=args.buyer_url,
        auth_token=args.buyer_auth_token,
        capability_token=cap,
        scope=args.scope,
        target=args.target,
        budget_minor=args.budget_minor,
        release_window=args.release_window,
    )
    _write(out / "agent-output.json", agent_out)

    # -- Extract contracts from agent tool calls --
    (out / "contracts").mkdir(parents=True, exist_ok=True)
    for call in agent_out.get("tool_calls", []):
        tool_out = call.get("output", {})
        if call["tool"] == "request_quote" and "quote" in tool_out:
            _write(out / "contracts" / "quote-response.json", tool_out["quote"])
        elif call["tool"] == "create_job" or call["tool"] == "approve_job":
            if "fulfillment" in tool_out and tool_out["fulfillment"]:
                _write(out / "contracts" / "fulfillment-package.json", tool_out["fulfillment"])
            if "settlement" in tool_out and tool_out["settlement"]:
                _write(out / "contracts" / "settlement-reconciliation.json", tool_out["settlement"])

    # -- Summary --
    summary = {
        "example": "agent-commerce-network",
        "scope": args.scope,
        "target": args.target,
        "budget_minor": args.budget_minor,
        "capability_id": cap["id"],
        "final_status": agent_out.get("final_status"),
        "price_minor": agent_out.get("price_minor"),
        "currency": agent_out.get("currency", "USD"),
        "agent_mode": agent_out.get("mode"),
        "tool_calls": len(agent_out.get("tool_calls", [])),
        "llm_mode": agent_out.get("mode"),
    }
    _write(out / "summary.json", summary)

    json.dump({"artifact_dir": str(out), "summary": summary}, sys.stdout, indent=2)
    print()
    return (
        0
        if summary["final_status"] in {"fulfilled", "pending_approval", "denied_budget", "disputed"}
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
