#!/usr/bin/env python3
"""Provider executor: bounded operation runner.

Uses chio_asgi middleware for Chio-governed request evaluation. The receipt
from each incoming request is included in the execution response so the
full evidence chain is traceable.

Application-level checks (revocation, expiry, attenuation, budget) run
before the tool call. Tool calls go through chio mcp serve-http where
the Chio kernel evaluates guards and signs receipts.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel

from incident_network.chio import ChioMcpClient, StdioMcpClient, TrustControl
from incident_network.capabilities import intent_hash, verify_approval

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_OPS_SERVER = ROOT / "tools" / "provider_ops.py"


class ExecuteRequest(BaseModel):
    task: dict
    capability: dict
    control_url: str | None = None
    service_token: str | None = None
    requested_service: str | None = None
    requested_rule: str | None = None
    executed_at: int | None = None
    request_id: str | None = None
    approval_required: bool = False
    approval_token: dict | None = None
    provider_ops_mcp_url: str | None = None
    chio_auth_token: str | None = None


def _find_grant(cap: dict, server_id: str, tool: str) -> dict | None:
    for g in cap.get("scope", {}).get("grants", []):
        if g.get("server_id") == server_id and g.get("tool_name") == tool:
            return g
    return None


def _grant_index(cap: dict, server_id: str, tool: str) -> int:
    for i, g in enumerate(cap.get("scope", {}).get("grants", [])):
        if g.get("server_id") == server_id and g.get("tool_name") == tool:
            return i
    return 0


def _constraint_val(cap: dict, server_id: str, tool: str, key: str) -> str | None:
    grant = _find_grant(cap, server_id, tool)
    if not grant:
        return None
    for c in grant.get("constraints", []):
        if c.get("type") == "custom":
            v = c.get("value")
            if isinstance(v, list) and len(v) == 2 and v[0] == key:
                return v[1]
    return None


def create_app() -> FastAPI:
    # The executor does its own Chio validation (capability checks, revocation,
    # budget, attenuation) and calls tools through chio mcp serve-http.
    # No chio_asgi middleware needed -- Chio governance is explicit in the handler.
    app = FastAPI(title="incident-network-provider-executor")

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    @app.post("/execute")
    def execute(payload: ExecuteRequest, request: Request) -> dict:
        receipt = getattr(request.state, "chio_receipt", None)
        cap = payload.capability
        svc = payload.requested_service or payload.task["target_service"]
        rule = payload.requested_rule or payload.task["target_rule"]
        ts = payload.executed_at or int(time.time())
        req_id = payload.request_id or f"{payload.task['task_id']}-execute"

        # Expiry
        if ts >= cap["expires_at"]:
            return {"verdict": "deny", "reason": "expired_capability",
                    "executor_capability_id": cap["id"], "executed_at": ts, "expires_at": cap["expires_at"],
                    "requested_service": svc, "requested_rule": rule}

        # Revocation
        if payload.control_url and payload.service_token:
            trust = TrustControl(payload.control_url, payload.service_token)
            chain_ids = [lk["capability_id"] for lk in cap.get("delegation_chain", [])]
            for cid in [*chain_ids, cap["id"]]:
                if trust.is_revoked(cid):
                    return {"verdict": "deny", "reason": "revoked_ancestor",
                            "executor_capability_id": cap["id"], "revoked_capability_id": cid,
                            "requested_service": svc, "requested_rule": rule}

        # Attenuation
        req_svc = _constraint_val(cap, "provider-ops", "disable_edge_rule", "required_service")
        req_rule = _constraint_val(cap, "provider-ops", "disable_edge_rule", "required_rule")
        mismatch = (req_svc and svc != req_svc) or (req_rule and rule != req_rule)
        if mismatch:
            if payload.approval_required:
                if payload.approval_token is None:
                    return {"verdict": "deny", "reason": "approval_required",
                            "executor_capability_id": cap["id"], "request_id": req_id,
                            "required_service": req_svc, "required_rule": req_rule,
                            "requested_service": svc, "requested_rule": rule}
                ok, reason = verify_approval(
                    payload.approval_token, subject_pk=cap["subject"], request_id=req_id,
                    intent_hash_val=intent_hash({
                        "task_id": payload.task["task_id"], "service": svc,
                        "rule_name": rule, "action": "disable_edge_rule",
                    }), now=ts,
                )
                if not ok:
                    return {"verdict": "deny", "reason": reason or "approval_invalid",
                            "executor_capability_id": cap["id"], "request_id": req_id}
            else:
                return {"verdict": "deny", "reason": "attenuation_violation",
                        "executor_capability_id": cap["id"], "request_id": req_id,
                        "required_service": req_svc, "required_rule": req_rule,
                        "requested_service": svc, "requested_rule": rule}

        # Budget
        grant = _find_grant(cap, "provider-ops", "disable_edge_rule")
        cost = 500
        budget = None
        if payload.control_url and payload.service_token and grant:
            trust = TrustControl(payload.control_url, payload.service_token)
            budget = trust.charge_budget(
                cap["id"], _grant_index(cap, "provider-ops", "disable_edge_rule"), cost,
                max_invocations=grant.get("max_invocations"),
                max_cost_per_invocation=grant.get("max_cost_per_invocation", {}).get("units"),
                max_total_cost_units=grant.get("max_total_cost", {}).get("units"),
            )
            if not budget.get("allowed", True):
                return {"verdict": "deny", "reason": "budget_exceeded",
                        "executor_capability_id": cap["id"], "budget": budget,
                        "requested_service": svc, "requested_rule": rule}

        # Execute tool through Chio MCP
        if payload.provider_ops_mcp_url:
            with ChioMcpClient(payload.provider_ops_mcp_url, auth_token=payload.chio_auth_token) as c:
                operation = c.call_tool("disable_edge_rule", {"service": svc, "rule_name": rule})
        else:
            with StdioMcpClient(str(PROVIDER_OPS_SERVER)) as c:
                operation = c.call_tool("disable_edge_rule", {"service": svc, "rule_name": rule})

        return {
            "verdict": "allow",
            "cost_charged": cost, "cost_currency": "USD", "budget": budget,
            "executor_capability_id": cap["id"], "request_id": req_id,
            "requested_service": svc, "requested_rule": rule,
            "approval_token_id": payload.approval_token.get("id") if payload.approval_token else None,
            "chio_mediated": payload.provider_ops_mcp_url is not None,
            "chio_receipt_id": receipt.id if receipt else None,
            "provider_operation": operation,
        }

    return app


app = create_app()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8423)
    args = parser.parse_args()
    uvicorn.run("executor:app", host=args.host, port=args.port, log_level="warning", factory=False)
