#!/usr/bin/env python3
"""Incident response orchestrator.

Runs the multi-org incident response flow:
  1. Issue root capability via trust-control
  2. Delegate narrower capabilities to sub-agents
  3. Run agents (triage, change, commander, vendor-liaison) with tool-use
  4. Create ACP task for cross-org provider engagement
  5. Delegate to provider coordinator/executor
  6. Record lineage, export evidence bundle
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from incident_network.chio import ChioMcpClient, TrustControl
from incident_network.capabilities import PublicKey, delegate, gen_identity
from incident_network.agents import run_agent

log = logging.getLogger("incident-network")


# -- Helpers ------------------------------------------------------------------

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
    """MonetaryAmount in USD minor units (cents)."""
    return {"units": cents, "currency": "USD"}


def _grant(
    server: str, tool: str, ops: list[str],
    *, max_invocations: int | None = None,
    max_cost: int | None = None,
    max_per_call: int | None = None,
) -> dict:
    g: dict[str, Any] = {"server_id": server, "tool_name": tool, "operations": ops, "constraints": []}
    if max_invocations is not None:
        g["max_invocations"] = max_invocations
    if max_cost is not None:
        g["max_total_cost"] = _usd(max_cost)
    if max_per_call is not None:
        g["max_cost_per_invocation"] = _usd(max_per_call)
    return g


def _scope(*grants: dict) -> dict:
    return {"grants": list(grants), "resource_grants": [], "prompt_grants": []}


def _write_manifest(d: Path) -> None:
    required = [
        "incident.json", "identities/public-identities.json",
        "capabilities/root-commander.json", "capabilities/triage-agent.json",
        "capabilities/change-agent.json", "capabilities/vendor-liaison-agent.json",
        "capabilities/provider-coordinator.json", "capabilities/provider-executor.json",
        "agents/triage-output.json", "agents/change-output.json",
        "agents/commander-output.json", "agents/vendor-liaison-output.json",
        "acp/task-created.json", "acp/task-final.json",
        "provider/process-task-response.json",
        *(f"lineage/{n}-chain.json" for n in [
            "root-commander", "triage-agent", "change-agent",
            "vendor-liaison-agent", "provider-coordinator", "provider-executor",
        ]),
        "summary.json",
    ]
    optional = [
        "revocation/revoke-response.json",
        "approval/approval-request.json", "approval/approval-response.json",
        "approval/approval-token.json", "approval/approver-health.json",
        "approval/pre-approval-execution.json",
        "financial/budget-usage.json",
        "financial/exposure-ledger.json",
        "financial/credit-scorecard.json",
        "financial/settlement-report.json",
    ]
    paths = required + [p for p in optional if (d / p).exists()]
    _write(d / "bundle-manifest.json", {
        "generated_at": _now(), "bundle_dir": str(d),
        "sha256": {p: _sha256(d / p) for p in paths},
    })


# -- Main ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    p = argparse.ArgumentParser()
    p.add_argument("--control-url", required=True)
    p.add_argument("--service-token", required=True)
    p.add_argument("--broker-url", required=True)
    p.add_argument("--provider-coordinator-url", required=True)
    p.add_argument("--provider-executor-url", required=True)
    p.add_argument("--provider-executor-internal-url", help="Raw executor URL (bypasses sidecar)")
    p.add_argument("--approval-service-url")
    p.add_argument("--artifact-dir")
    p.add_argument("--observability-mcp-url")
    p.add_argument("--github-mcp-url")
    p.add_argument("--pagerduty-mcp-url")
    p.add_argument("--provider-ops-mcp-url")
    p.add_argument("--chio-auth-token", default="demo-token")
    p.add_argument("--mode", default="happy-path", choices=[
        "happy-path", "approval-required", "attenuation-deny",
        "revoke-midchain", "expiry-async-failure",
    ])
    args = p.parse_args(argv)

    out = Path(args.artifact_dir) if args.artifact_dir else (
        ROOT / "artifacts" / "live" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    )
    out.mkdir(parents=True, exist_ok=True)

    trust = TrustControl(args.control_url, args.service_token)

    # -- Incident context --
    incident = json.loads(
        (ROOT / "workspaces" / "customer-lab" / "incident" / "current-incident.json").read_text()
    )
    _write(out / "incident.json", incident)

    # -- Identities --
    ids = {n: gen_identity(n) for n in [
        "commander-agent", "triage-agent", "change-agent",
        "vendor-liaison-agent", "provider-coordinator", "provider-executor",
    ]}
    _write(out / "identities" / "public-identities.json", {
        n: {"name": i.name, "public_key_hex": i.pk} for n, i in ids.items()
    })

    # -- Root capability --
    # Budget: $10 total for the entire incident response.
    # Read-only investigation tools are free. Provider operations cost $5 each.
    # The budget narrows at each delegation hop.
    root_cap = trust.issue_capability(
        ids["commander-agent"].pk,
        _scope(
            _grant("mcp-observability", "get_incident_summary", ["invoke", "delegate"]),
            _grant("mcp-observability", "query_spans", ["invoke", "delegate"]),
            _grant("mcp-observability", "get_deploy_timeline", ["invoke", "delegate"]),
            _grant("mcp-observability", "get_slo_status", ["invoke", "delegate"]),
            _grant("mcp-github", "search_commits", ["invoke", "delegate"]),
            _grant("mcp-github", "get_diff", ["invoke", "delegate"]),
            _grant("mcp-github", "get_file", ["invoke", "delegate"]),
            _grant("mcp-pagerduty", "get_oncall_state", ["invoke", "delegate"]),
            _grant("mcp-pagerduty", "get_escalation_timeline", ["invoke", "delegate"]),
            _grant("acp-broker", "create_task", ["invoke", "delegate"],
                   max_cost=1000, max_per_call=500),  # $10 total, $5/call
        ),
        ttl=1800,
    )
    trust.record_lineage(root_cap, None)
    _write(out / "capabilities" / "root-commander.json", root_cap)

    # -- Delegate to sub-agents --
    triage_cap = delegate(
        parent=root_cap, delegator=ids["commander-agent"], delegatee=ids["triage-agent"],
        scope=_scope(
            _grant("mcp-observability", "get_incident_summary", ["invoke"]),
            _grant("mcp-observability", "query_spans", ["invoke"]),
            _grant("mcp-observability", "get_deploy_timeline", ["invoke"]),
            _grant("mcp-observability", "get_slo_status", ["invoke"]),
            _grant("mcp-github", "search_commits", ["invoke"]),
            _grant("mcp-github", "get_diff", ["invoke"]),
            _grant("mcp-github", "get_file", ["invoke"]),
            _grant("mcp-pagerduty", "get_oncall_state", ["invoke"]),
            _grant("mcp-pagerduty", "get_escalation_timeline", ["invoke"]),
        ),
        ttl=900, cap_id=f"{incident['incident_id']}-triage",
    )
    trust.record_lineage(triage_cap, root_cap["id"])
    _write(out / "capabilities" / "triage-agent.json", triage_cap)

    change_cap = delegate(
        parent=root_cap, delegator=ids["commander-agent"], delegatee=ids["change-agent"],
        scope=_scope(), ttl=900, cap_id=f"{incident['incident_id']}-change",
    )
    trust.record_lineage(change_cap, root_cap["id"])
    _write(out / "capabilities" / "change-agent.json", change_cap)

    vendor_ttl = 2 if args.mode == "expiry-async-failure" else 900
    vendor_cap = delegate(
        parent=root_cap, delegator=ids["commander-agent"], delegatee=ids["vendor-liaison-agent"],
        scope=_scope(_grant("acp-broker", "create_task", ["invoke", "delegate"],
                            max_cost=500, max_per_call=500)),  # $5 budget for provider engagement
        ttl=vendor_ttl, cap_id=f"{incident['incident_id']}-vendor",
    )
    trust.record_lineage(vendor_cap, root_cap["id"])
    _write(out / "capabilities" / "vendor-liaison-agent.json", vendor_cap)

    # -- Run agents via Chio MCP endpoints --
    mcp: dict[str, ChioMcpClient] = {}
    auth = args.chio_auth_token
    if args.observability_mcp_url:
        mcp["observability"] = ChioMcpClient(args.observability_mcp_url, auth_token=auth)
    if args.github_mcp_url:
        mcp["github"] = ChioMcpClient(args.github_mcp_url, auth_token=auth)
    if args.pagerduty_mcp_url:
        mcp["pagerduty"] = ChioMcpClient(args.pagerduty_mcp_url, auth_token=auth)

    for c in mcp.values():
        c.__enter__()
    try:
        all_tools: list[dict] = []
        for c in mcp.values():
            all_tools.extend(c.list_tools())

        triage_out = run_agent("triage-agent", json.dumps({
            "incident": incident, "capability_id": triage_cap["id"],
            "instructions": "Investigate this incident using the tools available to you.",
        }, indent=2), mcp_clients=mcp, tools=all_tools)
        _write(out / "agents" / "triage-output.json", triage_out)

        change_out = run_agent("change-agent", json.dumps({
            "incident": incident, "triage_output": triage_out,
        }, indent=2))
        _write(out / "agents" / "change-output.json", change_out)

        commander_out = run_agent("commander-agent", json.dumps({
            "incident": incident, "triage_output": triage_out, "change_output": change_out,
        }, indent=2))
        _write(out / "agents" / "commander-output.json", commander_out)

        vendor_out = run_agent("vendor-liaison-agent", json.dumps({
            "incident": incident, "triage_output": triage_out,
            "change_output": change_out, "commander_output": commander_out,
            "suspected_rule": triage_out.get("suspected_rule", "geo-restrict-v42"),
        }, indent=2))
        _write(out / "agents" / "vendor-liaison-output.json", vendor_out)
    finally:
        for c in mcp.values():
            c.__exit__(None, None, None)

    # -- ACP task --
    task_resp = httpx.post(f"{args.broker_url.rstrip('/')}/tasks", json={
        "incident_id": incident["incident_id"],
        "target_service": vendor_out.get("target_service", "inference-gateway"),
        "target_rule": vendor_out.get("target_rule", "geo-restrict-v42"),
        "bounded_action": vendor_out.get("bounded_action", "disable_rule"),
        "provider_instructions": vendor_out.get("provider_instructions", ""),
        "vendor_liaison_capability": vendor_cap,
        "execution_deadline": vendor_cap["expires_at"],
    }, timeout=30.0)
    task_resp.raise_for_status()
    task = task_resp.json()
    _write(out / "acp" / "task-created.json", task)

    # -- Provider delegation (budget narrows: $5 total, 1 invocation at $5) --
    coord_cap = delegate(
        parent=vendor_cap, delegator=ids["vendor-liaison-agent"],
        delegatee=PublicKey(name="provider-coordinator", pk=ids["provider-coordinator"].pk),
        scope=_scope(_grant("provider-ops", "disable_edge_rule", ["invoke", "delegate"],
                            max_cost=500, max_per_call=500, max_invocations=2)),
        ttl=600, cap_id=f"{task['task_id']}-provider-coordinator",
    )
    trust.record_lineage(coord_cap, vendor_cap["id"])
    _write(out / "capabilities" / "provider-coordinator.json", coord_cap)

    # The coordinator calls the executor directly (bypasses sidecar).
    # External callers (orchestrator) go through sidecars.
    internal_exec_url = args.provider_executor_internal_url or args.provider_executor_url
    coord_req: dict[str, Any] = {
        "task": {**task, "provider_coordinator_capability": coord_cap},
        "provider_coordinator_seed_hex": ids["provider-coordinator"].seed,
        "provider_executor_public_key": ids["provider-executor"].pk,
        "control_url": args.control_url,
        "service_token": args.service_token,
        "provider_executor_url": internal_exec_url,
        "executor_ttl_seconds": 1 if args.mode == "expiry-async-failure" else 600,
    }
    if args.provider_ops_mcp_url:
        coord_req["provider_ops_mcp_url"] = args.provider_ops_mcp_url
        coord_req["chio_auth_token"] = auth

    # -- Issue capability for sidecar-protected endpoints --
    sidecar_cap = trust.issue_capability(
        ids["commander-agent"].pk,
        _scope(
            {**_grant("chio_http_authority", "authorize_http_request", ["invoke"], max_invocations=1),
             "constraints": [{"type": "path_prefix", "value": "/process-task"}]},
        ),
        ttl=1800,
    )
    _write(out / "capabilities" / "sidecar.json", sidecar_cap)
    sidecar_cap_header = json.dumps(sidecar_cap, separators=(",", ":"))

    # -- Execute scenario --
    provider_result = _run_scenario(args, coord_req, task, vendor_cap, trust, out, sidecar_cap_header)

    _write(out / "provider" / "process-task-response.json", provider_result)
    _write(out / "capabilities" / "provider-executor.json", provider_result["provider_executor_capability"])

    # -- Complete ACP task --
    httpx.post(
        f"{args.broker_url.rstrip('/')}/tasks/{task['task_id']}/complete",
        json=provider_result, timeout=30.0,
    ).raise_for_status()
    task_final = httpx.get(
        f"{args.broker_url.rstrip('/')}/tasks/{task['task_id']}", timeout=30.0,
    )
    task_final.raise_for_status()
    _write(out / "acp" / "task-final.json", task_final.json())

    # -- Lineage --
    cap_ids = {
        "root-commander": root_cap["id"], "triage-agent": triage_cap["id"],
        "change-agent": change_cap["id"], "vendor-liaison-agent": vendor_cap["id"],
        "provider-coordinator": coord_cap["id"],
        "provider-executor": provider_result["provider_executor_capability"]["id"],
    }
    for label, cid in cap_ids.items():
        _write(out / "lineage" / f"{label}-chain.json", trust.lineage_chain(cid))

    # -- Financial reports --
    executor_cap = provider_result["provider_executor_capability"]
    executor_pk = executor_cap["subject"]

    # Budget usage across the delegation chain
    budget_state = trust.query_budgets()
    _write(out / "financial" / "budget-usage.json", budget_state)

    # Exposure ledger: monetary exposure for the provider executor
    try:
        exposure = trust.exposure_ledger(agent_subject=executor_pk)
        _write(out / "financial" / "exposure-ledger.json", exposure)
    except Exception:
        _write(out / "financial" / "exposure-ledger.json", {"status": "not_available"})

    # Credit scorecard for the provider executor
    try:
        scorecard = trust.credit_scorecard(agent_subject=executor_pk)
        _write(out / "financial" / "credit-scorecard.json", scorecard)
    except Exception:
        _write(out / "financial" / "credit-scorecard.json", {"status": "not_available"})

    # Settlement status
    try:
        settlements = trust.settlement_report()
        _write(out / "financial" / "settlement-report.json", settlements)
    except Exception:
        _write(out / "financial" / "settlement-report.json", {"status": "not_available"})

    # -- Summary --
    execution = provider_result.get("execution", {})
    _write(out / "summary.json", {
        "example": "internet-of-agents-incident-network",
        "scenario_mode": args.mode,
        "incident_id": incident["incident_id"],
        "llm_mode": "openai" if os.getenv("OPENAI_API_KEY") else (
            "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "fallback"
        ),
        "capability_ids": cap_ids,
        "decision": commander_out.get("decision"),
        "task_id": task["task_id"],
        "task_status": task_final.json()["status"],
        "execution_verdict": execution.get("verdict"),
        "execution_reason": execution.get("reason"),
        "provider_operation_status": execution.get("provider_operation", {}).get("status"),
        "pre_approval_verdict": provider_result.get("pre_approval_execution", {}).get("verdict"),
        "pre_approval_reason": provider_result.get("pre_approval_execution", {}).get("reason"),
        "approval_token_id": provider_result.get("approval_token", {}).get("id"),
        "cost_charged": execution.get("cost_charged"),
        "cost_currency": execution.get("cost_currency"),
        "budget": execution.get("budget"),
    })
    _write_manifest(out)

    json.dump({"artifact_dir": str(out)}, sys.stdout, indent=2)
    print()
    return 0


def _run_scenario(args, coord_req, task, vendor_cap, trust, out, cap_header=""):
    """Execute the provider-side scenario and return the result."""
    coord_url = args.provider_coordinator_url.rstrip("/")
    exec_url = args.provider_executor_url.rstrip("/")
    hdr = {"X-Chio-Capability": cap_header} if cap_header else {}

    if args.mode == "happy-path":
        r = httpx.post(f"{coord_url}/process-task", json=coord_req, headers=hdr, timeout=30.0)
        if not r.is_success:
            raise RuntimeError(f"Provider request failed ({r.status_code}): {r.text[:2000]}")
        return r.json()

    if args.mode == "attenuation-deny":
        r = httpx.post(f"{coord_url}/process-task", json={
            **coord_req, "requested_service": "admin-api", "requested_rule": "global-rollback-v1",
        }, headers=hdr, timeout=30.0)
        if not r.is_success:
            raise RuntimeError(f"Provider request failed ({r.status_code}): {r.text[:2000]}")
        return r.json()

    # Deferred execution modes (revoke, expiry, approval)
    r = httpx.post(f"{coord_url}/process-task", json={**coord_req, "execute_now": False}, headers=hdr, timeout=30.0)
    r.raise_for_status()
    result = r.json()

    if args.mode == "revoke-midchain":
        _write(out / "revocation" / "revoke-response.json", trust.revoke(vendor_cap["id"]))

    if args.mode == "expiry-async-failure":
        time.sleep(2)

    if args.mode == "approval-required":
        return _run_approval(args, result, task, exec_url, trust, out, hdr)

    # Execute (will fail for revoke/expiry)
    er = httpx.post(f"{exec_url}/execute", json={
        "task": task, "capability": result["provider_executor_capability"],
        "control_url": args.control_url, "service_token": args.service_token,
        "executed_at": _now(),
    }, headers=hdr, timeout=30.0)
    er.raise_for_status()
    result["execution"] = er.json()
    return result


def _run_approval(args, result, task, exec_url, trust, out, hdr=None):
    """Approval-required scenario: try broad action, get denied, get approval, retry."""
    hdr = hdr or {}
    broader_svc, broader_rule = "edge-global", "global-rollback-v1"
    req_id = f"{task['task_id']}-broad-rollback"

    pre_payload = {
        "task": task, "capability": result["provider_executor_capability"],
        "control_url": args.control_url, "service_token": args.service_token,
        "requested_service": broader_svc, "requested_rule": broader_rule,
        "executed_at": _now(), "request_id": req_id, "approval_required": True,
    }
    pre = httpx.post(f"{exec_url}/execute", json=pre_payload, headers=hdr, timeout=30.0)
    pre.raise_for_status()
    _write(out / "approval" / "pre-approval-execution.json", pre.json())

    # Get approval
    approval_url = args.approval_service_url.rstrip("/")
    health = httpx.get(f"{approval_url}/health", timeout=30.0)
    health.raise_for_status()
    _write(out / "approval" / "approver-health.json", health.json())

    approval_req = {
        "request_id": req_id,
        "subject_public_key": result["provider_executor_capability"]["subject"],
        "governed_intent": {
            "task_id": task["task_id"], "service": broader_svc,
            "rule_name": broader_rule, "action": "disable_edge_rule",
        },
        "ttl_seconds": 300, "decision": "approved",
    }
    _write(out / "approval" / "approval-request.json", approval_req)

    ar = httpx.post(f"{approval_url}/approve", json=approval_req, timeout=30.0)
    ar.raise_for_status()
    approval_data = ar.json()
    token = approval_data["approval_token"]
    _write(out / "approval" / "approval-response.json", approval_data)
    _write(out / "approval" / "approval-token.json", token)

    # Retry with approval
    er = httpx.post(f"{exec_url}/execute", headers=hdr, json={
        **pre_payload, "approval_token": token, "executed_at": _now(),
    }, timeout=30.0)
    er.raise_for_status()
    result["pre_approval_execution"] = pre.json()
    result["approval_token"] = token
    result["execution"] = er.json()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
