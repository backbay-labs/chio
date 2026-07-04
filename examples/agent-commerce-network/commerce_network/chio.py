"""Chio integration: MCP clients and trust-control HTTP interface."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import httpx


# -- Chio MCP HTTP client (talks to chio mcp serve-http) -----------------------

class ChioMcpClient:
    """Calls MCP tools through an chio mcp serve-http endpoint.

    The Chio kernel validates capabilities, evaluates guard policies,
    and signs a receipt for every tool invocation.
    """

    def __init__(self, base_url: str, *, auth_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._session_id: str | None = None
        self._seq = 0
        self._http = httpx.Client(timeout=30.0)

    def __enter__(self) -> ChioMcpClient:
        self._handshake()
        return self

    def __exit__(self, *_: Any) -> None:
        if self._session_id:
            try:
                self._http.delete(f"{self.base_url}/mcp", headers=self._headers())
            except httpx.HTTPError:
                pass
        self._http.close()

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._auth_token:
            h["Authorization"] = f"Bearer {self._auth_token}"
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _rpc(self, method: str, params: dict[str, Any]) -> Any:
        self._seq += 1
        resp = self._http.post(
            f"{self.base_url}/mcp",
            headers=self._headers(),
            json={"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params},
        )
        resp.raise_for_status()
        sid = resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid
        msg = self._parse_response(resp)
        if "error" in msg:
            raise RuntimeError(f"MCP {msg['error'].get('code')}: {msg['error']['message']}")
        return msg.get("result", {})

    def _parse_response(self, resp: httpx.Response) -> dict[str, Any]:
        ct = resp.headers.get("content-type", "")
        if "text/event-stream" in ct:
            # Parse SSE: find the data: line with our JSON-RPC response
            for line in resp.text.splitlines():
                if line.startswith("data: "):
                    try:
                        return json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue
            raise RuntimeError("no JSON-RPC response in SSE stream")
        return resp.json()

    def _handshake(self) -> None:
        result = self._rpc("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "agent-commerce-network", "version": "0.2.0"},
        })
        # Notifications have no id and no response body
        self._http.post(
            f"{self.base_url}/mcp",
            headers=self._headers(),
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return self._rpc("tools/list", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments}).get("structuredContent", {})


# -- Stdio MCP client (direct, no Chio kernel) --------------------------------

class StdioMcpClient:
    """Talks to an MCP server subprocess over stdio. No Chio mediation."""

    def __init__(self, script: str):
        self._script = script
        self._proc: subprocess.Popen[str] | None = None
        self._seq = 0

    def __enter__(self) -> StdioMcpClient:
        self._proc = subprocess.Popen(
            [sys.executable, self._script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self._rpc("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "agent-commerce-network", "version": "0.2.0"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        return self

    def __exit__(self, *_: Any) -> None:
        if self._proc:
            self._proc.kill()
            self._proc.wait(timeout=5)

    def _send(self, msg: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _rpc(self, method: str, params: dict[str, Any]) -> Any:
        assert self._proc and self._proc.stdin and self._proc.stdout
        self._seq += 1
        self._send({"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params})
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"MCP server died: {err}")
        msg = json.loads(line)
        if "error" in msg:
            raise RuntimeError(msg["error"]["message"])
        return msg["result"]

    def list_tools(self) -> list[dict[str, Any]]:
        return self._rpc("tools/list", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments}).get("structuredContent", {})


# -- Trust-control HTTP client ------------------------------------------------

class TrustControl:
    """HTTP client for chio trust serve."""

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token
        self._http = httpx.Client(timeout=10.0)

    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def issue_capability(self, subject_pk: str, scope: dict, ttl: int) -> dict[str, Any]:
        r = self._http.post(
            f"{self.url}/v1/capabilities/issue",
            headers=self._auth(),
            json={"subjectPublicKey": subject_pk, "scope": scope, "ttlSeconds": ttl},
        )
        r.raise_for_status()
        return r.json()["capability"]

    def record_lineage(self, capability: dict, parent_id: str | None) -> None:
        self._http.post(
            f"{self.url}/v1/lineage",
            headers=self._auth(),
            json={"capability": capability, "parentCapabilityId": parent_id},
        ).raise_for_status()

    def lineage_chain(self, capability_id: str) -> dict[str, Any]:
        r = self._http.get(
            f"{self.url}/v1/lineage/{capability_id}/chain",
            headers=self._auth(),
        )
        r.raise_for_status()
        return r.json()

    def is_revoked(self, capability_id: str) -> bool:
        r = self._http.get(
            f"{self.url}/v1/revocations",
            headers=self._auth(),
            params={"capabilityId": capability_id, "limit": 1},
        )
        r.raise_for_status()
        return bool(r.json().get("revoked"))

    def revoke(self, capability_id: str) -> dict[str, Any]:
        r = self._http.post(
            f"{self.url}/v1/revocations",
            headers=self._auth(),
            json={"capabilityId": capability_id},
        )
        r.raise_for_status()
        return r.json()

    # -- Budget & cost tracking -----------------------------------------------

    def charge_budget(
        self, capability_id: str, grant_index: int, cost_units: int,
        *, max_invocations: int | None = None,
        max_cost_per_invocation: int | None = None,
        max_total_cost_units: int | None = None,
    ) -> dict[str, Any]:
        """Atomically check and charge cost against a capability's budget."""
        r = self._http.post(
            f"{self.url}/v1/budgets/charge",
            headers=self._auth(),
            json={
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "maxInvocations": max_invocations,
                "costUnits": cost_units,
                "maxCostPerInvocation": max_cost_per_invocation,
                "maxTotalCostUnits": max_total_cost_units,
            },
        )
        r.raise_for_status()
        return r.json()

    def query_budgets(self, capability_id: str | None = None) -> dict[str, Any]:
        """Query budget usage records."""
        params: dict[str, Any] = {"limit": 100}
        if capability_id:
            params["capabilityId"] = capability_id
        r = self._http.get(
            f"{self.url}/v1/budgets",
            headers=self._auth(),
            params=params,
        )
        r.raise_for_status()
        return r.json()

    # -- Financial reports ----------------------------------------------------

    def exposure_ledger(self, agent_subject: str | None = None, **filters: Any) -> dict[str, Any]:
        """Query the exposure ledger for monetary exposure across the delegation chain."""
        params: dict[str, Any] = {k: v for k, v in filters.items() if v is not None}
        if agent_subject:
            params["agentSubject"] = agent_subject
        r = self._http.get(
            f"{self.url}/v1/reports/exposure-ledger",
            headers=self._auth(),
            params=params,
        )
        r.raise_for_status()
        return r.json()

    def credit_scorecard(self, agent_subject: str, **filters: Any) -> dict[str, Any]:
        """Query the credit scorecard for a subject."""
        params: dict[str, Any] = {"agentSubject": agent_subject}
        params.update({k: v for k, v in filters.items() if v is not None})
        r = self._http.get(
            f"{self.url}/v1/reports/credit-scorecard",
            headers=self._auth(),
            params=params,
        )
        r.raise_for_status()
        return r.json()

    def settlement_report(self, **filters: Any) -> dict[str, Any]:
        """Query settlement reconciliation status."""
        params = {k: v for k, v in filters.items() if v is not None}
        r = self._http.get(
            f"{self.url}/v1/reports/settlements",
            headers=self._auth(),
            params=params,
        )
        r.raise_for_status()
        return r.json()
