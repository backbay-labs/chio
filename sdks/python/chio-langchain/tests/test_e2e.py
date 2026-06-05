"""E2E test: FastAPI + chio-fastapi producing verifiable receipts.

This test simulates the full flow:
1. FastAPI app with @chio_requires decorator
2. Request with capability token
3. Sidecar evaluates and returns signed receipt
4. Receipt is verifiable
5. LangChain tool wrapper records an advisory, non-authorizing result

The sidecar is mocked via respx to avoid requiring a running instance.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import respx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from chio_fastapi.decorators import chio_requires
from chio_fastapi.dependencies import set_chio_client
from chio_langchain.tool import ChioTool, ChioToolkit
from chio_sdk.client import ChioClient, _canonical_json, _sha256_hex
from chio_sdk.models import (
    EvaluateResponse,
    ChioReceipt,
    Decision,
    HttpReceipt,
    ToolCallAction,
    VerifyReceiptResponse,
)


BASE = "http://127.0.0.1:9090"


def _receipt_dict() -> dict:
    return {
        "id": "receipt-e2e",
        "request_id": "req-e2e",
        "route_pattern": "/tools/query",
        "method": "POST",
        "caller_identity_hash": "abc123",
        "verdict": {"verdict": "allow"},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "evidence": [
            {"guard_name": "CapabilityGuard", "verdict": True},
            {"guard_name": "PathGuard", "verdict": True},
        ],
        "response_status": 200,
        "timestamp": 1700000000,
        "content_hash": "e2e-hash",
        "policy_hash": "e2e-policy",
        "trust_level": "mediated",
        "kernel_key": "kernel-pub-e2e",
        "signature": "ed25519-sig-e2e",
    }


def _chio_receipt_dict() -> dict:
    return {
        "id": "1" * 64,
        "timestamp": 1700000000,
        "capability_id": "cap-e2e",
        "tool_server": "ai-server",
        "tool_name": "query",
        "action": {
            "parameters": {"prompt": "hello"},
            "parameter_hash": _sha256_hex(_canonical_json({"prompt": "hello"})),
        },
        "decision": None,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "observation_outcome": "evaluated",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "content_hash": "3" * 64,
        "policy_hash": "e2e-policy",
        "evidence": [
            {"guard_name": "CapabilityGuard", "verdict": True},
        ],
        "trust_level": "advisory",
        "kernel_key": "5" * 64,
        "signature": "6" * 128,
    }


def _advisory_wrapper(receipt: dict) -> dict:
    return {
        "schema": "chio.sidecar.advisory-evaluation.v1",
        "authorization": False,
        "authorizationBasis": "advisory_only",
        "receipt": receipt,
    }


def _advisory_verify_report() -> dict:
    return {
        "signature_valid": True,
        "signer_trusted": True,
        "receipt_id_valid": True,
        "parameter_hash_valid": True,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "trust_level": "advisory",
        "result": "allow",
        "authorized": False,
        "signer_key_hex": "5" * 64,
        "ok": False,
    }


def _mediated_verify_response() -> VerifyReceiptResponse:
    return VerifyReceiptResponse(
        signature_valid=True,
        signer_trusted=True,
        receipt_id_valid=True,
        parameter_hash_valid=True,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        trust_level="mediated",
        result="allow",
        authorized=True,
        signer_key_hex="5" * 64,
        ok=True,
    )


class TestE2EFastAPIWithReceipts:
    """End-to-end: FastAPI + @chio_requires producing verifiable receipts."""

    def test_full_flow(self) -> None:
        # 1. Set up FastAPI app with @chio_requires
        app = FastAPI()

        http_receipt = HttpReceipt.model_validate(_receipt_dict())

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=EvaluateResponse(
                verdict=http_receipt.verdict,
                receipt=http_receipt,
                evidence=http_receipt.evidence,
            )
        )
        mock_client.verify_http_receipt = AsyncMock(
            return_value=_mediated_verify_response()
        )
        set_chio_client(mock_client)

        @app.post("/tools/query")
        @chio_requires("ai-server", "query")
        async def query_tool(request: Request) -> dict:
            receipt = getattr(request.state, "chio_receipt", None)
            return {
                "result": "42",
                "receipt_id": receipt.id if receipt else None,
            }

        # 2. Make a request with a capability token
        client = TestClient(app)
        resp = client.post(
            "/tools/query",
            headers={"X-Chio-Capability": "cap-e2e"},
            json={"prompt": "What is the meaning?"},
        )

        # 3. Verify response
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"] == "42"
        assert body["receipt_id"] == "receipt-e2e"

        # 4. Verify the receipt structure
        assert http_receipt.is_allowed
        assert len(http_receipt.evidence) == 2
        assert all(e.verdict for e in http_receipt.evidence)

        # Cleanup
        set_chio_client(None)

    def test_denied_flow(self) -> None:
        """Verify denied requests return proper Chio error responses."""
        app = FastAPI()

        denied_receipt = HttpReceipt.model_validate(
            {
                "id": "receipt-denied-e2e",
                "request_id": "req-denied",
                "route_pattern": "/tools/dangerous",
                "method": "POST",
                "caller_identity_hash": "xyz",
                "verdict": {
                    "verdict": "deny",
                    "reason": "path /etc/shadow is forbidden",
                    "guard": "PathGuard",
                    "status_code": 403,
                },
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "evidence": [
                    {
                        "guard_name": "PathGuard",
                        "verdict": False,
                        "details": "path /etc/shadow matches forbidden pattern",
                    },
                ],
                "response_status": 403,
                "timestamp": 1700000000,
                "content_hash": "denied-hash",
                "policy_hash": "denied-policy",
                "trust_level": "mediated",
                "kernel_key": "k",
                "signature": "s",
            }
        )

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=EvaluateResponse(
                verdict=denied_receipt.verdict,
                receipt=denied_receipt,
                evidence=denied_receipt.evidence,
            )
        )
        set_chio_client(mock_client)

        @app.post("/tools/dangerous")
        @chio_requires("fs-server", "read_file")
        async def dangerous_tool(request: Request) -> dict:
            return {"data": "should not reach here"}

        client = TestClient(app)
        resp = client.post(
            "/tools/dangerous",
            headers={"X-Chio-Capability": "cap-123"},
            json={"path": "/etc/shadow"},
        )

        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "CHIO_GUARD_DENIED"
        assert "PathGuard" in body["error"].get("guard", "")

        set_chio_client(None)


class TestE2ELangChainTool:
    """End-to-end: LangChain wrapper recording advisory receipts."""

    @respx.mock
    async def test_langchain_tool_invocation(self) -> None:
        """Verify LangChain tool invocation is advisory only."""

        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                200,
                json=_advisory_wrapper(_chio_receipt_dict()),
            )
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        tool = ChioTool(
            name="query",
            description="Query the AI model",
            server_id="ai-server",
            capability_id="cap-e2e",
            sidecar_url=BASE,
            input_schema_def={
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "The prompt"},
                },
                "required": ["prompt"],
            },
        )

        # Invoke through LangChain interface
        result = await tool._arun(prompt="hello")
        data = json.loads(result)

        assert data["error"] == "non_authorizing"
        assert data["receipt_id"] == "1" * 64
        assert data["tool_server"] == "ai-server"
        assert data["tool_name"] == "query"

        # Verify advisory receipt stored for audit.
        assert tool.last_receipt is not None
        assert tool.last_receipt.receipt_kind.value == "advisory_evaluation"
        assert not tool.last_receipt.is_allowed

    @respx.mock
    async def test_toolkit_creates_tools_from_manifest(self) -> None:
        """Verify ChioToolkit can discover and wrap tools."""
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "ai-server",
                    "tools": [
                        {
                            "name": "query",
                            "description": "Query the AI",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "prompt": {"type": "string"},
                                },
                            },
                        },
                    ],
                },
            ],
        }
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ChioToolkit(capability_id="cap-e2e", sidecar_url=BASE)
        tools = await toolkit.get_tools()

        assert len(tools) == 1
        assert tools[0].name == "query"
        assert tools[0].capability_id == "cap-e2e"
        assert tools[0].server_id == "ai-server"


class TestReceiptChainVerification:
    """Verify receipt chain continuity across multiple invocations."""

    async def test_receipt_chain(self) -> None:
        r1 = ChioReceipt(
            id="1" * 64,
            timestamp=1000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="t1",
            action=ToolCallAction(parameters={}, parameter_hash="2" * 64),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            content_hash="3" * 64,
            policy_hash="p1",
            trust_level="mediated",
            kernel_key="5" * 64,
            signature="6" * 128,
        )

        # Chain: r2's content_hash = SHA-256 of canonical JSON of r1
        r1_canonical = _canonical_json(r1.model_dump(exclude_none=True))
        r1_hash = _sha256_hex(r1_canonical)

        r2 = ChioReceipt(
            id="7" * 64,
            timestamp=2000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="t2",
            action=ToolCallAction(parameters={}, parameter_hash="8" * 64),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            content_hash=r1_hash,
            policy_hash="p2",
            trust_level="mediated",
            kernel_key="9" * 64,
            signature="a" * 128,
        )

        async with ChioClient(BASE) as client:
            assert await client.verify_receipt_chain([r1, r2]) is True

            # Broken chain
            r3 = ChioReceipt(
                id="b" * 64,
                timestamp=3000,
                capability_id="cap-1",
                tool_server="srv",
                tool_name="t3",
                action=ToolCallAction(parameters={}, parameter_hash="c" * 64),
                decision=Decision.allow(),
                receipt_kind="mediated_decision",
                boundary_class="prevent",
                tool_origin="caller_executed",
                redaction_mode="none",
                content_hash="d" * 64,
                policy_hash="p3",
                trust_level="mediated",
                kernel_key="e" * 64,
                signature="f" * 128,
            )
            assert await client.verify_receipt_chain([r2, r3]) is False
