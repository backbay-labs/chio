"""Tests for chio-fastapi decorators."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from chio_fastapi.decorators import chio_requires, chio_approval, chio_budget
from chio_fastapi.dependencies import set_chio_client
from chio_sdk.errors import ChioConnectionError, ChioDeniedError
from chio_sdk.models import EvaluateResponse, HttpReceipt, Verdict, VerifyReceiptResponse


def _make_receipt(allowed: bool = True) -> HttpReceipt:
    verdict = (
        Verdict.allow()
        if allowed
        else Verdict.deny("blocked", "TestGuard", 403)
    )
    return HttpReceipt(
        id="receipt-test",
        request_id="req-1",
        route_pattern="/test",
        method="POST",
        caller_identity_hash="abc",
        verdict=verdict,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        observation_outcome=None,
        tool_origin="caller_executed",
        redaction_mode="none",
        response_status=200 if allowed else 403,
        timestamp=1700000000,
        content_hash="x",
        policy_hash="y",
        trust_level="mediated",
        kernel_key="k",
        signature="s",
    )


def _make_evaluation(allowed: bool = True) -> EvaluateResponse:
    receipt = _make_receipt(allowed=allowed)
    return EvaluateResponse(verdict=receipt.verdict, receipt=receipt, evidence=[])


def _make_verification(authorized: bool = True) -> VerifyReceiptResponse:
    return VerifyReceiptResponse(
        signature_valid=authorized,
        signer_trusted=authorized,
        receipt_id_valid=authorized,
        parameter_hash_valid=authorized,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        trust_level="mediated",
        result="allow" if authorized else "deny",
        authorized=authorized,
        signer_key_hex="kernel-key",
        ok=authorized,
    )


# ---------------------------------------------------------------------------
# chio_requires
# ---------------------------------------------------------------------------


class TestChioRequires:
    def test_missing_capability_returns_401(self) -> None:
        app = FastAPI()

        @app.post("/deploy")
        @chio_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post("/deploy")
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"]["code"] == "CHIO_CAPABILITY_REQUIRED"

    def test_allowed_request_passes_through(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_evaluation(allowed=True)
        )
        mock_client.verify_http_receipt = AsyncMock(return_value=_make_verification())
        set_chio_client(mock_client)

        @app.post("/deploy")
        @chio_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Chio-Capability": "cap-123"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deployed"

        # Cleanup
        set_chio_client(None)

    def test_denied_request_returns_403(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_evaluation(allowed=False)
        )
        mock_client.verify_http_receipt = AsyncMock(return_value=_make_verification(False))
        set_chio_client(mock_client)

        @app.post("/deploy")
        @chio_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Chio-Capability": "cap-123"},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "CHIO_GUARD_DENIED"

        set_chio_client(None)

    def test_sidecar_unavailable_returns_503(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            side_effect=ChioConnectionError("connection refused")
        )
        set_chio_client(mock_client)

        @app.post("/deploy")
        @chio_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Chio-Capability": "cap-123"},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert body["error"]["code"] == "CHIO_SIDECAR_UNAVAILABLE"

        set_chio_client(None)

    def test_metadata_attached(self) -> None:
        @chio_requires("srv", "tool", ["Invoke", "ReadResult"])
        async def handler(request: Request) -> dict:
            return {}

        assert handler._chio_requires == {
            "server_id": "srv",
            "tool_name": "tool",
            "operations": ["Invoke", "ReadResult"],
        }

    def test_capability_from_query_param(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_evaluation(allowed=True)
        )
        mock_client.verify_http_receipt = AsyncMock(return_value=_make_verification())
        set_chio_client(mock_client)

        @app.get("/read")
        @chio_requires("read-server", "read")
        async def read_handler(request: Request) -> dict:
            return {"data": "ok"}

        client = TestClient(app)
        resp = client.get("/read?chio_capability=cap-qp")
        assert resp.status_code == 200

        set_chio_client(None)

    def test_unverified_allow_returns_502(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_evaluation(allowed=True)
        )
        mock_client.verify_http_receipt = AsyncMock(return_value=_make_verification(False))
        set_chio_client(mock_client)

        @app.get("/read")
        @chio_requires("read-server", "read")
        async def read_handler(request: Request) -> dict:
            return {"data": "ok"}

        client = TestClient(app)
        resp = client.get("/read?chio_capability=cap-qp")
        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "CHIO_INTERNAL_ERROR"

        set_chio_client(None)


# ---------------------------------------------------------------------------
# chio_approval
# ---------------------------------------------------------------------------


class TestChioApproval:
    def test_missing_approval_returns_403(self) -> None:
        app = FastAPI()

        @app.post("/transfer")
        @chio_approval(threshold_cents=1000, currency="USD")
        async def transfer(request: Request) -> dict:
            return {"transferred": True}

        client = TestClient(app)
        resp = client.post("/transfer")
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "CHIO_APPROVAL_REQUIRED"
        assert body["error"]["details"]["threshold_cents"] == 1000

    def test_with_approval_passes(self) -> None:
        app = FastAPI()

        @app.post("/transfer")
        @chio_approval(threshold_cents=1000)
        async def transfer(request: Request) -> dict:
            return {"transferred": True}

        client = TestClient(app)
        resp = client.post(
            "/transfer",
            headers={"X-Chio-Approval": "approval-tok-abc"},
        )
        assert resp.status_code == 200
        assert resp.json()["transferred"] is True

    def test_metadata_attached(self) -> None:
        @chio_approval(threshold_cents=5000, currency="EUR")
        async def handler(request: Request) -> dict:
            return {}

        assert handler._chio_approval == {
            "threshold_cents": 5000,
            "currency": "EUR",
        }


# ---------------------------------------------------------------------------
# chio_budget
# ---------------------------------------------------------------------------


class TestChioBudget:
    def test_budget_metadata_attached(self) -> None:
        @chio_budget(max_cost_cents=200, currency="GBP")
        async def handler(request: Request) -> dict:
            return {}

        assert handler._chio_budget == {
            "max_cost_cents": 200,
            "currency": "GBP",
        }

    def test_passes_through(self) -> None:
        app = FastAPI()

        @app.post("/query")
        @chio_budget(max_cost_cents=500)
        async def query(request: Request) -> dict:
            return {"result": "ok"}

        client = TestClient(app)
        resp = client.post("/query")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"
