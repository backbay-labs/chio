"""Tests for Chio SDK Python client (uses respx to mock httpx)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from chio_sdk.client import ChioClient, _canonical_json, _sha256_hex
from chio_sdk.errors import (
    ChioConnectionError,
    ChioDeniedError,
    ChioError,
)
from chio_sdk.models import (
    ChioReceipt,
    ChioScope,
    CallerIdentity,
    CapabilityToken,
    Decision,
    EvaluateResponse,
    GuardEvidence,
    HttpReceipt,
    Operation,
    ToolCallAction,
    ToolGrant,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE = "http://127.0.0.1:9090"


def _make_token_dict() -> dict:
    return {
        "id": "tok-1",
        "issuer": "aa",
        "subject": "bb",
        "scope": {
            "grants": [
                {
                    "server_id": "s",
                    "tool_name": "t",
                    "operations": ["invoke"],
                }
            ]
        },
        "issued_at": 100,
        "expires_at": 200,
        "signature": "sig",
    }


def _make_receipt_dict() -> dict:
    return {
        "id": "r-1",
        "timestamp": 1700000000,
        "capability_id": "cap-1",
        "tool_server": "srv",
        "tool_name": "read",
        "action": {"parameters": {}, "parameter_hash": "abc"},
        "decision": {"verdict": "allow"},
        "content_hash": "deadbeef",
        "policy_hash": "cafe",
        "kernel_key": "kk",
        "signature": "ss",
    }


def _make_http_receipt_dict() -> dict:
    return {
        "id": "hr-1",
        "request_id": "req-1",
        "route_pattern": "/pets/{petId}",
        "method": "GET",
        "caller_identity_hash": "abc",
        "verdict": {"verdict": "allow"},
        "response_status": 200,
        "timestamp": 1700000000,
        "content_hash": "x",
        "policy_hash": "y",
        "kernel_key": "k",
        "signature": "s",
    }


# ---------------------------------------------------------------------------
# Canonical JSON / SHA-256
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    def test_sorted_keys(self) -> None:
        data = {"b": 2, "a": 1}
        result = _canonical_json(data)
        assert result == b'{"a":1,"b":2}'

    def test_sha256(self) -> None:
        h = _sha256_hex(b"hello")
        assert len(h) == 64
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestHealth:
    @respx.mock
    async def test_health(self) -> None:
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(200, json={"status": "healthy"})
        )
        async with ChioClient(BASE) as client:
            data = await client.health()
            assert data["status"] == "healthy"


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


class TestCreateCapability:
    @respx.mock
    async def test_create(self) -> None:
        respx.post(f"{BASE}/v1/capabilities").mock(
            return_value=httpx.Response(200, json=_make_token_dict())
        )
        async with ChioClient(BASE) as client:
            scope = ChioScope(
                grants=[
                    ToolGrant(
                        server_id="s",
                        tool_name="t",
                        operations=[Operation.INVOKE],
                    )
                ]
            )
            token = await client.create_capability(subject="bb", scope=scope)
            assert isinstance(token, CapabilityToken)
            assert token.id == "tok-1"


class TestValidateCapability:
    @respx.mock
    async def test_valid(self) -> None:
        respx.post(f"{BASE}/v1/capabilities/validate").mock(
            return_value=httpx.Response(200, json={"valid": True})
        )
        async with ChioClient(BASE) as client:
            token = CapabilityToken.model_validate(_make_token_dict())
            result = await client.validate_capability(token)
            assert result is True


class TestAttenuateCapability:
    @respx.mock
    async def test_attenuate(self) -> None:
        new_scope = ChioScope(
            grants=[
                ToolGrant(
                    server_id="s",
                    tool_name="t",
                    operations=[Operation.INVOKE],
                )
            ]
        )
        child_dict = _make_token_dict()
        child_dict["id"] = "tok-child"
        respx.post(f"{BASE}/v1/capabilities/attenuate").mock(
            return_value=httpx.Response(200, json=child_dict)
        )
        async with ChioClient(BASE) as client:
            parent = CapabilityToken.model_validate(_make_token_dict())
            child = await client.attenuate_capability(parent, new_scope=new_scope)
            assert child.id == "tok-child"


# ---------------------------------------------------------------------------
# Receipt verification
# ---------------------------------------------------------------------------


class TestVerifyReceipt:
    @respx.mock
    async def test_verify(self) -> None:
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json={"valid": True})
        )
        async with ChioClient(BASE) as client:
            receipt = ChioReceipt.model_validate(_make_receipt_dict())
            assert await client.verify_receipt(receipt) is True


class TestVerifyHttpReceipt:
    @respx.mock
    async def test_verify_http(self) -> None:
        respx.post(f"{BASE}/chio/verify").mock(
            return_value=httpx.Response(200, json={"valid": True})
        )
        async with ChioClient(BASE) as client:
            receipt = HttpReceipt.model_validate(_make_http_receipt_dict())
            assert await client.verify_http_receipt(receipt) is True


class TestReceiptChain:
    async def test_empty_chain(self) -> None:
        async with ChioClient(BASE) as client:
            assert await client.verify_receipt_chain([]) is True

    async def test_single_receipt(self) -> None:
        async with ChioClient(BASE) as client:
            r = ChioReceipt.model_validate(_make_receipt_dict())
            assert await client.verify_receipt_chain([r]) is True

    async def test_valid_chain(self) -> None:
        r1 = ChioReceipt.model_validate(_make_receipt_dict())
        # Compute the expected content_hash for r2
        r1_canonical = _canonical_json(r1.model_dump(exclude_none=True))
        r1_hash = _sha256_hex(r1_canonical)

        r2_dict = _make_receipt_dict()
        r2_dict["id"] = "r-2"
        r2_dict["content_hash"] = r1_hash
        r2 = ChioReceipt.model_validate(r2_dict)

        async with ChioClient(BASE) as client:
            assert await client.verify_receipt_chain([r1, r2]) is True

    async def test_broken_chain(self) -> None:
        r1 = ChioReceipt.model_validate(_make_receipt_dict())
        r2_dict = _make_receipt_dict()
        r2_dict["id"] = "r-2"
        r2_dict["content_hash"] = "wrong"
        r2 = ChioReceipt.model_validate(r2_dict)

        async with ChioClient(BASE) as client:
            assert await client.verify_receipt_chain([r1, r2]) is False


# ---------------------------------------------------------------------------
# Tool evaluation
# ---------------------------------------------------------------------------


class TestEvaluateToolCall:
    @respx.mock
    async def test_evaluate(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=_make_receipt_dict())
        )
        async with ChioClient(BASE) as client:
            receipt = await client.evaluate_tool_call(
                capability_id="cap-1",
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
            )
            assert isinstance(receipt, ChioReceipt)
            assert receipt.is_allowed


class TestEvaluateHttpRequest:
    @respx.mock
    async def test_evaluate_http(self) -> None:
        respx.post(f"{BASE}/chio/evaluate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verdict": {"verdict": "allow"},
                    "receipt": _make_http_receipt_dict(),
                    "evidence": [],
                },
            )
        )
        async with ChioClient(BASE) as client:
            result = await client.evaluate_http_request(
                request_id="req-1",
                method="GET",
                route_pattern="/pets/{petId}",
                path="/pets/42",
                caller=CallerIdentity.anonymous(),
            )
            assert isinstance(result, EvaluateResponse)
            assert result.receipt.is_allowed


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @respx.mock
    async def test_denied_error(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(
                403,
                json={
                    "message": "capability expired",
                    "guard": "TimeGuard",
                    "reason": "token expired",
                },
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="t",
                    parameters={},
                )
            assert exc_info.value.guard == "TimeGuard"

    @respx.mock
    async def test_server_error(self) -> None:
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(500, json={"error": "internal"})
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError):
                await client.health()


# ---------------------------------------------------------------------------
# Collect evidence
# ---------------------------------------------------------------------------


class TestCollectEvidence:
    def test_collect(self) -> None:
        r1 = ChioReceipt.model_validate(_make_receipt_dict())
        r2_dict = _make_receipt_dict()
        r2_dict["evidence"] = [
            {"guard_name": "PathGuard", "verdict": True, "details": "ok"}
        ]
        r2 = ChioReceipt.model_validate(r2_dict)

        evidence = ChioClient.collect_evidence([r1, r2])
        assert len(evidence) == 1
        assert evidence[0].guard_name == "PathGuard"
