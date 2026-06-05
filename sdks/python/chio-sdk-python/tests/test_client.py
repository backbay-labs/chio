"""Tests for Chio SDK Python client (uses respx to mock httpx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from chio_sdk.client import ChioClient, _canonical_json, _sha256_hex
from chio_sdk.errors import (
    ChioDeniedError,
    ChioError,
)
from chio_sdk.models import (
    ChioReceipt,
    ChioScope,
    CallerIdentity,
    CapabilityToken,
    EvaluateResponse,
    HttpReceipt,
    Operation,
    ToolGrant,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE = "http://127.0.0.1:9090"


def _make_token_dict() -> dict:
    return {
        "id": "tok-1",
        "issuer": "a" * 64,
        "subject": "b" * 64,
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
        "signature": "c" * 128,
    }


def _make_receipt_dict() -> dict:
    return {
        "id": "1" * 64,
        "timestamp": 1700000000,
        "capability_id": "cap-1",
        "tool_server": "srv",
        "tool_name": "read",
        "action": {"parameters": {}, "parameter_hash": "2" * 64},
        "decision": {"verdict": "allow"},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "content_hash": "3" * 64,
        "policy_hash": "4" * 64,
        "trust_level": "mediated",
        "kernel_key": "5" * 64,
        "signature": "6" * 128,
    }


def _make_http_receipt_dict() -> dict:
    return {
        "id": "7" * 64,
        "request_id": "req-1",
        "route_pattern": "/pets/{petId}",
        "method": "GET",
        "caller_identity_hash": "abc",
        "verdict": {"verdict": "allow"},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "trust_level": "mediated",
        "response_status": 200,
        "timestamp": 1700000000,
        "content_hash": "8" * 64,
        "policy_hash": "9" * 64,
        "kernel_key": "a" * 64,
        "signature": "b" * 128,
    }


def _verify_report(authorized: bool) -> dict:
    return {
        "signature_valid": authorized,
        "signer_trusted": authorized,
        "receipt_id_valid": authorized,
        "parameter_hash_valid": authorized,
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "trust_level": "mediated",
        "result": "allow" if authorized else "deny",
        "authorized": authorized,
        "signer_key_hex": "d" * 64,
        "ok": authorized,
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
                        operations=[Operation.invoke],
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
                    operations=[Operation.invoke],
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
            return_value=httpx.Response(200, json=_verify_report(True))
        )
        async with ChioClient(BASE) as client:
            receipt = ChioReceipt.model_validate(_make_receipt_dict())
            assert await client.verify_receipt(receipt) is True

    @respx.mock
    async def test_legacy_valid_true_is_not_authoritative(self) -> None:
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json={"valid": True})
        )
        async with ChioClient(BASE) as client:
            receipt = ChioReceipt.model_validate(_make_receipt_dict())
            assert await client.verify_receipt(receipt) is False

    @respx.mock
    async def test_untrusted_signer_report_is_not_authoritative(self) -> None:
        report = _verify_report(True)
        report["signer_trusted"] = False
        report["authorized"] = False
        report["ok"] = False
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=report)
        )
        async with ChioClient(BASE) as client:
            receipt = ChioReceipt.model_validate(_make_receipt_dict())
            assert await client.verify_receipt(receipt) is False


class TestVerifyHttpReceipt:
    @respx.mock
    async def test_verify_http(self) -> None:
        respx.post(f"{BASE}/chio/verify").mock(
            return_value=httpx.Response(200, json=_verify_report(True))
        )
        async with ChioClient(BASE) as client:
            receipt = HttpReceipt.model_validate(_make_http_receipt_dict())
            report = await client.verify_http_receipt(receipt)
            assert report.ok is True
            assert report.authorized is True


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
        r2_dict["id"] = "a" * 64
        r2_dict["content_hash"] = r1_hash
        r2 = ChioReceipt.model_validate(r2_dict)

        async with ChioClient(BASE) as client:
            assert await client.verify_receipt_chain([r1, r2]) is True

    async def test_broken_chain(self) -> None:
        r1 = ChioReceipt.model_validate(_make_receipt_dict())
        r2_dict = _make_receipt_dict()
        r2_dict["id"] = "a" * 64
        r2_dict["content_hash"] = "b" * 64
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
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_verify_report(True))
        )
        async with ChioClient(BASE) as client:
            receipt = await client.evaluate_tool_call(
                capability_id="cap-1",
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
            )
            assert isinstance(receipt, ChioReceipt)
            assert receipt.decision is not None
            assert receipt.decision.root.verdict == "allow"

    @respx.mock
    async def test_evaluate_rejects_unverified_receipt(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=_make_receipt_dict())
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_verify_report(False))
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
            assert exc_info.value.code == "INVALID_RECEIPT"

    @respx.mock
    async def test_evaluate_rejects_advisory_receipt_integrity(self) -> None:
        advisory = _make_receipt_dict()
        advisory["trust_level"] = "advisory"
        advisory["receipt_kind"] = "advisory_evaluation"
        advisory["boundary_class"] = "advisory_only"
        advisory["decision"] = None
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=advisory)
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(
                200,
                json={
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
                },
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError, match="advisory receipt"):
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )

    @respx.mock
    async def test_evaluate_rejects_advisory_dropped(self) -> None:
        advisory = _make_receipt_dict()
        advisory["trust_level"] = "advisory"
        advisory["receipt_kind"] = "advisory_evaluation"
        advisory["boundary_class"] = "advisory_only"
        advisory["decision"] = None
        advisory["observation_outcome"] = "dropped"
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=advisory)
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "signature_valid": True,
                    "signer_trusted": True,
                    "receipt_id_valid": True,
                    "parameter_hash_valid": True,
                    "receipt_kind": "advisory_evaluation",
                    "boundary_class": "advisory_only",
                    "trust_level": "advisory",
                    "result": "deny",
                    "authorized": False,
                    "signer_key_hex": "5" * 64,
                    "ok": False,
                },
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError):
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )


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
        respx.post(f"{BASE}/chio/verify").mock(
            return_value=httpx.Response(200, json=_verify_report(True))
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

    @respx.mock
    async def test_evaluate_http_rejects_unverified_allow_receipt(self) -> None:
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
        respx.post(f"{BASE}/chio/verify").mock(
            return_value=httpx.Response(200, json=_verify_report(False))
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_http_request(
                    request_id="req-1",
                    method="GET",
                    route_pattern="/pets/{petId}",
                    path="/pets/42",
                    caller=CallerIdentity.anonymous(),
                )
            assert exc_info.value.code == "INVALID_RECEIPT"

    @respx.mock
    async def test_evaluate_http_rejects_allow_without_structural_authority(self) -> None:
        receipt = _make_http_receipt_dict()
        receipt.pop("receipt_kind")
        receipt.pop("boundary_class")
        respx.post(f"{BASE}/chio/evaluate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verdict": {"verdict": "allow"},
                    "receipt": receipt,
                    "evidence": [],
                },
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_http_request(
                    request_id="req-1",
                    method="GET",
                    route_pattern="/pets/{petId}",
                    path="/pets/42",
                    caller=CallerIdentity.anonymous(),
                )
            assert exc_info.value.code == "INVALID_RECEIPT"


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
