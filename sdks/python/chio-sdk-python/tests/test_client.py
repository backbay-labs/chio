"""Tests for Chio SDK Python client (uses respx to mock httpx)."""

from __future__ import annotations

import json

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


def test_handle_response_maps_non_json_403_to_denied_error() -> None:
    response = httpx.Response(
        403,
        content=b"<html>forbidden by proxy</html>",
        headers={"content-type": "text/html"},
    )

    with pytest.raises(ChioDeniedError) as exc_info:
        ChioClient._handle_response(response)

    assert exc_info.value.reason == "<html>forbidden by proxy</html>"
    assert exc_info.value.reason_code == "HTTP_403"


def _advisory_receipt_dict(outcome: str = "evaluated") -> dict:
    advisory = _make_receipt_dict()
    advisory["trust_level"] = "advisory"
    advisory["receipt_kind"] = "advisory_evaluation"
    advisory["boundary_class"] = "advisory_only"
    advisory["observation_outcome"] = outcome
    advisory["decision"] = None
    return advisory


def _advisory_wrapper(receipt: dict) -> dict:
    return {
        "schema": "chio.sidecar.advisory-evaluation.v1",
        "authorization": False,
        "authorizationBasis": "advisory_only",
        "receipt": receipt,
    }


def _advisory_verify_report(result: str = "allow") -> dict:
    return {
        "signature_valid": True,
        "signer_trusted": True,
        "receipt_id_valid": True,
        "parameter_hash_valid": True,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "trust_level": "advisory",
        "result": result,
        "authorized": False,
        "signer_key_hex": "5" * 64,
        "ok": False,
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

    @respx.mock
    async def test_403_with_non_json_body_raises_denied(self) -> None:
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.health()
        assert exc_info.value.message == "denied"
        assert exc_info.value.reason == "forbidden"
        assert exc_info.value.reason_code == "HTTP_403"


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
    async def test_attenuate_fails_closed_without_subject_signer(self) -> None:
        new_scope = ChioScope(
            grants=[
                ToolGrant(
                    server_id="s",
                    tool_name="t",
                    operations=[Operation.invoke],
                )
            ]
        )
        route = respx.post(f"{BASE}/v1/capabilities/attenuate").mock(
            return_value=httpx.Response(
                403,
                json={
                    "error": "chio_attenuation_requires_subject_signer",
                    "message": "capability attenuation requires the parent subject signer; sidecar control routes must not hold or derive that key",
                    "authorization": False,
                },
            )
        )
        async with ChioClient(BASE) as client:
            parent = CapabilityToken.model_validate(_make_token_dict())
            with pytest.raises(ChioDeniedError) as exc:
                await client.attenuate_capability(parent, new_scope=new_scope)
            assert exc.value.reason_code == "chio_attenuation_requires_subject_signer"
        assert route.called

    @respx.mock
    async def test_attenuate_rejects_unexpected_success(self) -> None:
        new_scope = ChioScope(
            grants=[
                ToolGrant(
                    server_id="s",
                    tool_name="t",
                    operations=[Operation.invoke],
                )
            ]
        )
        respx.post(f"{BASE}/v1/capabilities/attenuate").mock(
            return_value=httpx.Response(200, json=_make_token_dict())
        )
        async with ChioClient(BASE) as client:
            parent = CapabilityToken.model_validate(_make_token_dict())
            with pytest.raises(ChioDeniedError) as exc:
                await client.attenuate_capability(parent, new_scope=new_scope)
            assert exc.value.reason_code == "chio_attenuation_requires_subject_signer"


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
    async def test_evaluate_tool_call_advisory_returns_observation_receipt(self) -> None:
        advisory = _advisory_receipt_dict()
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(advisory))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )
        async with ChioClient(BASE) as client:
            receipt = await client.evaluate_tool_call_advisory(
                capability_id="cap-1",
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
            )
            assert isinstance(receipt, ChioReceipt)
            assert receipt.decision is None
            assert getattr(receipt.receipt_kind, "value", receipt.receipt_kind) == "advisory_evaluation"
            assert getattr(receipt.boundary_class, "value", receipt.boundary_class) == "advisory_only"

    @respx.mock
    async def test_evaluate_tool_call_id_only_fails_closed(self) -> None:
        # The id-only default runs advisory evaluation for its audit receipt,
        # then fails closed: a capability id alone cannot authorize execution.
        # It must never post to the token-requiring /v1/evaluate route and must
        # never return a permissive receipt a wrapper could treat as allowed.
        advisory = _advisory_receipt_dict()
        advisory_route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(advisory))
        )
        mediated_route = respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
        assert (
            exc_info.value.reason_code
            == "chio_advisory_evaluation_not_authoritative"
        )
        assert advisory_route.called
        assert not mediated_route.called

    @respx.mock
    async def test_evaluate_tool_call_id_only_fails_closed_on_dropped(self) -> None:
        # A dropped advisory observation still fails closed, with a distinct
        # deny reason so callers can tell a refusal from a non-authoritative
        # observation.
        advisory = _advisory_receipt_dict(outcome="dropped")
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(advisory))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
        assert (
            exc_info.value.reason_code == "chio_advisory_evaluation_dropped"
        )

    @respx.mock
    async def test_evaluate_tool_call_mediated_returns_mediated_response(self) -> None:
        expected = {
            "status": "authorized",
            "receipt": _make_receipt_dict(),
            "execution_nonce": {"nonce_id": "n-1", "signature": "e" * 128},
        }
        route = respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=expected)
        )
        async with ChioClient(BASE) as client:
            result = await client.evaluate_tool_call_mediated(
                capability=_make_token_dict(),
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
            )
        assert result == expected
        # This authorization request must not carry an execution_nonce field.
        request_body = json.loads(route.calls.last.request.content)
        assert "execution_nonce" not in request_body

    @respx.mock
    async def test_reconcile_mediated_authorization_posts_nonce_and_cost(self) -> None:
        nonce = {"nonce_id": "n-1", "signature": "e" * 128}
        arguments = {"path": "/tmp"}
        realized_cost = {"units": 30, "currency": "USD", "breakdown": None}
        expected = {"status": "reconciled", "receipt": _make_receipt_dict()}
        route = respx.post(f"{BASE}/v1/reconcile").mock(
            return_value=httpx.Response(200, json=expected)
        )
        async with ChioClient(BASE) as client:
            result = await client.reconcile_mediated_authorization(
                control_token="ctl-secret",
                execution_nonce=nonce,
                arguments=arguments,
                realized_cost=realized_cost,
            )
        assert result == expected
        request = route.calls.last.request
        assert request.headers["authorization"] == "Bearer ctl-secret"
        body = json.loads(request.content)
        assert body["execution_nonce"] == nonce
        assert body["arguments"] == arguments
        assert body["realized_cost"] == realized_cost

    @respx.mock
    async def test_evaluate_tool_call_mediated_forwards_governed_and_dpop(self) -> None:
        # Single-phase authorization: the helper forwards governed intent,
        # approval token, request id, and DPoP proof for gated grants, and never
        # sends an execution_nonce (this route mints nonces, it does not settle
        # a presented one).
        route = respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "authorized",
                    "receipt": _make_receipt_dict(),
                    "execution_nonce": {"nonce_id": "n-1", "signature": "e" * 128},
                },
            )
        )
        governed_intent = {"kind": "eip3009_transfer", "amount": {"units": 5}}
        approval_token = {"request_id": "req-7", "signature": "a" * 128}
        dpop_proof = {"jkt": "thumb", "proof": "p" * 32}
        async with ChioClient(BASE) as client:
            await client.evaluate_tool_call_mediated(
                capability=_make_token_dict(),
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
                request_id="req-7",
                governed_intent=governed_intent,
                approval_token=approval_token,
                dpop_proof=dpop_proof,
            )
        body = json.loads(route.calls.last.request.content)
        assert body["request_id"] == "req-7"
        assert body["governed_intent"] == governed_intent
        assert body["approval_token"] == approval_token
        assert body["dpop_proof"] == dpop_proof
        assert "execution_nonce" not in body

    @respx.mock
    async def test_evaluate_rejects_unwrapped_advisory_route_response(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_make_receipt_dict())
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call_advisory(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
            assert exc_info.value.code == "INVALID_RECEIPT"

    @respx.mock
    async def test_advisory_helper_rejects_wrapped_mediated_receipt(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                200,
                json=_advisory_wrapper(_make_receipt_dict()),
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call_advisory(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
            assert exc_info.value.code == "INVALID_RECEIPT"

    @respx.mock
    async def test_evaluate_rejects_advisory_receipt_integrity(self) -> None:
        advisory = _advisory_receipt_dict()
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(advisory))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report() | {"signature_valid": False})
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call_advisory(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
            assert exc_info.value.code == "INVALID_RECEIPT"

    @respx.mock
    async def test_evaluate_tool_call_denied_when_advisory_disabled(self) -> None:
        # With the hardened sidecar default, /v1/evaluate/advisory answers 409
        # (advisory disabled). The id-only default must still honour the
        # always-deny contract: a capability id can never authorize execution,
        # so the 409 becomes a ChioDeniedError, not a bare infrastructure
        # ChioError that adapters would retry as a transport failure.
        advisory_route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                409,
                json={
                    "error": "chio_advisory_disabled",
                    "authorization": False,
                    "message": (
                        "advisory tool-call evaluation is disabled; use the "
                        "kernel-mediated route"
                    ),
                    "replacement": "/v1/evaluate",
                },
            )
        )
        mediated_route = respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json={})
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
        assert (
            exc_info.value.reason_code
            == "chio_advisory_evaluation_unavailable"
        )
        assert exc_info.value.tool_name == "read"
        assert exc_info.value.tool_server == "srv"
        assert advisory_route.called
        # Deny must not silently reach for the token-requiring mediated route.
        assert not mediated_route.called

    @respx.mock
    async def test_evaluate_tool_call_propagates_transport_error(self) -> None:
        # A genuine transport failure (5xx) is retryable infrastructure, not a
        # policy decision. It must surface as ChioError so adapters that
        # distinguish a DENY from a FAILURE do not mask it as a deny.
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(503, json={"error": "unavailable"})
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
        # Not a deny: the error keeps its transport code for retryability.
        assert not isinstance(exc_info.value, ChioDeniedError)
        assert exc_info.value.code == "HTTP_503"

    @respx.mock
    async def test_evaluate_tool_call_propagates_connection_error(self) -> None:
        # A connection failure is likewise infrastructure, not a policy deny.
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
        assert not isinstance(exc_info.value, ChioDeniedError)
        assert exc_info.value.code == "CONNECTION_ERROR"

    @respx.mock
    async def test_evaluate_tool_call_denied_on_403(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                403,
                json={
                    "message": "capability exhausted",
                    "guard": "BudgetGuard",
                    "reason": "budget exceeded",
                },
            )
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.evaluate_tool_call(
                    capability_id="cap-1",
                    tool_server="srv",
                    tool_name="read",
                    parameters={"path": "/tmp"},
                )
            assert exc_info.value.guard == "BudgetGuard"


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
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
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
    async def test_denied_error_handles_non_json_body(self) -> None:
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(403, text="<html>forbidden</html>")
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioDeniedError) as exc_info:
                await client.health()
            assert exc_info.value.message == "denied"
            assert exc_info.value.reason == "<html>forbidden</html>"
            assert exc_info.value.reason_code == "HTTP_403"

    @respx.mock
    async def test_malformed_success_raises_typed_chio_error(self) -> None:
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(200, text="not json")
        )
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as exc_info:
                await client.health()
            assert exc_info.value.code == "INVALID_RESPONSE"

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
