"""Tests for Chio SDK Python models."""

from __future__ import annotations

import json
import time

import pytest
from pydantic import ValidationError

from chio_sdk._generated import (
    CapabilityToken as GeneratedCapabilityToken,
    ChioCapabilitytoken,
)
from chio_sdk._generated.capability import Constraint as GeneratedConstraint
from chio_sdk._generated.jsonrpc import ChioJsonRpc20Response
from chio_sdk._generated.provenance import ChioProvenanceVerdictLink
from chio_sdk.models import (
    ChioReceipt,
    ChioScope,
    Attenuation,
    AuthMethod,
    CallerIdentity,
    CapabilityToken,
    CapabilityTokenBody,
    Constraint,
    Decision,
    DelegationLink,
    GuardEvidence,
    HttpReceipt,
    MonetaryAmount,
    Operation,
    PromptGrant,
    ResourceGrant,
    ToolCallAction,
    ToolGrant,
    Verdict,
)


# ---------------------------------------------------------------------------
# Operation enum
# ---------------------------------------------------------------------------


class TestOperation:
    def test_values(self) -> None:
        assert Operation.INVOKE.value == "invoke"
        assert Operation.READ_RESULT.value == "read_result"
        assert Operation.DELEGATE.value == "delegate"

    def test_legacy_input_aliases_serialize_snake_case(self) -> None:
        grant = ToolGrant.model_validate(
            {
                "server_id": "s",
                "tool_name": "t",
                "operations": ["Invoke", "ReadResult"],
            }
        )
        assert grant.operations == [Operation.INVOKE, Operation.READ_RESULT]
        data = json.loads(grant.model_dump_json())
        assert data["operations"] == ["invoke", "read_result"]


class TestGeneratedWireModels:
    def test_top_level_capability_token_alias_is_canonical(self) -> None:
        assert GeneratedCapabilityToken is ChioCapabilitytoken

    def test_constraint_value_payload_round_trips(self) -> None:
        constraint = GeneratedConstraint.model_validate(
            {"type": "path_prefix", "value": "/safe"}
        )
        assert constraint.value == "/safe"
        assert constraint.model_dump(exclude_none=True) == {
            "type": "path_prefix",
            "value": "/safe",
        }

    def test_jsonrpc_response_rejects_result_and_error_together(self) -> None:
        with pytest.raises(ValidationError):
            ChioJsonRpc20Response.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"ok": True},
                    "error": {"code": -32603, "message": "internal"},
                }
            )
        with pytest.raises(ValidationError):
            ChioJsonRpc20Response.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"ok": True},
                    "error": None,
                }
            )
        with pytest.raises(ValidationError):
            ChioJsonRpc20Response.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": None,
                    "error": {"code": -32603, "message": "internal"},
                }
            )

    def test_jsonrpc_response_accepts_one_branch(self) -> None:
        success = ChioJsonRpc20Response.model_validate(
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        )
        failure = ChioJsonRpc20Response.model_validate(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32603, "message": "internal"},
            }
        )
        assert success.root.jsonrpc == "2.0"
        assert failure.root.jsonrpc == "2.0"

    def test_provenance_verdict_link_rejects_forbidden_fields(self) -> None:
        base = {"requestId": "req-1", "chainId": "chain-1", "renderedAt": 1}
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {**base, "verdict": "allow", "reason": "not allowed"}
            )
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {**base, "verdict": "allow", "reason": None}
            )
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {
                    **base,
                    "verdict": "cancel",
                    "reason": "operator cancelled",
                    "guard": "pii_guard",
                }
            )
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {
                    **base,
                    "verdict": "cancel",
                    "reason": "operator cancelled",
                    "guard": None,
                }
            )
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {
                    **base,
                    "verdict": "incomplete",
                    "reason": "upstream interrupted",
                    "guard": "pii_guard",
                }
            )
        with pytest.raises(ValidationError):
            ChioProvenanceVerdictLink.model_validate(
                {
                    **base,
                    "verdict": "incomplete",
                    "reason": "upstream interrupted",
                    "guard": None,
                }
            )


# ---------------------------------------------------------------------------
# MonetaryAmount
# ---------------------------------------------------------------------------


class TestMonetaryAmount:
    def test_construction(self) -> None:
        m = MonetaryAmount(units=500, currency="USD")
        assert m.units == 500
        assert m.currency == "USD"

    def test_serde(self) -> None:
        m = MonetaryAmount(units=100, currency="EUR")
        data = m.model_dump()
        m2 = MonetaryAmount.model_validate(data)
        assert m2.units == 100
        assert m2.currency == "EUR"


# ---------------------------------------------------------------------------
# Constraint
# ---------------------------------------------------------------------------


class TestConstraint:
    def test_path_prefix(self) -> None:
        c = Constraint.path_prefix("/home/user")
        assert c.type == "path_prefix"
        assert c.value == "/home/user"

    def test_domain_exact(self) -> None:
        c = Constraint.domain_exact("example.com")
        assert c.type == "domain_exact"

    def test_max_length(self) -> None:
        c = Constraint.max_length(256)
        assert c.value == 256

    def test_json_value_payloads(self) -> None:
        object_constraint = Constraint(type="structured", value={"path": "/safe"})
        array_constraint = Constraint(type="one_of", value=["read", "list"])
        assert object_constraint.value == {"path": "/safe"}
        assert array_constraint.value == ["read", "list"]


# ---------------------------------------------------------------------------
# ToolGrant
# ---------------------------------------------------------------------------


class TestToolGrant:
    def test_basic_subset(self) -> None:
        parent = ToolGrant(
            server_id="srv-1",
            tool_name="read_file",
            operations=[Operation.INVOKE, Operation.READ_RESULT],
        )
        child = ToolGrant(
            server_id="srv-1",
            tool_name="read_file",
            operations=[Operation.INVOKE],
        )
        assert child.is_subset_of(parent)
        assert not parent.is_subset_of(child)

    def test_wildcard_server(self) -> None:
        parent = ToolGrant(
            server_id="*",
            tool_name="*",
            operations=[Operation.INVOKE],
        )
        child = ToolGrant(
            server_id="any-server",
            tool_name="any-tool",
            operations=[Operation.INVOKE],
        )
        assert child.is_subset_of(parent)

    def test_invocation_cap(self) -> None:
        parent = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_invocations=10,
        )
        child_ok = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_invocations=5,
        )
        child_bad = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            # no cap -- violates parent's cap
        )
        assert child_ok.is_subset_of(parent)
        assert not child_bad.is_subset_of(parent)

    def test_cost_cap(self) -> None:
        parent = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_cost_per_invocation=MonetaryAmount(units=100, currency="USD"),
        )
        child_ok = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_cost_per_invocation=MonetaryAmount(units=50, currency="USD"),
        )
        child_bad = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_cost_per_invocation=MonetaryAmount(units=200, currency="USD"),
        )
        assert child_ok.is_subset_of(parent)
        assert not child_bad.is_subset_of(parent)

    def test_dpop_required(self) -> None:
        parent = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            dpop_required=True,
        )
        child_ok = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            dpop_required=True,
        )
        child_bad = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            dpop_required=False,
        )
        assert child_ok.is_subset_of(parent)
        assert not child_bad.is_subset_of(parent)


# ---------------------------------------------------------------------------
# ChioScope
# ---------------------------------------------------------------------------


class TestChioScope:
    def test_subset(self) -> None:
        parent = ChioScope(
            grants=[
                ToolGrant(
                    server_id="s",
                    tool_name="*",
                    operations=[Operation.INVOKE],
                )
            ],
        )
        child = ChioScope(
            grants=[
                ToolGrant(
                    server_id="s",
                    tool_name="read",
                    operations=[Operation.INVOKE],
                )
            ],
        )
        assert child.is_subset_of(parent)

    def test_empty_scope_is_subset(self) -> None:
        parent = ChioScope(grants=[])
        child = ChioScope(grants=[])
        assert child.is_subset_of(parent)

    def test_resource_grants(self) -> None:
        parent = ChioScope(
            resource_grants=[
                ResourceGrant(uri_pattern="*", operations=[Operation.READ])
            ]
        )
        child = ChioScope(
            resource_grants=[
                ResourceGrant(
                    uri_pattern="file:///tmp", operations=[Operation.READ]
                )
            ]
        )
        assert child.is_subset_of(parent)


# ---------------------------------------------------------------------------
# CapabilityToken
# ---------------------------------------------------------------------------


class TestCapabilityToken:
    def test_time_validity(self) -> None:
        now = int(time.time())
        token = CapabilityToken(
            id="tok-1",
            issuer="aabbcc",
            subject="ddeeff",
            scope=ChioScope(),
            issued_at=now - 60,
            expires_at=now + 3600,
            signature="sig",
        )
        assert token.is_valid_at(now)
        assert not token.is_expired_at(now)
        assert token.is_expired_at(now + 7200)
        assert not token.is_valid_at(now - 120)

    def test_body_extraction(self) -> None:
        token = CapabilityToken(
            id="tok-2",
            issuer="aa",
            subject="bb",
            scope=ChioScope(),
            issued_at=100,
            expires_at=200,
            signature="sig",
        )
        body = token.body()
        assert isinstance(body, CapabilityTokenBody)
        assert body.id == "tok-2"
        assert body.issuer == "aa"

    def test_serde_roundtrip(self) -> None:
        token = CapabilityToken(
            id="tok-3",
            issuer="aa",
            subject="bb",
            scope=ChioScope(
                grants=[
                    ToolGrant(
                        server_id="s",
                        tool_name="t",
                        operations=[Operation.INVOKE],
                    )
                ]
            ),
            issued_at=100,
            expires_at=200,
            signature="sig123",
        )
        data = json.loads(token.model_dump_json())
        token2 = CapabilityToken.model_validate(data)
        assert token2.id == token.id
        assert len(token2.scope.grants) == 1


# ---------------------------------------------------------------------------
# Decision / Verdict
# ---------------------------------------------------------------------------


class TestDecision:
    def test_allow(self) -> None:
        d = Decision.allow()
        assert d.is_allowed
        assert not d.is_denied

    def test_deny(self) -> None:
        d = Decision.deny("not authorized", "CapabilityGuard")
        assert d.is_denied
        assert d.guard == "CapabilityGuard"

    def test_serde(self) -> None:
        d = Decision.deny("blocked", "TestGuard")
        data = d.model_dump(exclude_none=True)
        assert data["verdict"] == "deny"
        d2 = Decision.model_validate(data)
        assert d2.is_denied


class TestVerdict:
    def test_allow(self) -> None:
        v = Verdict.allow()
        assert v.is_allowed

    def test_deny_default_status(self) -> None:
        v = Verdict.deny("no cap", "Guard", 403)
        assert v.is_denied
        assert v.http_status == 403

    def test_to_decision(self) -> None:
        v = Verdict.deny("blocked", "TestGuard")
        d = v.to_decision()
        assert d.is_denied
        assert d.guard == "TestGuard"


# ---------------------------------------------------------------------------
# GuardEvidence
# ---------------------------------------------------------------------------


class TestGuardEvidence:
    def test_construction(self) -> None:
        e = GuardEvidence(
            guard_name="ForbiddenPathGuard",
            verdict=True,
            details="path allowed",
        )
        assert e.verdict is True
        assert e.guard_name == "ForbiddenPathGuard"


# ---------------------------------------------------------------------------
# ChioReceipt
# ---------------------------------------------------------------------------


class TestChioReceipt:
    def test_allowed_receipt(self) -> None:
        receipt = ChioReceipt(
            id="r-1",
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read_file",
            action=ToolCallAction(
                parameters={"path": "/tmp/f"},
                parameter_hash="abc",
            ),
            decision=Decision.allow(),
            content_hash="deadbeef",
            policy_hash="cafebabe",
            kernel_key="kernelkey",
            signature="sig",
        )
        assert receipt.is_allowed
        assert not receipt.is_denied

    def test_denied_receipt(self) -> None:
        receipt = ChioReceipt(
            id="r-2",
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write_file",
            action=ToolCallAction(parameters={}, parameter_hash="x"),
            decision=Decision.deny("forbidden", "PathGuard"),
            content_hash="aa",
            policy_hash="bb",
            evidence=[
                GuardEvidence(
                    guard_name="PathGuard", verdict=False, details="denied"
                )
            ],
            kernel_key="k",
            signature="s",
        )
        assert receipt.is_denied
        assert len(receipt.evidence) == 1


# ---------------------------------------------------------------------------
# HttpReceipt
# ---------------------------------------------------------------------------


class TestHttpReceipt:
    def test_serde(self) -> None:
        receipt = HttpReceipt(
            id="hr-1",
            request_id="req-1",
            route_pattern="/pets/{petId}",
            method="GET",
            caller_identity_hash="abc",
            verdict=Verdict.allow(),
            response_status=200,
            timestamp=1700000000,
            content_hash="x",
            policy_hash="y",
            kernel_key="k",
            signature="s",
        )
        data = json.loads(receipt.model_dump_json())
        hr2 = HttpReceipt.model_validate(data)
        assert hr2.is_allowed
        assert hr2.method == "GET"


# ---------------------------------------------------------------------------
# CallerIdentity
# ---------------------------------------------------------------------------


class TestCallerIdentity:
    def test_anonymous(self) -> None:
        ci = CallerIdentity.anonymous()
        assert ci.subject == "anonymous"
        assert ci.auth_method.method == "anonymous"
        assert ci.verified is False

    def test_bearer(self) -> None:
        ci = CallerIdentity(
            subject="user-1",
            auth_method=AuthMethod.bearer(token_hash="abc"),
            verified=True,
        )
        assert ci.auth_method.method == "bearer"
        assert ci.auth_method.token_hash == "abc"


# ---------------------------------------------------------------------------
# Attenuation / DelegationLink
# ---------------------------------------------------------------------------


class TestAttenuation:
    def test_remove_tool(self) -> None:
        a = Attenuation.remove_tool("srv", "dangerous_tool")
        assert a.type == "remove_tool"
        assert a.server_id == "srv"

    def test_add_constraint(self) -> None:
        a = Attenuation.add_constraint(
            "srv", "read_file", Constraint.path_prefix("/safe")
        )
        assert a.type == "add_constraint"
        assert a.constraint is not None
        assert a.constraint.value == "/safe"


class TestDelegationLink:
    def test_construction(self) -> None:
        dl = DelegationLink(
            capability_id="cap-1",
            delegator="aabb",
            delegatee="ccdd",
            timestamp=1000,
            signature="sig",
        )
        assert dl.delegator == "aabb"
        assert len(dl.attenuations) == 0
