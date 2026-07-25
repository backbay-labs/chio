"""Tests for Chio SDK Python models."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from chio_sdk._generated import (
    CapabilityToken as GeneratedCapabilityToken,
    ChioCapabilitytoken,
)
from chio_sdk._generated.capability import Constraint as GeneratedConstraint
from chio_sdk._generated.jsonrpc import ChioJsonRpc20Response
from chio_sdk._generated.provenance import ChioProvenanceVerdictLink
from chio_sdk._generated.agent.active_response_governed_intent_schema import (
    ChioGovernedActiveResponseIntentBody,
)
from chio_sdk._generated.capability.aggregate_invocation_budget_schema import (
    ChioAggregateInvocationBudget,
)
from chio_sdk._generated.capability.governed_approval_token_schema import (
    ChioGovernedApprovalToken,
)
from chio_sdk._generated.capability.supplemental_authorization_schema import (
    ChioOpaqueSupplementalAuthorization,
)
from chio_sdk._generated.capability.threshold_approval_proposal_schema import (
    ChioThresholdApprovalProposal,
)
from chio_sdk._generated.kernel.combined_capture_metadata_schema import (
    ChioCombinedAdmissionCaptureMetadata,
)
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


def _generated_v1_token() -> dict[str, object]:
    return {
        "schema": "chio.capability.v1",
        "id": "cap-v1",
        "issuer": "a" * 64,
        "subject": "b" * 64,
        "scope": {},
        "issued_at": 1,
        "expires_at": 2,
        "signature": "c" * 128,
    }


def _generated_attenuated_token() -> dict[str, object]:
    return {
        "schema": "chio.capability.v1",
        "id": "cap-attenuated",
        "issuer": "a" * 64,
        "subject": "b" * 64,
        "scope": {"grants": []},
        "issued_at": 1,
        "expires_at": 2,
        "attenuation_proof": {
            "parentScopeHash": "0" * 64,
            "childScopeHash": "1" * 64,
            "normalizedSubsetProof": {
                "normalizedParentScope": "{}",
                "normalizedChildScope": "{}",
            },
        },
        "signature": "c" * 128,
    }


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
    def test_protocol_primitives_shared_fixtures_parse_reject_and_round_trip(
        self,
    ) -> None:
        models: dict[str, type[Any]] = {
            "capability/token.schema.json": ChioCapabilitytoken,
            "capability/aggregate-invocation-budget.schema.json": ChioAggregateInvocationBudget,
            "capability/threshold-approval-proposal.schema.json": ChioThresholdApprovalProposal,
            "capability/governed-approval-token.schema.json": ChioGovernedApprovalToken,
            "agent/active-response-governed-intent.schema.json": ChioGovernedActiveResponseIntentBody,
            "kernel/combined-capture-metadata.schema.json": ChioCombinedAdmissionCaptureMetadata,
            "capability/supplemental-authorization.schema.json": ChioOpaqueSupplementalAuthorization,
        }
        corpus = json.loads(
            (
                Path(__file__).resolve().parents[4]
                / "tests/bindings/fixtures/protocol-primitives-v1.json"
            ).read_text(encoding="utf-8")
        )

        for case in corpus["cases"]:
            model = models[case["schema_file"]]
            if case["valid"]:
                parsed = model.model_validate(case["instance"])
                assert parsed.model_dump(mode="json", by_alias=True, exclude_none=True) == case[
                    "instance"
                ]
            else:
                with pytest.raises(ValidationError):
                    model.model_validate(case["instance"])

    def test_top_level_capability_token_alias_is_canonical(self) -> None:
        token = GeneratedCapabilityToken.model_validate(_generated_v1_token())
        assert isinstance(token, ChioCapabilitytoken)

    def test_top_level_capability_token_alias_accepts_attenuated_current(self) -> None:
        token = GeneratedCapabilityToken.model_validate(_generated_attenuated_token())
        assert isinstance(token, ChioCapabilitytoken)

    def test_top_level_capability_token_constructor_dispatches(self) -> None:
        token_v1 = GeneratedCapabilityToken(**_generated_v1_token())
        token_attenuated = GeneratedCapabilityToken(**_generated_attenuated_token())

        assert isinstance(token_v1, ChioCapabilitytoken)
        assert isinstance(token_attenuated, ChioCapabilitytoken)

    def test_top_level_capability_token_schema_is_current(self) -> None:
        schema = GeneratedCapabilityToken.model_json_schema()
        serialized = json.dumps(schema)
        assert "chio.capability.v1" in serialized
        assert "chio.capability.experimental" not in serialized

    def test_top_level_capability_token_type_adapter_dispatches_python(self) -> None:
        token = GeneratedCapabilityToken.model_validate(_generated_v1_token())
        assert isinstance(token, ChioCapabilitytoken)
        dumped = token.model_dump(by_alias=True, exclude_none=True)
        assert dumped["schema"] == "chio.capability.v1"
        assert dumped["id"] == "cap-v1"

        adapted_v1 = TypeAdapter(GeneratedCapabilityToken).validate_python(
            _generated_v1_token()
        )
        adapted_attenuated = TypeAdapter(GeneratedCapabilityToken).validate_python(
            _generated_attenuated_token()
        )
        assert isinstance(adapted_v1, ChioCapabilitytoken)
        assert isinstance(adapted_attenuated, ChioCapabilitytoken)

    def test_top_level_capability_token_json_dispatch_accepts_attenuated_current(
        self,
    ) -> None:
        token = GeneratedCapabilityToken.model_validate_json(
            json.dumps(_generated_attenuated_token())
        )
        assert isinstance(token, ChioCapabilitytoken)

        adapted = TypeAdapter(GeneratedCapabilityToken).validate_json(
            json.dumps(_generated_attenuated_token())
        )
        assert isinstance(adapted, ChioCapabilitytoken)

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

    def test_resource_grant_prefix_pattern_subset(self) -> None:
        parent = ChioScope(
            resource_grants=[
                ResourceGrant(
                    uri_pattern="file:///tenant/*",
                    operations=[Operation.READ, Operation.SUBSCRIBE],
                )
            ]
        )
        child = ChioScope(
            resource_grants=[
                ResourceGrant(
                    uri_pattern="file:///tenant/a", operations=[Operation.READ]
                )
            ]
        )
        outside = ChioScope(
            resource_grants=[
                ResourceGrant(
                    uri_pattern="file:///other/a", operations=[Operation.READ]
                )
            ]
        )
        assert child.is_subset_of(parent)
        assert not outside.is_subset_of(parent)

    def test_prompt_grant_name_and_operation_subset(self) -> None:
        parent = ChioScope(
            prompt_grants=[
                PromptGrant(
                    prompt_name="*",
                    operations=[Operation.GET, Operation.DELEGATE],
                )
            ]
        )
        child = ChioScope(
            prompt_grants=[
                PromptGrant(prompt_name="welcome", operations=[Operation.GET])
            ]
        )
        overbroad = ChioScope(
            prompt_grants=[
                PromptGrant(
                    prompt_name="welcome",
                    operations=[Operation.GET, Operation.DELEGATE],
                )
            ]
        )
        assert child.is_subset_of(parent)
        assert overbroad.is_subset_of(parent)

        read_only_parent = ChioScope(
            prompt_grants=[
                PromptGrant(prompt_name="welcome", operations=[Operation.GET])
            ]
        )
        assert not overbroad.is_subset_of(read_only_parent)


# ---------------------------------------------------------------------------
# CapabilityToken
# ---------------------------------------------------------------------------


class TestCapabilityToken:
    def test_time_validity(self) -> None:
        now = int(time.time())
        token = CapabilityToken(
            id="tok-1",
            issuer="a" * 64,
            subject="b" * 64,
            scope=ChioScope(),
            issued_at=now - 60,
            expires_at=now + 3600,
            signature="c" * 128,
        )
        assert token.is_valid_at(now)
        assert not token.is_expired_at(now)
        assert token.is_expired_at(now + 7200)
        assert not token.is_valid_at(now - 120)

    def test_body_extraction(self) -> None:
        token = CapabilityToken(
            id="tok-2",
            issuer="a" * 64,
            subject="b" * 64,
            scope=ChioScope(),
            issued_at=100,
            expires_at=200,
            signature="c" * 128,
        )
        body = token.body()
        assert isinstance(body, CapabilityTokenBody)
        assert body.id == "tok-2"
        assert body.issuer == "a" * 64
        assert body.delegation_chain == []

    def test_serde_roundtrip(self) -> None:
        token = CapabilityToken(
            id="tok-3",
            issuer="a" * 64,
            subject="b" * 64,
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
            signature="c" * 128,
        )
        data = json.loads(token.model_dump_json(by_alias=True))
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
            id="1" * 64,
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read_file",
            action=ToolCallAction(
                parameters={"path": "/tmp/f"},
                parameter_hash="a" * 64,
            ),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            trust_level="mediated",
            content_hash="d" * 64,
            policy_hash="cafebabe",
            kernel_key="b" * 64,
            signature="c" * 128,
        )
        assert receipt.is_allowed
        assert not receipt.is_denied

    def test_denied_receipt(self) -> None:
        receipt = ChioReceipt(
            id="2" * 64,
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write_file",
            action=ToolCallAction(parameters={}, parameter_hash="a" * 64),
            decision=Decision.deny("forbidden", "PathGuard"),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            trust_level="mediated",
            content_hash="d" * 64,
            policy_hash="bb",
            evidence=[
                GuardEvidence(
                    guard_name="PathGuard", verdict=False, details="denied"
                )
            ],
            kernel_key="b" * 64,
            signature="c" * 128,
        )
        assert receipt.is_denied
        assert len(receipt.evidence) == 1

    def test_missing_decision_receipt_is_not_allowed_or_denied(self) -> None:
        receipt = ChioReceipt.model_construct(decision=None)
        assert not receipt.is_allowed
        assert not receipt.is_denied

    def test_non_bbs_receipt_omits_bbs_fields_from_wire_dump(self) -> None:
        receipt = ChioReceipt(
            id="5" * 64,
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read_file",
            action=ToolCallAction(
                parameters={"path": "/tmp/f"},
                parameter_hash="a" * 64,
            ),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            trust_level="mediated",
            content_hash="d" * 64,
            policy_hash="cafebabe",
            kernel_key="b" * 64,
            signature="c" * 128,
        )

        dumped = receipt.model_dump(by_alias=True, exclude_none=True)
        assert "bbs_projection_version" not in dumped
        assert "bbs_signature" not in dumped

    def test_bbs_receipt_fields_must_be_paired(self) -> None:
        base = {
            "id": "6" * 64,
            "timestamp": 1700000000,
            "capability_id": "cap-1",
            "tool_server": "srv",
            "tool_name": "read_file",
            "action": ToolCallAction(
                parameters={"path": "/tmp/f"},
                parameter_hash="a" * 64,
            ),
            "decision": Decision.allow(),
            "receipt_kind": "mediated_decision",
            "boundary_class": "prevent",
            "tool_origin": "caller_executed",
            "redaction_mode": "none",
            "trust_level": "mediated",
            "content_hash": "d" * 64,
            "policy_hash": "cafebabe",
            "kernel_key": "b" * 64,
            "signature": "c" * 128,
        }
        signature = {
            "schema": "chio.receipt.bbs_signature.v1",
            "projection_version": "chio.bbs-projection.receipt.v1",
            "algorithm": "bbs",
            "ciphersuite": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            "issuer_fingerprint": "issuer:chio:test-bbs",
            "issuer_public_key_hex": "11" * 96,
            "message_count": 14,
            "signature_hex": "22" * 80,
        }

        with pytest.raises(ValidationError):
            ChioReceipt(**base, bbs_projection_version="chio.bbs-projection.receipt.v1")
        with pytest.raises(ValidationError):
            ChioReceipt(**base, bbs_signature=signature)

    def test_bbs_receipt_fields_validate(self) -> None:
        receipt = ChioReceipt(
            id="3" * 64,
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read_file",
            action=ToolCallAction(
                parameters={"path": "/tmp/f"},
                parameter_hash="a" * 64,
            ),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            trust_level="mediated",
            content_hash="d" * 64,
            policy_hash="cafebabe",
            bbs_projection_version="chio.bbs-projection.receipt.v1",
            bbs_signature={
                "schema": "chio.receipt.bbs_signature.v1",
                "projection_version": "chio.bbs-projection.receipt.v1",
                "algorithm": "bbs",
                "ciphersuite": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
                "issuer_fingerprint": "issuer:chio:test-bbs",
                "issuer_public_key_hex": "11" * 96,
                "message_count": 14,
                "signature_hex": "22" * 80,
            },
            kernel_key="b" * 64,
            signature="c" * 128,
        )

        dumped = receipt.model_dump(by_alias=True)
        assert dumped["bbs_projection_version"] == "chio.bbs-projection.receipt.v1"
        assert dumped["bbs_signature"]["issuer_fingerprint"] == "issuer:chio:test-bbs"

    def test_bbs_receipt_rejects_wire_invalid_fingerprint(self) -> None:
        with pytest.raises(ValidationError):
            ChioReceipt(
                id="4" * 64,
                timestamp=1700000000,
                capability_id="cap-1",
                tool_server="srv",
                tool_name="read_file",
                action=ToolCallAction(
                    parameters={"path": "/tmp/f"},
                    parameter_hash="a" * 64,
                ),
                decision=Decision.allow(),
                receipt_kind="mediated_decision",
                boundary_class="prevent",
                tool_origin="caller_executed",
                redaction_mode="none",
                trust_level="mediated",
                content_hash="d" * 64,
                policy_hash="cafebabe",
                bbs_projection_version="chio.bbs-projection.receipt.v1",
                bbs_signature={
                    "schema": "chio.receipt.bbs_signature.v1",
                    "projection_version": "chio.bbs-projection.receipt.v1",
                    "algorithm": "bbs",
                    "ciphersuite": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
                    "issuer_fingerprint": "issuer chio test-bbs",
                    "issuer_public_key_hex": "11" * 96,
                    "message_count": 14,
                    "signature_hex": "22" * 80,
                },
                kernel_key="b" * 64,
                signature="c" * 128,
            )


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
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            response_status=200,
            timestamp=1700000000,
            content_hash="x",
            policy_hash="y",
            trust_level="mediated",
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
            delegator="a" * 64,
            delegatee="b" * 64,
            timestamp=1000,
            signature="c" * 128,
            scope_hash="d" * 64,
        )
        assert dl.delegator == "a" * 64
        assert len(dl.attenuations or []) == 0
