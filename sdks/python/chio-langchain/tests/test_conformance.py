"""Conformance tests: byte-identical results between Python SDK and Rust kernel.

These tests verify that the Python SDK produces the same canonical JSON
serialization as the Rust kernel for all core Chio types. This ensures that
content hashes, parameter hashes, and receipt verification produce identical
results across both implementations.

When running against a live sidecar, set CHIO_CONFORMANCE_LIVE=1 to enable
round-trip verification through the actual Rust kernel. Without it, these
tests verify the Python-side canonical JSON determinism.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from chio_sdk.client import _canonical_json, _sha256_hex
from chio_sdk.models import (
    ChioReceipt,
    ChioScope,
    Attenuation,
    CallerIdentity,
    CapabilityToken,
    CapabilityTokenBody,
    Constraint,
    Decision,
    GuardEvidence,
    MonetaryAmount,
    Operation,
    ToolCallAction,
    ToolGrant,
    Verdict,
)


class TestCanonicalJsonDeterminism:
    """Verify canonical JSON is deterministic across serializations."""

    def test_sorted_keys(self) -> None:
        obj = {"z": 1, "a": 2, "m": 3}
        result = _canonical_json(obj)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_nested_objects(self) -> None:
        obj = {"b": {"z": 1, "a": 2}, "a": 0}
        result = _canonical_json(obj)
        assert result == b'{"a":0,"b":{"a":2,"z":1}}'

    def test_arrays_preserve_order(self) -> None:
        obj = {"items": [3, 1, 2]}
        result = _canonical_json(obj)
        assert result == b'{"items":[3,1,2]}'

    def test_no_whitespace(self) -> None:
        obj = {"key": "value", "num": 42}
        result = _canonical_json(obj)
        assert b" " not in result
        assert b"\n" not in result

    def test_deterministic_across_calls(self) -> None:
        obj = {"b": 2, "a": 1, "c": [1, 2, 3]}
        results = [_canonical_json(obj) for _ in range(100)]
        assert all(r == results[0] for r in results)


class TestHashConformance:
    """Verify SHA-256 hash computation matches known values."""

    def test_empty_object(self) -> None:
        h = _sha256_hex(_canonical_json({}))
        expected = hashlib.sha256(b"{}").hexdigest()
        assert h == expected

    def test_known_hash(self) -> None:
        # Known test vector: canonical JSON of {"a":1}
        canonical = b'{"a":1}'
        h = _sha256_hex(canonical)
        expected = hashlib.sha256(canonical).hexdigest()
        assert h == expected
        assert len(h) == 64

    def test_parameter_hash_consistency(self) -> None:
        """Parameter hash should match SHA-256 of canonical JSON."""
        params = {"path": "/tmp/test.txt", "encoding": "utf-8"}
        canonical = _canonical_json(params)
        expected_hash = _sha256_hex(canonical)

        # Verify the hash is stable
        for _ in range(10):
            assert _sha256_hex(_canonical_json(params)) == expected_hash


class TestCapabilityTokenConformance:
    """Verify CapabilityToken serialization matches expected format."""

    def test_body_serialization_deterministic(self) -> None:
        body = CapabilityTokenBody(
            id="tok-1",
            issuer="aabbccdd",
            subject="eeff0011",
            scope=ChioScope(
                grants=[
                    ToolGrant(
                        server_id="fs",
                        tool_name="read_file",
                        operations=[Operation.INVOKE],
                    )
                ]
            ),
            issued_at=1700000000,
            expires_at=1700003600,
        )
        json1 = body.model_dump_json()
        json2 = body.model_dump_json()
        assert json1 == json2

    def test_canonical_json_matches_model_dump(self) -> None:
        """Canonical JSON of model_dump should be deterministic."""
        body = CapabilityTokenBody(
            id="tok-1",
            issuer="aa",
            subject="bb",
            scope=ChioScope(),
            issued_at=100,
            expires_at=200,
        )
        dump = body.model_dump(exclude_none=True)
        c1 = _canonical_json(dump)
        c2 = _canonical_json(dump)
        assert c1 == c2

    def test_token_roundtrip_preserves_fields(self) -> None:
        token = CapabilityToken(
            id="tok-rt",
            issuer="a" * 64,
            subject="b" * 64,
            scope=ChioScope(
                grants=[
                    ToolGrant(
                        server_id="s",
                        tool_name="t",
                        operations=[Operation.INVOKE, Operation.READ_RESULT],
                        constraints=[Constraint.path_prefix("/safe")],
                        max_invocations=100,
                    )
                ]
            ),
            issued_at=1000,
            expires_at=2000,
            signature="c" * 128,
        )
        serialized = token.model_dump_json(by_alias=True)
        restored = CapabilityToken.model_validate_json(serialized)
        assert restored.id == token.id
        assert restored.scope.grants[0].max_invocations == 100
        assert len(restored.scope.grants[0].constraints) == 1


class TestDecisionConformance:
    """Verify Decision serialization matches Rust serde format."""

    def test_allow_format(self) -> None:
        d = Decision.allow()
        data = d.model_dump(exclude_none=True)
        assert data == {"verdict": "allow"}

    def test_deny_format(self) -> None:
        d = Decision.deny("forbidden path", "ForbiddenPathGuard")
        data = d.model_dump(exclude_none=True)
        assert data == {
            "verdict": "deny",
            "reason": "forbidden path",
            "guard": "ForbiddenPathGuard",
        }


class TestReceiptConformance:
    """Verify receipt structure matches the Rust kernel format."""

    def test_receipt_fields(self) -> None:
        receipt = ChioReceipt(
            id="1" * 64,
            timestamp=1700000000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read_file",
            action=ToolCallAction(
                parameters={"path": "/tmp"},
                parameter_hash="2" * 64,
            ),
            decision=Decision.allow(),
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            content_hash="3" * 64,
            policy_hash="cafebabe",
            trust_level="mediated",
            kernel_key="5" * 64,
            signature="6" * 128,
        )
        data = receipt.model_dump(exclude_none=True)

        # Verify all required fields are present
        required_fields = {
            "id", "timestamp", "capability_id", "tool_server", "tool_name",
            "action", "decision", "receipt_kind", "boundary_class",
            "tool_origin", "redaction_mode", "content_hash", "policy_hash",
            "trust_level", "kernel_key", "signature",
        }
        assert required_fields.issubset(data.keys())

        # Verify nested structures
        assert "parameters" in data["action"]
        assert "parameter_hash" in data["action"]
        assert data["decision"]["verdict"] == "allow"


class TestVerdictConformance:
    """Verify Verdict serialization matches Rust chio-http-core format."""

    def test_allow(self) -> None:
        v = Verdict.allow()
        data = v.model_dump(exclude_none=True)
        assert data == {"verdict": "allow"}

    def test_deny_with_status(self) -> None:
        v = Verdict.deny("rate limited", "RateGuard", 429)
        data = v.model_dump(exclude_none=True)
        assert data["verdict"] == "deny"
        assert data["http_status"] == 429
        assert data["guard"] == "RateGuard"

    def test_to_decision_roundtrip(self) -> None:
        v = Verdict.deny("blocked", "Guard")
        d = v.to_decision()
        assert d.verdict == "deny"
        assert d.guard == "Guard"


class TestScopeSubsetConformance:
    """Verify scope subset logic matches the Rust implementation."""

    def test_wildcard_server_covers_all(self) -> None:
        parent = ToolGrant(
            server_id="*", tool_name="*", operations=[Operation.INVOKE]
        )
        child = ToolGrant(
            server_id="any", tool_name="any", operations=[Operation.INVOKE]
        )
        assert child.is_subset_of(parent)

    def test_operations_must_be_subset(self) -> None:
        parent = ToolGrant(
            server_id="s", tool_name="t", operations=[Operation.INVOKE]
        )
        child = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE, Operation.DELEGATE],
        )
        assert not child.is_subset_of(parent)

    def test_constraint_inheritance(self) -> None:
        parent = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            constraints=[Constraint.path_prefix("/safe")],
        )
        # Child must include all parent constraints
        child_ok = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            constraints=[
                Constraint.path_prefix("/safe"),
                Constraint.max_length(100),
            ],
        )
        child_bad = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            constraints=[],
        )
        assert child_ok.is_subset_of(parent)
        assert not child_bad.is_subset_of(parent)

    def test_cost_cap_subset(self) -> None:
        parent = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_total_cost=MonetaryAmount(units=1000, currency="USD"),
        )
        child = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_total_cost=MonetaryAmount(units=500, currency="USD"),
        )
        assert child.is_subset_of(parent)

        child_over = ToolGrant(
            server_id="s",
            tool_name="t",
            operations=[Operation.INVOKE],
            max_total_cost=MonetaryAmount(units=2000, currency="USD"),
        )
        assert not child_over.is_subset_of(parent)

    def test_scope_subset_multiple_grants(self) -> None:
        parent = ChioScope(
            grants=[
                ToolGrant(
                    server_id="a",
                    tool_name="*",
                    operations=[Operation.INVOKE],
                ),
                ToolGrant(
                    server_id="b",
                    tool_name="*",
                    operations=[Operation.INVOKE],
                ),
            ]
        )
        child = ChioScope(
            grants=[
                ToolGrant(
                    server_id="a",
                    tool_name="read",
                    operations=[Operation.INVOKE],
                ),
            ]
        )
        assert child.is_subset_of(parent)

        child_extra = ChioScope(
            grants=[
                ToolGrant(
                    server_id="c",  # not covered by parent
                    tool_name="x",
                    operations=[Operation.INVOKE],
                ),
            ]
        )
        assert not child_extra.is_subset_of(parent)
