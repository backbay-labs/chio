"""Shared test fixtures for chio-observability."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from chio_sdk.models import (
    ChioReceipt,
    Decision,
    GuardEvidence,
    ToolCallAction,
)

_DEFAULT_DECISION = object()


def _param_hash(params: dict[str, Any]) -> str:
    import json

    canonical = json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_receipt(
    *,
    receipt_id: str = "rcpt_001",
    tool_server: str = "tools-srv",
    tool_name: str = "search",
    capability_id: str = "cap-abc",
    parameters: dict[str, Any] | None = None,
    decision: Decision | None | object = _DEFAULT_DECISION,
    evidence: list[GuardEvidence] | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: int = 1_700_000_000,
) -> ChioReceipt:
    """Construct an :class:`ChioReceipt` for tests.

    The signature and kernel key fields carry placeholder hex strings;
    no cryptographic verification is performed by the bridges.
    """
    params = parameters if parameters is not None else {"q": "hello"}
    actual_decision = Decision.allow() if decision is _DEFAULT_DECISION else decision
    return ChioReceipt(
        id=receipt_id,
        timestamp=timestamp,
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        action=ToolCallAction(
            parameters=params,
            parameter_hash=_param_hash(params),
        ),
        decision=actual_decision,
        receipt_kind="mediated_decision" if actual_decision is not None else "trace_observation",
        boundary_class="prevent" if actual_decision is not None else "detect_only",
        observation_outcome=None if actual_decision is not None else "observed",
        tool_origin="caller_executed",
        redaction_mode="none",
        trust_level="mediated" if actual_decision is not None else "verified",
        content_hash="a" * 64,
        policy_hash="b" * 64,
        evidence=evidence or [],
        metadata=metadata,
        kernel_key="c" * 64,
        signature="d" * 128,
    )


@pytest.fixture()
def allow_receipt() -> ChioReceipt:
    return build_receipt()


@pytest.fixture()
def deny_receipt() -> ChioReceipt:
    return build_receipt(
        receipt_id="rcpt_002",
        tool_name="write",
        parameters={"path": "/etc/passwd", "content": "x"},
        decision=Decision.deny(reason="path not allowed", guard="PathGuard"),
        evidence=[
            GuardEvidence(
                guard_name="PathGuard",
                verdict=False,
                details="path /etc/passwd is on the deny list",
            ),
            GuardEvidence(
                guard_name="PiiGuard",
                verdict=True,
                details="no PII detected",
            ),
        ],
        metadata={
            "trace": {
                "langsmith_run_id": "run_parent_123",
                "langsmith_parent_run_id": "run_parent_123",
                "langfuse_trace_id": "trace_parent_xyz",
                "langfuse_parent_observation_id": "obs_parent_456",
            },
            "cost": {"units": 42, "currency": "USD"},
            "extra_tag": "demo",
        },
    )
