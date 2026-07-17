"""Unit tests for WorkflowReceipt aggregation and serialisation."""

from __future__ import annotations

import json
from typing import Any

import pytest
from chio_sdk.models import (
    ChioReceipt,
    Decision,
    ToolCallAction,
)

from chio_temporal import (
    ChioTemporalConfigError,
    WorkflowReceipt,
    WorkflowStepReceipt,
)
from chio_temporal.receipt import ENVELOPE_VERSION

# ---------------------------------------------------------------------------
# Receipt factory
# ---------------------------------------------------------------------------


def _build_receipt(
    *,
    receipt_id: str,
    tool_name: str,
    allow: bool = True,
    capability_id: str = "cap-1",
    tool_server: str = "srv",
    timestamp: int = 100,
) -> ChioReceipt:
    """Build a synthetic :class:`ChioReceipt` for test ingest."""
    decision = (
        Decision.allow()
        if allow
        else Decision.deny(reason="denied in test", guard="TestGuard")
    )
    return ChioReceipt.model_construct(
        id=receipt_id,
        timestamp=timestamp,
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        action=ToolCallAction(parameters={}, parameter_hash="0" * 64),
        decision=decision,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        observation_outcome=None,
        tool_origin="caller_executed",
        redaction_mode="none",
        actor_chain=[],
        content_hash="content-hash",
        policy_hash="policy-hash",
        evidence=[],
        trust_level="mediated",
        kernel_key="kernel-key",
        signature="sig",
    )


# ---------------------------------------------------------------------------
# (a) Aggregation preserves call order
# ---------------------------------------------------------------------------


class TestAggregationOrder:
    def test_steps_are_appended_in_call_order(self) -> None:
        receipt = WorkflowReceipt(
            workflow_id="wf-1",
            run_id="run-1",
            started_at=10,
        )
        for i, name in enumerate(["first", "second", "third"]):
            receipt.record_step(
                activity_type=name,
                activity_id=f"act-{i}",
                attempt=1,
                receipt=_build_receipt(
                    receipt_id=f"r-{i}", tool_name=name, timestamp=10 + i
                ),
            )

        assert [s.activity_type for s in receipt.steps] == [
            "first",
            "second",
            "third",
        ]
        assert [s.activity_id for s in receipt.steps] == [
            "act-0",
            "act-1",
            "act-2",
        ]

    def test_step_attempts_are_preserved_per_activity(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        receipt.record_step(
            activity_type="retry_me",
            activity_id="act-1",
            attempt=1,
            receipt=_build_receipt(receipt_id="r-1", tool_name="retry_me"),
        )
        receipt.record_step(
            activity_type="retry_me",
            activity_id="act-1",
            attempt=2,
            receipt=_build_receipt(receipt_id="r-2", tool_name="retry_me"),
        )

        assert [s.attempt for s in receipt.steps] == [1, 2]
        # Both steps carry the same activity_id -- the aggregator does
        # not dedupe by id; it's an append log of attempts.
        assert {s.receipt.id for s in receipt.steps} == {"r-1", "r-2"}


# ---------------------------------------------------------------------------
# (b) Partial workflows (mixed allow/deny)
# ---------------------------------------------------------------------------


class TestPartialWorkflows:
    def test_counts_reflect_mixed_verdicts(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        receipt.record_step(
            activity_type="search",
            activity_id="act-1",
            attempt=1,
            receipt=_build_receipt(receipt_id="r-1", tool_name="search", allow=True),
        )
        receipt.record_step(
            activity_type="write",
            activity_id="act-2",
            attempt=1,
            receipt=_build_receipt(receipt_id="r-2", tool_name="write", allow=False),
        )
        receipt.record_step(
            activity_type="search",
            activity_id="act-3",
            attempt=1,
            receipt=_build_receipt(receipt_id="r-3", tool_name="search", allow=True),
        )

        assert receipt.step_count == 3
        assert receipt.allow_count == 2
        assert receipt.deny_count == 1

    def test_finalize_failure_preserves_deny_steps(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        receipt.record_step(
            activity_type="write",
            activity_id="act-1",
            attempt=1,
            receipt=_build_receipt(
                receipt_id="r-1", tool_name="write", allow=False
            ),
        )
        receipt.finalize(outcome="failure", completed_at=1000)

        envelope = receipt.to_envelope()
        assert envelope["outcome"] == "failure"
        assert envelope["completed_at"] == 1000
        assert envelope["deny_count"] == 1
        assert len(envelope["steps"]) == 1

    def test_finalize_rejects_conflicting_outcomes(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        receipt.finalize(outcome="success", completed_at=10)
        # Re-finalising with the same outcome is a no-op.
        receipt.finalize(outcome="success", completed_at=20)
        assert receipt.completed_at == 20
        # Re-finalising with a different outcome is a config error.
        with pytest.raises(ChioTemporalConfigError):
            receipt.finalize(outcome="failure", completed_at=30)


# ---------------------------------------------------------------------------
# (c) Stable JSON serialisation
# ---------------------------------------------------------------------------


class TestStableSerialisation:
    def test_to_json_is_stable_across_runs(self) -> None:
        def _build() -> WorkflowReceipt:
            receipt = WorkflowReceipt(
                workflow_id="wf-1",
                run_id="run-1",
                parent_workflow_ids=["wf-root", "wf-parent"],
                started_at=100,
                metadata={"z": "last", "a": "first"},
            )
            receipt.record_step(
                activity_type="search",
                activity_id="act-1",
                attempt=1,
                receipt=_build_receipt(
                    receipt_id="r-1",
                    tool_name="search",
                    timestamp=101,
                ),
            )
            receipt.record_step(
                activity_type="write",
                activity_id="act-2",
                attempt=1,
                receipt=_build_receipt(
                    receipt_id="r-2",
                    tool_name="write",
                    allow=False,
                    timestamp=102,
                ),
            )
            receipt.finalize(outcome="failure", completed_at=200)
            return receipt

        a = _build().to_json()
        b = _build().to_json()
        assert a == b

    def test_envelope_matches_schema(self) -> None:
        receipt = WorkflowReceipt(
            workflow_id="wf-1",
            run_id="run-1",
            parent_workflow_ids=["root"],
            started_at=100,
            metadata={"origin": "test"},
        )
        receipt.record_step(
            activity_type="search",
            activity_id="act-1",
            attempt=1,
            receipt=_build_receipt(receipt_id="r-1", tool_name="search"),
        )
        receipt.finalize(outcome="success", completed_at=200)

        envelope: dict[str, Any] = json.loads(receipt.to_json())

        assert envelope["version"] == ENVELOPE_VERSION
        assert envelope["workflow_id"] == "wf-1"
        assert envelope["run_id"] == "run-1"
        assert envelope["parent_workflow_ids"] == ["root"]
        assert envelope["started_at"] == 100
        assert envelope["completed_at"] == 200
        assert envelope["outcome"] == "success"
        assert envelope["step_count"] == 1
        assert envelope["allow_count"] == 1
        assert envelope["deny_count"] == 0
        assert envelope["metadata"] == {"origin": "test"}
        assert len(envelope["steps"]) == 1

        step = envelope["steps"][0]
        assert step["activity_type"] == "search"
        assert step["activity_id"] == "act-1"
        assert step["attempt"] == 1
        assert step["receipt"]["id"] == "r-1"
        assert step["receipt"]["decision"]["verdict"] == "allow"

    def test_to_json_serializes_validated_receipt_enums(self) -> None:
        receipt_id = "1" * 64
        raw_receipt = _build_receipt(
            receipt_id=receipt_id,
            tool_name="search",
        ).model_dump(mode="json")
        raw_receipt["content_hash"] = "2" * 64
        raw_receipt["kernel_key"] = "3" * 64
        raw_receipt["signature"] = "4" * 128
        validated = ChioReceipt.model_validate(raw_receipt)
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        receipt.record_step(
            activity_type="search",
            activity_id="act-1",
            attempt=1,
            receipt=validated,
        )

        envelope: dict[str, Any] = json.loads(receipt.to_json())

        assert envelope["steps"][0]["receipt"]["id"] == receipt_id
        assert envelope["steps"][0]["receipt"]["decision"]["verdict"] == "allow"

    def test_in_progress_envelope_has_null_completed_at(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1", started_at=0)
        envelope = receipt.to_envelope()
        assert envelope["outcome"] == "in_progress"
        assert envelope["completed_at"] is None
        assert envelope["step_count"] == 0


# ---------------------------------------------------------------------------
# (d) Validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_empty_workflow_id_is_rejected(self) -> None:
        with pytest.raises(ChioTemporalConfigError):
            WorkflowReceipt(workflow_id="")

    def test_invalid_outcome_is_rejected(self) -> None:
        with pytest.raises(ChioTemporalConfigError):
            WorkflowReceipt(workflow_id="wf-1", outcome="not-an-outcome")

    def test_record_step_requires_activity_type(self) -> None:
        receipt = WorkflowReceipt(workflow_id="wf-1")
        with pytest.raises(ChioTemporalConfigError):
            receipt.record_step(
                activity_type="",
                activity_id="act-1",
                attempt=1,
                receipt=_build_receipt(receipt_id="r-1", tool_name="x"),
            )


# ---------------------------------------------------------------------------
# (e) Step receipt dict round-trip
# ---------------------------------------------------------------------------


def test_step_receipt_to_dict_roundtrip() -> None:
    step = WorkflowStepReceipt(
        activity_type="search",
        activity_id="act-1",
        attempt=2,
        receipt=_build_receipt(receipt_id="r-1", tool_name="search"),
    )
    payload = step.to_dict()
    assert payload["activity_type"] == "search"
    assert payload["activity_id"] == "act-1"
    assert payload["attempt"] == 2
    assert payload["receipt"]["id"] == "r-1"
