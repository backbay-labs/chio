"""Unit tests for :func:`chio_dagster.chio_asset`.

Exercise the decorator end-to-end against Dagster's
:func:`dagster.materialize` harness so we test the real asset
materialization path, capability evaluation via a
:class:`chio_sdk.testing.MockChioClient`, the partition-key scoping rule,
and the deny path that raises :class:`PermissionError` + attaches
receipt metadata.

Note: We deliberately do NOT use ``from __future__ import annotations``
here because Dagster's ``asset`` / ``op`` decorators inspect the
``context`` parameter's annotation by identity (not by name) and reject
string annotations produced by PEP 563. Tests that annotate ``context``
with :class:`dagster.AssetExecutionContext` must keep eager annotations.
"""

from typing import Any

from chio_sdk.models import ChioReceipt, ChioScope, Operation, ToolCallAction, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all
from dagster import (
    AssetExecutionContext,
    DagsterInstance,
    StaticPartitionsDefinition,
    materialize,
)

from chio_dagster import chio_asset


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


def _ephemeral_instance() -> DagsterInstance:
    """Return a fresh ephemeral Dagster instance for each test run."""
    return DagsterInstance.ephemeral()


class _DecisionlessReceiptClient:
    async def evaluate_tool_call(self, **kwargs: Any) -> ChioReceipt:
        return ChioReceipt(
            id="mock-trace-receipt",
            timestamp=1_700_000_000,
            capability_id=str(kwargs["capability_id"]),
            tool_server=str(kwargs["tool_server"]),
            tool_name=str(kwargs["tool_name"]),
            action=ToolCallAction(parameters=dict(kwargs["parameters"]), parameter_hash="hash"),
            decision=None,
            receipt_kind="trace_observation",
            boundary_class="detect_only",
            observation_outcome="observed_allow",
            tool_origin="provider_reported",
            redaction_mode="metadata_only",
            content_hash="content",
            policy_hash="policy",
            trust_level="verified",
            kernel_key="kernel",
            signature="signature",
        )

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# (a) Allow path -- asset materializes, receipt is attached as metadata.
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_unpartitioned_asset_materializes_under_allow(self) -> None:
        chio = allow_all()

        @chio_asset(
            scope=_scope_for_tools("customer_embeddings"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def customer_embeddings(context: AssetExecutionContext) -> int:
            return 42

        result = materialize(
            [customer_embeddings],
            instance=_ephemeral_instance(),
        )
        assert result.success

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        call = evaluate_calls[0]
        assert call.tool_name == "customer_embeddings"
        assert call.tool_server == "srv"
        assert call.capability_id == "cap-1"
        assert call.parameters["asset"] == "customer_embeddings"
        assert "partition" not in call.parameters
        assert "partition_key" not in call.parameters

        mats = result.asset_materializations_for_node("customer_embeddings")
        assert mats, "expected an asset materialization"
        metadata = mats[0].metadata
        assert "chio_receipt_id" in metadata
        assert "chio_verdict" in metadata
        assert metadata["chio_verdict"].value == "allow"
        assert metadata["chio_capability_id"].value == "cap-1"
        assert metadata["chio_tool_server"].value == "srv"

    def test_asset_body_receives_its_context(self) -> None:
        chio = allow_all()
        captured: dict[str, Any] = {}

        @chio_asset(
            scope=_scope_for_tools("observed"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def observed(context: AssetExecutionContext) -> int:
            captured["run_id"] = context.run.run_id
            return 7

        result = materialize([observed], instance=_ephemeral_instance())
        assert result.success
        assert captured["run_id"]


# ---------------------------------------------------------------------------
# (b) Partition-key-in-scope test.
# ---------------------------------------------------------------------------


class TestPartitionScoping:
    """The partition key MUST appear in the capability evaluation payload."""

    def test_partition_key_flows_into_capability_evaluation(self) -> None:
        chio = allow_all()
        regions = StaticPartitionsDefinition(["us-east", "eu-west", "ap-south"])

        @chio_asset(
            scope=_scope_for_tools("regional_analytics"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            partitions_def=regions,
        )
        def regional_analytics(context: AssetExecutionContext) -> str:
            return context.partition_key

        result = materialize(
            [regional_analytics],
            partition_key="eu-west",
            instance=_ephemeral_instance(),
        )
        assert result.success

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        params = evaluate_calls[0].parameters
        # Primary mirror field the guards documented in DAGSTER-INTEGRATION.md
        # expect to find.
        assert params["partition_key"] == "eu-west"
        # Structured field for guards that want the full partition info.
        assert params["partition"]["partition_key"] == "eu-west"

        mats = result.asset_materializations_for_node("regional_analytics")
        assert mats
        assert mats[0].metadata["chio_partition_key"].value == "eu-west"

    def test_partition_scoped_deny_for_unauthorised_region(self) -> None:
        """Operators can grant access to some partitions but not others."""

        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            context: dict[str, Any],
        ) -> MockVerdict:
            partition = context["parameters"].get("partition_key")
            if partition == "eu-west":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"partition {partition!r} not in grant",
                guard="DataResidencyGuard",
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)
        regions = StaticPartitionsDefinition(["us-east", "eu-west"])

        @chio_asset(
            scope=_scope_for_tools("regional_analytics"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            partitions_def=regions,
        )
        def regional_analytics(context: AssetExecutionContext) -> str:
            return context.partition_key

        # eu-west -- allowed.
        ok = materialize(
            [regional_analytics],
            partition_key="eu-west",
            instance=_ephemeral_instance(),
        )
        assert ok.success

        # us-east -- denied; the run must fail with a PermissionError.
        denied = materialize(
            [regional_analytics],
            partition_key="us-east",
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not denied.success
        failure_events = [
            e
            for e in denied.all_events
            if getattr(e, "event_type_value", None) == "STEP_FAILURE"
        ]
        assert failure_events, "expected a STEP_FAILURE for denied partition"
        failure_info = failure_events[0].event_specific_data.error
        # The chain contains PermissionError as the original cause of the
        # DagsterExecutionStepExecutionError.
        error_chain = _error_chain_class_names(failure_info)
        assert "PermissionError" in error_chain

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        allowed_partitions = [
            c.parameters["partition_key"]
            for c in evaluate_calls
            if c.verdict is not None and c.verdict.allow
        ]
        denied_partitions = [
            c.parameters["partition_key"]
            for c in evaluate_calls
            if c.verdict is not None and not c.verdict.allow
        ]
        assert allowed_partitions == ["eu-west"]
        assert denied_partitions == ["us-east"]


# ---------------------------------------------------------------------------
# (c) Deny path -- PermissionError raised, deny metadata attached.
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_deny_receipt_path_fails_the_materialization(self) -> None:
        chio = deny_all(
            reason="tool not in scope",
            guard="ScopeGuard",
            raise_on_deny=False,
        )

        @chio_asset(
            scope=_scope_for_tools("write_output"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def write_output(context: AssetExecutionContext) -> str:
            return "wrote"

        result = materialize(
            [write_output],
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not result.success
        failure_events = [
            e
            for e in result.all_events
            if getattr(e, "event_type_value", None) == "STEP_FAILURE"
        ]
        assert failure_events
        error_chain = _error_chain_class_names(
            failure_events[0].event_specific_data.error
        )
        assert "PermissionError" in error_chain

    def test_deny_403_path_fails_the_materialization(self) -> None:
        chio = deny_all(reason="no write perms", guard="CapabilityGuard")

        @chio_asset(
            scope=_scope_for_tools("delete_something"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def delete_something(context: AssetExecutionContext) -> None:
            return None

        result = materialize(
            [delete_something],
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not result.success
        failure_events = [
            e
            for e in result.all_events
            if getattr(e, "event_type_value", None) == "STEP_FAILURE"
        ]
        assert failure_events
        error_chain = _error_chain_class_names(
            failure_events[0].event_specific_data.error
        )
        assert "PermissionError" in error_chain

    def test_decisionless_non_authorizing_receipt_fails_without_attribute_error(self) -> None:
        chio = _DecisionlessReceiptClient()

        @chio_asset(
            scope=_scope_for_tools("observe"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def observe(context: AssetExecutionContext) -> str:
            return "observed"

        result = materialize(
            [observe],
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not result.success
        failure_events = [
            e
            for e in result.all_events
            if getattr(e, "event_type_value", None) == "STEP_FAILURE"
        ]
        assert failure_events
        error_chain = _error_chain_class_names(
            failure_events[0].event_specific_data.error
        )
        assert "PermissionError" in error_chain
        assert "AttributeError" not in error_chain


# ---------------------------------------------------------------------------
# (d) Config errors
# ---------------------------------------------------------------------------


class TestConfigErrors:
    def test_missing_capability_id_raises_config_error(self) -> None:
        chio = allow_all()

        @chio_asset(
            scope=_scope_for_tools("no_cap"),
            tool_server="srv",
            chio_client=chio,
        )
        def no_cap(context: AssetExecutionContext) -> int:
            return 1

        result = materialize(
            [no_cap],
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not result.success
        failure_events = [
            e
            for e in result.all_events
            if getattr(e, "event_type_value", None) == "STEP_FAILURE"
        ]
        assert failure_events
        error_chain = _error_chain_class_names(
            failure_events[0].event_specific_data.error
        )
        assert "ChioDagsterConfigError" in error_chain


# ---------------------------------------------------------------------------
# (e) Policy-sensitive
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_policy_allows_specific_tool_denies_others(self) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _context: dict[str, Any],
        ) -> MockVerdict:
            if tool_name == "embedding_asset":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"tool {tool_name!r} not allowed",
                guard="ScopeGuard",
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)

        @chio_asset(
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def embedding_asset(context: AssetExecutionContext) -> int:
            return 1

        @chio_asset(
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def write_asset(context: AssetExecutionContext) -> int:
            return 2

        allow_result = materialize(
            [embedding_asset],
            instance=_ephemeral_instance(),
        )
        assert allow_result.success

        deny_result = materialize(
            [write_asset],
            instance=_ephemeral_instance(),
            raise_on_error=False,
        )
        assert not deny_result.success


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error_chain_class_names(error: Any) -> list[str]:
    """Return the ``cls_name`` chain on a Dagster ``SerializableErrorInfo``.

    Dagster wraps the original exception in one or more intermediate
    exception types (``DagsterExecutionStepExecutionError``, etc.). We
    walk the ``.cause`` chain so tests can assert on the root exception
    type (``PermissionError``, ``ChioDagsterConfigError``) regardless of
    the wrappers Dagster inserts.
    """
    names: list[str] = []
    current: Any = error
    while current is not None:
        cls_name = getattr(current, "cls_name", None)
        if cls_name:
            names.append(str(cls_name))
        current = getattr(current, "cause", None)
    # Dagster exposes the entire error as a string too; pull class names
    # out of the rendered traceback as a fallback.
    tb = getattr(error, "message", "") or ""
    for candidate in ("PermissionError", "ChioDagsterConfigError"):
        if candidate in tb and candidate not in names:
            names.append(candidate)
    return names
