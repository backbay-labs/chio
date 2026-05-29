"""Unit tests for :class:`chio_airflow.ChioOperator`.

The tests drive the operator directly through :meth:`execute` with a
synthetic Airflow context dict so we exercise allow / deny /
XCom-push logic without a scheduler. The sidecar is mocked via
:class:`chio_sdk.testing.MockChioClient`.
"""

from __future__ import annotations

from typing import Any

import pytest
from airflow.exceptions import AirflowException
from airflow.models import BaseOperator
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_airflow import (
    XCOM_CAPABILITY_KEY,
    XCOM_RECEIPT_ID_KEY,
    XCOM_SCOPE_KEY,
    ChioAirflowConfigError,
    ChioOperator,
)

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingTI:
    """Stand-in task instance that records ``xcom_push`` calls.

    Airflow's real TI is heavyweight and coupled to the metadata
    database. For unit tests we only need the surface the operator
    touches: ``xcom_push(key=, value=)`` and a stable ``task_id``.
    """

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.pushed: list[tuple[str, Any]] = []

    def xcom_push(self, key: str, value: Any) -> None:
        self.pushed.append((key, value))

    def get(self, key: str, default: Any = None) -> Any:
        for k, v in self.pushed:
            if k == key:
                return v
        return default


class _StubDag:
    def __init__(self, dag_id: str) -> None:
        self.dag_id = dag_id


class _EchoOperator(BaseOperator):
    """Simple inner operator that returns a caller-supplied value.

    Exists purely as a test fixture so we can assert the allow path
    returned the inner operator's value unchanged. We accept ``**kwargs``
    because Airflow's operator metaclass threads keyword arguments
    (``default_args``, dag, task_group) through ``__init__`` at DAG
    attachment time.
    """

    def __init__(self, *, value: Any, task_id: str = "echo", **kwargs: Any) -> None:
        super().__init__(task_id=task_id, **{k: v for k, v in kwargs.items() if k != "default_args"})
        self._value = value

    def execute(self, context: Any) -> Any:
        return self._value


class _ExplodingOperator(BaseOperator):
    """Inner operator that always raises during ``execute``.

    Used to confirm that exceptions raised by the inner operator
    propagate unchanged (the capability was granted; the task body
    just failed).
    """

    def __init__(self, *, task_id: str = "boom", **kwargs: Any) -> None:
        super().__init__(task_id=task_id, **{k: v for k, v in kwargs.items() if k != "default_args"})

    def execute(self, context: Any) -> Any:
        raise RuntimeError("inner blew up")


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    return ChioScope(
        grants=[
            ToolGrant(
                server_id=server_id,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tool_names
        ]
    )


def _context(
    *,
    dag_id: str = "test_dag",
    run_id: str = "run-1",
    task_id: str = "echo",
) -> dict[str, Any]:
    ti = _RecordingTI(task_id=task_id)
    return {
        "dag": _StubDag(dag_id),
        "dag_id": dag_id,
        "run_id": run_id,
        "ti": ti,
        "task_instance": ti,
        "execution_date": "2026-04-16T00:00:00+00:00",
        "logical_date": "2026-04-16T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# (a) Allow path
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_allow_runs_inner_and_pushes_receipt_to_xcom(self) -> None:
        chio = allow_all()
        inner = _EchoOperator(value={"hello": "world"})
        op = ChioOperator(
            inner_operator=inner,
            scope=_scope_for_tools("echo"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )

        ctx = _context()
        result = op.execute(ctx)

        assert result == {"hello": "world"}

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_name == "echo"
        assert evaluate_calls[0].tool_server == "srv"
        assert evaluate_calls[0].capability_id == "cap-1"
        assert evaluate_calls[0].parameters["dag_id"] == "test_dag"
        assert evaluate_calls[0].parameters["run_id"] == "run-1"

        ti = ctx["ti"]
        pushed = dict(ti.pushed)
        assert pushed[XCOM_RECEIPT_ID_KEY].startswith("mock-r-")
        assert pushed[XCOM_CAPABILITY_KEY] == "cap-1"
        assert pushed[XCOM_SCOPE_KEY] is not None

    def test_default_task_id_prefixes_inner(self) -> None:
        chio = allow_all()
        inner = _EchoOperator(value=1, task_id="inner-t")
        op = ChioOperator(
            inner_operator=inner,
            capability_id="cap-1",
            chio_client=chio,
        )
        assert op.task_id == "chio_inner-t"

    def test_inner_operator_exception_propagates(self) -> None:
        """Allow-path inner operator exceptions are not translated."""
        chio = allow_all()
        inner = _ExplodingOperator()
        op = ChioOperator(
            inner_operator=inner,
            capability_id="cap-1",
            chio_client=chio,
        )
        with pytest.raises(RuntimeError, match="inner blew up"):
            op.execute(_context())


# ---------------------------------------------------------------------------
# (b) Deny path -- AirflowException with PermissionError as cause
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_deny_receipt_raises_airflow_exception_with_permission_cause(
        self,
    ) -> None:
        chio = deny_all(
            reason="tool not in scope",
            guard="ScopeGuard",
            raise_on_deny=False,
        )
        inner = _EchoOperator(value="never-runs")
        op = ChioOperator(
            inner_operator=inner,
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )

        ctx = _context()
        with pytest.raises(AirflowException) as exc_info:
            op.execute(ctx)

        # PermissionError is the __cause__.
        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError), (
            f"expected PermissionError cause, got {type(cause)!r}"
        )
        assert "Chio capability denied" in str(cause)
        # Structured deny error rides along on the cause.
        chio_error = getattr(cause, "chio_error", None)
        assert chio_error is not None
        assert chio_error.reason == "tool not in scope"
        assert chio_error.guard == "ScopeGuard"
        # Inner operator never ran -- nothing was pushed to XCom.
        ti = ctx["ti"]
        assert XCOM_RECEIPT_ID_KEY not in dict(ti.pushed)

    def test_deny_403_raises_airflow_exception_with_permission_cause(self) -> None:
        chio = deny_all(reason="no write perms", guard="CapabilityGuard")
        inner = _EchoOperator(value="never-runs")
        op = ChioOperator(
            inner_operator=inner,
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )

        with pytest.raises(AirflowException) as exc_info:
            op.execute(_context())

        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError)
        assert "Chio capability denied" in str(cause)


# ---------------------------------------------------------------------------
# (c) Configuration errors
# ---------------------------------------------------------------------------


class TestConfigurationErrors:
    def test_missing_capability_id_raises_config_error(self) -> None:
        inner = _EchoOperator(value=1)
        with pytest.raises(ChioAirflowConfigError, match="capability_id"):
            ChioOperator(inner_operator=inner, capability_id="")

    def test_missing_inner_operator_raises_config_error(self) -> None:
        with pytest.raises(ChioAirflowConfigError, match="inner_operator"):
            ChioOperator(inner_operator=None, capability_id="cap-1")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# (d) Policy-sensitive
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_policy_allows_specific_tool_denies_others(self) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _ctx: dict[str, Any],
        ) -> MockVerdict:
            if tool_name == "search":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"tool {tool_name!r} not allowed",
                guard="ScopeGuard",
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)

        search_inner = _EchoOperator(value="hits", task_id="search")
        write_inner = _EchoOperator(value="bytes", task_id="write")

        search_op = ChioOperator(
            inner_operator=search_inner,
            capability_id="cap-1",
            chio_client=chio,
        )
        write_op = ChioOperator(
            inner_operator=write_inner,
            capability_id="cap-1",
            chio_client=chio,
        )

        assert search_op.execute(_context(task_id="search")) == "hits"

        with pytest.raises(AirflowException) as exc_info:
            write_op.execute(_context(task_id="write"))
        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError)
        assert "tool 'write' not allowed" in str(cause)
