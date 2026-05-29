"""Tests for :func:`chio_airflow.chio_task` (TaskFlow API).

We exercise the decorator's underlying evaluation + XCom-push logic
directly via the wrapped function that the decorator stores on the
TaskFlow object. Driving TaskFlow through a real DagRun would require
the full scheduler. The contract is that denied tasks raise
``PermissionError`` and that receipt ids are pushed to XCom on allow.
Both are properties of the inner wrapper, so we test it at that level.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from airflow.exceptions import AirflowException
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_airflow import (
    XCOM_CAPABILITY_KEY,
    XCOM_RECEIPT_ID_KEY,
    XCOM_SCOPE_KEY,
    ChioAirflowConfigError,
    chio_task,
)


class _RecordingTI:
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.pushed: list[tuple[str, Any]] = []

    def xcom_push(self, key: str, value: Any) -> None:
        self.pushed.append((key, value))


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


class _FakeDag:
    def __init__(self, dag_id: str) -> None:
        self.dag_id = dag_id


def _install_context(ti: _RecordingTI, *, dag_id: str = "d", run_id: str = "r1") -> Any:
    """Patch :func:`airflow.sdk.get_current_context` for the duration of a call.

    The TaskFlow wrapper reaches into the Airflow runtime to fetch the
    live TI. In unit tests there is no live TaskInstance, so we patch
    the context accessor to return our recording double.
    """
    fake_context = {
        "ti": ti,
        "task_instance": ti,
        "dag": _FakeDag(dag_id),
        "run_id": run_id,
    }
    return patch("airflow.sdk.get_current_context", return_value=fake_context)


def _wrapped_function(decorator_output: Any) -> Any:
    """Return the user function wrapped by :func:`chio_task`.

    Airflow's TaskFlow decorator returns a ``_TaskDecorator`` instance;
    the wrapped body lives on ``.function``. Tests call the wrapped
    body directly to sidestep the scheduler.
    """
    fn = getattr(decorator_output, "function", None)
    assert fn is not None, (
        "chio_task did not return an Airflow TaskFlow decorator with a .function"
    )
    return fn


# ---------------------------------------------------------------------------
# (a) Allow path
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_sync_allow_pushes_receipt_to_xcom(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("double"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def double(x: int) -> int:
            return x * 2

        ti = _RecordingTI(task_id="double")
        body = _wrapped_function(double)

        with _install_context(ti):
            result = body(21)

        assert result == 42
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_name == "double"
        # Wire shape preserved: positional values stay positional. The
        # redactor still sees them as named fields internally (via
        # bind_partial) so protected bodies get scrubbed, but the call
        # bucket on the wire matches what the caller passed.
        assert evaluate_calls[0].parameters == {"args": [21], "kwargs": {}}

        pushed = dict(ti.pushed)
        assert pushed[XCOM_RECEIPT_ID_KEY].startswith("mock-r-")
        assert pushed[XCOM_CAPABILITY_KEY] == "cap-1"
        assert pushed[XCOM_SCOPE_KEY] is not None

    async def test_async_allow_runs_body(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        async def fetch(path: str) -> str:
            return f"fetched:{path}"

        ti = _RecordingTI(task_id="fetch")
        body = _wrapped_function(fetch)

        with _install_context(ti):
            result = await body("/tmp/data")

        assert result == "fetched:/tmp/data"
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        # Wire shape preserved: positional values stay positional. See
        # the sync companion test for rationale.
        assert evaluate_calls[0].parameters == {
            "args": ["/tmp/data"],
            "kwargs": {},
        }


# ---------------------------------------------------------------------------
# (b) Deny path
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

        @chio_task(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def write_something() -> str:
            return "wrote"

        ti = _RecordingTI(task_id="write_something")
        body = _wrapped_function(write_something)

        with _install_context(ti):
            with pytest.raises(AirflowException) as exc_info:
                body()

        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError), (
            f"expected PermissionError cause, got {type(cause)!r}"
        )
        assert "Chio capability denied" in str(cause)

        chio_error = getattr(cause, "chio_error", None)
        assert chio_error is not None
        assert chio_error.reason == "tool not in scope"
        assert chio_error.guard == "ScopeGuard"

        # No receipt pushed on deny.
        pushed = dict(ti.pushed)
        assert XCOM_RECEIPT_ID_KEY not in pushed

    def test_deny_403_raises_airflow_exception_with_permission_cause(self) -> None:
        chio = deny_all(reason="no write perms", guard="CapabilityGuard")

        @chio_task(
            scope=_scope_for_tools("delete"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def delete_something() -> None:
            return None

        ti = _RecordingTI(task_id="delete_something")
        body = _wrapped_function(delete_something)

        with _install_context(ti):
            with pytest.raises(AirflowException) as exc_info:
                body()

        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError)
        assert "Chio capability denied" in str(cause)


# ---------------------------------------------------------------------------
# (c) Configuration
# ---------------------------------------------------------------------------


class TestConfigurationErrors:
    def test_missing_capability_id_raises_at_decoration_time(self) -> None:
        with pytest.raises(ChioAirflowConfigError, match="capability_id"):

            @chio_task(scope=_scope_for_tools("x"), tool_server="srv")
            def _bad() -> None:
                return None


# ---------------------------------------------------------------------------
# (d) Policy-sensitive
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_policy_allows_one_tool_denies_another(self) -> None:
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

        @chio_task(
            scope=_scope_for_tools("search"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def search() -> str:
            return "ok"

        @chio_task(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def write() -> str:
            return "ok"

        ti_search = _RecordingTI(task_id="search")
        ti_write = _RecordingTI(task_id="write")

        with _install_context(ti_search):
            assert _wrapped_function(search)() == "ok"

        with _install_context(ti_write):
            with pytest.raises(AirflowException) as exc_info:
                _wrapped_function(write)()

        cause = exc_info.value.__cause__
        assert isinstance(cause, PermissionError)
        assert "tool 'write' not allowed" in str(cause)
