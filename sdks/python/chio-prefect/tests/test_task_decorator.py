"""Unit tests for :func:`chio_prefect.chio_task`.

The tests run real Prefect flow / task machinery against a
:class:`chio_sdk.testing.MockChioClient` so we exercise the decorator's
sidecar-evaluation path, deny translation to ``PermissionError``, and
receipt-event emission without needing a live Chio kernel or a live
Prefect API.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from chio_sdk.models import ChioReceipt, ChioScope, Operation, ToolCallAction, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_prefect import chio_flow, chio_task
from chio_prefect.errors import ChioPrefectConfigError
from chio_prefect.events import EVENT_ALLOW, EVENT_DENY

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


class _EmittedEvent:
    """Record of a single patched :func:`prefect.events.emit_event` call."""

    def __init__(
        self,
        *,
        event: str,
        resource: dict[str, str],
        payload: dict[str, Any],
        related: list[dict[str, str]],
    ) -> None:
        self.event = event
        self.resource = resource
        self.payload = payload
        self.related = related


class _EventCapture:
    """Patch context manager for :func:`prefect.events.emit_event`.

    The SDK uses a lazy import inside ``_prefect_emit_event`` so we have
    to patch the symbol at the import site rather than
    ``prefect.events.emit_event``. Anything the decorator would emit is
    recorded on ``events``.
    """

    def __init__(self) -> None:
        self.events: list[_EmittedEvent] = []
        self._patch: Any = None

    def __enter__(self) -> _EventCapture:
        def _fake_emit(
            *,
            event: str,
            resource: dict[str, str],
            payload: dict[str, Any] | None = None,
            related: list[dict[str, str]] | None = None,
            **_: Any,
        ) -> None:
            self.events.append(
                _EmittedEvent(
                    event=event,
                    resource=dict(resource),
                    payload=dict(payload or {}),
                    related=list(related or []),
                )
            )
            return None

        # Patch the module the decorator imports lazily.
        from prefect import events as prefect_events

        self._patch = patch.object(
            prefect_events, "emit_event", side_effect=_fake_emit
        )
        self._patch.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._patch is not None:
            self._patch.stop()

    def of(self, event_name: str) -> list[_EmittedEvent]:
        return [e for e in self.events if e.event == event_name]


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
# (a) Allow path -- decorator evaluates, event fires, function runs.
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_sync_task_runs_under_allow_verdict(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("double"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def double(x: int) -> int:
            return x * 2

        @chio_flow(
            scope=_scope_for_tools("double"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> int:
            return double(21)

        with _EventCapture() as capture:
            result = myflow()

        assert result == 42
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_name == "double"
        assert evaluate_calls[0].tool_server == "srv"
        assert evaluate_calls[0].capability_id == "cap-1"

        allows = capture.of(EVENT_ALLOW)
        assert len(allows) == 1
        assert allows[0].payload["tool_name"] == "double"
        assert allows[0].payload["verdict"] == "allow"
        assert allows[0].payload["receipt_id"].startswith("mock-r-")

    async def test_async_task_runs_under_allow_verdict(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        async def fetch(path: str) -> str:
            return f"fetched:{path}"

        @chio_flow(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        async def myflow() -> str:
            return await fetch("/tmp/data")

        with _EventCapture() as capture:
            result = await myflow()

        assert result == "fetched:/tmp/data"
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        # Wire shape preserved: positional values stay positional. The
        # redactor still binds them to declared names internally so
        # protected bodies get scrubbed, but the call bucket on the
        # wire matches what the caller passed.
        assert evaluate_calls[0].parameters == {
            "args": ["/tmp/data"],
            "kwargs": {},
        }
        assert capture.of(EVENT_ALLOW)

    def test_standalone_task_requires_capability_id(self) -> None:
        """A task with no ``capability_id`` invoked outside an ``chio_flow`` must
        surface ``ChioPrefectConfigError`` (a configuration problem, not a
        capability denial)."""
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("no_flow"),
            chio_client=chio,
        )
        def no_flow() -> int:
            return 1

        with pytest.raises(ChioPrefectConfigError) as exc_info:
            no_flow()

        assert "capability_id" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (b) Deny path -- PermissionError raised, deny event emitted.
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_deny_receipt_path_raises_permission_error(self) -> None:
        # raise_on_deny=False: the mock returns a deny receipt instead
        # of raising ChioDeniedError. This covers the receipt-path deny.
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

        @chio_flow(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_something()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError) as exc_info:
                myflow()

        assert "Chio capability denied" in str(exc_info.value)
        # Structured error is attached via ``chio_error`` attribute.
        chio_error = getattr(exc_info.value, "chio_error", None)
        assert chio_error is not None
        assert chio_error.reason == "tool not in scope"
        assert chio_error.guard == "ScopeGuard"
        assert chio_error.task_name == "write_something"

        denies = capture.of(EVENT_DENY)
        assert len(denies) == 1
        assert denies[0].payload["verdict"] == "deny"
        assert denies[0].payload["reason"] == "tool not in scope"
        assert denies[0].payload["guard"] == "ScopeGuard"
        assert capture.of(EVENT_ALLOW) == []

    def test_deny_403_path_raises_permission_error(self) -> None:
        # Default raise_on_deny=True: the mock raises ChioDeniedError
        # (the HTTP-403 path). The decorator translates it to
        # PermissionError and synthesises the deny event.
        chio = deny_all(reason="no write perms", guard="CapabilityGuard")

        @chio_task(
            scope=_scope_for_tools("delete"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def delete_something() -> None:
            return None

        @chio_flow(
            scope=_scope_for_tools("delete"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> None:
            delete_something()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError) as exc_info:
                myflow()

        assert "Chio capability denied" in str(exc_info.value)
        denies = capture.of(EVENT_DENY)
        assert len(denies) == 1
        assert denies[0].payload["reason"] == "no write perms"
        assert denies[0].payload["guard"] == "CapabilityGuard"

    def test_deny_event_carries_flow_run_id(self) -> None:
        chio = deny_all(reason="nope", guard="g", raise_on_deny=False)

        @chio_task(
            scope=_scope_for_tools("t"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def t() -> None:
            return None

        @chio_flow(
            scope=_scope_for_tools("t"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> None:
            t()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError):
                myflow()

        denies = capture.of(EVENT_DENY)
        assert denies, "deny event must be emitted"
        related = denies[0].related
        # Task-run id should be present on the related resource list;
        # when Prefect is running its in-process engine, it assigns
        # one. Some offline test paths may skip this -- accept either.
        roles = {r.get("prefect.resource.role") for r in related}
        assert "task-run" in roles or roles == set()

    def test_decisionless_non_authorizing_receipt_denies_without_crashing(self) -> None:
        chio = _DecisionlessReceiptClient()

        @chio_task(
            scope=_scope_for_tools("observe"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def observe() -> str:
            return "observed"

        @chio_flow(
            scope=_scope_for_tools("observe"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return observe()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError) as exc_info:
                myflow()

        chio_error = getattr(exc_info.value, "chio_error", None)
        assert chio_error is not None
        assert chio_error.reason == "non-authorizing Chio receipt"
        assert chio_error.guard is None
        assert chio_error.decision is None
        denies = capture.of(EVENT_DENY)
        assert len(denies) == 1
        assert denies[0].payload["reason"] == "non-authorizing Chio receipt"


# ---------------------------------------------------------------------------
# (c) Policy-sensitive -- only specific tools allowed
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_policy_allows_specific_tool_denies_others(self) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _context: dict[str, Any],
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

        @chio_flow(
            scope=_scope_for_tools("search", "write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> tuple[str, Any]:
            a = search()
            try:
                b = write()
            except PermissionError as e:
                b = e
            return a, b

        with _EventCapture() as capture:
            first, second = myflow()

        assert first == "ok"
        assert isinstance(second, PermissionError)
        assert "tool 'write' not allowed" in str(second)

        allows = capture.of(EVENT_ALLOW)
        denies = capture.of(EVENT_DENY)
        assert len(allows) == 1
        assert allows[0].payload["tool_name"] == "search"
        assert len(denies) == 1
        assert denies[0].payload["tool_name"] == "write"


# ---------------------------------------------------------------------------
# (d) Parameter canonicalisation
# ---------------------------------------------------------------------------


def test_task_parameters_include_kwargs_and_args() -> None:
    chio = allow_all()

    @chio_task(
        scope=_scope_for_tools("hello"),
        capability_id="cap-1",
        tool_server="srv",
        chio_client=chio,
    )
    def hello(name: str, *, excited: bool = False) -> str:
        return f"hi {name}{'!' if excited else ''}"

    @chio_flow(
        scope=_scope_for_tools("hello"),
        capability_id="cap-1",
        tool_server="srv",
        chio_client=chio,
    )
    def myflow() -> str:
        return hello("ada", excited=True)

    result = myflow()
    assert result == "hi ada!"
    evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
    assert len(evaluate_calls) == 1
    # Wire shape preserved: positional ``"ada"`` stays in args while
    # keyword ``excited=True`` stays in kwargs. The redactor still
    # binds positional values to declared names internally for body
    # field lookup, but does not migrate values between buckets.
    assert evaluate_calls[0].parameters == {
        "args": ["ada"],
        "kwargs": {"excited": True},
    }
