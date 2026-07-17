"""Unit tests for ChioActivityInterceptor capability enforcement.

The tests exercise the inbound-interceptor path without a live
Temporal cluster: we build an :class:`ExecuteActivityInput`, construct
an :class:`activity.Info`, patch ``activity.info()`` to return it, and
invoke the ``_ChioInboundInterceptor.execute_activity`` directly.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from chio_sdk.errors import ChioDeniedError, ChioValidationError
from chio_sdk.models import (
    CapabilityToken,
    ChioScope,
    Operation,
    ToolGrant,
)
from chio_sdk.testing import (
    MockChioClient,
    MockVerdict,
    allow_all,
    deny_all,
)
from temporalio import activity
from temporalio.exceptions import ApplicationError

from chio_temporal import (
    ChioActivityInterceptor,
    WorkflowGrant,
)
from chio_temporal.interceptor import (
    DENIED_ERROR_TYPE,
    _ChioInboundInterceptor,
    _deny_receipt_from_error,
    _is_sha256_hex,
)

INVOKE_OPERATION = getattr(Operation, "INVOKE", Operation.invoke)

# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[INVOKE_OPERATION],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


def _default_info(
    *,
    activity_type: str,
    activity_id: str = "act-1",
    workflow_id: str = "wf-1",
    workflow_run_id: str = "run-1",
    attempt: int = 1,
) -> activity.Info:
    """Build a minimal :class:`activity.Info` for direct interceptor testing."""
    utc_zero = datetime.fromtimestamp(0, tz=UTC)
    # Temporal's Priority type is a dataclass on modern versions; we
    # replicate its default via an attribute shim that is attribute-
    # compatible enough for info construction. Falling back to
    # ``Priority.default`` keeps us aligned with upstream when present.
    import temporalio.common as temporal_common

    return activity.Info(
        activity_id=activity_id,
        activity_type=activity_type,
        attempt=attempt,
        current_attempt_scheduled_time=utc_zero,
        heartbeat_details=[],
        heartbeat_timeout=None,
        is_local=False,
        namespace="default",
        schedule_to_close_timeout=timedelta(seconds=10),
        scheduled_time=utc_zero,
        start_to_close_timeout=timedelta(seconds=10),
        started_time=utc_zero,
        task_queue="tq",
        task_token=b"tt",
        workflow_id=workflow_id,
        workflow_namespace="default",
        workflow_run_id=workflow_run_id,
        workflow_type="TestWorkflow",
        priority=temporal_common.Priority.default,
        retry_policy=None,
        activity_run_id=None,
    )


class _NextInterceptor:
    """Stand-in for the downstream :class:`ActivityInboundInterceptor`."""

    def __init__(self, result: Any = "ok") -> None:
        self.result = result
        self.called = False

    def init(self, outbound: Any) -> None:  # pragma: no cover -- unused
        pass

    async def execute_activity(self, input: Any) -> Any:
        self.called = True
        return self.result


class AttenuatingMockChioClient(MockChioClient):
    async def attenuate_capability(
        self,
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        child = await self.create_capability(
            subject=getattr(token, "subject", "agent:attenuated"),
            scope=new_scope,
        )
        store: dict[str, Any] = getattr(self, "_tokens", {})
        store[child.id] = child
        self._tokens = store  # type: ignore[attr-defined]
        return child


@contextmanager
def _patched_activity_info(info: activity.Info):
    """Temporarily patch ``activity.info()`` to return ``info``."""
    original = activity.info
    activity.info = lambda: info  # type: ignore[assignment]
    try:
        yield
    finally:
        activity.info = original  # type: ignore[assignment]


def _make_input(*args: Any) -> Any:
    """Build an :class:`ExecuteActivityInput`-compatible object."""
    from temporalio.worker import ExecuteActivityInput

    async def _fn() -> None:  # pragma: no cover -- not invoked
        pass

    return ExecuteActivityInput(
        fn=_fn,
        args=list(args),
        executor=None,
        headers={},
    )


async def _mint_token(
    chio: MockChioClient,
    *,
    subject: str,
    scope: ChioScope,
) -> CapabilityToken:
    """Mint a capability via the mock and index it for policy lookups."""
    token = await chio.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(chio, "_tokens", {})
    store[token.id] = token
    chio._tokens = store  # type: ignore[attr-defined]
    return token


def _install_minting_attenuation(chio: MockChioClient) -> None:
    async def attenuate_capability(
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        if not new_scope.is_subset_of(token.scope):
            raise ChioValidationError(
                "new_scope must be a subset of the parent token scope"
            )
        return await _mint_token(chio, subject=token.subject, scope=new_scope)

    chio.attenuate_capability = attenuate_capability  # type: ignore[method-assign]


def _scope_aware_policy(chio: MockChioClient) -> Any:
    """Policy that enforces the scope bound to the capability_id."""

    def policy(
        tool_name: str,
        scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = getattr(chio, "_tokens", {}).get(cap_id)
        if token is None:
            return MockVerdict.deny_verdict(
                f"unknown capability {cap_id!r}",
                guard="CapabilityGuard",
            )
        allowed = {g.tool_name for g in token.scope.grants}
        if tool_name in allowed or "*" in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"tool {tool_name!r} not in capability scope",
            guard="ScopeGuard",
        )

    return policy


# ---------------------------------------------------------------------------
# (a) Allow verdict delegates to the next interceptor
# ---------------------------------------------------------------------------


class TestAllowVerdict:
    async def test_allow_runs_next_interceptor(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor(result="delivered")
            inbound = _ChioInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                result = await inbound.execute_activity(_make_input("hi"))

        assert result == "delivered"
        assert next_interceptor.called

        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.step_count == 1
        assert receipt.allow_count == 1
        assert receipt.deny_count == 0
        assert receipt.steps[0].activity_type == "send_email"
        assert receipt.steps[0].activity_id == "act-1"
        assert receipt.steps[0].receipt.is_allowed

    async def test_allow_respects_activity_tool_server_map(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email", server_id="srv"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="unused",
            )
            interceptor = ChioActivityInterceptor(
                chio_client=chio,
                activity_tool_server_map={"send_email": "email-srv"},
            )
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor()
            inbound = _ChioInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input())

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_server == "email-srv"

    async def test_run_scoped_grant_rejects_missing_run_id(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
                run_id="run-1",
            )

        assert grant.matches(workflow_id="wf-1", run_id="run-1")
        assert not grant.matches(workflow_id="wf-1", run_id="run-2")
        assert not grant.matches(workflow_id="wf-1", run_id=None)


# ---------------------------------------------------------------------------
# (b) Deny verdict raises non-retryable ApplicationError
# ---------------------------------------------------------------------------


class TestDenyVerdict:
    async def test_deny_raises_non_retryable_application_error(self) -> None:
        # raise_on_deny=False -> receipt-based deny path
        async with deny_all(raise_on_deny=False) as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor()
            inbound = _ChioInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                with pytest.raises(ApplicationError) as exc_info:
                    await inbound.execute_activity(_make_input("payload"))

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE
        assert "Chio capability denied" in str(err)
        assert not next_interceptor.called

        # Deny receipt is recorded even though the activity did not run.
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1
        assert receipt.allow_count == 0
        assert receipt.steps[0].receipt.is_denied

    async def test_deny_from_403_raises_non_retryable(self) -> None:
        # raise_on_deny=True -> mock raises ChioDeniedError that the
        # interceptor translates to a non-retryable ApplicationError.
        async with deny_all(reason="no write perms", guard="ScopeGuard") as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                with pytest.raises(ApplicationError) as exc_info:
                    await inbound.execute_activity(_make_input())

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1
        assert receipt.allow_count == 0
        assert receipt.steps[0].receipt.is_denied
        assert receipt.steps[0].receipt.id

    def test_deny_receipt_preserves_schema_valid_sidecar_receipt_id(self) -> None:
        sidecar_receipt_id = "a" * 64
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=sidecar_receipt_id,
            ),
        )

        assert receipt.id == sidecar_receipt_id
        assert receipt.metadata["sidecar_receipt_id"] == sidecar_receipt_id
        assert receipt.is_denied

    def test_deny_receipt_hashes_non_sha256_sidecar_receipt_id(self) -> None:
        import hashlib

        opaque_receipt_id = "receipt-from-sidecar-not-a-digest"
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=opaque_receipt_id,
            ),
        )

        expected_id = hashlib.sha256(opaque_receipt_id.encode("utf-8")).hexdigest()
        assert receipt.id == expected_id
        assert receipt.id != opaque_receipt_id
        assert receipt.metadata["sidecar_receipt_id"] == opaque_receipt_id
        assert receipt.is_denied

    def test_deny_receipt_hashes_mixed_case_sidecar_receipt_id(self) -> None:
        import hashlib

        mixed_case_receipt_id = "A" * 64
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=mixed_case_receipt_id,
            ),
        )

        expected_id = hashlib.sha256(mixed_case_receipt_id.encode("utf-8")).hexdigest()
        assert receipt.id == expected_id
        assert receipt.id != mixed_case_receipt_id.lower()
        assert receipt.metadata["sidecar_receipt_id"] == mixed_case_receipt_id

    def test_is_sha256_hex_accepts_only_lowercase_digest(self) -> None:
        assert _is_sha256_hex("a" * 64)
        assert not _is_sha256_hex("A" * 64)
        assert not _is_sha256_hex("not-a-digest")
        assert not _is_sha256_hex("a" * 63)

    async def test_missing_workflow_grant_raises_config_error(self) -> None:
        """Activities with no registered grant must be refused before dispatch.

        :class:`ChioTemporalConfigError` is used so the failure is a
        configuration issue surfaced to the operator, not a kernel
        denial. Temporal's worker treats unhandled exceptions from an
        interceptor as a (retryable) activity failure unless they are
        :class:`ApplicationError`; callers that want non-retryable
        behaviour should raise from their own wiring.
        """
        from chio_temporal import ChioTemporalConfigError

        async with allow_all() as chio:
            interceptor = ChioActivityInterceptor(chio_client=chio)
            # Deliberately no register_workflow_grant.

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="send_email", workflow_id="wf-missing")
            with _patched_activity_info(info):
                with pytest.raises(ChioTemporalConfigError):
                    await inbound.execute_activity(_make_input())


# ---------------------------------------------------------------------------
# (c) Attenuated activity-level grant enforcement
# ---------------------------------------------------------------------------


class TestAttenuatedGrant:
    async def test_activity_override_narrows_scope_and_is_enforced(self) -> None:
        chio = AttenuatingMockChioClient()
        chio.set_policy(_scope_aware_policy(chio))

        parent = await _mint_token(
            chio,
            subject="agent:parent",
            scope=_scope_for_tools("search", "write"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Child scope only authorises "search". Register it via the
        # override hook so the interceptor swaps it in for the
        # ``write`` activity type.
        child_scope = _scope_for_tools("search")
        child_grant = await parent_grant.attenuate_for_activity(
            chio, new_scope=child_scope
        )

        interceptor = ChioActivityInterceptor(chio_client=chio)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override(
            "write", lambda _info: child_grant
        )

        inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)

        # The ``write`` activity now runs under the attenuated grant
        # that does NOT include ``write`` -- must be denied.
        info = _default_info(activity_type="write", activity_id="act-write")
        with _patched_activity_info(info):
            with pytest.raises(ApplicationError) as exc_info:
                await inbound.execute_activity(_make_input("/tmp/x"))

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE

    async def test_attenuation_rejects_broader_scope(self) -> None:
        chio = MockChioClient()
        parent = await _mint_token(
            chio,
            subject="agent:parent",
            scope=_scope_for_tools("search"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Broader scope -- must raise ChioValidationError.
        from chio_sdk.errors import ChioValidationError

        broader = _scope_for_tools("search", "write")
        with pytest.raises(ChioValidationError):
            await parent_grant.attenuate_for_activity(chio, new_scope=broader)

    async def test_activity_override_rejects_scope_outside_parent(self) -> None:
        """Override hooks that return a non-subset grant must be refused.

        A hook that smuggles in a broader-than-workflow grant (e.g. by
        bypassing attenuate_for_activity) is caught by the interceptor's
        subset check before any evaluation occurs.
        """
        chio = MockChioClient()
        chio.set_policy(_scope_aware_policy(chio))

        parent = await _mint_token(
            chio,
            subject="agent:parent",
            scope=_scope_for_tools("search"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Craft a rogue grant whose scope exceeds the parent's. This
        # should never happen via attenuate_for_activity, but a buggy
        # hook could produce one.
        rogue_token = parent.model_copy(
            update={"scope": _scope_for_tools("search", "write")}
        )
        rogue_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=rogue_token,
            tool_server="srv",
        )

        interceptor = ChioActivityInterceptor(chio_client=chio)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override(
            "write", lambda _info: rogue_grant
        )

        inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
        info = _default_info(activity_type="write")
        with _patched_activity_info(info):
            with pytest.raises(Exception) as exc_info:
                await inbound.execute_activity(_make_input())

        # ChioTemporalConfigError expected; not an ApplicationError.
        from chio_temporal import ChioTemporalConfigError

        assert isinstance(exc_info.value, ChioTemporalConfigError)
