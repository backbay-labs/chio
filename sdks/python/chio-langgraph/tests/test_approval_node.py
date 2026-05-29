"""Tests for :func:`chio_langgraph.chio_approval_node`.

``chio_approval_node`` pauses the graph via ``interrupt()``, waits for
human approval, and resumes. The tests exercise:

* Approved resume: node body runs, returns the final state update.
* Denied resume: wrapper raises :class:`ChioLangGraphError` carrying the
  approval id and reason.
* Policy skip: when the local approval policy returns ``False``, the
  node proceeds without an interrupt.
* Dispatcher hook: optional HTTP dispatcher is called with the payload.
* Sidecar deny before approval: a hard deny from the sidecar short-
  circuits the approval flow.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import allow_all, deny_all

from chio_langgraph import (
    ApprovalRequestPayload,
    ApprovalResolution,
    ChioGraphConfig,
    ChioLangGraphError,
    chio_approval_node,
)


class State(TypedDict, total=False):
    value: str


SERVER_ID = "demo-srv"


def _scope(*tools: str) -> ChioScope:
    return ChioScope(
        grants=[
            ToolGrant(
                server_id=SERVER_ID,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tools
        ]
    )


class FakeInterrupt:
    """Drop-in replacement for ``langgraph.types.interrupt`` in tests.

    Captures the payload handed to ``interrupt`` and returns a canned
    resume value so the wrapper can proceed without a real checkpointer.
    """

    def __init__(self, resume_value: Any) -> None:
        self.resume_value = resume_value
        self.payloads: list[dict[str, Any]] = []

    def __call__(self, payload: Any) -> Any:
        self.payloads.append(dict(payload))
        return self.resume_value


# ---------------------------------------------------------------------------
# (a) Approved flow
# ---------------------------------------------------------------------------


class TestApprovedFlow:
    async def test_approved_resume_runs_body(self) -> None:
        ran: list[dict[str, Any]] = []

        def dangerous_body(state: State) -> dict[str, Any]:
            ran.append(dict(state))
            return {"value": "executed"}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio,
            node_scopes={"danger": _scope("danger")},
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(
            resume_value={"outcome": "approved", "approver": "ops@acme"}
        )
        wrapped = chio_approval_node(
            dangerous_body,
            scope=_scope("danger"),
            config=cfg,
            name="danger",
            interrupt_fn=interrupt_fn,
            summary="Please approve dangerous action",
        )

        update = await wrapped({"value": "x"})
        assert update == {"value": "executed"}
        assert ran == [{"value": "x"}]
        assert len(interrupt_fn.payloads) == 1
        payload = interrupt_fn.payloads[0]
        assert payload["tool_name"] == "danger"
        assert payload["summary"] == "Please approve dangerous action"
        assert "approval_id" in payload
        assert "capability_id" in payload
        assert payload["expires_at"] > payload["created_at"]

    async def test_approved_via_bool_resume(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            return {"value": "done"}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(resume_value=True)
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            interrupt_fn=interrupt_fn,
        )
        assert await wrapped({"value": "x"}) == {"value": "done"}

    async def test_approved_via_resolution_instance(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            return {"value": "done"}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        resume = ApprovalResolution(outcome="approved", approver="alice")
        interrupt_fn = FakeInterrupt(resume_value=resume)
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            interrupt_fn=interrupt_fn,
        )
        assert await wrapped({"value": "x"}) == {"value": "done"}


# ---------------------------------------------------------------------------
# (b) Denied flow
# ---------------------------------------------------------------------------


class TestDeniedFlow:
    async def test_denied_resume_raises(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            pytest.fail("body must not run on denied approval")
            return {}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio,
            node_scopes={"danger": _scope("danger")},
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(
            resume_value={
                "outcome": "denied",
                "reason": "human rejected the action",
                "approver": "ops@acme",
            }
        )
        wrapped = chio_approval_node(
            body,
            scope=_scope("danger"),
            config=cfg,
            name="danger",
            interrupt_fn=interrupt_fn,
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        err = exc_info.value
        assert err.guard == "ApprovalGuard"
        assert "human rejected" in (err.reason or "")
        assert err.approval_id is not None

    async def test_rejected_resume_string_raises(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            pytest.fail("must not run")
            return {}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(resume_value="rejected")
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            interrupt_fn=interrupt_fn,
        )
        with pytest.raises(ChioLangGraphError):
            await wrapped({"value": "x"})


# ---------------------------------------------------------------------------
# (c) Local policy can skip the approval pause
# ---------------------------------------------------------------------------


class TestPolicySkip:
    async def test_policy_returning_false_runs_body_without_interrupt(
        self,
    ) -> None:
        def body(_s: State) -> dict[str, Any]:
            return {"value": "done"}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(resume_value={"outcome": "denied"})

        async def never_approve(_state: State, _rc: Any) -> bool:
            return False

        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            approval_policy=never_approve,
            interrupt_fn=interrupt_fn,
        )

        assert await wrapped({"value": "x"}) == {"value": "done"}
        assert interrupt_fn.payloads == []  # no pause occurred


# ---------------------------------------------------------------------------
# (d) Dispatcher hook receives the payload
# ---------------------------------------------------------------------------


class TestDispatcherHook:
    async def test_dispatcher_is_called_with_payload(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            return {"value": "done"}

        chio = allow_all()
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        sent: list[ApprovalRequestPayload] = []

        async def dispatch(payload: ApprovalRequestPayload) -> None:
            sent.append(payload)

        interrupt_fn = FakeInterrupt(
            resume_value={"outcome": "approved"}
        )
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            dispatcher=dispatch,
            interrupt_fn=interrupt_fn,
        )

        await wrapped({"value": "x"})
        assert len(sent) == 1
        assert sent[0].tool_name == "t"
        assert sent[0].capability_id
        # Dispatcher and interrupt must have seen the same approval_id.
        assert sent[0].approval_id == interrupt_fn.payloads[0]["approval_id"]


# ---------------------------------------------------------------------------
# (e) Hard deny from the sidecar short-circuits the approval flow
# ---------------------------------------------------------------------------


class TestSidecarDeny:
    async def test_sidecar_deny_short_circuits(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            pytest.fail("body must not run when sidecar denies")
            return {}

        chio = deny_all(reason="scope mismatch", guard="ScopeGuard")
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )
        await cfg.provision()

        interrupt_fn = FakeInterrupt(
            resume_value={"outcome": "approved"}
        )
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            interrupt_fn=interrupt_fn,
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        assert exc_info.value.guard == "ScopeGuard"
        assert interrupt_fn.payloads == []  # never paused


# ---------------------------------------------------------------------------
# (f) Missing capability short-circuits before interrupt
# ---------------------------------------------------------------------------


class TestMissingCapability:
    async def test_missing_capability_raises(self) -> None:
        def body(_s: State) -> dict[str, Any]:
            pytest.fail("must not run")
            return {}

        chio = allow_all()
        # No provision() -> no tokens minted.
        cfg = ChioGraphConfig(
            chio_client=chio, node_scopes={"t": _scope("t")}
        )

        interrupt_fn = FakeInterrupt(resume_value={"outcome": "approved"})
        wrapped = chio_approval_node(
            body,
            scope=_scope("t"),
            config=cfg,
            name="t",
            interrupt_fn=interrupt_fn,
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        assert exc_info.value.reason == "missing_capability"
        assert interrupt_fn.payloads == []
