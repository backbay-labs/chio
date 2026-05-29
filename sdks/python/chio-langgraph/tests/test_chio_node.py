"""Unit tests for :func:`chio_langgraph.chio_node`.

A LangGraph state graph with ``chio_node`` wrappers where each node
operates under a scoped capability. These tests validate the three
branches of the wrapper:

* allow verdict runs the wrapped body and preserves the state update;
* deny verdict raises :class:`ChioLangGraphError` without running the body;
* async nodes are awaited and their contract preserved.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_langgraph import (
    ChioGraphConfig,
    ChioLangGraphError,
    chio_node,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


SERVER_ID = "demo-srv"


class State(TypedDict, total=False):
    value: str
    count: int


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


async def _build_config(
    chio: MockChioClient,
    *,
    node_name: str,
    scope: ChioScope,
    workflow_scope: ChioScope | None = None,
) -> ChioGraphConfig:
    cfg = ChioGraphConfig(
        chio_client=chio,
        workflow_scope=workflow_scope,
        node_scopes={node_name: scope},
    )
    await cfg.provision()
    return cfg


# ---------------------------------------------------------------------------
# (a) allow verdict runs the wrapped body and preserves the state update
# ---------------------------------------------------------------------------


class TestAllowInvokesBody:
    async def test_sync_node_allow_runs_body(self) -> None:
        calls: list[dict[str, Any]] = []

        def search_node(state: State) -> dict[str, Any]:
            calls.append(dict(state))
            return {"value": f"searched:{state.get('value', '')}"}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="search", scope=_scope("search")
        )

        wrapped = chio_node(
            search_node, scope=_scope("search"), config=cfg, name="search"
        )

        # LangGraph calls nodes with a config positional; we pass one
        # even though the body only takes ``state`` -- the wrapper must
        # drop the extra argument cleanly.
        update = await wrapped({"value": "quantum"}, {"configurable": {}})

        assert update == {"value": "searched:quantum"}
        assert calls == [{"value": "quantum"}]
        # Evaluate call was recorded.
        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        assert eval_calls[0].tool_name == "search"
        assert eval_calls[0].tool_server == "langgraph"

    async def test_async_node_is_awaited(self) -> None:
        async def async_node(state: State) -> dict[str, Any]:
            return {"value": f"async:{state.get('value', '')}"}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="async_node", scope=_scope("async_node")
        )
        wrapped = chio_node(
            async_node,
            scope=_scope("async_node"),
            config=cfg,
            name="async_node",
        )

        update = await wrapped({"value": "go"})
        assert update == {"value": "async:go"}

    async def test_node_accepting_config_gets_runtime_config(self) -> None:
        seen: list[Any] = []

        def node_with_cfg(state: State, runtime_cfg: Any) -> dict[str, Any]:
            seen.append(runtime_cfg)
            return {"value": "ok"}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="with_cfg", scope=_scope("with_cfg")
        )
        wrapped = chio_node(
            node_with_cfg,
            scope=_scope("with_cfg"),
            config=cfg,
            name="with_cfg",
        )

        runtime_cfg = {"configurable": {"thread_id": "T1"}}
        await wrapped({"value": "x"}, runtime_cfg)
        assert len(seen) == 1
        assert seen[0] is runtime_cfg


# ---------------------------------------------------------------------------
# (b) deny verdict raises ChioLangGraphError without running the body
# ---------------------------------------------------------------------------


class TestDenyRaises:
    async def test_deny_from_403_raises_chio_langgraph_error(self) -> None:
        def forbidden_node(_state: State) -> dict[str, Any]:
            pytest.fail("body must not run on deny")
            return {}

        chio = deny_all(reason="out of scope", guard="ScopeGuard")
        cfg = await _build_config(
            chio, node_name="write", scope=_scope("write")
        )
        wrapped = chio_node(
            forbidden_node,
            scope=_scope("write"),
            config=cfg,
            name="write",
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        err = exc_info.value
        assert err.guard == "ScopeGuard"
        assert "out of scope" in (err.reason or "")

    async def test_deny_receipt_path_also_raises(self) -> None:
        # ``raise_on_deny=False`` forces the mock to return a deny
        # receipt rather than raising, exercising the receipt-based
        # denial path inside the wrapper.
        def node(_state: State) -> dict[str, Any]:
            pytest.fail("body must not run on deny")
            return {}

        chio = deny_all(
            reason="scope mismatch",
            guard="ScopeGuard",
            raise_on_deny=False,
        )
        cfg = await _build_config(
            chio, node_name="write", scope=_scope("write")
        )
        wrapped = chio_node(
            node, scope=_scope("write"), config=cfg, name="write"
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        assert exc_info.value.guard == "ScopeGuard"
        assert exc_info.value.receipt_id is not None

    async def test_missing_capability_raises(self) -> None:
        def node(_state: State) -> dict[str, Any]:
            pytest.fail("body must not run when no capability is bound")
            return {}

        chio = allow_all()
        # Build a config *without* calling provision() so no tokens are
        # minted; the wrapper must refuse to dispatch.
        cfg = ChioGraphConfig(
            chio_client=chio,
            node_scopes={"write": _scope("write")},
        )
        wrapped = chio_node(
            node, scope=_scope("write"), config=cfg, name="write"
        )

        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped({"value": "x"})
        assert exc_info.value.reason == "missing_capability"


# ---------------------------------------------------------------------------
# (c) scope-aware policy: researcher cannot write, writer cannot search
# ---------------------------------------------------------------------------


def _scope_aware_policy(chio: MockChioClient) -> Any:
    def policy(
        tool_name: str,
        _scope_hint: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = getattr(chio, "_tokens", {}).get(cap_id)
        if token is None:
            return MockVerdict.deny_verdict(
                f"unknown capability {cap_id!r}", guard="CapabilityGuard"
            )
        allowed = {g.tool_name for g in token.scope.grants}
        if tool_name in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"node {tool_name!r} not in capability scope",
            guard="ScopeGuard",
        )

    return policy


def _instrumented_client() -> MockChioClient:
    chio = MockChioClient()
    chio._tokens = {}  # type: ignore[attr-defined]
    orig = chio.create_capability

    async def create_capability(**kwargs: Any) -> Any:
        tok = await orig(**kwargs)
        chio._tokens[tok.id] = tok  # type: ignore[attr-defined]
        return tok

    chio.create_capability = create_capability  # type: ignore[method-assign]
    chio.set_policy(_scope_aware_policy(chio))
    return chio


class TestPerNodeScope:
    async def test_writer_node_cannot_search(self) -> None:
        chio = _instrumented_client()
        cfg = ChioGraphConfig(
            chio_client=chio,
            node_scopes={
                "search": _scope("search"),
                "write": _scope("write"),
            },
        )
        await cfg.provision()

        def search_body(_state: State) -> dict[str, Any]:
            return {"value": "searched"}

        def write_body(_state: State) -> dict[str, Any]:
            return {"value": "written"}

        wrapped_search = chio_node(
            search_body, scope=_scope("search"), config=cfg, name="search"
        )
        wrapped_write = chio_node(
            write_body, scope=_scope("write"), config=cfg, name="write"
        )

        # Happy path: each node runs under its own scope.
        assert (await wrapped_search({"value": "x"})) == {"value": "searched"}
        assert (await wrapped_write({"value": "x"})) == {"value": "written"}

        # A search node tries to run under a write capability. We
        # simulate this by overriding the capability id via runtime
        # config -- the same mechanism supervisors use to hand a
        # narrower token down the graph.
        write_token = cfg.token_for("write")
        assert write_token is not None
        runtime_cfg = {
            "configurable": {"chio_capability_id": write_token.id}
        }
        with pytest.raises(ChioLangGraphError) as exc_info:
            await wrapped_search({"value": "x"}, runtime_cfg)
        assert exc_info.value.guard == "ScopeGuard"
