"""Integration tests for per-role capability scoping on ChioGroupChat.

An AutoGen GroupChat where registered functions are Chio-governed and
nested chat spawns get attenuated capability tokens. These tests set up
that situation against a mocked sidecar and assert the verdicts
end-to-end without needing an actual LLM.
"""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.errors import ChioValidationError
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict
from autogen import ConversableAgent

from chio_autogen import (
    ChioAutogenConfigError,
    ChioFunctionRegistry,
    ChioGroupChat,
    ChioGroupChatManager,
    ChioToolError,
    attach_registry,
    register_nested_chats_with_attenuation,
)

SERVER_ID = "demo-srv"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _make_agent(name: str) -> ConversableAgent:
    return ConversableAgent(
        name=name,
        llm_config=False,
        human_input_mode="NEVER",
        code_execution_config=False,
    )


def _capability_aware_policy(chio: MockChioClient) -> Any:
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
            f"tool {tool_name!r} not in capability scope",
            guard="ScopeGuard",
        )

    return policy


def _instrumented_client() -> MockChioClient:
    """MockChioClient that indexes minted tokens for policy lookup."""

    chio = MockChioClient()
    chio._tokens = {}  # type: ignore[attr-defined]

    original_create = chio.create_capability
    original_attenuate = chio.attenuate_capability

    async def create_capability(**kwargs: Any) -> Any:
        token = await original_create(**kwargs)
        chio._tokens[token.id] = token  # type: ignore[attr-defined]
        return token

    async def attenuate_capability(parent: Any, **kwargs: Any) -> Any:
        child = await original_attenuate(parent, **kwargs)
        chio._tokens[child.id] = child  # type: ignore[attr-defined]
        return child

    chio.create_capability = create_capability  # type: ignore[method-assign]
    chio.attenuate_capability = attenuate_capability  # type: ignore[method-assign]
    chio.set_policy(_capability_aware_policy(chio))
    return chio


def _attach_registry(
    agent: ConversableAgent,
    *,
    chio: MockChioClient,
    functions: dict[str, Any],
) -> ChioFunctionRegistry:
    """Attach a new registry to an agent and register the given functions."""
    registry = ChioFunctionRegistry(
        agent=agent,
        chio_client=chio,
        server_id=SERVER_ID,
    )
    for name, fn in functions.items():
        registry.register(name, fn, scope=_scope(name))
    attach_registry(agent, registry)
    return registry


# ---------------------------------------------------------------------------
# Acceptance: role-scoped functions are Chio-governed
# ---------------------------------------------------------------------------


class TestResearcherWriterScoping:
    async def test_researcher_can_search_not_write(self) -> None:
        chio = _instrumented_client()

        researcher = _make_agent("researcher")
        writer = _make_agent("writer")

        def do_search(**kwargs: Any) -> str:
            return f"search:{kwargs.get('q', '')}"

        def do_write(**kwargs: Any) -> str:
            return f"write:{kwargs.get('path', '')}"

        researcher_reg = _attach_registry(
            researcher,
            chio=chio,
            functions={"search": do_search, "write": do_write},
        )
        writer_reg = _attach_registry(
            writer,
            chio=chio,
            functions={"search": do_search, "write": do_write},
        )

        groupchat = ChioGroupChat(
            capability_scope={
                "researcher": _scope("search"),
                "writer": _scope("write"),
            },
            agents=[researcher, writer],
            messages=[],
            max_round=2,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat,
            chio_client=chio,
            llm_config=False,
        )
        await manager.provision_capabilities()

        # Tokens were minted and bound onto each registry.
        assert manager.token_for("researcher") is not None
        assert manager.token_for("writer") is not None
        assert researcher_reg.capability_id == manager.token_for(
            "researcher"
        ).id  # type: ignore[union-attr]
        assert writer_reg.capability_id == manager.token_for(
            "writer"
        ).id  # type: ignore[union-attr]

        # Researcher: search allowed.
        search_rfn = researcher.function_map["search"]
        assert search_rfn(q="quantum") == "search:quantum"

        # Researcher: write denied by Chio scope guard.
        write_rfn = researcher.function_map["write"]
        with pytest.raises(ChioToolError) as exc_info:
            write_rfn(path="/out")
        assert exc_info.value.guard == "ScopeGuard"
        assert "not in capability scope" in (exc_info.value.reason or "")

        # Writer: write allowed.
        write_wfn = writer.function_map["write"]
        assert write_wfn(path="/out") == "write:/out"

        # Writer: search denied.
        search_wfn = writer.function_map["search"]
        with pytest.raises(ChioToolError) as exc_info:
            search_wfn(q="leak")
        assert exc_info.value.guard == "ScopeGuard"

    async def test_ensure_function_in_scope_blocks_offline(self) -> None:
        chio = _instrumented_client()
        agent = _make_agent("researcher")
        _attach_registry(
            agent, chio=chio, functions={"search": lambda **_kw: "ok"}
        )
        groupchat = ChioGroupChat(
            capability_scope={"researcher": _scope("search")},
            agents=[agent],
            messages=[],
            max_round=1,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat, chio_client=chio, llm_config=False
        )
        await manager.provision_capabilities()

        # In-scope: no exception.
        manager.ensure_function_in_scope("researcher", "search")

        # Out-of-scope: raises without contacting the sidecar.
        with pytest.raises(ChioToolError):
            manager.ensure_function_in_scope("researcher", "write")

    async def test_unknown_role_raises_config_error(self) -> None:
        chio = _instrumented_client()
        rogue = _make_agent("rogue")
        _attach_registry(
            rogue, chio=chio, functions={"search": lambda **_kw: "ok"}
        )
        groupchat = ChioGroupChat(
            capability_scope={"researcher": _scope("search")},
            agents=[rogue],
            messages=[],
            max_round=1,
        )
        with pytest.raises(ChioAutogenConfigError):
            groupchat.scope_for("rogue")

    async def test_empty_scope_mapping_rejected(self) -> None:
        agent = _make_agent("r")
        with pytest.raises(ChioAutogenConfigError):
            ChioGroupChat(
                capability_scope={},
                agents=[agent],
                messages=[],
                max_round=1,
            )

    async def test_manager_requires_chio_group_chat(self) -> None:
        from autogen import GroupChat as PlainGroupChat

        agent = _make_agent("r")
        plain = PlainGroupChat(agents=[agent], messages=[], max_round=1)
        with pytest.raises(ChioAutogenConfigError):
            ChioGroupChatManager(
                groupchat=plain,  # type: ignore[arg-type]
                chio_client=_instrumented_client(),
                llm_config=False,
            )


# ---------------------------------------------------------------------------
# Acceptance: nested chats get attenuated capability tokens
# ---------------------------------------------------------------------------


class TestNestedChatAttenuation:
    async def test_nested_spawn_gets_attenuated_token(self) -> None:
        chio = _instrumented_client()

        parent = _make_agent("lead")
        child_recipient = _make_agent("junior")

        parent_reg = _attach_registry(
            parent,
            chio=chio,
            functions={
                "search": lambda **_kw: "parent-search",
                "write": lambda **_kw: "parent-write",
            },
        )
        child_reg = _attach_registry(
            child_recipient,
            chio=chio,
            functions={
                "search": lambda **_kw: "child-search",
                "write": lambda **_kw: "child-write",
            },
        )

        groupchat = ChioGroupChat(
            capability_scope={
                "lead": _scope("search", "write"),
                "junior": _scope("search", "write"),
            },
            agents=[parent, child_recipient],
            messages=[],
            max_round=3,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat, chio_client=chio, llm_config=False
        )
        await manager.provision_capabilities()

        parent_token = manager.token_for("lead")
        assert parent_token is not None

        # Before attenuation, child can write using its own role token.
        assert child_recipient.function_map["write"](path="/x") == "child-write"

        # Register nested chat with an attenuated "search-only" scope.
        child_token = await register_nested_chats_with_attenuation(
            parent_agent=parent,
            child_configs=[
                {
                    "recipient": child_recipient,
                    "message": "handoff",
                    "max_turns": 1,
                }
            ],
            parent_capability=parent_token,
            child_scope=_scope("search"),
            chio_client=chio,
        )

        # Strict subset of the parent capability.
        assert child_token.scope.is_subset_of(parent_token.scope)
        assert not parent_token.scope.is_subset_of(child_token.scope)

        # The child's registry is now bound to the attenuated token, so
        # a write attempt from the nested chat is denied even though
        # the child's original role scope allowed it.
        assert child_reg.capability_id == child_token.id
        with pytest.raises(ChioToolError) as exc_info:
            child_recipient.function_map["write"](path="/x")
        assert exc_info.value.guard == "ScopeGuard"

        # Search remains allowed through the attenuated token.
        assert (
            child_recipient.function_map["search"](q="papers")
            == "child-search"
        )

        # Parent's registry was not touched by the attenuation.
        assert parent_reg.capability_id == parent_token.id

    async def test_nested_cannot_escalate_beyond_parent(self) -> None:
        chio = _instrumented_client()

        parent = _make_agent("lead")
        child_recipient = _make_agent("junior")
        _attach_registry(
            parent, chio=chio, functions={"search": lambda **_kw: "ok"}
        )
        _attach_registry(
            child_recipient,
            chio=chio,
            functions={"search": lambda **_kw: "ok"},
        )

        groupchat = ChioGroupChat(
            capability_scope={
                "lead": _scope("search"),
                "junior": _scope("search"),
            },
            agents=[parent, child_recipient],
            messages=[],
            max_round=2,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat, chio_client=chio, llm_config=False
        )
        await manager.provision_capabilities()
        parent_token = manager.token_for("lead")
        assert parent_token is not None

        # Asking to attenuate to a *broader* scope must raise.
        with pytest.raises(ChioValidationError):
            await register_nested_chats_with_attenuation(
                parent_agent=parent,
                child_configs=[
                    {"recipient": child_recipient, "message": "ignored"}
                ],
                parent_capability=parent_token,
                child_scope=_scope("search", "write"),
                chio_client=chio,
            )

    async def test_attenuate_for_handoff_narrows_role(self) -> None:
        chio = _instrumented_client()
        lead = _make_agent("lead")
        junior = _make_agent("junior")

        _attach_registry(
            lead,
            chio=chio,
            functions={
                "search": lambda **_kw: "ok",
                "write": lambda **_kw: "ok",
            },
        )
        _attach_registry(
            junior,
            chio=chio,
            functions={
                "search": lambda **_kw: "ok",
                "write": lambda **_kw: "ok",
            },
        )

        groupchat = ChioGroupChat(
            capability_scope={
                "lead": _scope("search", "write"),
                "junior": _scope("search"),
            },
            agents=[lead, junior],
            messages=[],
            max_round=2,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat, chio_client=chio, llm_config=False
        )
        await manager.provision_capabilities()

        child = await manager.attenuate_for_handoff(
            delegator_role="lead",
            delegate_role="junior",
            new_scope=_scope("search"),
        )
        parent = manager.token_for("lead")
        assert parent is not None
        assert child.scope.is_subset_of(parent.scope)
        assert not parent.scope.is_subset_of(child.scope)
