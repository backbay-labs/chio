"""Integration-style tests for per-role capability scoping on ChioCrew.

A CrewAI crew where the researcher agent can search but not write, and
the writer agent can write but not search. These tests set up that crew
against a mocked sidecar and assert the verdicts end-to-end.
"""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.errors import ChioValidationError
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict
from crewai import Agent, Task

from chio_crewai import ChioBaseTool, ChioCrew, ChioCrewConfigError, ChioToolError

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


def _capability_aware_policy(chio: MockChioClient) -> Any:
    """Policy that denies when the tool isn't in the token's scope."""

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
    """MockChioClient that records minted tokens for policy lookup."""

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


def _make_tools(
    chio: MockChioClient,
) -> tuple[ChioBaseTool, ChioBaseTool]:
    """Return an (search, write) pair of ChioBaseTools."""
    search_calls: list[dict[str, Any]] = []
    write_calls: list[dict[str, Any]] = []

    def do_search(**kwargs: Any) -> str:
        search_calls.append(kwargs)
        return f"search:{kwargs.get('q', '')}"

    def do_write(**kwargs: Any) -> str:
        write_calls.append(kwargs)
        return f"write:{kwargs.get('path', '')}"

    search_tool = ChioBaseTool(
        name="search",
        description="search the web",
        server_id=SERVER_ID,
        executor=do_search,
        chio_client=chio,
    )
    search_tool.scope = _scope("search")
    search_tool._search_calls = search_calls  # type: ignore[attr-defined]

    write_tool = ChioBaseTool(
        name="write",
        description="write to disk",
        server_id=SERVER_ID,
        executor=do_write,
        chio_client=chio,
    )
    write_tool.scope = _scope("write")
    write_tool._write_calls = write_calls  # type: ignore[attr-defined]

    return search_tool, write_tool


def _make_agent(role: str, goal: str, tools: list[Any]) -> Agent:
    return Agent(
        role=role,
        goal=goal,
        backstory=f"{role} agent for Chio tests",
        tools=tools,
        allow_delegation=False,
        llm="gpt-4o-mini",  # never actually invoked in unit tests
    )


# ---------------------------------------------------------------------------
# Acceptance: researcher-vs-writer scoping
# ---------------------------------------------------------------------------


class TestResearcherWriterScoping:
    async def test_researcher_can_search_not_write(self) -> None:
        chio = _instrumented_client()
        search_tool_r, write_tool_r = _make_tools(chio)
        search_tool_w, write_tool_w = _make_tools(chio)

        researcher = _make_agent(
            "researcher",
            "find good sources",
            [search_tool_r, write_tool_r],
        )
        writer = _make_agent(
            "writer",
            "write good prose",
            [search_tool_w, write_tool_w],
        )

        task = Task(
            description="ignored in unit tests",
            expected_output="ignored",
            agent=researcher,
        )

        crew = ChioCrew(
            capability_scope={
                "researcher": _scope("search"),
                "writer": _scope("write"),
            },
            chio_client=chio,
            agents=[researcher, writer],
            tasks=[task],
        )
        await crew.provision_capabilities()

        # Researcher: search allowed.
        assert await search_tool_r._arun(q="quantum") == "search:quantum"

        # Researcher: write denied.
        with pytest.raises(ChioToolError) as exc_info:
            await write_tool_r._arun(path="/out")
        assert exc_info.value.guard == "ScopeGuard"
        assert "not in capability scope" in (exc_info.value.reason or "")

        # Writer: write allowed.
        assert await write_tool_w._arun(path="/out") == "write:/out"

        # Writer: search denied.
        with pytest.raises(ChioToolError) as exc_info:
            await search_tool_w._arun(q="leak")
        assert exc_info.value.guard == "ScopeGuard"

    async def test_unknown_role_raises_config_error(self) -> None:
        chio = _instrumented_client()
        search_tool, _ = _make_tools(chio)
        rogue = _make_agent("rogue", "cause trouble", [search_tool])

        crew = ChioCrew(
            capability_scope={"researcher": _scope("search")},
            chio_client=chio,
            agents=[rogue],
            tasks=[
                Task(
                    description="x",
                    expected_output="y",
                    agent=rogue,
                )
            ],
        )
        with pytest.raises(ChioCrewConfigError):
            crew.scope_for("rogue")

    async def test_empty_scope_mapping_rejected(self) -> None:
        chio = _instrumented_client()
        search_tool, _ = _make_tools(chio)
        agent = _make_agent("r", "research", [search_tool])
        task = Task(description="x", expected_output="y", agent=agent)
        with pytest.raises(ChioCrewConfigError):
            ChioCrew(
                capability_scope={},
                chio_client=chio,
                agents=[agent],
                tasks=[task],
            )


# ---------------------------------------------------------------------------
# Delegation attenuation
# ---------------------------------------------------------------------------


class TestDelegationAttenuation:
    async def test_child_capability_is_subset_of_parent(self) -> None:
        chio = _instrumented_client()
        search_tool, write_tool = _make_tools(chio)
        lead = _make_agent(
            "lead",
            "lead the crew",
            [search_tool, write_tool],
        )
        junior = _make_agent("junior", "help out", [])

        crew = ChioCrew(
            capability_scope={
                "lead": _scope("search", "write"),
                "junior": _scope("search"),
            },
            chio_client=chio,
            agents=[lead, junior],
            tasks=[
                Task(
                    description="x",
                    expected_output="y",
                    agent=lead,
                )
            ],
        )
        await crew.provision_capabilities()

        # Delegation narrows lead -> junior to just 'search'.
        child = await crew.attenuate_for_delegation(
            delegator_role="lead",
            delegate_role="junior",
            new_scope=_scope("search"),
        )
        parent = crew.token_for("lead")
        assert parent is not None
        assert child.scope.is_subset_of(parent.scope)
        assert not parent.scope.is_subset_of(child.scope)

    async def test_child_cannot_escalate(self) -> None:
        chio = _instrumented_client()
        search_tool, write_tool = _make_tools(chio)
        lead = _make_agent("lead", "lead", [search_tool, write_tool])

        crew = ChioCrew(
            capability_scope={"lead": _scope("search")},
            chio_client=chio,
            agents=[lead],
            tasks=[
                Task(
                    description="x",
                    expected_output="y",
                    agent=lead,
                )
            ],
        )
        await crew.provision_capabilities()

        # Asking to attenuate to a broader scope is a bug; the SDK raises.
        with pytest.raises(ChioValidationError):
            await crew.attenuate_for_delegation(
                delegator_role="lead",
                delegate_role="phantom",
                new_scope=_scope("search", "write"),
            )
