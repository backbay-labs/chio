"""Collection-scoping tests for :class:`ChioQueryEngineTool`.

QueryEngineTool scoped to specific vector collections. These tests
exercise both the client-side allowlist check and the sidecar-driven
deny paths.
"""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.models import ChioScope, Constraint, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all
from llama_index.core.base.base_query_engine import BaseQueryEngine
from llama_index.core.base.response.schema import Response
from llama_index.core.tools import ToolOutput

from chio_llamaindex import (
    ChioLlamaIndexConfigError,
    ChioQueryEngineTool,
    ChioToolError,
)
from chio_llamaindex.query_engine_tool import MEMORY_STORE_ALLOWLIST_TAG

# ---------------------------------------------------------------------------
# Fake query engine
# ---------------------------------------------------------------------------


class _FakeQueryEngine(BaseQueryEngine):
    """In-memory query engine used in place of a real RAG pipeline."""

    def __init__(self, label: str = "fake") -> None:
        super().__init__(callback_manager=None)
        self._label = label
        self.queries: list[str] = []

    def _query(self, query_bundle: Any) -> Any:  # pragma: no cover - sync path
        self.queries.append(str(query_bundle))
        return Response(response=f"{self._label}:{query_bundle}")

    async def _aquery(self, query_bundle: Any) -> Any:
        self.queries.append(str(query_bundle))
        return Response(response=f"{self._label}:{query_bundle}")

    def _get_prompt_modules(self) -> dict[str, Any]:
        return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope_with_memory_allowlist(
    *collections: str,
    tool_name: str = "rag",
    server_id: str = "rag-srv",
) -> ChioScope:
    """Build a scope whose grant carries a ``MemoryStoreAllowlist`` entry per
    collection.

    The current Python :class:`Constraint` only holds a single ``str`` per
    entry; we emit one constraint per collection so the wrapper can
    aggregate them into a set.
    """
    constraints = [
        Constraint(type=MEMORY_STORE_ALLOWLIST_TAG, value=collection)
        for collection in collections
    ]
    return ChioScope(
        grants=[
            ToolGrant(
                server_id=server_id,
                tool_name=tool_name,
                operations=[Operation.INVOKE],
                constraints=constraints,
            )
        ]
    )


def _collection_policy(allowed: set[str]) -> Any:
    """Sidecar-side policy that enforces a collection allowlist."""

    def policy(
        _tool_name: str,
        _scope_hint: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        params = context.get("parameters", {})
        collection = params.get("collection")
        if collection in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"collection {collection!r} not allowed",
            guard="CollectionScopeGuard",
        )

    return policy


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_empty_collection_raises_config_error(self) -> None:
        engine = _FakeQueryEngine()
        with pytest.raises(ChioLlamaIndexConfigError):
            ChioQueryEngineTool(
                query_engine=engine,
                collection="",
                capability_id="cap",
                server_id="srv",
            )

    def test_default_name_includes_collection(self) -> None:
        engine = _FakeQueryEngine()
        tool = ChioQueryEngineTool(
            query_engine=engine,
            collection="prod-docs",
            capability_id="cap",
            server_id="srv",
        )
        assert tool.metadata.name == "query_prod-docs"
        assert tool.collection == "prod-docs"


# ---------------------------------------------------------------------------
# Client-side allowlist enforcement
# ---------------------------------------------------------------------------


class TestClientSideCollectionScoping:
    async def test_allowed_collection_passes_and_queries_engine(self) -> None:
        engine = _FakeQueryEngine(label="prod")

        async with allow_all() as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="prod-docs",
                capability_scope=_scope_with_memory_allowlist(
                    "prod-docs", "public-docs"
                ),
                capability_id="cap-analyst",
                server_id="rag-srv",
                chio_client=chio,
            )
            output = await tool.acall("quarterly earnings")

        assert isinstance(output, ToolOutput)
        assert "prod:" in output.content
        assert engine.queries == ["quarterly earnings"]

    async def test_disallowed_collection_is_denied_client_side(self) -> None:
        """Acceptance check: scope for 'public-docs' cannot touch 'finance-private'."""
        engine = _FakeQueryEngine()

        async with allow_all() as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="finance-private",
                capability_scope=_scope_with_memory_allowlist(
                    "public-docs",
                ),
                capability_id="cap-analyst",
                server_id="rag-srv",
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall("leak secrets")

        err = exc_info.value
        assert err.guard == "CollectionScopeGuard"
        assert err.reason == "collection_not_allowed"
        # The engine must not have been hit.
        assert engine.queries == []
        # The sidecar must not have been hit either (client-side denial is
        # the very first gate).
        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert eval_calls == []

    async def test_empty_allowlist_is_fail_closed(self) -> None:
        engine = _FakeQueryEngine()

        async with allow_all() as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="prod-docs",
                capability_scope=ChioScope(),  # no grants at all
                capability_id="cap-analyst",
                server_id="rag-srv",
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall("list invoices")

        assert exc_info.value.reason == "missing_collection_allowlist"

    async def test_allowed_collections_override(self) -> None:
        engine = _FakeQueryEngine()

        async with allow_all() as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="prod-docs",
                allowed_collections=["prod-docs", "qa-docs"],
                capability_id="cap",
                server_id="rag-srv",
                chio_client=chio,
            )
            assert tool.allowed_collections() == frozenset(
                {"prod-docs", "qa-docs"}
            )
            output = await tool.acall("any question")
            assert isinstance(output, ToolOutput)

    async def test_no_allowlist_defers_to_sidecar(self) -> None:
        """If neither scope nor override is set, the client-side check is a no-op
        and the sidecar's policy is the only gate."""
        engine = _FakeQueryEngine()

        async with allow_all() as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="prod-docs",
                capability_id="cap",
                server_id="rag-srv",
                chio_client=chio,
            )
            output = await tool.acall("anything")
        assert isinstance(output, ToolOutput)


# ---------------------------------------------------------------------------
# Sidecar-driven denial (independent policy layer)
# ---------------------------------------------------------------------------


class TestSidecarEnforcement:
    async def test_sidecar_deny_raises(self) -> None:
        engine = _FakeQueryEngine()

        async with deny_all(reason="policy block", guard="RagPolicyGuard") as chio:
            tool = ChioQueryEngineTool(
                query_engine=engine,
                collection="prod-docs",
                allowed_collections=["prod-docs"],  # passes client-side
                capability_id="cap",
                server_id="rag-srv",
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall("top secret question")

        assert exc_info.value.guard == "RagPolicyGuard"
        assert engine.queries == []

    async def test_sidecar_forwards_collection_in_parameters(self) -> None:
        """The sidecar sees the collection so policy can inspect it."""
        engine = _FakeQueryEngine()

        chio = MockChioClient()
        chio.set_policy(_collection_policy({"prod-docs"}))
        tool = ChioQueryEngineTool(
            query_engine=engine,
            collection="prod-docs",
            allowed_collections=["prod-docs"],
            capability_id="cap",
            server_id="rag-srv",
            chio_client=chio,
        )
        output = await tool.acall("how many widgets")
        assert isinstance(output, ToolOutput)

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        params = eval_calls[0].parameters
        assert params["collection"] == "prod-docs"
        assert params["query"] == "how many widgets"


# ---------------------------------------------------------------------------
# bind_capability updates both id and scope in one call
# ---------------------------------------------------------------------------


class TestBindCapability:
    async def test_bind_capability_updates_scope(self) -> None:
        engine = _FakeQueryEngine()
        chio = allow_all()

        tool = ChioQueryEngineTool(
            query_engine=engine,
            collection="prod-docs",
            capability_id="old",
            server_id="rag-srv",
            chio_client=chio,
        )
        new_scope = _scope_with_memory_allowlist("prod-docs")
        tool.bind_capability("new-cap", scope=new_scope)

        assert tool.capability_id == "new-cap"
        assert tool.capability_scope is new_scope
        # And subsequent calls use the new scope for the allowlist check.
        output = await tool.acall("why")
        assert isinstance(output, ToolOutput)
