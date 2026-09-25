"""Unit tests for ChioBaseTool capability enforcement."""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.errors import ChioDeniedError
from chio_sdk.models import (
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

from chio_crewai import ChioBaseTool, ChioToolError

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    """Build a scope that authorises exactly the given tools."""
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


def _scope_aware_policy(
    mock_client: MockChioClient,
) -> Any:
    """Policy that enforces the scope bound to the capability_id.

    Looks up the token behind the ``capability_id`` in the mock
    client's internal state and denies if the tool being evaluated is
    not authorised by that token's scope.
    """

    def policy(
        tool_name: str,
        scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = _find_token_by_id(mock_client, cap_id)
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


def _find_token_by_id(client: MockChioClient, cap_id: str | None) -> Any:
    """Dig through recorded calls to reconstruct the active token list."""
    if cap_id is None:
        return None
    for call in client.calls:
        if call.method == "create_capability" and call.context.get("token_id") == cap_id:
            return call.context["token"]
    # Fallback: the mock records only the minted scope on create; we keep
    # a side-channel via the ``_tokens`` attribute set in _mint_token.
    return getattr(client, "_tokens", {}).get(cap_id)


async def _mint_token(
    client: MockChioClient,
    *,
    subject: str,
    scope: ChioScope,
) -> Any:
    """Mint a capability via the mock and index it for the policy."""
    token = await client.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(client, "_tokens", {})
    store[token.id] = token
    client._tokens = store  # type: ignore[attr-defined]
    return token


# ---------------------------------------------------------------------------
# (a) allow verdict runs the underlying tool
# ---------------------------------------------------------------------------


class TestAllowVerdict:
    async def test_allow_runs_executor(self) -> None:
        called: list[dict[str, Any]] = []

        def executor(**kwargs: Any) -> str:
            called.append(kwargs)
            return f"result={kwargs.get('q')}"

        async with allow_all() as chio:
            tool = ChioBaseTool(
                name="search",
                description="search the web",
                server_id="srv",
                capability_id="cap-1",
                executor=executor,
                chio_client=chio,
            )
            result = await tool._arun(q="hello")

        assert result == "result=hello"
        assert called == [{"q": "hello"}]
        assert tool.last_chio_receipt is not None
        assert tool.last_chio_receipt.is_allowed

    async def test_allow_awaits_async_executor(self) -> None:
        async def executor(**kwargs: Any) -> str:
            return f"async:{kwargs.get('q')}"

        async with allow_all() as chio:
            tool = ChioBaseTool(
                name="search",
                description="search the web",
                server_id="srv",
                capability_id="cap-1",
                executor=executor,
                chio_client=chio,
            )
            result = await tool._arun(q="hi")

        assert result == "async:hi"


# ---------------------------------------------------------------------------
# (b) deny verdict raises ChioToolError
# ---------------------------------------------------------------------------


class TestDenyVerdict:
    async def test_deny_raises_chio_tool_error(self) -> None:
        def executor(**kwargs: Any) -> str:
            pytest.fail("executor must not run on deny")
            return ""

        # ``raise_on_deny=False`` forces the mock to return a deny
        # receipt that the tool then converts into ChioToolError itself,
        # exercising the receipt-based path.
        async with deny_all(raise_on_deny=False) as chio:
            tool = ChioBaseTool(
                name="write",
                description="write a file",
                server_id="srv",
                capability_id="cap-x",
                executor=executor,
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool._arun(path="/tmp/x")

        err = exc_info.value
        assert err.tool_name == "write"
        assert err.server_id == "srv"
        assert "denied" in (err.reason or "").lower()
        assert err.receipt_id is not None
        assert tool.last_chio_receipt is not None
        assert tool.last_chio_receipt.is_denied

    async def test_deny_from_403_raises_chio_tool_error(self) -> None:
        # ``raise_on_deny=True`` -> mock raises ChioDeniedError which the
        # tool translates to ChioToolError.
        async with deny_all(reason="no write perms", guard="ScopeGuard") as chio:
            tool = ChioBaseTool(
                name="write",
                description="write a file",
                server_id="srv",
                capability_id="cap-x",
                executor=lambda **_kw: "unreached",
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool._arun(path="/tmp/x")

        err = exc_info.value
        assert err.guard == "ScopeGuard"
        assert "no write perms" in err.reason if err.reason else False

    async def test_missing_capability_id_denies(self) -> None:
        async with allow_all() as chio:
            tool = ChioBaseTool(
                name="search",
                description="search",
                server_id="srv",
                capability_id="",
                executor=lambda **_kw: "unreached",
                chio_client=chio,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool._arun(q="hi")
        assert exc_info.value.reason == "missing_capability"


# ---------------------------------------------------------------------------
# (c) researcher cannot invoke a write-scoped tool
# ---------------------------------------------------------------------------


class TestResearcherCannotWrite:
    async def test_researcher_write_is_denied(self) -> None:
        chio = MockChioClient()
        chio.set_policy(_scope_aware_policy(chio))

        researcher_token = await _mint_token(
            chio,
            subject="agent:researcher",
            scope=_scope_for_tools("search", "browse"),
        )

        write_tool = ChioBaseTool(
            name="write",
            description="write a file",
            server_id="srv",
            capability_id=researcher_token.id,
            executor=lambda **_kw: "unreached",
            chio_client=chio,
        )

        with pytest.raises(ChioToolError) as exc_info:
            await write_tool._arun(path="/out")

        assert exc_info.value.guard == "ScopeGuard"
        assert "not in capability scope" in (exc_info.value.reason or "")


# ---------------------------------------------------------------------------
# (d) writer cannot invoke a search-scoped tool
# ---------------------------------------------------------------------------


class TestWriterCannotSearch:
    async def test_writer_search_is_denied(self) -> None:
        chio = MockChioClient()
        chio.set_policy(_scope_aware_policy(chio))

        writer_token = await _mint_token(
            chio,
            subject="agent:writer",
            scope=_scope_for_tools("write", "format"),
        )

        search_tool = ChioBaseTool(
            name="search",
            description="search the web",
            server_id="srv",
            capability_id=writer_token.id,
            executor=lambda **_kw: "unreached",
            chio_client=chio,
        )

        with pytest.raises(ChioToolError) as exc_info:
            await search_tool._arun(q="hello")

        assert exc_info.value.guard == "ScopeGuard"


# ---------------------------------------------------------------------------
# (e) attenuated delegation child cannot escalate
# ---------------------------------------------------------------------------


class TestAttenuatedDelegation:
    async def test_child_cannot_escalate_beyond_parent(self) -> None:
        chio = MockChioClient()
        chio.set_policy(_scope_aware_policy(chio))

        # Parent has search + browse; child should be a subset.
        parent = await _mint_token(
            chio,
            subject="agent:parent",
            scope=_scope_for_tools("search", "browse"),
        )
        child_scope = _scope_for_tools("search")
        with pytest.raises(ChioDeniedError) as error:
            await chio.attenuate_capability(parent, new_scope=child_scope)
        assert error.value.reason_code == "chio_attenuation_requires_subject_signer"

        # Refusing attenuation must not expand the existing parent scope.
        escalate_tool = ChioBaseTool(
            name="write",
            description="escalation attempt",
            server_id="srv",
            capability_id=parent.id,
            executor=lambda **_kw: "unreached",
            chio_client=chio,
        )
        with pytest.raises(ChioToolError):
            await escalate_tool._arun(path="/out")

        # Asking the SDK to attenuate to a *broader* scope must raise.
        from chio_sdk.errors import ChioValidationError

        broader = _scope_for_tools("search", "browse", "write")
        with pytest.raises(ChioValidationError):
            await chio.attenuate_capability(parent, new_scope=broader)
