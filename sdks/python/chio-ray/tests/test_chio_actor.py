"""Unit tests for :class:`chio_ray.ChioActor` and :meth:`ChioActor.requires`.

Exercises the documented usage shape: a Ray actor with
``@ChioActor.requires("tools:search")`` on its methods, a standing
grant that authorises ``tools:search`` only, and calls outside the
granted scope that are denied with :class:`PermissionError`.

Ray's scheduler is replaced by the lightweight fake in
``conftest.py``; the Chio enforcement path we are validating is
identical under the real scheduler but the fake keeps the suite fast.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
import ray
from chio_sdk.models import ChioScope, CapabilityToken, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all

from chio_ray import ChioActor, ChioRayConfigError, ChioRayError, StandingGrant, requires

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


def _local_token(
    scope: ChioScope,
    *,
    token_id: str = "tok-1",
    subject: str = "agent:researcher",
) -> CapabilityToken:
    now = int(time.time())
    return CapabilityToken(
        id=token_id,
        issuer="test-issuer",
        subject=subject,
        scope=scope,
        issued_at=now,
        expires_at=now + 3600,
        signature="test-signature",
    )


def _scope_aware_policy(
    mock_client: MockChioClient,
    scopes_by_cap: dict[str, set[str]],
) -> Any:
    """Policy that allows tool_name iff the capability token authorises it."""

    def policy(
        tool_name: str,
        _scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        allowed = scopes_by_cap.get(cap_id or "", set())
        if tool_name in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"tool {tool_name!r} not in capability {cap_id!r}",
            guard="ScopeGuard",
        )

    return policy


# ---------------------------------------------------------------------------
# (a) In-scope method call succeeds.
# ---------------------------------------------------------------------------


class TestRoadmapAcceptance:
    """In-scope method calls succeed under a standing grant."""

    def test_search_method_allowed_when_standing_grant_authorises_search(
        self,
    ) -> None:
        chio = MockChioClient()
        search_token = _local_token(
            _scope_for_tools("search"), token_id="tok-search"
        )
        chio.set_policy(
            _scope_aware_policy(chio, {"tok-search": {"search"}})
        )

        class ResearchAgent(ChioActor):
            def __init__(self, *, chio_client: Any, token: CapabilityToken) -> None:
                super().__init__(
                    token=token,
                    tool_server="srv",
                    chio_client=chio_client,
                )

            @ChioActor.requires("tools:search")
            def search(self, query: str) -> list[str]:
                return [f"hit:{query}"]

        # Wrap with the ray fake to match the documented usage:
        # `ActorClass.remote(...)` to instantiate,
        # `handle.method.remote(...)` to call.
        remote_cls = ray.remote(ResearchAgent)
        handle = remote_cls.remote(chio_client=chio, token=search_token)

        ref = handle.search.remote("quantum")
        assert ray.get(ref) == ["hit:quantum"]

        # The sidecar was evaluated exactly once, under the standing
        # grant's capability id, with ``tool_name="search"``.
        eval_calls = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ]
        assert len(eval_calls) == 1
        assert eval_calls[0].tool_name == "search"
        assert eval_calls[0].capability_id == "tok-search"

    def test_out_of_scope_method_call_is_denied(self) -> None:
        """The acceptance case -- a method whose scope exceeds the grant is denied."""
        chio = MockChioClient()
        search_only = _local_token(
            _scope_for_tools("search"), token_id="tok-search"
        )
        chio.set_policy(
            _scope_aware_policy(chio, {"tok-search": {"search"}})
        )

        class ResearchAgent(ChioActor):
            def __init__(self, *, chio_client: Any, token: CapabilityToken) -> None:
                super().__init__(
                    token=token,
                    tool_server="srv",
                    chio_client=chio_client,
                )

            @ChioActor.requires("tools:search")
            def search(self, query: str) -> list[str]:
                return [f"hit:{query}"]

            @ChioActor.requires("tools:write")
            def write(self, path: str, body: str) -> None:
                pytest.fail("write must not execute without capability")

        remote_cls = ray.remote(ResearchAgent)
        handle = remote_cls.remote(chio_client=chio, token=search_only)

        # In-scope call still works as a control.
        assert ray.get(handle.search.remote("alpha")) == ["hit:alpha"]

        # Out-of-scope call denied -- propagates through ray.get as
        # PermissionError.
        write_ref = handle.write.remote("/tmp/x", "body")
        with pytest.raises(PermissionError) as exc_info:
            ray.get(write_ref)

        inner: ChioRayError = exc_info.value.chio_error  # type: ignore[attr-defined]
        # The short-circuit subset check catches this before the
        # sidecar evaluation because ``tools:write`` is not in the
        # standing grant.
        assert inner.guard == "StandingGrantSubsetGuard"
        assert inner.method_name == "write"
        assert "search" not in (inner.reason or "")


# ---------------------------------------------------------------------------
# (b) Sidecar-path deny -- standing grant admits the scope but the sidecar denies.
# ---------------------------------------------------------------------------


class TestSidecarDeny:
    def test_sidecar_deny_raises_permission_error(self) -> None:
        # ``raise_on_deny=False`` forces the mock to return a deny
        # receipt (so the ChioRayError carries ``receipt_id``) rather
        # than raising :class:`ChioDeniedError` off the HTTP-403 path.
        chio = MockChioClient(raise_on_deny=False)
        token = _local_token(
            _scope_for_tools("search", "write"), token_id="tok-rw"
        )
        # Sidecar denies write even though the standing grant admits
        # it -- simulates a narrower runtime policy (e.g. a read-only
        # session override) layered on top of the token's scope.
        chio.set_policy(_scope_aware_policy(chio, {"tok-rw": {"search"}}))

        class Agent(ChioActor):
            def __init__(self, *, chio_client: Any, token: CapabilityToken) -> None:
                super().__init__(
                    token=token, tool_server="srv", chio_client=chio_client
                )

            @ChioActor.requires("tools:write")
            def write(self, path: str) -> None:
                pytest.fail("body must not run on deny")

        remote_cls = ray.remote(Agent)
        handle = remote_cls.remote(chio_client=chio, token=token)

        with pytest.raises(PermissionError) as exc_info:
            ray.get(handle.write.remote("/tmp/x"))

        inner: ChioRayError = exc_info.value.chio_error  # type: ignore[attr-defined]
        # Sidecar denies (not the short-circuit guard) since the
        # standing grant authorises both tools.
        assert inner.guard == "ScopeGuard"
        assert inner.receipt_id is not None


# ---------------------------------------------------------------------------
# (c) Standing grant introspection + receipt trail.
# ---------------------------------------------------------------------------


class TestStandingGrantIntrospection:
    def test_chio_grant_exposed_on_actor(self) -> None:
        chio = allow_all()
        token = _local_token(_scope_for_tools("search"), token_id="tok-i")

        class Agent(ChioActor):
            def __init__(self) -> None:
                super().__init__(token=token, tool_server="srv", chio_client=chio)

            @ChioActor.requires("tools:search")
            def search(self, q: str) -> str:
                return q

        # Construct directly -- ChioActor does not require being inside
        # a Ray actor; ``@ray.remote`` merely schedules it.
        agent = Agent()
        assert isinstance(agent.chio_grant, StandingGrant)
        assert agent.chio_capability_id == "tok-i"
        assert agent.chio_scope.grants[0].tool_name == "search"
        assert agent.chio_receipts == []

        # After a call, the receipt is recorded on the trail.
        _ = ray.get(ray.remote(Agent).remote().search.remote("x"))
        # In the fake, driver-side and Ray-side are independent instances
        # so the receipt trail lives on the per-handle instance. We also confirm the direct-call trail:
        agent.search("y")
        assert len(agent.chio_receipts) == 1
        assert agent.chio_receipts[0].is_allowed

    def test_standalone_requires_alias_matches_method(self) -> None:
        assert requires is ChioActor.requires


# ---------------------------------------------------------------------------
# (d) Construction invariants.
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_missing_grant_token_is_config_error(self) -> None:
        with pytest.raises(ChioRayConfigError):

            class Bad(ChioActor):
                def __init__(self) -> None:
                    super().__init__()

            Bad()

    def test_conflicting_grant_forms_are_config_error(self) -> None:
        token = _local_token(_scope_for_tools("search"))
        grant = StandingGrant(token=token, tool_server="srv")

        class Bad(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, token=token)

        with pytest.raises(ChioRayConfigError):
            Bad()

    def test_scope_broader_than_token_is_config_error(self) -> None:
        token = _local_token(_scope_for_tools("search"))
        broader = _scope_for_tools("search", "write")

        class Bad(ChioActor):
            def __init__(self) -> None:
                super().__init__(token=token, scope=broader, tool_server="srv")

        with pytest.raises(ChioRayConfigError):
            Bad()

    def test_standing_grants_list_merges_scopes(self) -> None:
        search_token = _local_token(
            _scope_for_tools("search"), token_id="tok-a"
        )
        write_token = _local_token(
            _scope_for_tools("write"), token_id="tok-b"
        )
        grant_a = StandingGrant(token=search_token, tool_server="srv")
        grant_b = StandingGrant(token=write_token, tool_server="srv")

        class Merged(ChioActor):
            def __init__(self) -> None:
                super().__init__(
                    standing_grants=[grant_a, grant_b],
                    tool_server="srv",
                    chio_client=allow_all(),
                )

            @ChioActor.requires("tools:search")
            def search(self, q: str) -> str:
                return q

            @ChioActor.requires("tools:write")
            def write(self, path: str) -> str:
                return path

        actor = Merged()
        assert actor.search("hello") == "hello"
        assert actor.write("/out") == "/out"
        assert "delegated_capability_ids" in actor.chio_grant.metadata
        assert actor.chio_grant.metadata["delegated_capability_ids"] == ["tok-b"]


# ---------------------------------------------------------------------------
# (e) Attenuation of standing grants.
# ---------------------------------------------------------------------------


class TestAttenuation:
    async def test_attenuate_child_grant_is_subset_of_parent(self) -> None:
        chio = allow_all()
        parent_token = _local_token(
            _scope_for_tools("search", "browse"), token_id="tok-parent"
        )
        parent_grant = StandingGrant(token=parent_token, tool_server="srv")

        child_scope = _scope_for_tools("search")
        child_grant = await parent_grant.attenuate(chio, new_scope=child_scope)

        assert child_grant.scope.is_subset_of(parent_grant.scope)
        assert child_grant.metadata["parent_capability_id"] == parent_grant.capability_id
        assert child_grant.tool_server == "srv"

    async def test_attenuate_broader_scope_rejected(self) -> None:
        chio = allow_all()
        parent_token = _local_token(
            _scope_for_tools("search"), token_id="tok-parent"
        )
        parent_grant = StandingGrant(token=parent_token, tool_server="srv")
        broader = _scope_for_tools("search", "write")

        from chio_sdk.errors import ChioValidationError

        with pytest.raises(ChioValidationError):
            await parent_grant.attenuate(chio, new_scope=broader)
