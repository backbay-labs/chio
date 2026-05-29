"""Chio-governed base class for Ray actors.

:class:`ChioActor` holds a standing capability grant (lifetime of the
actor) and exposes :meth:`ChioActor.requires`, a method-level decorator
that gates each call on a sidecar verdict. Construct with one of
``standing_grant=``, ``standing_grants=`` (merged), or ``token=`` +
``scope=``. Denied calls raise ``PermissionError``; Ray propagates them
through ``ray.get`` as a ``RayTaskError``.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, TypeVar, cast

from chio_adapter_base.redact import RedactionPolicy, bind_and_redact
from chio_sdk.models import CapabilityToken, ChioScope, Operation, ToolGrant

from chio_ray.errors import ChioRayConfigError, ChioRayError
from chio_ray.grants import ChioClientLike, StandingGrant, scope_from_spec
from chio_ray.remote import (
    _evaluate_allow_or_raise,
    _permission_error,
)

F = TypeVar("F", bound=Callable[..., Any])


# Stamped on each wrapper for introspection / discovery.
_REQUIRES_ATTR = "_chio_required_scope"
_REQUIRES_SPEC_ATTR = "_chio_required_scope_spec"

# Module-level singleton so the per-call getattr fallback below does not
# allocate a fresh policy on every method invocation.
_DEFAULT_REDACTION_POLICY: RedactionPolicy = RedactionPolicy.chio_default()
_REQUIRES_TOOL_NAME_ATTR = "_chio_required_tool_name"


class ChioActor:
    """Base class Ray actors inherit from to acquire Chio-governed method dispatch.

    Pass one of ``standing_grant`` / ``standing_grants`` / ``token`` (+
    optional ``scope``). ``redaction_policy`` only governs receipt-log
    parameters; Ray's object store still holds the pickled originals.
    """

    def __init__(
        self,
        *,
        standing_grant: StandingGrant | None = None,
        standing_grants: Iterable[StandingGrant] | None = None,
        token: CapabilityToken | None = None,
        scope: ChioScope | None = None,
        tool_server: str = "",
        chio_client: ChioClientLike | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        grant = _resolve_standing_grant(
            standing_grant=standing_grant,
            standing_grants=standing_grants,
            token=token,
            scope=scope,
            tool_server=tool_server,
            actor_class=self._actor_class_name(),
        )
        self._chio_grant: StandingGrant = grant
        self._chio_client: ChioClientLike | None = chio_client
        self._chio_sidecar_url: str = sidecar_url
        self._chio_redaction_policy: RedactionPolicy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )
        self._chio_receipts: list[Any] = []

    @property
    def chio_grant(self) -> StandingGrant:
        return self._chio_grant

    @property
    def chio_scope(self) -> ChioScope:
        return self._chio_grant.scope

    @property
    def chio_capability_id(self) -> str:
        return self._chio_grant.capability_id

    @property
    def chio_receipts(self) -> list[Any]:
        return list(self._chio_receipts)

    def bind_chio_client(self, client: ChioClientLike) -> None:
        """Attach or replace the :class:`ChioClient` used for evaluation."""
        self._chio_client = client

    @staticmethod
    def requires(
        scope: str | ChioScope,
        *,
        tool_name: str | None = None,
        tool_server: str | None = None,
    ) -> Callable[[F], F]:
        """Gate an actor method on a Chio capability check.

        ``scope`` may be a short-string spec (``"tools:search"``) or a
        :class:`ChioScope`. ``tool_name`` defaults to the method name.
        """
        # Defer scope resolution so the short-string form can inherit
        # the actor's standing-grant tool_server at call time.
        scope_spec = scope if isinstance(scope, str) else None
        explicit_scope = scope if isinstance(scope, ChioScope) else None

        def decorator(method: F) -> F:
            is_coro = inspect.iscoroutinefunction(method)
            resolved_tool_name = tool_name or method.__name__

            if is_coro:

                @functools.wraps(method)
                async def async_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
                    await _enforce_actor_method(
                        actor=self,
                        method=method,
                        scope_spec=scope_spec,
                        explicit_scope=explicit_scope,
                        method_name=method.__name__,
                        tool_name_override=resolved_tool_name,
                        tool_server_override=tool_server,
                        args=args,
                        kwargs=kwargs,
                    )
                    return await cast(
                        Callable[..., Awaitable[Any]], method
                    )(self, *args, **kwargs)

                wrapper = async_wrapper
            else:

                @functools.wraps(method)
                def sync_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
                    asyncio.run(
                        _enforce_actor_method(
                            actor=self,
                            method=method,
                            scope_spec=scope_spec,
                            explicit_scope=explicit_scope,
                            method_name=method.__name__,
                            tool_name_override=resolved_tool_name,
                            tool_server_override=tool_server,
                            args=args,
                            kwargs=kwargs,
                        )
                    )
                    return method(self, *args, **kwargs)

                wrapper = sync_wrapper

            setattr(wrapper, _REQUIRES_ATTR, explicit_scope)
            setattr(wrapper, _REQUIRES_SPEC_ATTR, scope_spec)
            setattr(wrapper, _REQUIRES_TOOL_NAME_ATTR, resolved_tool_name)
            return cast(F, wrapper)

        return decorator

    def _actor_class_name(self) -> str:
        cls = type(self)
        module = cls.__module__
        name = cls.__qualname__
        return f"{module}.{name}" if module else name


async def _enforce_actor_method(
    *,
    actor: Any,
    method: Callable[..., Any],
    scope_spec: str | None,
    explicit_scope: ChioScope | None,
    method_name: str,
    tool_name_override: str,
    tool_server_override: str | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Standing-grant subset check then sidecar evaluation.

    Raises :class:`PermissionError` on deny (either subset failure or
    sidecar deny). Allow receipts are appended to
    ``actor._chio_receipts``.
    """
    grant: StandingGrant | None = getattr(actor, "_chio_grant", None)
    if grant is None:
        raise _permission_error(
            ChioRayError(
                "ChioActor.__init__ was never called; standing grant is missing",
                method_name=method_name,
                reason="uninitialized_actor",
            )
        )

    # Resolve here so the short-string form inherits the actor's tool_server.
    required_scope: ChioScope
    if explicit_scope is not None:
        required_scope = explicit_scope
    else:
        assert scope_spec is not None  # nosec
        default_server = (
            tool_server_override
            if tool_server_override is not None
            else grant.tool_server
        )
        required_scope = scope_from_spec(
            scope_spec, server_id=default_server or ""
        )

    # Short-circuit deny without a sidecar round-trip.
    if not grant.authorises(required_scope):
        err = ChioRayError(
            f"method {method_name!r} requires scope outside actor's standing grant",
            actor_class=grant.actor_class,
            method_name=method_name,
            capability_id=grant.capability_id,
            tool_server=grant.tool_server,
            guard="StandingGrantSubsetGuard",
            reason="scope_exceeds_standing_grant",
        )
        raise _permission_error(err)

    tool_server = (
        tool_server_override
        if tool_server_override is not None
        else grant.tool_server
    )

    chio_client: ChioClientLike | None = getattr(actor, "_chio_client", None)
    sidecar_url: str = getattr(actor, "_chio_sidecar_url", "http://127.0.0.1:9090")

    redaction_policy: RedactionPolicy = getattr(
        actor, "_chio_redaction_policy", _DEFAULT_REDACTION_POLICY
    )
    # TODO(v0.2): Ray pickles args into the object store BEFORE this hook
    # fires; the original (unredacted) values may persist in the cluster's
    # object store even though the sidecar payload below is redacted. Cross-
    # adapter object-store hardening (a chio-adapter-base concern) needs to
    # land before this leak path is closed end-to-end.
    bound_args, bound_kwargs = _redact_method_call(
        method=method,
        args=args,
        kwargs=kwargs,
        tool_name=tool_name_override,
        policy=redaction_policy,
    )

    receipt = await _evaluate_allow_or_raise(
        chio_client=chio_client,
        sidecar_url=sidecar_url,
        capability_id=grant.capability_id,
        tool_server=tool_server,
        tool_name=tool_name_override,
        parameters={"args": bound_args, "kwargs": bound_kwargs},
        actor_class=grant.actor_class,
        method_name=method_name,
    )
    actor._chio_receipts.append(receipt)


# Pre-bound to the receiver slot via functools.partial so
# bind_and_redact sees a signature aligned with the wrapper's
# receiver-less ``args`` (the wrapper has already stripped ``self``).
_RECEIVER_PLACEHOLDER: Any = object()


def _redact_method_call(
    *,
    method: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
) -> tuple[list[Any], dict[str, Any]]:
    """Bind positional args to parameter names and redact protected fields."""
    receiver_less = functools.partial(method, _RECEIVER_PLACEHOLDER)
    return bind_and_redact(
        receiver_less,
        args,
        kwargs,
        tool_name=tool_name,
        policy=policy,
    )


def _resolve_standing_grant(
    *,
    standing_grant: StandingGrant | None,
    standing_grants: Iterable[StandingGrant] | None,
    token: CapabilityToken | None,
    scope: ChioScope | None,
    tool_server: str,
    actor_class: str,
) -> StandingGrant:
    """Normalise the three mutually-exclusive construction paths into one grant."""
    supplied = [
        ("standing_grant", standing_grant is not None),
        ("standing_grants", standing_grants is not None),
        ("token", token is not None),
    ]
    truthy = [name for name, present in supplied if present]
    if not truthy:
        raise ChioRayConfigError(
            "ChioActor requires one of 'standing_grant', 'standing_grants', or "
            "'token' to be supplied"
        )
    if len(truthy) > 1:
        raise ChioRayConfigError(
            f"ChioActor: supply exactly one of standing_grant / standing_grants / token "
            f"(got {truthy})"
        )

    if standing_grant is not None:
        # Let supervisors retarget the tool_server without re-minting.
        if tool_server and not standing_grant.tool_server:
            return StandingGrant(
                token=standing_grant.token,
                tool_server=tool_server,
                actor_class=standing_grant.actor_class or actor_class,
                metadata=dict(standing_grant.metadata),
            )
        if standing_grant.actor_class is None:
            return StandingGrant(
                token=standing_grant.token,
                tool_server=standing_grant.tool_server,
                actor_class=actor_class,
                metadata=dict(standing_grant.metadata),
            )
        return standing_grant

    if standing_grants is not None:
        merged = _merge_standing_grants(
            standing_grants, tool_server=tool_server, actor_class=actor_class
        )
        return merged

    # token path
    if token is None:  # pragma: no cover -- guarded by the "no form" branch above
        raise ChioRayConfigError("unreachable: token path requires token")
    resolved_scope = scope if scope is not None else token.scope
    # An explicit scope must be a subset of the token's scope.
    if scope is not None and not resolved_scope.is_subset_of(token.scope):
        raise ChioRayConfigError(
            "ChioActor: explicit 'scope' must be a subset of the token's scope"
        )
    # No derived token here; cryptographic attenuation requires the
    # kernel via :meth:`StandingGrant.attenuate`.
    projected_token = (
        token.model_copy(update={"scope": resolved_scope})
        if scope is not None
        else token
    )
    return StandingGrant(
        token=projected_token,
        tool_server=tool_server,
        actor_class=actor_class,
    )


def _merge_standing_grants(
    grants: Iterable[StandingGrant],
    *,
    tool_server: str,
    actor_class: str,
) -> StandingGrant:
    """Union of input scopes; primary capability id wins; rest stored under metadata."""
    grant_list = list(grants)
    if not grant_list:
        raise ChioRayConfigError(
            "ChioActor: 'standing_grants' must be a non-empty iterable"
        )
    if len(grant_list) == 1:
        primary = grant_list[0]
        return StandingGrant(
            token=primary.token,
            tool_server=tool_server or primary.tool_server,
            actor_class=primary.actor_class or actor_class,
            metadata=dict(primary.metadata),
        )

    all_tool_grants: list[ToolGrant] = []
    for g in grant_list:
        all_tool_grants.extend(g.scope.grants)
    merged_scope = ChioScope(
        grants=_dedupe_tool_grants(all_tool_grants),
        resource_grants=[r for g in grant_list for r in g.scope.resource_grants],
        prompt_grants=[p for g in grant_list for p in g.scope.prompt_grants],
    )

    primary = grant_list[0]
    merged_metadata = dict(primary.metadata)
    merged_metadata["delegated_capability_ids"] = [
        g.capability_id for g in grant_list[1:]
    ]

    merged_token = primary.token.model_copy(update={"scope": merged_scope})
    return StandingGrant(
        token=merged_token,
        tool_server=tool_server or primary.tool_server,
        actor_class=actor_class,
        metadata=merged_metadata,
    )


def _dedupe_tool_grants(grants: list[ToolGrant]) -> list[ToolGrant]:
    seen: set[tuple[str, str, tuple[Operation, ...]]] = set()
    out: list[ToolGrant] = []
    for g in grants:
        key = (g.server_id, g.tool_name, tuple(sorted(g.operations, key=str)))
        if key in seen:
            continue
        seen.add(key)
        out.append(g)
    return out


__all__ = [
    "ChioActor",
]
