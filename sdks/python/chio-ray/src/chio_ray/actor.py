"""Chio-governed base class for Ray actors.

:class:`ChioActor` holds a *standing* capability grant (minted at actor
construction, valid for the actor's lifetime) and exposes
:meth:`ChioActor.requires` -- a method-level decorator that validates a
per-call scope against the grant before the method body runs.

Typical usage -- the roadmap acceptance shape::

    import ray
    from chio_ray import ChioActor

    @ray.remote
    class ResearchAgent(ChioActor):
        @ChioActor.requires("tools:search")
        def search(self, query: str) -> list[dict]:
            return _do_search(query)

        @ChioActor.requires("tools:write")
        def write(self, path: str, body: str) -> None:
            _do_write(path, body)

The actor is constructed with either:

* ``standing_grant=`` -- a pre-minted :class:`StandingGrant` (preferred
  in production, since the driver owns token minting).
* ``standing_grants=`` -- a list of grants that are merged into one
  (used when a supervisor delegates multiple attenuated grants to a
  child actor).
* ``token=`` + ``scope=`` -- ergonomic shortcut for the single-grant
  case.

Denied method calls raise :class:`PermissionError` (with the
:class:`ChioRayError` on ``__cause__``), which Ray propagates through
``ray.get`` as a ``RayTaskError`` whose underlying exception is a
``PermissionError`` -- the shape the roadmap acceptance test asserts.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, TypeVar, cast

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.models import CapabilityToken, ChioScope, Operation, ToolGrant

from chio_ray.errors import ChioRayConfigError, ChioRayError
from chio_ray.grants import ChioClientLike, StandingGrant, scope_from_spec
from chio_ray.remote import _evaluate_allow_or_raise, _permission_error

F = TypeVar("F", bound=Callable[..., Any])


# Sentinel attribute the method decorator stamps on the wrapper so the
# metaclass / introspection helpers can discover decorated methods
# without re-running the decorator logic.
_REQUIRES_ATTR = "_chio_required_scope"
_REQUIRES_SPEC_ATTR = "_chio_required_scope_spec"
_REQUIRES_TOOL_NAME_ATTR = "_chio_required_tool_name"


class ChioActor:
    """Base class Ray actors inherit from to acquire Chio-governed method dispatch.

    Subclasses decorate methods with :meth:`ChioActor.requires` to gate
    them on an Chio capability check. The base class handles the
    standing-grant bookkeeping so subclass ``__init__`` bodies remain
    focussed on their own state.

    Parameters
    ----------
    standing_grant:
        A single :class:`StandingGrant` pinned to the actor.
    standing_grants:
        A list of grants to merge. When multiple grants are supplied,
        the resulting scope is the union of all grants (the standing
        scope is the ceiling for every ``requires`` check). Mutually
        exclusive with ``standing_grant``.
    token:
        A pre-minted :class:`CapabilityToken` -- ergonomic shortcut
        for the single-grant case. Ignored when ``standing_grant`` /
        ``standing_grants`` is supplied.
    scope:
        Optional :class:`ChioScope` the standing grant authorises. Only
        used with ``token``; when ``None`` the token's own scope is
        used.
    tool_server:
        Default Chio tool server id for per-method evaluation when a
        method-level override is not supplied.
    chio_client:
        Optional :class:`chio_sdk.ChioClient` (or
        :class:`chio_sdk.testing.MockChioClient`) used for every method's
        sidecar evaluation. When ``None`` each method call mints a
        fresh client against :attr:`sidecar_url`.
    sidecar_url:
        Base URL of the node-local Chio sidecar. Defaults to
        ``http://127.0.0.1:9090``.
    redaction_policy:
        Optional :class:`chio_adapter_base.redact.RedactionPolicy` used
        to scrub secret-bearing arg fields (e.g. the ``content`` of
        ``chio_file_write``) from the kwargs forwarded to the sidecar.
        Defaults to :meth:`RedactionPolicy.chio_default` when omitted.
        Note that Ray pickles actor method arguments before they reach
        the wrapper; the original (unredacted) values may still live
        in the Ray object store. This policy only governs what the
        Chio sidecar records on the receipt.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

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
        # Tracks every successful evaluation so subclasses / tests can
        # inspect the receipt trail for the actor's lifetime.
        self._chio_receipts: list[Any] = []

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def chio_grant(self) -> StandingGrant:
        """Return the standing grant bound to this actor."""
        return self._chio_grant

    @property
    def chio_scope(self) -> ChioScope:
        """Shortcut for :attr:`self.chio_grant.scope`."""
        return self._chio_grant.scope

    @property
    def chio_capability_id(self) -> str:
        """The token id of the standing grant."""
        return self._chio_grant.capability_id

    @property
    def chio_receipts(self) -> list[Any]:
        """All receipts produced by :meth:`requires`-gated method calls."""
        return list(self._chio_receipts)

    def bind_chio_client(self, client: ChioClientLike) -> None:
        """Attach or replace the :class:`chio_sdk.ChioClient` used for evaluation.

        Useful when the actor constructs its own client lazily (for
        example, in a Ray actor's ``__init__`` after dependencies are
        wired up).
        """
        self._chio_client = client

    # ------------------------------------------------------------------
    # Method decorator
    # ------------------------------------------------------------------

    @staticmethod
    def requires(
        scope: str | ChioScope,
        *,
        tool_name: str | None = None,
        tool_server: str | None = None,
    ) -> Callable[[F], F]:
        """Gate an actor method on an Chio capability check.

        The returned decorator wraps the method so that every invocation
        first:

        1. Verifies the required ``scope`` is a subset of the actor's
           standing grant (short-circuit deny when the actor was never
           granted the scope in the first place).
        2. Evaluates the call through the Chio sidecar using the
           standing grant's capability id and the decorator's
           ``scope`` / ``tool_name`` metadata.
        3. On allow -- records the receipt and invokes the method body.
        4. On deny -- raises :class:`PermissionError` (so Ray's
           ``ray.get`` rethrows it from ``RayTaskError``).

        Parameters
        ----------
        scope:
            Either a short-string spec (``"tools:search"``) or a fully
            formed :class:`ChioScope`. The short-string form is the
            ergonomic shape the roadmap acceptance test exercises.
        tool_name:
            Chio tool name the sidecar evaluates on. Defaults to the
            method name (which in the common case matches the short
            spec's tool component, e.g. ``"search"`` for
            ``"tools:search"``).
        tool_server:
            Optional per-method Chio tool server override. Defaults to
            the actor's standing-grant ``tool_server``.
        """
        # Scope resolution is deferred to call time so the required
        # scope can inherit the actor's standing-grant ``tool_server``
        # when the short-string form (``"tools:search"``) omits a
        # server prefix. Storing the raw spec keeps
        # ``@ChioActor.requires("tools:search")`` portable across
        # actors that happen to be pinned to different server ids.
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

            # Stamp introspection metadata so tooling can discover
            # decorated methods without re-running the decorator logic.
            setattr(wrapper, _REQUIRES_ATTR, explicit_scope)
            setattr(wrapper, _REQUIRES_SPEC_ATTR, scope_spec)
            setattr(wrapper, _REQUIRES_TOOL_NAME_ATTR, resolved_tool_name)
            return cast(F, wrapper)

        return decorator

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _actor_class_name(self) -> str:
        """Return the fully-qualified class name (``module.Class``)."""
        cls = type(self)
        module = cls.__module__
        name = cls.__qualname__
        return f"{module}.{name}" if module else name


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------


async def _enforce_actor_method(
    *,
    actor: Any,
    scope_spec: str | None,
    explicit_scope: ChioScope | None,
    method_name: str,
    tool_name_override: str,
    tool_server_override: str | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Run the standing-grant subset check and sidecar evaluation.

    Raises :class:`PermissionError` on deny (either because the
    required scope is not a subset of the standing grant or because the
    sidecar returned a deny verdict). Allow receipts are appended to
    ``actor._chio_receipts`` so subclasses / tests can inspect the trail.
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

    # Resolve the required scope now that we know the actor's
    # standing-grant ``tool_server``. For the short-string form, the
    # required scope inherits the server from the grant (or the
    # per-method override) so the subset check against a server-scoped
    # standing grant behaves naturally.
    required_scope: ChioScope
    if explicit_scope is not None:
        required_scope = explicit_scope
    else:
        # scope_spec must be non-None here -- requires() rejects anything
        # that is neither a string nor an ChioScope.
        assert scope_spec is not None  # nosec -- asserted invariant
        default_server = (
            tool_server_override
            if tool_server_override is not None
            else grant.tool_server
        )
        required_scope = scope_from_spec(
            scope_spec, server_id=default_server or ""
        )

    # Short-circuit deny: if the standing scope does not even authorise
    # the required scope, there is no point calling the sidecar.
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

    # Redact secret-bearing fields (e.g. chio_file_write.content) from
    # the kwargs before they cross into the sidecar so the receipt log
    # never carries the raw bytes. Positional args are forwarded as-is;
    # callers that pass secrets positionally bypass redaction by
    # definition - adapters that care about positional secrets should
    # surface them as named kwargs so the policy can match.
    redaction_policy: RedactionPolicy = getattr(
        actor, "_chio_redaction_policy", RedactionPolicy.chio_default()
    )
    redacted_kwargs = redact_args(
        tool_name_override, dict(kwargs), policy=redaction_policy
    )

    receipt = await _evaluate_allow_or_raise(
        chio_client=chio_client,
        sidecar_url=sidecar_url,
        capability_id=grant.capability_id,
        tool_server=tool_server,
        tool_name=tool_name_override,
        parameters={"args": list(args), "kwargs": redacted_kwargs},
        actor_class=grant.actor_class,
        method_name=method_name,
    )
    actor._chio_receipts.append(receipt)


# ---------------------------------------------------------------------------
# Grant resolution
# ---------------------------------------------------------------------------


def _resolve_standing_grant(
    *,
    standing_grant: StandingGrant | None,
    standing_grants: Iterable[StandingGrant] | None,
    token: CapabilityToken | None,
    scope: ChioScope | None,
    tool_server: str,
    actor_class: str,
) -> StandingGrant:
    """Normalise the mutually-exclusive construction paths into one grant.

    Precedence: ``standing_grant`` > ``standing_grants`` > ``token``.
    Exactly one of the three forms must be supplied.
    """
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
        # Honour the caller's tool_server override even when the grant
        # already declared one; this lets supervisors retarget a worker
        # grant to a different server without minting a new token.
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
    # When the caller supplies an explicit scope, it must be a subset
    # of the token's scope -- otherwise the "grant" would authorise
    # more than the underlying token actually allows.
    if scope is not None and not resolved_scope.is_subset_of(token.scope):
        raise ChioRayConfigError(
            "ChioActor: explicit 'scope' must be a subset of the token's scope"
        )
    # We do not mint a derived token here; the StandingGrant simply
    # records the narrower scope for subset checks and carries the
    # original token id for the sidecar call. A cryptographic
    # attenuation requires the kernel in the loop via
    # StandingGrant.attenuate.
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
    """Merge a list of grants into a single standing grant.

    The merged scope is the union of all input scopes. The merged
    capability id is the first grant's id (the remaining grants'
    metadata is retained in ``metadata["delegated_capability_ids"]``
    for audit).
    """
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

    # Union the tool grants across all supplied standing grants. We
    # keep resource and prompt grants from each as well so a merged
    # actor can mix tool + resource authorisations.
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
    """Remove duplicate (server_id, tool_name, operations) grants."""
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
