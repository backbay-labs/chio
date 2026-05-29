"""Standing-grant helpers for Chio-governed Ray actors.

A :class:`StandingGrant` pins a pre-minted :class:`CapabilityToken` to a
Ray actor for the actor's lifetime. Methods gated by
:meth:`ChioActor.requires` evaluate the per-call scope against the
standing grant; attenuated child grants can be minted at runtime (for
example, when an ``ChioActor`` spawns worker actors with narrower scope)
via :meth:`StandingGrant.attenuate`.

Ray actors are long-lived processes. Unlike per-request workflows (see
:mod:`chio_temporal.grants`), the standing grant's TTL should be sized to
match the actor's expected lifetime and refreshed from within the actor
when the owning process is still healthy.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from chio_sdk.errors import ChioValidationError
from chio_sdk.models import ChioScope, CapabilityToken, Operation, ToolGrant

from chio_ray.errors import ChioRayConfigError

# Anything that quacks like an :class:`chio_sdk.ChioClient` -- the real
# client and :class:`chio_sdk.testing.MockChioClient` are accepted
# interchangeably so tests can inject an in-memory policy.
ChioClientLike = Any


@dataclass(frozen=True)
class StandingGrant:
    """Capability grant pinned to a Ray actor's lifetime.

    Parameters
    ----------
    token:
        :class:`CapabilityToken` minted by the Chio capability authority.
        Its :attr:`CapabilityToken.scope` is the ceiling for every
        method call on the owning actor.
    tool_server:
        Default Chio tool server id for this actor. Method-level
        :meth:`ChioActor.requires` scopes fall back to this server unless
        they specify their own.
    actor_class:
        Fully-qualified actor class name (``module.Class``). Populated
        automatically when the grant is minted inside
        :meth:`ChioActor.__init__`; surfaced on :class:`ChioRayError`
        deny payloads for audit correlation.
    metadata:
        Optional free-form metadata attached to the grant. Surfaced on
        deny payloads so downstream receipt consumers can correlate
        actor-level context (placement group, worker node, parent
        actor handle, ...).
    """

    token: CapabilityToken
    tool_server: str = ""
    actor_class: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def capability_id(self) -> str:
        """Convenience accessor for the underlying capability token id."""
        return self.token.id

    @property
    def scope(self) -> ChioScope:
        """The :class:`ChioScope` this grant authorises."""
        return self.token.scope

    # ------------------------------------------------------------------
    # Subset checks
    # ------------------------------------------------------------------

    def authorises(self, required: ChioScope) -> bool:
        """Return ``True`` when ``required`` is a subset of this grant's scope.

        This is the fast-path guard executed before a method body runs;
        the sidecar's receipt-producing evaluation is still the source
        of truth on the allow/deny path, but this check lets the actor
        short-circuit obvious deny cases without a network round-trip
        when no client is bound (e.g. during startup ordering).
        """
        return required.is_subset_of(self.scope)

    # ------------------------------------------------------------------
    # Attenuation
    # ------------------------------------------------------------------

    async def attenuate(
        self,
        chio_client: ChioClientLike,
        *,
        new_scope: ChioScope,
        tool_server: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StandingGrant:
        """Mint a child grant whose scope is strictly narrower than this grant's.

        Intended for the supervisor-worker pattern where a parent
        :class:`ChioActor` spawns worker actors with attenuated
        capabilities. Raises
        :class:`chio_sdk.errors.ChioValidationError` when ``new_scope``
        is not a subset of the parent scope.
        """
        if not new_scope.is_subset_of(self.scope):
            raise ChioValidationError(
                "new_scope must be a subset of the parent StandingGrant scope"
            )
        child_token = await chio_client.attenuate_capability(
            self.token, new_scope=new_scope
        )
        merged_metadata = dict(self.metadata)
        if metadata:
            merged_metadata.update(metadata)
        merged_metadata.setdefault("parent_capability_id", self.capability_id)
        return StandingGrant(
            token=child_token,
            tool_server=tool_server if tool_server is not None else self.tool_server,
            actor_class=self.actor_class,
            metadata=merged_metadata,
        )


# ---------------------------------------------------------------------------
# Scope parsing helpers
# ---------------------------------------------------------------------------


def scope_from_spec(spec: str | ChioScope, *, server_id: str = "") -> ChioScope:
    """Coerce a method-decorator ``scope`` argument into an :class:`ChioScope`.

    Accepts either:

    * A fully-formed :class:`ChioScope` -- returned as-is.
    * A short-string spec in the shape ``"<prefix>:<tool>"`` (e.g.
      ``"tools:search"``). The prefix is ignored for scope-matching
      purposes but recorded in metadata so denied receipts carry the
      human-friendly string. Multiple scopes may be comma-separated
      (``"tools:search,tools:browse"``).

    The string form is the ergonomic path
    (``@ChioActor.requires("tools:search")``); the :class:`ChioScope`
    form is for callers who already know the full :class:`ToolGrant`
    shape.
    """
    if isinstance(spec, ChioScope):
        return spec
    if not isinstance(spec, str):
        raise ChioRayConfigError(
            f"scope must be a string or ChioScope, got {type(spec).__name__!r}"
        )
    cleaned = spec.strip()
    if not cleaned:
        raise ChioRayConfigError("scope spec must not be empty")

    tool_names = list(_parse_scope_string(cleaned))
    grants = [
        ToolGrant(
            server_id=server_id or "*",
            tool_name=tool_name,
            operations=[Operation.INVOKE],
        )
        for tool_name in tool_names
    ]
    return ChioScope(grants=grants)


def _parse_scope_string(spec: str) -> Iterable[str]:
    """Yield tool names from a comma-separated ``prefix:tool`` scope string."""
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # Accept either ``tools:search`` or bare ``search``.
        if ":" in entry:
            _prefix, _, tool_name = entry.partition(":")
            tool_name = tool_name.strip()
        else:
            tool_name = entry
        if not tool_name:
            raise ChioRayConfigError(
                f"scope entry {entry!r} is missing the tool-name component "
                "(expected '<prefix>:<tool>' or '<tool>')"
            )
        yield tool_name


__all__ = [
    "ChioClientLike",
    "StandingGrant",
    "scope_from_spec",
]
