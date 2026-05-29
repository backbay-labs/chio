"""Capability-scoped AutoGen GroupChat.

:class:`ChioGroupChat` and :class:`ChioGroupChatManager` are drop-in
subclasses of :class:`autogen.GroupChat` / :class:`autogen.GroupChatManager`
that accept a per-role capability scope mapping. Every participant in
the chat receives a capability token scoped to that role, so:

* A ``researcher`` role whose scope grants ``search`` tools cannot
  invoke a ``write`` tool, even if the LLM hallucinates the call.
* Handoff between agents produces attenuated child capabilities
  (``child ⊆ parent``) via
  :meth:`chio_sdk.ChioClient.attenuate_capability`.

The actual enforcement happens in :class:`chio_autogen.ChioFunctionRegistry`,
which is installed on each agent ahead of time. This class is
responsible for minting the tokens and rebinding the registries when a
role changes.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from chio_sdk.errors import ChioValidationError
from chio_sdk.models import ChioScope, CapabilityToken
from autogen import GroupChat, GroupChatManager

from chio_autogen.errors import ChioAutogenConfigError
from chio_autogen.functions import (
    ChioClientLike,
    ChioFunctionRegistry,
    registry_for,
)

logger = logging.getLogger(__name__)


class ChioGroupChat(GroupChat):
    """A :class:`autogen.GroupChat` augmented with per-role scoping.

    Parameters
    ----------
    capability_scope:
        Mapping from agent ``name`` (or custom role label) to the
        :class:`ChioScope` that role is allowed to exercise. The
        :class:`ChioGroupChatManager` uses this map to mint and rebind
        capability tokens.
    role_key:
        Attribute on each agent to treat as the role. Defaults to
        ``"name"`` which matches the standard :class:`ConversableAgent`
        identity; set to ``"role"`` to match CrewAI-style labels.
    **groupchat_kwargs:
        Forwarded to :class:`autogen.GroupChat`.
    """

    def __init__(
        self,
        *,
        capability_scope: Mapping[str, ChioScope],
        role_key: str = "name",
        **groupchat_kwargs: Any,
    ) -> None:
        if not capability_scope:
            raise ChioAutogenConfigError(
                "capability_scope must contain at least one role"
            )
        super().__init__(**groupchat_kwargs)
        self._chio_capability_scope: dict[str, ChioScope] = dict(capability_scope)
        self._chio_role_key: str = role_key

    @property
    def capability_scope(self) -> dict[str, ChioScope]:
        """Role -> scope mapping in effect for this chat."""
        return dict(self._chio_capability_scope)

    @property
    def role_key(self) -> str:
        """Attribute name used to derive an agent's role."""
        return self._chio_role_key

    def role_of(self, agent: Any) -> str | None:
        """Return the role label for ``agent``.

        Falls back to the agent's ``name`` when the configured role key
        is absent; that keeps this helper stable on the heterogeneous
        agent types AutoGen accepts.
        """
        role = getattr(agent, self._chio_role_key, None)
        if role is None and self._chio_role_key != "name":
            role = getattr(agent, "name", None)
        return role

    def scope_for(self, role: str) -> ChioScope:
        """Return the :class:`ChioScope` granted to ``role``.

        Raises :class:`ChioAutogenConfigError` if no scope is configured.
        """
        if role not in self._chio_capability_scope:
            raise ChioAutogenConfigError(
                f"no capability scope configured for role {role!r}"
            )
        return self._chio_capability_scope[role]


class ChioGroupChatManager(GroupChatManager):
    """A :class:`autogen.GroupChatManager` that enforces role-scoped dispatch.

    Parameters
    ----------
    groupchat:
        The :class:`ChioGroupChat` (or compatible) to manage.
    chio_client:
        :class:`chio_sdk.ChioClient` (or test double) used to mint and
        attenuate capability tokens for participants.
    subject_map:
        Optional mapping from role to the hex-encoded Ed25519 public
        key to bind each capability to. Defaults to a deterministic
        ``agent:<role>`` placeholder.
    ttl_seconds:
        Lifetime of each minted capability token (default 1 hour).
    **manager_kwargs:
        Forwarded to :class:`autogen.GroupChatManager`.
    """

    def __init__(
        self,
        *,
        groupchat: ChioGroupChat,
        chio_client: ChioClientLike,
        subject_map: Mapping[str, str] | None = None,
        ttl_seconds: int = 3600,
        **manager_kwargs: Any,
    ) -> None:
        if not isinstance(groupchat, ChioGroupChat):
            raise ChioAutogenConfigError(
                "groupchat must be a ChioGroupChat instance"
            )
        super().__init__(groupchat=groupchat, **manager_kwargs)
        self._chio_client: ChioClientLike = chio_client
        self._chio_subject_map: dict[str, str] = dict(subject_map or {})
        self._chio_ttl_seconds: int = int(ttl_seconds)
        self._chio_role_tokens: dict[str, CapabilityToken] = {}
        self._chio_groupchat: ChioGroupChat = groupchat

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def chio_client(self) -> ChioClientLike:
        """The :class:`ChioClient` (or mock) bound to this manager."""
        return self._chio_client

    @property
    def chio_groupchat(self) -> ChioGroupChat:
        """The :class:`ChioGroupChat` managed here."""
        return self._chio_groupchat

    def token_for(self, role: str) -> CapabilityToken | None:
        """Return the :class:`CapabilityToken` minted for ``role``, if any."""
        return self._chio_role_tokens.get(role)

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------

    async def provision_capabilities(self) -> dict[str, CapabilityToken]:
        """Mint a capability token per role and bind agent registries.

        Returns the mapping from role to :class:`CapabilityToken`.
        Registries attached to each agent via
        :func:`chio_autogen.functions.attach_registry` are updated in
        place so that subsequent invocations go through the Chio sidecar
        with the correct token.
        """
        tokens: dict[str, CapabilityToken] = {}
        for role, scope in self._chio_groupchat.capability_scope.items():
            subject = self._chio_subject_map.get(role, _default_subject(role))
            token = await self._chio_client.create_capability(
                subject=subject,
                scope=scope,
                ttl_seconds=self._chio_ttl_seconds,
            )
            tokens[role] = token

        self._chio_role_tokens = tokens
        self._bind_registries(tokens)
        return tokens

    async def attenuate_for_handoff(
        self,
        *,
        delegator_role: str,
        delegate_role: str,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        """Produce a child token for an agent-to-agent handoff.

        The child is strictly narrower than the delegator's token.
        Raises :class:`ChioAutogenConfigError` if ``delegator_role`` has
        no active token, and :class:`chio_sdk.errors.ChioValidationError`
        if ``new_scope`` is not a subset of the delegator's scope.
        """
        parent = self.token_for(delegator_role)
        if parent is None:
            raise ChioAutogenConfigError(
                f"delegator role {delegator_role!r} has no minted capability; "
                "call provision_capabilities() first"
            )
        try:
            child = await self._chio_client.attenuate_capability(
                parent, new_scope=new_scope
            )
        except ChioValidationError:
            raise

        self._chio_role_tokens[delegate_role] = child
        self._bind_registries({delegate_role: child})
        return child

    # ------------------------------------------------------------------
    # Scope-aware invocation helper
    # ------------------------------------------------------------------

    def ensure_function_in_scope(self, role: str, function_name: str) -> None:
        """Assert ``function_name`` is within the scope granted to ``role``.

        Even if the LLM hallucinates a call into a cross-role function
        map, this local check refuses the dispatch before the Chio
        sidecar is reached.

        Raises :class:`chio_autogen.ChioAutogenConfigError` when the role
        is not configured at all, and
        :class:`chio_autogen.ChioToolError` when the function is outside
        the role's scope.
        """
        from chio_autogen.errors import ChioToolError

        scope = self._chio_groupchat.scope_for(role)
        allowed = {g.tool_name for g in scope.grants}
        if function_name in allowed or "*" in allowed:
            return
        raise ChioToolError(
            f"function {function_name!r} not in scope for role {role!r}",
            tool_name=function_name,
            reason="not_in_role_scope",
            guard="ChioGroupChatManager",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _bind_registries(
        self, tokens: Mapping[str, CapabilityToken]
    ) -> None:
        """Rewrite each agent's registry with the fresh token."""
        for agent in self._chio_groupchat.agents or []:
            role = self._chio_groupchat.role_of(agent)
            if role is None or role not in tokens:
                continue
            token = tokens[role]
            reg = registry_for(agent)
            if reg is None:
                continue
            reg.bind_capability(token)
            reg.bind_chio_client(self._chio_client)


def _default_subject(role: str) -> str:
    """Produce a deterministic subject placeholder for a role.

    A real deployment supplies its own ``subject_map``; this fallback
    keeps the chat runnable in tests and local demos.
    """
    safe = "".join(c if c.isalnum() else "_" for c in role.lower())
    return f"agent:{safe}"


__all__ = [
    "ChioGroupChat",
    "ChioGroupChatManager",
]

# Re-export used implicitly above so the symbol is available at module
# import time for static checkers.
_ = ChioFunctionRegistry
