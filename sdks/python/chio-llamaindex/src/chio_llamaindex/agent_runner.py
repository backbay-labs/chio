"""Capability-scoped LlamaIndex :class:`AgentRunner`.

LlamaIndex's :class:`AgentRunner` dispatches tool calls through an
``AgentWorker`` that holds a list of :class:`BaseTool` instances. This
module provides :class:`ChioAgentRunner`, a thin wrapper that mints a
capability token for the agent as a whole and binds it to every
Chio-governed tool on the runner. Every tool dispatch the runner then
performs flows through the Chio sidecar under the agent's capability.

The wrapper is intentionally *composition* rather than *subclassing*:
LlamaIndex's :class:`AgentRunner` class is :class:`~pydantic.BaseModel`-
adjacent and its constructor takes a worker + state, neither of which
we want to shadow. Instead, :class:`ChioAgentRunner` accepts an already-
constructed :class:`AgentRunner` (or any object that exposes ``.chat`` /
``.achat`` methods and holds tools on an ``agent_worker``) and rewrites
its Chio-governed tools in place.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from chio_sdk.models import ChioScope, CapabilityToken

from chio_llamaindex.errors import ChioLlamaIndexConfigError
from chio_llamaindex.function_tool import ChioClientLike, ChioFunctionTool
from chio_llamaindex.query_engine_tool import ChioQueryEngineTool

logger = logging.getLogger(__name__)


# Structural alias for the object we wrap: in practice this is always
# :class:`llama_index.core.agent.runner.base.AgentRunner`, but we stay
# duck-typed so tests can inject lightweight fakes.
AgentRunnerLike = Any


class ChioAgentRunner:
    """Attach a Chio capability to every tool on a LlamaIndex agent runner.

    Parameters
    ----------
    runner:
        The underlying :class:`AgentRunner` (or compatible object).
    capability_scope:
        :class:`ChioScope` describing what the agent is allowed to do.
    chio_client:
        :class:`chio_sdk.ChioClient` (or mock) used to mint capability
        tokens and evaluate tool calls. Reused across every tool.
    subject:
        Hex-encoded Ed25519 public key to bind the capability to. If
        omitted, a deterministic ``agent:<name>`` placeholder is used.
    agent_name:
        Human-readable identifier used when synthesising ``subject``
        and for logging.
    ttl_seconds:
        Lifetime of the minted capability token.

    Typical use
    -----------

    .. code-block:: python

        runner = AgentRunner.from_llm(llm=my_llm, tools=[search, write])
        chio_runner = ChioAgentRunner(
            runner=runner,
            capability_scope=ChioScope(grants=[...]),
            chio_client=chio,
            agent_name="analyst",
        )
        await chio_runner.provision_capability()
        response = runner.chat("summarise Q4 filings")
    """

    def __init__(
        self,
        *,
        runner: AgentRunnerLike,
        capability_scope: ChioScope,
        chio_client: ChioClientLike,
        subject: str | None = None,
        agent_name: str = "agent",
        ttl_seconds: int = 3600,
    ) -> None:
        if runner is None:
            raise ChioLlamaIndexConfigError("runner must not be None")
        if capability_scope is None:
            raise ChioLlamaIndexConfigError(
                "capability_scope must be provided"
            )

        self._runner = runner
        self._capability_scope = capability_scope
        self._chio_client = chio_client
        self._agent_name = agent_name
        self._subject = subject or _default_subject(agent_name)
        self._ttl_seconds = int(ttl_seconds)
        self._token: CapabilityToken | None = None

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def runner(self) -> AgentRunnerLike:
        """The wrapped :class:`AgentRunner`."""
        return self._runner

    @property
    def chio_client(self) -> ChioClientLike:
        """The :class:`ChioClient` bound to this agent."""
        return self._chio_client

    @property
    def capability_scope(self) -> ChioScope:
        """The :class:`ChioScope` granted to the agent."""
        return self._capability_scope

    @property
    def subject(self) -> str:
        """Hex-encoded subject key bound to the agent's capability."""
        return self._subject

    @property
    def agent_name(self) -> str:
        """Human-readable agent identifier."""
        return self._agent_name

    @property
    def token(self) -> CapabilityToken | None:
        """Minted :class:`CapabilityToken`, if :meth:`provision_capability` ran."""
        return self._token

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------

    async def provision_capability(
        self,
        *,
        extra_tools: Iterable[Any] | None = None,
    ) -> CapabilityToken:
        """Mint a capability token and bind it to every Chio-governed tool.

        Parameters
        ----------
        extra_tools:
            Optional extra tools to bind in addition to those discovered
            on the runner (e.g. tools about to be passed to
            ``runner.chat``). Non-Chio tools in this iterable are ignored.

        Returns
        -------
        CapabilityToken
            The freshly-minted token. Also stored on ``self.token``.
        """
        token = await self._chio_client.create_capability(
            subject=self._subject,
            scope=self._capability_scope,
            ttl_seconds=self._ttl_seconds,
        )
        self._token = token
        self._bind_tools_from_runner(token)
        if extra_tools is not None:
            self._bind_tools(extra_tools, token)
        return token

    def bind_tools(self, tools: Iterable[Any]) -> None:
        """Bind additional tools to the currently-minted capability.

        Raises :class:`ChioLlamaIndexConfigError` if
        :meth:`provision_capability` has not been called yet.
        """
        if self._token is None:
            raise ChioLlamaIndexConfigError(
                "no capability token minted; call provision_capability() first"
            )
        self._bind_tools(tools, self._token)

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    async def attenuate(
        self,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        """Derive a narrower child token from this agent's capability.

        The child is strictly ``child ⊆ parent``. Raises
        :class:`chio_sdk.errors.ChioValidationError` via the SDK when the
        new scope is broader than the parent.
        """
        if self._token is None:
            raise ChioLlamaIndexConfigError(
                "no parent capability; call provision_capability() first"
            )
        return await self._chio_client.attenuate_capability(
            self._token, new_scope=new_scope
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _bind_tools_from_runner(self, token: CapabilityToken) -> None:
        """Walk the runner for Chio tools and bind the token to each."""
        tools = _discover_tools(self._runner)
        self._bind_tools(tools, token)

    def _bind_tools(
        self,
        tools: Iterable[Any],
        token: CapabilityToken,
    ) -> None:
        """Bind ``token`` to every Chio-governed tool in ``tools``."""
        for tool in tools:
            if isinstance(tool, ChioFunctionTool):
                tool.bind_capability(token.id)
                tool.bind_chio_client(self._chio_client)
                tool.scope = self._capability_scope
            elif isinstance(tool, ChioQueryEngineTool):
                tool.bind_capability(token.id, scope=self._capability_scope)
                tool.bind_chio_client(self._chio_client)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_tools(runner: AgentRunnerLike) -> list[Any]:
    """Best-effort discovery of tools registered on an :class:`AgentRunner`.

    LlamaIndex has shipped several agent architectures across 0.11 --
    0.14 (classic ``AgentRunner`` with an ``agent_worker``, newer
    ``FunctionAgent`` workflows, and the 0.14 ``AgentWorkflow``). Each
    stores tools in a different attribute, so we probe the common
    locations and return the first non-empty list we find.
    """
    for attr_path in (
        ("agent_worker", "_tools"),
        ("agent_worker", "tools"),
        ("_tools",),
        ("tools",),
    ):
        target: Any = runner
        ok = True
        for part in attr_path:
            target = getattr(target, part, None)
            if target is None:
                ok = False
                break
        if ok and isinstance(target, (list, tuple)):
            return list(target)
        if ok and isinstance(target, Mapping):
            return list(target.values())
    return []


def _default_subject(agent_name: str) -> str:
    """Produce a deterministic subject placeholder for an agent.

    A real deployment supplies its own ``subject``; this fallback keeps
    the runner usable in tests and local demos.
    """
    safe = "".join(c if c.isalnum() else "_" for c in agent_name.lower())
    return f"agent:{safe}"


__all__ = [
    "AgentRunnerLike",
    "ChioAgentRunner",
]
