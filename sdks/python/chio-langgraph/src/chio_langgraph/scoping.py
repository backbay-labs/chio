"""Graph-level scope management for Chio-governed LangGraph state graphs.

LangGraph supports nested *subgraphs*: a compiled state graph can be
added to an outer graph as a single node. Chio's capability model must
follow suit -- the subgraph's effective scope is bounded by the parent
graph's *ceiling*, and per-node scopes inside the subgraph must attenuate
the ceiling further (never widen it).

:class:`ChioGraphConfig` is the single object a user builds to describe:

* the :class:`chio_sdk.ChioClient` (or test double) used to mint tokens
  and evaluate node dispatches;
* the workflow-level scope ceiling (what the *graph* is allowed to do);
* the per-node scope assignments;
* the subject hex / TTL for capability minting.

:func:`enforce_subgraph_ceiling` is a helper used by :mod:`chio_langgraph.nodes`
to verify that a per-node scope is a strict subset of the current graph
ceiling before any dispatch happens. It is also safe to call ahead of
time from user code to validate a graph at compile time.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from chio_sdk.models import ChioScope, CapabilityToken

from chio_langgraph.errors import ChioLangGraphConfigError

logger = logging.getLogger(__name__)


# ``ChioClient`` (or the ``MockChioClient`` test double) both expose the
# same async surface used here. Keeping the annotation structural avoids
# importing the testing helper in production code.
ChioClientLike = Any


@dataclass
class ChioGraphConfig:
    """Graph-level Chio configuration.

    Parameters
    ----------
    chio_client:
        An :class:`chio_sdk.ChioClient` or test double used to mint
        capability tokens and evaluate node dispatches.
    workflow_scope:
        The :class:`ChioScope` that bounds *everything* the graph can do.
        Per-node scopes and subgraph ceilings must be subsets of this
        scope. If ``None`` (default) no ceiling is enforced at the
        workflow level -- callers may still attach per-node scopes via
        :meth:`register_node_scope`.
    node_scopes:
        Optional mapping from node name to the per-node :class:`ChioScope`.
        Each entry is validated against ``workflow_scope`` at
        registration time.
    subject:
        Hex-encoded Ed25519 subject key used when a capability token is
        minted for the graph. Defaults to a deterministic fallback subject so
        tests and local demos work without a real keyring.
    ttl_seconds:
        Lifetime of minted capability tokens.
    parent_ceiling:
        If this graph is compiled as a subgraph of another graph, the
        parent's ceiling is supplied here. Any node scope registered on
        this graph is verified against both ``workflow_scope`` and
        ``parent_ceiling``.
    sidecar_url:
        Base URL of the Chio sidecar. Passed through to the eventual
        :class:`chio_sdk.ChioClient`.
    """

    chio_client: ChioClientLike
    workflow_scope: ChioScope | None = None
    node_scopes: dict[str, ChioScope] = field(default_factory=dict)
    subject: str = "agent:langgraph"
    ttl_seconds: int = 3600
    parent_ceiling: ChioScope | None = None
    sidecar_url: str = "http://127.0.0.1:9090"

    # Minted tokens live here once ``provision`` is called. Keyed by
    # node name; ``__graph__`` holds the workflow-level token.
    _tokens: dict[str, CapabilityToken] = field(
        default_factory=dict, repr=False, compare=False
    )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        # Normalise the node_scopes mapping to a plain dict so later
        # mutations (register_node_scope) do not mutate caller state.
        self.node_scopes = dict(self.node_scopes)
        ceiling = self.effective_ceiling()
        for name, scope in list(self.node_scopes.items()):
            if ceiling is not None and not scope.is_subset_of(ceiling):
                raise ChioLangGraphConfigError(
                    f"node {name!r} scope is broader than the graph ceiling; "
                    "subgraph / per-node scopes must attenuate, not widen"
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def effective_ceiling(self) -> ChioScope | None:
        """Return the narrowest scope that bounds this graph.

        If a ``parent_ceiling`` is set (i.e. this graph is running as a
        subgraph), the effective ceiling is the parent ceiling. If no
        parent ceiling is set but a ``workflow_scope`` is, the latter
        is the ceiling. When both are unset the graph is unbounded --
        :func:`enforce_subgraph_ceiling` becomes a no-op.
        """
        if self.parent_ceiling is not None:
            # Prefer the tighter of parent_ceiling vs workflow_scope, if
            # both are set. The parent is the authoritative ceiling;
            # the workflow_scope cannot widen it.
            if self.workflow_scope is None:
                return self.parent_ceiling
            if self.workflow_scope.is_subset_of(self.parent_ceiling):
                return self.workflow_scope
            # workflow_scope claims to be broader than parent_ceiling --
            # a misconfiguration; return the stricter parent ceiling.
            return self.parent_ceiling
        return self.workflow_scope

    def register_node_scope(self, node_name: str, scope: ChioScope) -> None:
        """Attach a scope to ``node_name``, verifying the ceiling."""
        enforce_subgraph_ceiling(self, node_name, scope)
        self.node_scopes[node_name] = scope

    def scope_for(self, node_name: str) -> ChioScope | None:
        """Return the registered scope for ``node_name``, if any."""
        return self.node_scopes.get(node_name)

    def token_for(self, node_name: str) -> CapabilityToken | None:
        """Return the capability token minted for ``node_name``, if any."""
        return self._tokens.get(node_name)

    def workflow_token(self) -> CapabilityToken | None:
        """Return the workflow-level token, if minted."""
        return self._tokens.get("__graph__")

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------

    async def provision(self) -> dict[str, CapabilityToken]:
        """Mint a capability token per node (and for the workflow).

        Tokens are stored on the config so subsequent node dispatches
        can look them up by name. Returns the mapping for inspection.
        """
        tokens: dict[str, CapabilityToken] = {}

        if self.workflow_scope is not None:
            wf_token = await self.chio_client.create_capability(
                subject=self.subject,
                scope=self.workflow_scope,
                ttl_seconds=self.ttl_seconds,
            )
            tokens["__graph__"] = wf_token

        for name, scope in self.node_scopes.items():
            node_token = await self.chio_client.create_capability(
                subject=f"{self.subject}/node:{name}",
                scope=scope,
                ttl_seconds=self.ttl_seconds,
            )
            tokens[name] = node_token

        self._tokens.update(tokens)
        return tokens

    def subgraph_config(
        self,
        *,
        workflow_scope: ChioScope | None = None,
        node_scopes: Mapping[str, ChioScope] | None = None,
        subject: str | None = None,
    ) -> ChioGraphConfig:
        """Build a child :class:`ChioGraphConfig` for a subgraph.

        The child's ``parent_ceiling`` is set to this config's effective
        ceiling, so any node scope the subgraph tries to register must
        attenuate the parent.
        """
        return ChioGraphConfig(
            chio_client=self.chio_client,
            workflow_scope=workflow_scope,
            node_scopes=dict(node_scopes or {}),
            subject=subject or self.subject,
            ttl_seconds=self.ttl_seconds,
            parent_ceiling=self.effective_ceiling(),
            sidecar_url=self.sidecar_url,
        )


def enforce_subgraph_ceiling(
    config: ChioGraphConfig,
    node_name: str,
    scope: ChioScope,
) -> None:
    """Raise :class:`ChioLangGraphConfigError` if ``scope`` exceeds the ceiling.

    The ceiling is the ``effective_ceiling`` of ``config``. When the
    graph has no ceiling the call is a no-op. This is the single place
    where subgraph attenuation is enforced; both
    :meth:`ChioGraphConfig.register_node_scope` and the eager
    ``chio_node`` factory call through here.
    """
    ceiling = config.effective_ceiling()
    if ceiling is None:
        return
    if not scope.is_subset_of(ceiling):
        raise ChioLangGraphConfigError(
            f"node {node_name!r} scope exceeds the parent graph ceiling; "
            "subgraph nodes must attenuate the ceiling, not widen it"
        )


__all__ = [
    "ChioClientLike",
    "ChioGraphConfig",
    "enforce_subgraph_ceiling",
]
