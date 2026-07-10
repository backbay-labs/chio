"""Workflow-scoped capability grants for Chio-governed Temporal workflows.

A :class:`WorkflowGrant` pins a capability token (minted via
:meth:`chio_sdk.ChioClient.create_capability`) to a Temporal
``workflow_id``. Activities executing under that workflow inherit the
grant by default; callers may also attenuate the grant to a strictly
narrower scope for a specific activity invocation before handing it to
the interceptor.

Two shapes are supported:

1. *Workflow default* -- the ``WorkflowGrant`` is registered with the
   :class:`chio_temporal.ChioActivityInterceptor` under its ``workflow_id``.
   Every activity on that workflow uses the grant's capability_id to
   evaluate through the Chio sidecar.
2. *Activity attenuation* -- callers invoke
   :meth:`WorkflowGrant.attenuate_for_activity` with a narrower
   :class:`ChioScope`; the resulting child :class:`WorkflowGrant` is
   strictly narrower (``child.scope ⊆ parent.scope``) and bound to the
   same workflow_id.

This module is deliberately sync-only on the data class surface; the
async attenuation helper returns the child grant without mutating the
parent, so callers can compose grants freely across tasks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from chio_sdk.errors import ChioValidationError
from chio_sdk.models import ChioScope, CapabilityToken

from chio_temporal.errors import ChioTemporalConfigError

# Anything that looks like an ``ChioClient`` -- we accept the real client
# and the ``MockChioClient`` from ``chio_sdk.testing`` interchangeably. A
# structural type alias keeps the annotation readable without importing
# the testing helpers in production code.
ChioClientLike = Any


@dataclass(frozen=True)
class WorkflowGrant:
    """Capability grant pinned to a Temporal ``workflow_id``.

    Parameters
    ----------
    workflow_id:
        Temporal workflow identifier this grant authorises. The
        interceptor looks up grants by this key when evaluating an
        activity execution.
    token:
        The underlying :class:`CapabilityToken` minted by the Chio
        capability authority. Its :attr:`CapabilityToken.scope` is the
        ceiling for every activity in the workflow.
    tool_server:
        Default Chio tool server id to use when an activity does not
        explicitly declare one. Activities normally map 1:1 to a tool
        server; this default keeps interceptor wiring minimal.
    run_id:
        Optional Temporal ``run_id`` this grant is bound to. When
        ``None``, the grant applies across every run of
        ``workflow_id``. When set, the interceptor only matches on an
        exact (``workflow_id``, ``run_id``) pair.
    metadata:
        Optional free-form metadata (e.g. parent workflow ids) attached
        to the grant. Surfaced on the :class:`chio_temporal.WorkflowReceipt`
        envelope for audit correlation.
    """

    workflow_id: str
    token: CapabilityToken
    tool_server: str = ""
    run_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.workflow_id:
            raise ChioTemporalConfigError(
                "WorkflowGrant.workflow_id must be a non-empty string"
            )

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

    def matches(
        self,
        *,
        workflow_id: str | None,
        run_id: str | None,
    ) -> bool:
        """Return ``True`` when this grant applies to ``workflow_id`` / ``run_id``.

        The match is exact on ``workflow_id``. ``run_id`` is compared
        only when this grant pinned one at construction time; a grant
        without a ``run_id`` matches every run of its workflow.
        """
        if workflow_id is None or workflow_id != self.workflow_id:
            return False
        if self.run_id is not None:
            return run_id == self.run_id
        return True

    # ------------------------------------------------------------------
    # Attenuation
    # ------------------------------------------------------------------

    async def attenuate_for_activity(
        self,
        chio_client: ChioClientLike,
        *,
        new_scope: ChioScope,
        run_id: str | None = None,
        tool_server: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> WorkflowGrant:
        """Mint a child grant whose scope is narrower than this grant's.

        Raises :class:`chio_sdk.errors.ChioValidationError` if ``new_scope``
        is not a strict subset of the parent's scope.
        """
        if not new_scope.is_subset_of(self.scope):
            raise ChioValidationError(
                "new_scope must be a subset of the parent WorkflowGrant scope"
            )
        child_token = await chio_client.attenuate_capability(
            self.token, new_scope=new_scope
        )
        merged_metadata = dict(self.metadata)
        if metadata:
            merged_metadata.update(metadata)
        # Preserve the parent capability id for audit correlation.
        merged_metadata.setdefault("parent_capability_id", self.capability_id)
        return WorkflowGrant(
            workflow_id=self.workflow_id,
            token=child_token,
            tool_server=tool_server if tool_server is not None else self.tool_server,
            run_id=run_id if run_id is not None else self.run_id,
            metadata=merged_metadata,
        )


__all__ = [
    "WorkflowGrant",
    "ChioClientLike",
]
