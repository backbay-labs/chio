"""Convenience builder for a Chio-governed Temporal worker.

:func:`build_chio_worker` wires the standard pieces together:

* An :class:`chio_temporal.ChioActivityInterceptor` mounted on the
  Temporal :class:`temporalio.worker.Worker`'s ``interceptors`` list.
* A :class:`chio_temporal.WorkflowGrant` minted from
  ``capability_id`` / ``workflow_id`` and pre-registered on the
  interceptor.

The function returns ``(worker, interceptor, grant)`` so callers retain
handles to the interceptor (for per-run :class:`WorkflowReceipt`
inspection) and the grant (for attenuation).

For tests and offline usage, the returned ``interceptor`` is the same
one installed on the worker, so you can rebind its Chio client to a
:class:`chio_sdk.testing.MockChioClient` after construction if needed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any

from chio_sdk.models import ChioScope, CapabilityToken
from temporalio.client import Client
from temporalio.worker import Worker

from chio_temporal.errors import ChioTemporalConfigError
from chio_temporal.grants import ChioClientLike, WorkflowGrant
from chio_temporal.interceptor import ChioActivityInterceptor


async def build_chio_worker(
    client: Client,
    *,
    task_queue: str,
    activities: Sequence[Callable[..., Any]],
    workflows: Sequence[type] | None = None,
    capability_id: str,
    workflow_id: str,
    chio_client: ChioClientLike,
    scope: ChioScope | None = None,
    subject: str | None = None,
    tool_server: str = "",
    default_tool_server: str = "",
    activity_tool_server_map: dict[str, str] | None = None,
    sidecar_url: str = "http://127.0.0.1:9090",
    ttl_seconds: int = 3600,
    interceptors: Iterable[Any] | None = None,
    receipt_sink: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    **worker_kwargs: Any,
) -> tuple[Worker, ChioActivityInterceptor, WorkflowGrant]:
    """Build a Temporal worker with the Chio interceptor + grant wired in.

    Parameters
    ----------
    client:
        A connected :class:`temporalio.client.Client`.
    task_queue:
        Temporal task queue the worker polls.
    activities:
        Activity callables to register.
    workflows:
        Workflow classes to register. Optional; activity-only workers
        are valid.
    capability_id:
        Pre-existing capability token id. When ``scope`` is also
        supplied, the builder mints a fresh capability via the supplied
        ``chio_client`` and uses its id instead; ``capability_id`` then
        acts as a label on the grant metadata for audit correlation.
    workflow_id:
        Temporal workflow identifier the grant is scoped to.
    chio_client:
        :class:`chio_sdk.ChioClient` (or mock) used to mint the capability
        token and evaluate activity calls. The interceptor reuses this
        client; callers own its lifecycle.
    scope:
        Optional :class:`ChioScope`. When provided, the builder mints a
        new capability token via ``chio_client.create_capability`` and
        uses that token. When ``None``, the caller must have already
        minted the token externally and is responsible for passing its
        id (the builder then constructs a synthetic stand-in token with
        an empty scope so the grant envelope still serialises).
    subject:
        Hex-encoded Ed25519 public key bound to the minted capability.
        Required when ``scope`` is provided; ignored otherwise.
    tool_server:
        Default Chio tool server id for activities that do not appear in
        ``activity_tool_server_map``. Can be overridden per-activity.
    default_tool_server:
        Fallback when neither the grant nor the map resolve a server.
        Takes effect only when ``tool_server`` is empty.
    activity_tool_server_map:
        Optional mapping from activity type to Chio tool server id. See
        :class:`ChioActivityInterceptor`.
    sidecar_url:
        Sidecar base URL. Only used when ``chio_client`` is ``None`` in
        the interceptor chain; the builder always passes ``chio_client``
        so this is a pass-through for completeness.
    ttl_seconds:
        Lifetime of the minted capability token when ``scope`` is set.
    interceptors:
        Extra :class:`temporalio.worker.Interceptor` instances to chain
        after the Chio interceptor.
    receipt_sink:
        Optional callable invoked with each finalised workflow receipt
        envelope. See :class:`ChioActivityInterceptor.receipt_sink`.
    worker_kwargs:
        Forwarded to :class:`temporalio.worker.Worker`.

    Returns
    -------
    (worker, interceptor, grant):
        ``worker`` is the configured :class:`temporalio.worker.Worker`;
        ``interceptor`` is the :class:`ChioActivityInterceptor` mounted
        on it; ``grant`` is the :class:`WorkflowGrant` registered for
        ``workflow_id``.
    """
    if not capability_id and scope is None:
        raise ChioTemporalConfigError(
            "build_chio_worker requires either capability_id or scope"
        )

    if scope is not None:
        if not subject:
            raise ChioTemporalConfigError(
                "subject is required when scope is provided"
            )
        token = await chio_client.create_capability(
            subject=subject, scope=scope, ttl_seconds=ttl_seconds
        )
    else:
        # No minting requested -- callers supplied a pre-existing
        # capability id. We construct a stand-in token carrying only
        # that id so the grant envelope serialises without guessing at
        # the token body. The interceptor only uses token.id at
        # evaluate time, so this is safe.
        token = _placeholder_token(capability_id)

    grant_metadata: dict[str, Any] = {"supplied_capability_id": capability_id}
    grant = WorkflowGrant(
        workflow_id=workflow_id,
        token=token,
        tool_server=tool_server,
        metadata=grant_metadata,
    )

    interceptor = ChioActivityInterceptor(
        chio_client=chio_client,
        sidecar_url=sidecar_url,
        default_tool_server=default_tool_server,
        activity_tool_server_map=activity_tool_server_map,
        receipt_sink=receipt_sink,
    )
    interceptor.register_workflow_grant(grant)

    all_interceptors: list[Any] = [interceptor]
    if interceptors:
        all_interceptors.extend(interceptors)

    worker = Worker(
        client,
        task_queue=task_queue,
        activities=list(activities),
        workflows=list(workflows or []),
        interceptors=all_interceptors,
        **worker_kwargs,
    )
    return worker, interceptor, grant


def _placeholder_token(capability_id: str) -> CapabilityToken:
    """Build a stand-in :class:`CapabilityToken` for a supplied id.

    The kernel already issued (and is persisting) the real token; we
    only need its id to address the sidecar on evaluate. The other
    fields are filled with non-sensitive placeholders and the
    ``scope`` is empty, so any attenuation attempt locally will
    correctly refuse to broaden scope.
    """
    return CapabilityToken(
        id=capability_id,
        issuer="chio-temporal-placeholder",
        subject="chio-temporal-placeholder",
        scope=ChioScope(),
        issued_at=0,
        expires_at=0,
        signature="chio-temporal-placeholder",
    )


__all__ = [
    "build_chio_worker",
]
