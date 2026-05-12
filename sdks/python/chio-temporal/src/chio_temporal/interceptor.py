"""Chio-governed Temporal Activity interceptor.

:class:`ChioActivityInterceptor` plugs into a Temporal
:class:`temporalio.worker.Worker`'s ``interceptors`` list. For every
activity execution it:

1. Looks up the :class:`chio_temporal.WorkflowGrant` registered for the
   running activity's workflow_id (inheriting from the parent workflow
   by default; explicit per-activity attenuated grants also supported).
2. Evaluates the activity through the Chio sidecar with the grant's
   capability_id.
3. On ``allow`` -- records a :class:`chio_temporal.WorkflowStepReceipt`
   on the workflow's :class:`chio_temporal.WorkflowReceipt` and delegates
   to the next interceptor.
4. On ``deny`` -- raises
   :class:`temporalio.exceptions.ApplicationError` with
   ``non_retryable=True`` so Temporal records the denial in workflow
   history and does not retry. The denial receipt is also recorded on
   the :class:`WorkflowReceipt`.

The interceptor is safe to use without an active sidecar for unit
tests: pass a :class:`chio_sdk.testing.MockChioClient` as ``chio_client``.

.. note::
   Human-in-the-loop approval support (pause Activity on a pending
   approval guard, resume via Temporal Signal) is planned for v2 once
   Phase 3.4 lands. This v1 only implements the synchronous allow/deny
   path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, Decision, ToolCallAction
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
)

from chio_temporal.errors import ChioTemporalConfigError, ChioTemporalError
from chio_temporal.grants import ChioClientLike, WorkflowGrant
from chio_temporal.receipt import WorkflowReceipt

logger = logging.getLogger(__name__)

#: Application error ``type`` used when an activity is denied. Matches
#: the string documented in ``docs/protocols/TEMPORAL-INTEGRATION.md``
#: so saga compensation can match on it.
DENIED_ERROR_TYPE = "ChioCapabilityDenied"

# Callable signature for a per-activity grant override hook. When an
# override is registered for an activity type, it takes precedence over
# the workflow-level grant. The hook receives the activity info and
# must return a ``WorkflowGrant`` (or ``None`` to fall back to the
# workflow grant).
ActivityGrantOverride = Callable[[activity.Info], "WorkflowGrant | None"]


@dataclass
class _WorkflowRunState:
    """Per-(workflow_id, run_id) state held by the interceptor.

    We keep a :class:`WorkflowReceipt` per run so concurrent workflows
    executing on the same worker do not stomp each other's step lists.
    """

    receipt: WorkflowReceipt
    grant: WorkflowGrant
    overrides: dict[str, WorkflowGrant] = field(default_factory=dict)


class ChioActivityInterceptor(Interceptor):
    """Worker-level :class:`Interceptor` that gates every Activity on Chio.

    Parameters
    ----------
    chio_client:
        :class:`chio_sdk.ChioClient` or compatible mock used to call the
        sidecar. When ``None``, the interceptor constructs a default
        client pointing at ``sidecar_url``; in that mode the client is
        owned by the interceptor and closed on :meth:`close`.
    sidecar_url:
        Base URL of the Chio sidecar. Only used when ``chio_client`` is
        ``None``. Defaults to ``http://127.0.0.1:9090``.
    default_tool_server:
        Fallback ``tool_server`` id when an activity has no grant-level
        override and no per-activity mapping. Activities map 1:1 to a
        tool server in most deployments.
    activity_tool_server_map:
        Optional mapping from activity type -> Chio tool server id.
        Overrides ``default_tool_server`` for matching activities.
    receipt_sink:
        Optional callable invoked with the finalised
        :class:`WorkflowReceipt` envelope (a dict from
        :meth:`WorkflowReceipt.to_envelope`). Fire-and-forget; exceptions
        are logged and swallowed so sink failures do not fail workflows.
    redaction_policy:
        Optional :class:`RedactionPolicy` applied to activity
        parameters before sidecar evaluation. Defaults to
        :meth:`RedactionPolicy.chio_default`. Runs in the activity
        layer so workflow determinism is unaffected.
    """

    def __init__(
        self,
        *,
        chio_client: ChioClientLike | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
        default_tool_server: str = "",
        activity_tool_server_map: dict[str, str] | None = None,
        receipt_sink: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self._chio_client = chio_client
        self._owns_client = chio_client is None
        self._sidecar_url = sidecar_url
        self._default_tool_server = default_tool_server
        self._activity_tool_server_map: dict[str, str] = dict(
            activity_tool_server_map or {}
        )
        self._receipt_sink = receipt_sink
        self._redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )
        self._runs: dict[tuple[str, str], _WorkflowRunState] = {}
        # Grants registered before the workflow runs. Keyed on
        # workflow_id; a per-run state is materialised lazily on first
        # activity execution.
        self._pending_grants: dict[str, WorkflowGrant] = {}
        # Global activity-type -> grant-override hook. See
        # :meth:`register_activity_grant_override`.
        self._override_hooks: dict[str, ActivityGrantOverride] = {}
        # HITL approval is intentionally outside the v1 synchronous
        # allow/deny path. A future version can resume activities from
        # an approval Signal once that payload shape is stable.

    # ------------------------------------------------------------------
    # Grant registration
    # ------------------------------------------------------------------

    def register_workflow_grant(self, grant: WorkflowGrant) -> None:
        """Register a :class:`WorkflowGrant` for ``grant.workflow_id``.

        Call this *before* starting the workflow (e.g. immediately after
        minting the capability via the Chio authority). Subsequent
        activity executions for that workflow resolve their capability
        through this grant.
        """
        if not isinstance(grant, WorkflowGrant):
            raise ChioTemporalConfigError(
                "register_workflow_grant expects a WorkflowGrant instance"
            )
        self._pending_grants[grant.workflow_id] = grant

    def register_activity_grant_override(
        self,
        activity_type: str,
        hook: ActivityGrantOverride,
    ) -> None:
        """Register a hook that returns an attenuated grant per activity.

        The hook is invoked with the :class:`activity.Info` for each
        execution of ``activity_type``. Returning ``None`` from the hook
        falls back to the workflow-level grant.
        """
        if not activity_type:
            raise ChioTemporalConfigError(
                "activity_type must be a non-empty string"
            )
        self._override_hooks[activity_type] = hook

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def workflow_receipt(
        self,
        workflow_id: str,
        run_id: str | None = None,
    ) -> WorkflowReceipt | None:
        """Return the in-flight :class:`WorkflowReceipt` for a run.

        ``None`` is returned when no activity has executed for the
        (workflow_id, run_id) pair yet.
        """
        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        return state.receipt if state else None

    def finalize_workflow(
        self,
        *,
        workflow_id: str,
        run_id: str | None = None,
        outcome: str = "success",
        completed_at: int | None = None,
    ) -> WorkflowReceipt | None:
        """Finalise the workflow receipt for ``workflow_id`` / ``run_id``.

        Call this from the workflow entry point in a ``try/finally``
        block once the workflow completes. Returns the finalised
        :class:`WorkflowReceipt` (or ``None`` when no activities ran).
        """
        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        if state is None:
            return None
        state.receipt.finalize(
            outcome=outcome,
            completed_at=completed_at if completed_at is not None else int(time.time()),
        )
        return state.receipt

    async def flush_workflow_receipt(
        self,
        *,
        workflow_id: str,
        run_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Drain the finalised receipt to the configured sink.

        Returns the envelope dict that was forwarded (or ``None`` when
        nothing was registered). Errors from the sink are logged and
        swallowed.
        """
        key = self._run_key(workflow_id, run_id)
        state = self._runs.pop(key, None)
        if state is None:
            return None
        envelope = state.receipt.to_envelope()
        if self._receipt_sink is not None:
            try:
                result = self._receipt_sink(envelope)
                if isinstance(result, Awaitable):
                    await result
            except Exception:  # noqa: BLE001 -- sink must not fail the workflow
                logger.exception(
                    "chio-temporal receipt sink raised; envelope dropped"
                )
        return envelope

    # ------------------------------------------------------------------
    # Temporal Interceptor contract
    # ------------------------------------------------------------------

    def intercept_activity(
        self,
        next: ActivityInboundInterceptor,
    ) -> ActivityInboundInterceptor:
        """Return an :class:`ActivityInboundInterceptor` bound to this worker."""
        return _ChioInboundInterceptor(next, self)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying :class:`ChioClient` if we own it."""
        if self._owns_client and self._chio_client is not None:
            await self._chio_client.close()
            self._chio_client = None

    # ------------------------------------------------------------------
    # Internal helpers (visible to the inbound interceptor)
    # ------------------------------------------------------------------

    def _arc(self) -> ChioClientLike:
        """Return (creating if needed) the Chio client to use."""
        if self._chio_client is None:
            self._chio_client = ChioClient(self._sidecar_url)
        return self._chio_client

    def _tool_server_for(self, info: activity.Info, grant: WorkflowGrant) -> str:
        """Resolve the Chio tool server id for ``info``.

        Precedence: explicit map entry > grant's ``tool_server`` >
        interceptor default.
        """
        explicit = self._activity_tool_server_map.get(info.activity_type)
        if explicit:
            return explicit
        if grant.tool_server:
            return grant.tool_server
        return self._default_tool_server

    def _resolve_grant(self, info: activity.Info) -> WorkflowGrant:
        """Resolve the :class:`WorkflowGrant` for an activity execution.

        Materialises per-run state on first access so subsequent
        activities on the same run share a :class:`WorkflowReceipt`.
        """
        workflow_id = info.workflow_id
        run_id = info.workflow_run_id
        if not workflow_id:
            raise ChioTemporalConfigError(
                f"activity {info.activity_type!r} (id={info.activity_id!r}) has no "
                "workflow_id; chio-temporal requires activities to run under a workflow"
            )

        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        if state is None:
            pending = self._pending_grants.get(workflow_id)
            if pending is None:
                raise ChioTemporalConfigError(
                    f"no WorkflowGrant registered for workflow_id={workflow_id!r}; "
                    "call ChioActivityInterceptor.register_workflow_grant(...) before "
                    "starting the workflow"
                )
            # ``pending.matches`` enforces run_id pinning when set.
            if not pending.matches(workflow_id=workflow_id, run_id=run_id):
                raise ChioTemporalConfigError(
                    f"WorkflowGrant for {workflow_id!r} is pinned to a different run_id "
                    f"({pending.run_id!r}); got {run_id!r}"
                )
            state = _WorkflowRunState(
                receipt=WorkflowReceipt(
                    workflow_id=workflow_id,
                    run_id=run_id,
                    parent_workflow_ids=list(
                        pending.metadata.get("parent_workflow_ids", [])
                    ),
                    started_at=int(time.time()),
                    metadata=dict(pending.metadata),
                ),
                grant=pending,
            )
            self._runs[key] = state

        # Per-activity override hook takes precedence.
        override_hook = self._override_hooks.get(info.activity_type)
        if override_hook is not None:
            override = override_hook(info)
            if override is not None:
                if not override.scope.is_subset_of(state.grant.scope):
                    raise ChioTemporalConfigError(
                        f"activity-level grant for {info.activity_type!r} is not a "
                        "subset of the workflow grant scope"
                    )
                state.overrides[info.activity_id] = override
                return override

        return state.grant

    def _record_step(
        self,
        info: activity.Info,
        receipt: ChioReceipt,
    ) -> None:
        """Append ``receipt`` to the workflow receipt for ``info``."""
        key = self._run_key(info.workflow_id, info.workflow_run_id)
        state = self._runs.get(key)
        if state is None:
            # Should be unreachable -- _resolve_grant created the state
            # before execution -- but we defensively no-op rather than
            # raising from a receipt-recording path.
            logger.warning(
                "chio-temporal: no run state for workflow_id=%s run_id=%s",
                info.workflow_id,
                info.workflow_run_id,
            )
            return
        state.receipt.record_step(
            activity_type=info.activity_type,
            activity_id=info.activity_id,
            attempt=info.attempt,
            receipt=receipt,
        )

    @staticmethod
    def _run_key(
        workflow_id: str | None, run_id: str | None
    ) -> tuple[str, str]:
        """Canonicalise the (workflow_id, run_id) dict key."""
        return (workflow_id or "", run_id or "")


class _ChioInboundInterceptor(ActivityInboundInterceptor):
    """Per-activity inbound interceptor wired by :class:`ChioActivityInterceptor`."""

    def __init__(
        self,
        next: ActivityInboundInterceptor,
        parent: ChioActivityInterceptor,
    ) -> None:
        super().__init__(next)
        self._parent = parent

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        """Evaluate via Chio, then delegate to the wrapped interceptor."""
        info = activity.info()
        grant = self._parent._resolve_grant(info)
        tool_server = self._parent._tool_server_for(info, grant)

        parameters = _activity_parameters(
            input,
            tool_name=info.activity_type,
            policy=self._parent._redaction_policy,
        )

        receipt = await self._evaluate(
            info=info,
            grant=grant,
            tool_server=tool_server,
            parameters=parameters,
        )
        self._parent._record_step(info, receipt)

        if receipt.is_denied:
            raise _denied_application_error(info, receipt)

        return await self.next.execute_activity(input)

    async def _evaluate(
        self,
        *,
        info: activity.Info,
        grant: WorkflowGrant,
        tool_server: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        """Call the Chio sidecar to evaluate this activity invocation.

        :class:`ChioDeniedError` (HTTP 403) is translated into a deny
        :class:`ChioReceipt` so the caller's flow stays uniform: ``deny``
        receipts flow through :meth:`_record_step` before being raised
        as :class:`ApplicationError`.
        """
        if not grant.capability_id:
            raise _denied_application_error_from_config(
                info,
                reason="missing_capability",
                message=(
                    f"WorkflowGrant for {info.workflow_id!r} has an empty capability_id"
                ),
            )

        client = self._parent._arc()
        try:
            return await client.evaluate_tool_call(
                capability_id=grant.capability_id,
                tool_server=tool_server,
                tool_name=info.activity_type,
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            return _deny_receipt_from_error(
                info=info,
                capability_id=grant.capability_id,
                tool_server=tool_server,
                parameters=parameters,
                exc=exc,
            )
        except ChioError as exc:
            # Sidecar/transport failure -- let Temporal retry per its
            # retry policy. Callers can still inspect the underlying
            # ChioError via __cause__.
            raise ApplicationError(
                f"Chio sidecar error: {exc}",
                type="ChioSidecarError",
                non_retryable=False,
            ) from exc


def _activity_parameters(
    input: ExecuteActivityInput,
    *,
    tool_name: str | None = None,
    policy: RedactionPolicy | None = None,
) -> dict[str, Any]:
    """Extract a parameter dict to send to the Chio sidecar.

    Wraps positional args under a stable ``args`` key so the parameter
    hash stays deterministic. When ``policy`` is supplied and the
    activity is invoked with a single dict-shaped argument (the common
    Temporal ``run(payload)`` convention), redaction is applied to that
    dict; non-dict positional args are forwarded unchanged.
    """
    args_list = list(input.args)
    if policy is not None and len(args_list) == 1 and isinstance(args_list[0], dict):
        args_list[0] = redact_args(tool_name, args_list[0], policy=policy)
    return {"args": args_list}


def _denied_application_error(
    info: activity.Info, receipt: ChioReceipt
) -> ApplicationError:
    """Build the non-retryable :class:`ApplicationError` for a deny receipt."""
    reason = receipt.decision.reason or "denied by Chio kernel"
    guard = receipt.decision.guard or "unknown"
    tool_error = ChioTemporalError(
        reason,
        activity_type=info.activity_type,
        activity_id=info.activity_id,
        workflow_id=info.workflow_id,
        run_id=info.workflow_run_id,
        guard=guard,
        reason=reason,
        receipt_id=receipt.id,
        decision=receipt.decision.model_dump(exclude_none=True),
    )
    return ApplicationError(
        f"Chio capability denied: {reason}",
        tool_error.to_dict(),
        type=DENIED_ERROR_TYPE,
        non_retryable=True,
    )


def _deny_receipt_from_error(
    *,
    info: activity.Info,
    capability_id: str,
    tool_server: str,
    parameters: dict[str, Any],
    exc: ChioDeniedError,
) -> ChioReceipt:
    """Materialize a deny receipt for sidecar 403 responses."""
    canonical_parameters = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    parameter_hash = hashlib.sha256(canonical_parameters).hexdigest()
    receipt_id = exc.receipt_id or (
        f"chio-temporal-deny-{info.workflow_id}-{info.activity_id}-{int(time.time())}"
    )
    return ChioReceipt(
        id=receipt_id,
        timestamp=int(time.time()),
        capability_id=capability_id,
        tool_server=exc.tool_server or tool_server,
        tool_name=exc.tool_name or info.activity_type,
        action=ToolCallAction(
            parameters=dict(parameters),
            parameter_hash=parameter_hash,
        ),
        decision=Decision.deny(
            reason=exc.reason or exc.message or "Chio capability denied",
            guard=exc.guard or "ChioDeniedError",
        ),
        content_hash="synthetic-deny-receipt",
        policy_hash="synthetic-deny-receipt",
        evidence=[],
        metadata={
            "synthetic": True,
            "reason_code": exc.reason_code,
            "requested_action": exc.requested_action,
            "required_scope": exc.required_scope,
            "granted_scope": exc.granted_scope,
            "hint": exc.hint,
            "docs_url": exc.docs_url,
        },
        kernel_key="0" * 64,
        signature="0" * 128,
    )


def _denied_application_error_from_config(
    info: activity.Info, *, reason: str, message: str
) -> ApplicationError:
    """Build a config-error :class:`ApplicationError` (non-retryable)."""
    tool_error = ChioTemporalError(
        message,
        activity_type=info.activity_type,
        activity_id=info.activity_id,
        workflow_id=info.workflow_id,
        run_id=info.workflow_run_id,
        reason=reason,
    )
    return ApplicationError(
        message,
        tool_error.to_dict(),
        type=DENIED_ERROR_TYPE,
        non_retryable=True,
    )

__all__ = [
    "DENIED_ERROR_TYPE",
    "ActivityGrantOverride",
    "ChioActivityInterceptor",
]
