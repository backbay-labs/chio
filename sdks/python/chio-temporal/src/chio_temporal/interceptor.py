"""Chio-governed Temporal Activity interceptor.

:class:`ChioActivityInterceptor` plugs into a Temporal
:class:`temporalio.worker.Worker`'s ``interceptors`` list. Each
activity is evaluated via the Chio sidecar; allow records a
:class:`WorkflowStepReceipt` and delegates to the next interceptor;
deny raises non-retryable
:class:`temporalio.exceptions.ApplicationError` so Temporal records the
denial in workflow history. HITL approval support is planned for v2.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
    build_alias_map,
    redact_args,
)
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

#: ``ApplicationError.type`` for denied activities. Saga compensation
#: matches on this string -- see ``docs/protocols/TEMPORAL-INTEGRATION.md``.
DENIED_ERROR_TYPE = "ChioCapabilityDenied"

# Per-activity grant-override hook; ``None`` falls back to the workflow grant.
ActivityGrantOverride = Callable[[activity.Info], "WorkflowGrant | None"]


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass
class _WorkflowRunState:
    """Per-(workflow_id, run_id) state; isolates concurrent runs on one worker."""

    receipt: WorkflowReceipt
    grant: WorkflowGrant
    overrides: dict[str, WorkflowGrant] = field(default_factory=dict)


class ChioActivityInterceptor(Interceptor):
    """Worker-level :class:`Interceptor` that gates every Activity on Chio.

    Redaction runs in the activity layer so workflow determinism is
    unaffected. Receipt-sink failures are logged and swallowed.
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
        # Pre-registered grants keyed on workflow_id; per-run state is
        # materialised lazily on first activity execution.
        self._pending_grants: dict[str, WorkflowGrant] = {}
        self._override_hooks: dict[str, ActivityGrantOverride] = {}

    def register_workflow_grant(self, grant: WorkflowGrant) -> None:
        """Register a :class:`WorkflowGrant` for ``grant.workflow_id``.

        Must be called before the workflow starts so subsequent activity
        executions can resolve their capability.
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
        """Register a per-activity grant-override hook (``None`` -> workflow grant)."""
        if not activity_type:
            raise ChioTemporalConfigError(
                "activity_type must be a non-empty string"
            )
        self._override_hooks[activity_type] = hook

    def workflow_receipt(
        self,
        workflow_id: str,
        run_id: str | None = None,
    ) -> WorkflowReceipt | None:
        """Return the in-flight :class:`WorkflowReceipt` (``None`` if nothing yet)."""
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
        """Finalise the workflow receipt; call from a ``try/finally`` at workflow exit."""
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
        """Drain the finalised receipt to the sink; sink errors are swallowed."""
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

    def intercept_activity(
        self,
        next: ActivityInboundInterceptor,
    ) -> ActivityInboundInterceptor:
        return _ChioInboundInterceptor(next, self)

    async def close(self) -> None:
        """Close the underlying :class:`ChioClient` if we own it."""
        if self._owns_client and self._chio_client is not None:
            await self._chio_client.close()
            self._chio_client = None

    def _arc(self) -> ChioClientLike:
        if self._chio_client is None:
            self._chio_client = ChioClient(self._sidecar_url)
        return self._chio_client

    def _tool_server_for(self, info: activity.Info, grant: WorkflowGrant) -> str:
        """Resolve tool server: explicit map > grant.tool_server > interceptor default."""
        explicit = self._activity_tool_server_map.get(info.activity_type)
        if explicit:
            return explicit
        if grant.tool_server:
            return grant.tool_server
        return self._default_tool_server

    def _resolve_grant(self, info: activity.Info) -> WorkflowGrant:
        """Resolve the :class:`WorkflowGrant`; lazily materialise per-run state."""
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
        key = self._run_key(info.workflow_id, info.workflow_run_id)
        state = self._runs.get(key)
        if state is None:
            # Defensive no-op; _resolve_grant should have created state.
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
        """Evaluate via the sidecar; HTTP-403 becomes a synthetic deny receipt."""
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
            # Transport failure: retryable; let Temporal apply its policy.
            raise ApplicationError(
                f"Chio sidecar error: {exc}",
                type="ChioSidecarError",
                non_retryable=False,
            ) from exc


def _fixed_positional_param_names(fn: Callable[..., Any] | None) -> tuple[str, ...]:
    """Return fixed positional parameter names from ``fn``, if introspectable."""
    if fn is None:
        return ()
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return ()
    return tuple(
        param.name
        for param in sig.parameters.values()
        if param.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    )


def _temporal_dict_lift(
    fn: Callable[..., Any] | None,
    *,
    tool_name: str,
    redacted_args: Sequence[Any],
    table_slots: tuple[str, ...],
    policy: RedactionPolicy,
) -> list[Any] | None:
    """Lift redacted positional values into Temporal's dict wire shape."""
    sig_names = _fixed_positional_param_names(fn)
    if sig_names:
        alias_map = build_alias_map(
            sig_names,
            table_slots,
            policy.body_fields.get(tool_name) or (),
            allow_ambiguous_cycling=tool_name in DEFAULT_TOOL_POSITIONAL_NAMES,
        )
        canonical_dict: dict[str, Any] = {}
        for idx, sig_name in enumerate(sig_names):
            if idx >= len(redacted_args):
                break
            canonical_name = alias_map.get(sig_name, sig_name)
            canonical_dict[canonical_name] = redacted_args[idx]
        extras = list(redacted_args[len(sig_names) :])
        return [canonical_dict, *extras]

    if len(redacted_args) >= len(table_slots):
        prefix_count = len(table_slots)
        bound = dict(zip(table_slots, redacted_args[:prefix_count], strict=True))
        extras = list(redacted_args[prefix_count:])
        return [bound, *extras]
    return None


def _activity_parameters(
    input: ExecuteActivityInput,
    *,
    tool_name: str | None = None,
    policy: RedactionPolicy | None = None,
) -> dict[str, Any]:
    """Build the sidecar payload, redacting body fields where possible.

    Positional activities delegate to
    :func:`chio_adapter_base.redact.bind_and_redact` using the activity
    callable supplied by the Temporal worker, then lift the redacted result
    into Temporal's dict wire shape.
    """
    args_list = list(input.args)
    if policy is None:
        return {"args": args_list}

    # Shape 1: single dict.
    if len(args_list) == 1 and isinstance(args_list[0], dict):
        args_list[0] = redact_args(tool_name, args_list[0], policy=policy)
        return {"args": args_list}

    effective_tool_name = tool_name or ""
    redacted_args, redacted_kwargs = bind_and_redact(
        input.fn,
        args_list,
        {},
        tool_name=effective_tool_name,
        policy=policy,
    )
    if redacted_kwargs:
        return {"args": list(redacted_args), "kwargs": redacted_kwargs}

    table_slots = DEFAULT_TOOL_POSITIONAL_NAMES.get(effective_tool_name)
    if (
        table_slots is not None
        and effective_tool_name in policy.body_fields
        and redacted_args
    ):
        lifted = _temporal_dict_lift(
            input.fn,
            tool_name=effective_tool_name,
            redacted_args=redacted_args,
            table_slots=table_slots,
            policy=policy,
        )
        if lifted is not None:
            return {"args": lifted}

    return {"args": list(redacted_args)}


def _denied_application_error(
    info: activity.Info, receipt: ChioReceipt
) -> ApplicationError:
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
    """Synthesise a deny :class:`ChioReceipt` for HTTP-403 sidecar responses."""
    canonical_parameters = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    parameter_hash = hashlib.sha256(canonical_parameters).hexdigest()
    fallback_receipt_id = (
        f"chio-temporal-deny-{info.workflow_id}-{info.activity_id}-{int(time.time())}"
    )
    receipt_id_source = exc.receipt_id or fallback_receipt_id
    if exc.receipt_id and _is_sha256_hex(exc.receipt_id):
        receipt_id = exc.receipt_id
    else:
        receipt_id = hashlib.sha256(receipt_id_source.encode("utf-8")).hexdigest()
    synthetic_hash = hashlib.sha256(
        f"synthetic-deny-receipt:{receipt_id_source}".encode()
    ).hexdigest()
    metadata = {
        "synthetic": True,
        "reason_code": exc.reason_code,
        "requested_action": exc.requested_action,
        "required_scope": exc.required_scope,
        "granted_scope": exc.granted_scope,
        "hint": exc.hint,
        "docs_url": exc.docs_url,
    }
    if exc.receipt_id:
        metadata["sidecar_receipt_id"] = exc.receipt_id
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
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        observation_outcome=None,
        tool_origin="caller_executed",
        redaction_mode="none",
        actor_chain=[],
        content_hash=synthetic_hash,
        policy_hash=synthetic_hash,
        evidence=[],
        trust_level="mediated",
        metadata=metadata,
        kernel_key="0" * 64,
        signature="0" * 128,
    )


def _denied_application_error_from_config(
    info: activity.Info, *, reason: str, message: str
) -> ApplicationError:
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
