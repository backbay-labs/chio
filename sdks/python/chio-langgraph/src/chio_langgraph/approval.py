"""The :func:`chio_approval_node` wrapper.

Bridges LangGraph's :func:`langgraph.types.interrupt` mechanism to Chio's
``Verdict::PendingApproval`` path.

Flow
----

1. The wrapped node is invoked. Before running the user body we evaluate
   the node dispatch through the Chio sidecar just like :func:`chio_node`.
2. If the verdict is ``allow`` we proceed directly to the wrapped body.
3. If the verdict is ``pending_approval`` (the sidecar opened an
   approval request behind the scenes), we build a payload describing
   the pending approval and hand it to :func:`langgraph.types.interrupt`.
   LangGraph will pause the graph at this node; the caller resumes it
   later via ``Command(resume=<decision>)``.
4. When the graph resumes, ``interrupt`` returns the resume value. The
   wrapper treats it as an
   :class:`ApprovalResolution` (either a dict with ``outcome`` or an
   :class:`ApprovalResolution` instance). An ``approved`` outcome
   triggers the wrapped body; a ``denied``/``rejected`` outcome raises
   :class:`ChioLangGraphError` so the graph's error handling can react.
5. If the verdict is ``deny`` we raise :class:`ChioLangGraphError`
   immediately.

The wrapper also accepts an ``approval_policy`` callable which lets the
node *locally* decide whether an approval is required even in the
absence of a sidecar PendingApproval signal. This matches the spec: the
node itself owns the decision to request approval; the sidecar owns the
capability/guard evaluation.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_langgraph.errors import ChioLangGraphConfigError, ChioLangGraphError
from chio_langgraph.nodes import _state_to_parameters
from chio_langgraph.scoping import ChioGraphConfig, enforce_subgraph_ceiling

logger = logging.getLogger(__name__)


# ``langgraph.types.interrupt`` is imported lazily so that the SDK can be
# used from tests that mock out the interrupt surface. When the function
# is patched we want the patched version to be used.
_InterruptFn = Callable[[Any], Any]


@dataclass
class ApprovalRequestPayload:
    """Wire-shape sent to the Chio sidecar to open an approval.

    The fields mirror the ``ApprovalRequest`` type in ``chio-kernel``.
    This SDK produces the payload locally; the sidecar is the system of
    record for approval state.
    """

    approval_id: str
    policy_id: str
    subject_id: str
    capability_id: str
    tool_server: str
    tool_name: str
    action: str
    parameter_hash: str
    summary: str
    expires_at: int
    created_at: int
    callback_hint: str | None = None
    triggered_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly dict for HTTP dispatch or interrupt payload."""
        payload: dict[str, Any] = {
            "approval_id": self.approval_id,
            "policy_id": self.policy_id,
            "subject_id": self.subject_id,
            "capability_id": self.capability_id,
            "tool_server": self.tool_server,
            "tool_name": self.tool_name,
            "action": self.action,
            "parameter_hash": self.parameter_hash,
            "summary": self.summary,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }
        if self.callback_hint is not None:
            payload["callback_hint"] = self.callback_hint
        if self.triggered_by:
            payload["triggered_by"] = list(self.triggered_by)
        return payload


@dataclass
class ApprovalResolution:
    """The human's answer, delivered back through ``interrupt``'s return.

    LangGraph passes whatever you hand to ``Command(resume=...)`` back to
    the paused node. :func:`chio_approval_node` normalises a handful of
    common shapes (dict, ``ApprovalResolution``, plain string) into this
    dataclass so callers can be liberal with what they feed in.
    """

    outcome: str  # "approved" | "denied" | "rejected"
    approval_id: str | None = None
    reason: str | None = None
    approver: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_approved(self) -> bool:
        return self.outcome.lower() == "approved"


# Optional hook a caller can install to actually send the approval
# request to an Chio sidecar HTTP endpoint. The default (``None``) keeps
# the approval in-memory and assumes the graph caller is responsible for
# watching ``interrupt``'s payload and posting to the sidecar themselves.
# This is convenient for tests and for environments where the ``interrupt``
# payload is already surfaced through the LangGraph runtime.
ApprovalDispatcher = Callable[[ApprovalRequestPayload], Awaitable[None]]

# Local policy callable: ``(state, config) -> ApprovalPolicyDecision``.
# Returning ``True`` means "require approval before running the body";
# returning ``False`` means "skip approval and run directly". Returning
# an :class:`ApprovalRequestPayload` lets callers override the default
# payload fields (summary, policy_id, ...).
ApprovalPolicyDecision = bool | ApprovalRequestPayload
ApprovalPolicy = Callable[[Any, Any], Awaitable[ApprovalPolicyDecision] | ApprovalPolicyDecision]


def chio_approval_node(
    fn: Callable[..., Any],
    *,
    scope: ChioScope,
    config: ChioGraphConfig,
    approval_policy: ApprovalPolicy | None = None,
    name: str | None = None,
    tool_server: str = "langgraph",
    dispatcher: ApprovalDispatcher | None = None,
    approval_ttl_seconds: int = 3600,
    summary: str | None = None,
    interrupt_fn: _InterruptFn | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> Callable[..., Any]:
    """Wrap ``fn`` in an Chio-governed HITL approval node.

    Parameters
    ----------
    fn:
        Underlying LangGraph node callable. Sync or async; ``(state)`` or
        ``(state, config)``.
    scope:
        The :class:`ChioScope` this node operates under. Must be a subset
        of the graph's effective ceiling.
    config:
        The enclosing :class:`ChioGraphConfig`.
    approval_policy:
        Optional callable deciding whether to require approval for this
        dispatch. ``None`` means approval is *always* required (the most
        conservative default for HITL). A callable returning ``False``
        skips the approval pause and runs the body directly after the
        sidecar allow verdict.
    name:
        Name under which to register the node.
    tool_server:
        Sidecar ``tool_server`` identifier.
    dispatcher:
        Optional async callable that posts the approval request to the
        Chio sidecar's ``/approvals`` surface. When ``None`` (the default)
        the payload is surfaced via :func:`interrupt` only; the graph
        caller is responsible for forwarding it.
    approval_ttl_seconds:
        Default approval TTL if the policy does not supply one.
    summary:
        Human-readable default summary for the approval prompt.
    interrupt_fn:
        Indirection hook for :func:`langgraph.types.interrupt`. Tests
        substitute a fake so they can drive the resume payload directly.
    redaction_policy:
        Per-tool argument redaction policy. Applied to the parameters
        derived from LangGraph state right before the sidecar
        evaluation, so neither the receipt log nor the HITL approval
        prompt carries raw secret bytes (e.g. the ``content`` of
        ``chio_file_write``). Defaults to
        :meth:`RedactionPolicy.chio_default`; pass a custom
        :class:`RedactionPolicy` to extend with adapter or
        workspace-specific tool names. The wrapped node body always
        receives the original LangGraph state untouched.
    """
    node_name: str = name or str(getattr(fn, "__name__", "approval_node"))
    enforce_subgraph_ceiling(config, node_name, scope)
    config.node_scopes.setdefault(node_name, scope)

    if approval_policy is None:
        # Default: every dispatch requires approval. Callers opt into a
        # softer policy explicitly.
        async def _default_policy(_state: Any, _rc: Any) -> bool:
            return True

        approval_policy = _default_policy

    default_summary = summary or f"Approve execution of node '{node_name}'"
    effective_redaction_policy: RedactionPolicy = (
        redaction_policy
        if redaction_policy is not None
        else RedactionPolicy.chio_default()
    )

    async def _dispatch(state: Any, runtime_config: Any) -> Any:
        cap_id = _resolve_capability_id(
            config=config,
            node_name=node_name,
            runtime_config=runtime_config,
        )
        if not cap_id:
            raise ChioLangGraphError(
                "no capability bound to approval node; call "
                "ChioGraphConfig.provision() before running the graph",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                reason="missing_capability",
            )

        # Step 1: sidecar evaluation. Deny -> immediate raise; allow ->
        # proceed; pending_approval -> branch to the interrupt path with
        # the approval_id the kernel emitted. Redact body fields from
        # the parameters derived from state before they cross into the
        # sidecar so the receipt and any HITL approval prompt never
        # carry raw secret bytes; the wrapped node body, when it runs
        # later, still sees the original LangGraph state untouched.
        parameters = redact_args(
            node_name,
            _state_to_parameters(state),
            policy=effective_redaction_policy,
        )
        try:
            receipt = await config.chio_client.evaluate_tool_call(
                capability_id=cap_id,
                tool_server=tool_server,
                tool_name=node_name,
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            raise ChioLangGraphError(
                exc.message,
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ChioError:
            raise

        sidecar_approval_id: str | None = None
        if receipt.decision.is_denied:
            raise ChioLangGraphError(
                receipt.decision.reason or "denied by Chio kernel",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )
        if receipt.decision.verdict == "pending_approval":
            sidecar_approval_id = _approval_id_from_receipt(receipt)

        # Step 2: local policy decides whether an approval pause is
        # required in addition to the sidecar verdict. When the sidecar
        # already returned PendingApproval we always pause.
        require_approval = sidecar_approval_id is not None
        policy_payload: ApprovalRequestPayload | None = None
        if not require_approval:
            policy_result = approval_policy(state, runtime_config)
            if isinstance(policy_result, Awaitable):
                policy_result = await policy_result
            if isinstance(policy_result, ApprovalRequestPayload):
                require_approval = True
                policy_payload = policy_result
            else:
                require_approval = bool(policy_result)

        if not require_approval:
            return await _invoke_body(fn, state, runtime_config)

        # Step 3: build the request payload, dispatch (if wired), then
        # pause the graph via ``interrupt``.
        now = int(time.time())
        payload = policy_payload or ApprovalRequestPayload(
            approval_id=sidecar_approval_id or f"approval-{uuid.uuid4().hex[:12]}",
            policy_id=f"node:{node_name}",
            subject_id=config.subject,
            capability_id=cap_id,
            tool_server=tool_server,
            tool_name=node_name,
            action="invoke",
            parameter_hash=receipt.action.parameter_hash if receipt.action else "",
            summary=default_summary,
            expires_at=now + approval_ttl_seconds,
            created_at=now,
        )
        if sidecar_approval_id and payload.approval_id != sidecar_approval_id:
            # Keep the sidecar-issued id authoritative when both are present.
            payload.approval_id = sidecar_approval_id

        if dispatcher is not None:
            await dispatcher(payload)

        resolver = interrupt_fn or _load_interrupt()
        resume_value = resolver(payload.to_dict())
        resolution = _normalise_resolution(resume_value, payload.approval_id)

        if not resolution.is_approved:
            raise ChioLangGraphError(
                resolution.reason or "approval denied by human reviewer",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard="ApprovalGuard",
                reason=resolution.reason,
                receipt_id=receipt.id,
                approval_id=resolution.approval_id or payload.approval_id,
            )

        # Approved -- run the wrapped body.
        return await _invoke_body(fn, state, runtime_config)

    if asyncio.iscoroutinefunction(fn):

        async def async_wrapper(
            state: Any, runtime_config: Any = None
        ) -> Any:
            return await _dispatch(state, runtime_config)

        _copy_metadata(fn, async_wrapper, node_name)
        async_wrapper.__chio_scope__ = scope  # type: ignore[attr-defined]
        async_wrapper.__chio_approval_node__ = True  # type: ignore[attr-defined]
        return async_wrapper

    def sync_wrapper(state: Any, runtime_config: Any = None) -> Any:
        coro = _dispatch(state, runtime_config)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        return coro

    _copy_metadata(fn, sync_wrapper, node_name)
    sync_wrapper.__chio_scope__ = scope  # type: ignore[attr-defined]
    sync_wrapper.__chio_approval_node__ = True  # type: ignore[attr-defined]
    return sync_wrapper


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _load_interrupt() -> _InterruptFn:
    """Import ``langgraph.types.interrupt`` lazily.

    The import is deferred so test suites that monkey-patch the symbol
    get the patched version, and so that early import errors do not
    prevent the SDK from being used in pure-unit-test mode.
    """
    try:
        from langgraph.types import interrupt as _real_interrupt
    except ImportError as exc:  # pragma: no cover - langgraph is required
        raise ChioLangGraphConfigError(
            "langgraph.types.interrupt is unavailable; install langgraph>=0.2"
        ) from exc
    return _real_interrupt


def _approval_id_from_receipt(receipt: ChioReceipt) -> str | None:
    """Scan guard evidence for an approval id the kernel attached."""
    for ev in receipt.evidence:
        details = getattr(ev, "details", None)
        if isinstance(details, str) and details.startswith("approval_id="):
            return details.split("=", 1)[1]
    return None


def _resolve_capability_id(
    *,
    config: ChioGraphConfig,
    node_name: str,
    runtime_config: Any,
) -> str | None:
    if isinstance(runtime_config, dict):
        configurable = runtime_config.get("configurable")
        if isinstance(configurable, dict):
            override = configurable.get("chio_capability_id")
            if isinstance(override, str) and override:
                return override
    token = config.token_for(node_name)
    if token is not None:
        return token.id
    workflow = config.workflow_token()
    if workflow is not None:
        return workflow.id
    return None


def _normalise_resolution(
    resume_value: Any, approval_id: str
) -> ApprovalResolution:
    """Coerce ``Command(resume=...)`` payloads into an :class:`ApprovalResolution`."""
    if isinstance(resume_value, ApprovalResolution):
        if resume_value.approval_id is None:
            resume_value.approval_id = approval_id
        return resume_value
    if isinstance(resume_value, Mapping):
        outcome = str(resume_value.get("outcome", "")).lower()
        if outcome not in {"approved", "denied", "rejected"}:
            # Accept a friendlier ``approved: bool`` shape too.
            if "approved" in resume_value:
                outcome = "approved" if bool(resume_value["approved"]) else "denied"
        if outcome not in {"approved", "denied", "rejected"}:
            raise ChioLangGraphError(
                "approval resume payload missing 'outcome' field",
                approval_id=approval_id,
                reason="invalid_resume_payload",
            )
        return ApprovalResolution(
            outcome=outcome,
            approval_id=str(
                resume_value.get("approval_id") or approval_id
            ),
            reason=_as_optional_str(resume_value.get("reason")),
            approver=_as_optional_str(resume_value.get("approver")),
            metadata=dict(resume_value.get("metadata") or {}),
        )
    if isinstance(resume_value, str):
        outcome = resume_value.lower()
        if outcome not in {"approved", "denied", "rejected"}:
            raise ChioLangGraphError(
                "approval resume string must be 'approved', 'denied', or 'rejected'",
                approval_id=approval_id,
                reason="invalid_resume_payload",
            )
        return ApprovalResolution(outcome=outcome, approval_id=approval_id)
    if isinstance(resume_value, bool):
        return ApprovalResolution(
            outcome="approved" if resume_value else "denied",
            approval_id=approval_id,
        )
    raise ChioLangGraphError(
        "unrecognised approval resume payload type; expected dict, "
        "ApprovalResolution, str, or bool",
        approval_id=approval_id,
        reason="invalid_resume_payload",
    )


def _as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


async def _invoke_body(
    fn: Callable[..., Any], state: Any, runtime_config: Any
) -> Any:
    """Run the wrapped node body, awaiting if it was async."""
    import inspect as _inspect

    sig = _inspect.signature(fn)
    positional = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (
            _inspect.Parameter.POSITIONAL_ONLY,
            _inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(positional) >= 2:
        result = fn(state, runtime_config)
    else:
        result = fn(state)
    if isinstance(result, Awaitable):
        return await result
    return result


def _copy_metadata(src: Any, dest: Any, node_name: str) -> None:
    try:
        dest.__name__ = node_name
    except (AttributeError, TypeError):
        pass
    if getattr(src, "__doc__", None):
        try:
            dest.__doc__ = src.__doc__
        except (AttributeError, TypeError):
            pass


__all__ = [
    "ApprovalDispatcher",
    "ApprovalPolicy",
    "ApprovalPolicyDecision",
    "ApprovalRequestPayload",
    "ApprovalResolution",
    "chio_approval_node",
]
