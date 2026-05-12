"""Chio-governed Prefect decorators.

:func:`chio_task` wraps Prefect's :func:`prefect.task` so every task
invocation flows through the Chio sidecar for capability-scoped
authorisation. :func:`chio_flow` wraps :func:`prefect.flow` to bind a
capability id and a flow-level scope that bounds every task's scope via
attenuation.

The decorators preserve Prefect's sync / async contract: wrapping a
``def`` function yields a sync Prefect task; wrapping an ``async def``
function yields an async Prefect task. All Prefect options (``name``,
``retries``, ``retry_delay_seconds``, ``tags``, ``timeout_seconds``,
etc.) pass straight through to the underlying :func:`prefect.task` /
:func:`prefect.flow`.

Denied tasks raise :class:`PermissionError`. Prefect routes any
exception raised inside a task body to a ``Failed`` task-run state, so
``PermissionError`` surfaces naturally on the flow-run timeline. The
integration also emits an ``chio.receipt.deny`` Prefect event (see
:mod:`chio_prefect.events`) before raising so Automations can fire.

Allow verdicts emit an ``chio.receipt.allow`` event with the receipt id
so the receipt renders on the Prefect UI timeline.

Flow scope attenuation
----------------------

``@chio_flow(scope=..., capability_id=...)`` registers a flow-level grant
on a per-flow-run registry (keyed by the Prefect flow run id). Tasks
decorated with ``@chio_task(scope=...)`` check, at call time, that their
declared scope is a subset of the enclosing flow's scope (the "scope
bounds every task" rule). A task call outside any Chio-governed flow
falls back to the task's own scope without attenuation; this keeps
``@chio_task`` usable in non-Chio flows for gradual adoption.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, TypeVar, cast, overload

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_prefect.errors import ChioPrefectConfigError, ChioPrefectError
from chio_prefect.events import emit_allow_event, emit_deny_event

# Anything that quacks like an :class:`chio_sdk.ChioClient` -- we accept
# the real client and the :class:`chio_sdk.testing.MockChioClient`
# interchangeably, so tests can inject an in-memory policy.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Flow-scope registry (ContextVar-backed so concurrent flow runs do not
# stomp each other's grants, even on async task runners).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FlowContext:
    """Per-flow-run Chio context visible to enclosed :func:`chio_task` calls."""

    capability_id: str
    scope: ChioScope
    tool_server: str
    chio_client: ChioClientLike | None
    sidecar_url: str
    flow_run_id: str | None
    # Per-flow argument redaction policy, propagated to enclosed
    # :func:`chio_task` invocations whose own ``redaction_policy`` is
    # unset. ``None`` means "use the chio-default policy at the task
    # boundary" (resolved in :func:`_invoke_task`).
    redaction_policy: RedactionPolicy | None = None


_current_flow: ContextVar[_FlowContext | None] = ContextVar(
    "chio_prefect_current_flow", default=None
)


def _current_flow_run_id() -> str | None:
    """Best-effort fetch of the current Prefect flow-run id (or ``None``)."""
    try:
        from prefect.runtime import flow_run

        return str(flow_run.id) if flow_run.id else None
    except Exception:
        return None


def _current_task_run_id() -> str | None:
    """Best-effort fetch of the current Prefect task-run id (or ``None``)."""
    try:
        from prefect.runtime import task_run

        return str(task_run.id) if task_run.id else None
    except Exception:
        return None


def _current_task_name(fallback: str) -> str:
    """Best-effort fetch of the Prefect-resolved task-run name."""
    try:
        from prefect.runtime import task_run

        name = task_run.name
        if name:
            return str(name)
    except Exception:
        pass
    return fallback


# ---------------------------------------------------------------------------
# Shared Chio client plumbing
# ---------------------------------------------------------------------------


class _ChioClientOwner:
    """Owns a lazily-constructed :class:`ChioClient` for an integration call.

    The decorator path may see an explicit client (from the flow
    context or a test fixture) or may need to mint a default pointing at
    ``sidecar_url``. We track ownership so we only close the client we
    created, never a caller-supplied one.
    """

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(
        self, *, client: ChioClientLike | None, sidecar_url: str
    ) -> None:
        self._client = client
        self._owns = client is None
        self._sidecar_url = sidecar_url

    def get(self) -> ChioClientLike:
        if self._client is None:
            self._client = ChioClient(self._sidecar_url)
        return self._client

    async def close(self) -> None:
        if self._owns and self._client is not None:
            try:
                await self._client.close()
            finally:
                self._client = None


# ---------------------------------------------------------------------------
# Core evaluation: call the sidecar, emit events, raise on deny.
# ---------------------------------------------------------------------------


async def _evaluate_and_emit(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    flow_run_id: str | None,
    task_run_id: str | None,
) -> ChioReceipt:
    """Evaluate a task invocation via the Chio sidecar and emit the receipt event.

    Returns the :class:`ChioReceipt`. Raises :class:`PermissionError` on
    deny (both the receipt-path deny and the HTTP-403 ``ChioDeniedError``
    path). Kernel / transport errors propagate as the original
    :class:`ChioError` so Prefect can apply its retry policy.
    """
    try:
        receipt = await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        # HTTP 403 path -- no full receipt body; synthesise a deny event
        # and translate to PermissionError.
        emit_deny_event(
            receipt=None,
            task_name=tool_name,
            reason=exc.reason or exc.message,
            guard=exc.guard,
            receipt_id=exc.receipt_id,
            capability_id=capability_id,
            tool_server=tool_server,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
        )
        raise _denied_permission_error(
            task_name=tool_name,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=exc.reason or exc.message,
            guard=exc.guard,
            receipt_id=exc.receipt_id,
        ) from exc
    except ChioError:
        # Transport / sidecar error -- let Prefect retry per the task's
        # configured retry policy. We deliberately do NOT translate to
        # PermissionError here; the task is not denied, the kernel was
        # unreachable.
        raise

    if receipt.is_denied:
        decision = receipt.decision
        emit_deny_event(
            receipt=receipt,
            task_name=tool_name,
            reason=decision.reason or "denied by Chio kernel",
            guard=decision.guard,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
        )
        raise _denied_permission_error(
            task_name=tool_name,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=decision.reason or "denied by Chio kernel",
            guard=decision.guard,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )

    emit_allow_event(
        receipt=receipt,
        task_name=tool_name,
        flow_run_id=flow_run_id,
        task_run_id=task_run_id,
    )
    return receipt


def _denied_permission_error(
    *,
    task_name: str,
    flow_run_id: str | None,
    task_run_id: str | None,
    capability_id: str | None,
    tool_server: str | None,
    reason: str,
    guard: str | None,
    receipt_id: str | None,
    decision: dict[str, Any] | None = None,
) -> PermissionError:
    """Build the :class:`PermissionError` the task decorator raises on deny.

    The :class:`ChioPrefectError` rides along on ``__cause__`` (via
    ``raise ... from``) so structured-log consumers can inspect the full
    deny context; the surface type is :class:`PermissionError` so
    callers can ``except PermissionError`` naturally, per the roadmap
    acceptance criterion.
    """
    err = ChioPrefectError(
        reason,
        task_name=task_name,
        flow_run_id=flow_run_id,
        task_run_id=task_run_id,
        capability_id=capability_id,
        tool_server=tool_server,
        guard=guard,
        reason=reason,
        receipt_id=receipt_id,
        decision=decision,
    )
    permission_error = PermissionError(f"Chio capability denied: {reason}")
    permission_error.chio_error = err  # type: ignore[attr-defined]
    return permission_error


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------


def _resolve_task_context(
    *,
    task_scope: ChioScope | None,
    task_capability_id: str | None,
    task_tool_server: str | None,
    task_name: str,
    chio_client_override: ChioClientLike | None,
    sidecar_url_override: str | None,
) -> tuple[_FlowContext | None, str, ChioScope, str]:
    """Resolve the capability_id / scope / tool_server for a task call.

    Returns ``(flow_context, capability_id, scope, tool_server)``. The
    ``flow_context`` is ``None`` when the task is executing outside any
    Chio-governed flow; in that case the task's own ``capability_id`` is
    required (otherwise :class:`ChioPrefectConfigError`).
    """
    flow_ctx = _current_flow.get()
    if flow_ctx is not None:
        # Flow-attenuation rule: task scope (when declared) must be a
        # subset of the flow scope. An empty ``task_scope`` inherits the
        # flow scope as-is, which is the common case for flows that
        # already declared a tight ceiling.
        if task_scope is not None and not task_scope.is_subset_of(flow_ctx.scope):
            raise ChioPrefectConfigError(
                f"chio_task scope for {task_name!r} is not a subset of the "
                "enclosing chio_flow scope"
            )
        resolved_scope = task_scope if task_scope is not None else flow_ctx.scope
        capability_id = task_capability_id or flow_ctx.capability_id
        tool_server = task_tool_server or flow_ctx.tool_server
        return flow_ctx, capability_id, resolved_scope, tool_server

    # No flow context -- standalone task call. Require capability id.
    if not task_capability_id:
        raise ChioPrefectConfigError(
            f"chio_task {task_name!r} was invoked outside an @chio_flow and no "
            "capability_id was supplied; either wrap the flow in @chio_flow or "
            "pass capability_id=... on @chio_task"
        )
    if task_scope is None:
        task_scope = ChioScope()
    tool_server = task_tool_server or ""
    return None, task_capability_id, task_scope, tool_server


# ---------------------------------------------------------------------------
# @chio_task
# ---------------------------------------------------------------------------


@overload
def chio_task(
    __fn: F,
) -> F: ...


@overload
def chio_task(
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **task_options: Any,
) -> Callable[[F], F]: ...


def chio_task(
    __fn: F | None = None,
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **task_options: Any,
) -> Any:
    """Decorator that wraps a function as an Chio-governed Prefect task.

    Parameters
    ----------
    scope:
        The task's :class:`ChioScope`. When the task runs inside an
        :func:`chio_flow`, ``scope`` must be a subset of the flow's
        scope. When ``None`` inside an ``chio_flow``, the task inherits
        the flow scope.
    capability_id:
        Pre-minted capability id to use for standalone task calls
        (outside any ``chio_flow``). Ignored when an ``chio_flow`` context
        is active (the flow's capability_id wins).
    tool_server:
        Chio tool server id for this task's evaluation. Falls back to the
        flow's ``tool_server`` when unset.
    tool_name:
        Chio tool name to use for evaluation. Defaults to the function
        name.
    chio_client:
        Optional :class:`chio_sdk.ChioClient` (or mock) to use instead of
        minting a default one. The decorator does not close caller-owned
        clients; it only closes clients it created itself.
    sidecar_url:
        Base URL of the Chio sidecar when the decorator has to mint its
        own client. Defaults to the flow context's url or
        ``http://127.0.0.1:9090``.
    redaction_policy:
        Per-task argument redaction policy. Applied to the task kwargs
        right before they are forwarded to the Chio sidecar so secret-
        bearing fields (e.g. the ``content`` of ``chio_file_write``)
        never land in the receipt log. Defaults to the policy of the
        enclosing :func:`chio_flow` (when set) and otherwise to
        :meth:`RedactionPolicy.chio_default`. The wrapped function body
        always sees the original, unredacted arguments.
    task_options:
        Forwarded verbatim to :func:`prefect.task` (e.g. ``retries``,
        ``retry_delay_seconds``, ``tags``, ``timeout_seconds``,
        ``name``). The wrapper preserves Prefect's sync / async
        contract.
    """
    # Lazy import keeps the module importable for unit tests that do
    # not exercise Prefect.
    from prefect import task as prefect_task

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__
        # Preserve Prefect's naming default unless the caller overrode it.
        task_kwargs = dict(task_options)
        task_kwargs.setdefault("name", resolved_tool_name)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            async def async_body(*args: Any, **kwargs: Any) -> Any:
                return await _invoke_task(
                    fn=fn,
                    args=args,
                    kwargs=kwargs,
                    task_scope=scope,
                    task_capability_id=capability_id,
                    task_tool_server=tool_server,
                    tool_name_override=resolved_tool_name,
                    chio_client_override=chio_client,
                    sidecar_url_override=sidecar_url,
                    redaction_policy_override=redaction_policy,
                    is_async=True,
                )

            return cast(F, prefect_task(**task_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            # Run the (async) evaluation plumbing on a throwaway event
            # loop so the task body itself stays synchronous. Prefect
            # synchronises task calls on the caller's loop when one
            # exists; this local runner is only hit for true sync
            # tasks.
            return asyncio.run(
                _invoke_task(
                    fn=fn,
                    args=args,
                    kwargs=kwargs,
                    task_scope=scope,
                    task_capability_id=capability_id,
                    task_tool_server=tool_server,
                    tool_name_override=resolved_tool_name,
                    chio_client_override=chio_client,
                    sidecar_url_override=sidecar_url,
                    redaction_policy_override=redaction_policy,
                    is_async=False,
                )
            )

        return cast(F, prefect_task(**task_kwargs)(sync_body))

    if __fn is not None:
        # Used as ``@chio_task`` with no parens.
        return decorator(__fn)
    return decorator


async def _invoke_task(
    *,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    task_scope: ChioScope | None,
    task_capability_id: str | None,
    task_tool_server: str | None,
    tool_name_override: str,
    chio_client_override: ChioClientLike | None,
    sidecar_url_override: str | None,
    redaction_policy_override: RedactionPolicy | None,
    is_async: bool,
) -> Any:
    """Shared task-body implementation for sync and async variants.

    This performs the full pre-dispatch flow: resolve the scope, evaluate
    via the sidecar, emit the receipt event, raise :class:`PermissionError`
    on deny, otherwise invoke the wrapped function.
    """
    flow_ctx, cap_id, _resolved_scope, server = _resolve_task_context(
        task_scope=task_scope,
        task_capability_id=task_capability_id,
        task_tool_server=task_tool_server,
        task_name=tool_name_override,
        chio_client_override=chio_client_override,
        sidecar_url_override=sidecar_url_override,
    )

    resolved_client = chio_client_override
    if resolved_client is None and flow_ctx is not None:
        resolved_client = flow_ctx.chio_client
    resolved_sidecar = (
        sidecar_url_override
        or (flow_ctx.sidecar_url if flow_ctx is not None else None)
        or ChioClient.DEFAULT_BASE_URL
    )

    # Resolution order for the redaction policy:
    #   1. Per-task override (explicit ``redaction_policy=`` on @chio_task).
    #   2. Enclosing flow's policy (when running inside @chio_flow).
    #   3. The chio-default policy (covers chio_file_write.content,
    #      chio_file_edit.patch).
    # We always apply *some* policy; defaulting to chio_default keeps
    # adoption a no-op for callers that do not explicitly configure one.
    resolved_policy = redaction_policy_override
    if resolved_policy is None and flow_ctx is not None:
        resolved_policy = flow_ctx.redaction_policy
    if resolved_policy is None:
        resolved_policy = RedactionPolicy.chio_default()

    flow_run_id = _current_flow_run_id()
    task_run_id = _current_task_run_id()
    resolved_task_name = _current_task_name(tool_name_override)

    owner = _ChioClientOwner(client=resolved_client, sidecar_url=resolved_sidecar)
    try:
        await _evaluate_and_emit(
            chio_client=owner.get(),
            capability_id=cap_id,
            tool_server=server,
            tool_name=tool_name_override,
            parameters=_task_parameters(
                args, kwargs, tool_name_override, resolved_policy
            ),
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
        )
    finally:
        await owner.close()

    # Allow path -- run the original function body. Preserve sync /
    # async contract: async bodies are awaited, sync bodies are invoked
    # in a thread so we never block the loop for a long-running sync
    # task.
    _ = resolved_task_name  # reserved for future metadata on receipts
    if is_async:
        return await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
    return await asyncio.to_thread(fn, *args, **kwargs)


def _task_parameters(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
) -> dict[str, Any]:
    """Canonicalise task call arguments for the sidecar payload.

    Prefect delivers tasks with both positional and keyword arguments;
    the Chio sidecar evaluates on a dict. We wrap positional args under a
    stable ``args`` key and forward kwargs as-is so the parameter hash
    remains deterministic across runs with identical inputs.

    The ``kwargs`` dict is run through :func:`redact_args` so secret-
    bearing fields named by ``policy`` (e.g. ``content`` for
    ``chio_file_write``) are replaced with a byte-count stub before they
    reach the sidecar (and therefore the receipt log). Positional
    ``args`` are not redacted because the wrapper does not know the
    callable's parameter names; tools that carry secret bodies should
    accept them as keyword-only arguments to opt in to redaction.
    """
    return {
        "args": list(args),
        "kwargs": redact_args(tool_name, kwargs, policy=policy),
    }


# ---------------------------------------------------------------------------
# @chio_flow
# ---------------------------------------------------------------------------


@overload
def chio_flow(
    __fn: F,
) -> F: ...


@overload
def chio_flow(
    *,
    scope: ChioScope,
    capability_id: str,
    tool_server: str = "",
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **flow_options: Any,
) -> Callable[[F], F]: ...


def chio_flow(
    __fn: F | None = None,
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str = "",
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **flow_options: Any,
) -> Any:
    """Decorator that wraps a function as an Chio-governed Prefect flow.

    The flow's ``scope`` becomes the ceiling for every :func:`chio_task`
    inside its body; tasks declaring a broader scope are rejected with
    :class:`ChioPrefectConfigError` at call time. The ``capability_id``
    is the pre-minted capability token id the enclosed tasks evaluate
    against.

    Parameters
    ----------
    scope:
        Flow :class:`ChioScope`. Required when using the keyword form.
    capability_id:
        Flow-level capability id. Required when using the keyword form.
    tool_server:
        Default Chio tool server id for tasks whose own ``tool_server``
        is unset.
    chio_client:
        Optional :class:`chio_sdk.ChioClient` (or mock). Shared with all
        enclosed :func:`chio_task` invocations so tests can observe every
        call via a single mock.
    sidecar_url:
        Fallback sidecar URL. Default ``http://127.0.0.1:9090``.
    redaction_policy:
        Default argument-redaction policy for every enclosed
        :func:`chio_task` whose own ``redaction_policy`` is unset. When
        ``None``, the chio-default policy is applied at the task
        boundary (covers ``chio_file_write.content`` and
        ``chio_file_edit.patch``).
    flow_options:
        Forwarded verbatim to :func:`prefect.flow` (``name``,
        ``retries``, ``timeout_seconds``, ``task_runner``, ``tags``,
        etc.).
    """
    from prefect import flow as prefect_flow

    def decorator(fn: F) -> F:
        if scope is None or not capability_id:
            raise ChioPrefectConfigError(
                "chio_flow requires both 'scope' (ChioScope) and 'capability_id' (str)"
            )
        flow_kwargs = dict(flow_options)
        flow_kwargs.setdefault("name", fn.__name__)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            async def async_body(*args: Any, **kwargs: Any) -> Any:
                token = _enter_flow_context(
                    capability_id=capability_id,
                    scope=scope,
                    tool_server=tool_server,
                    chio_client=chio_client,
                    sidecar_url=sidecar_url,
                    redaction_policy=redaction_policy,
                )
                try:
                    return await cast(
                        Callable[..., Awaitable[Any]], fn
                    )(*args, **kwargs)
                finally:
                    _current_flow.reset(token)

            return cast(F, prefect_flow(**flow_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            token = _enter_flow_context(
                capability_id=capability_id,
                scope=scope,
                tool_server=tool_server,
                chio_client=chio_client,
                sidecar_url=sidecar_url,
                redaction_policy=redaction_policy,
            )
            try:
                return fn(*args, **kwargs)
            finally:
                _current_flow.reset(token)

        return cast(F, prefect_flow(**flow_kwargs)(sync_body))

    if __fn is not None:
        return decorator(__fn)
    return decorator


def _enter_flow_context(
    *,
    capability_id: str,
    scope: ChioScope,
    tool_server: str,
    chio_client: ChioClientLike | None,
    sidecar_url: str | None,
    redaction_policy: RedactionPolicy | None = None,
) -> Any:
    """Push a :class:`_FlowContext` onto the ContextVar stack for this flow run."""
    flow_run_id = _current_flow_run_id() or f"adhoc-{uuid.uuid4().hex[:8]}"
    ctx = _FlowContext(
        capability_id=capability_id,
        scope=scope,
        tool_server=tool_server,
        chio_client=chio_client,
        sidecar_url=sidecar_url or ChioClient.DEFAULT_BASE_URL,
        flow_run_id=flow_run_id,
        redaction_policy=redaction_policy,
    )
    return _current_flow.set(ctx)


__all__ = [
    "ChioClientLike",
    "chio_flow",
    "chio_task",
]
