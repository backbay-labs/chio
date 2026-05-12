"""Chio-governed Prefect decorators.

``@chio_task`` and ``@chio_flow`` wrap Prefect's ``task`` / ``flow`` so
every invocation flows through the Chio sidecar. Denied tasks raise
``PermissionError``; allow / deny verdicts emit ``chio.receipt.*``
Prefect events. A ``@chio_flow``'s scope bounds every enclosed task's
scope via attenuation; a task outside any ``@chio_flow`` runs against
its own scope (gradual adoption).
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

# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


# ContextVar-backed so concurrent flow runs do not stomp each other.
@dataclass(frozen=True)
class _FlowContext:
    """Per-flow-run Chio context visible to enclosed :func:`chio_task` calls."""

    capability_id: str
    scope: ChioScope
    tool_server: str
    chio_client: ChioClientLike | None
    sidecar_url: str
    flow_run_id: str | None
    # ``None`` means "use the chio-default policy at the task boundary".
    redaction_policy: RedactionPolicy | None = None


_current_flow: ContextVar[_FlowContext | None] = ContextVar(
    "chio_prefect_current_flow", default=None
)


def _current_flow_run_id() -> str | None:
    try:
        from prefect.runtime import flow_run

        return str(flow_run.id) if flow_run.id else None
    except Exception:
        return None


def _current_task_run_id() -> str | None:
    try:
        from prefect.runtime import task_run

        return str(task_run.id) if task_run.id else None
    except Exception:
        return None


def _current_task_name(fallback: str) -> str:
    try:
        from prefect.runtime import task_run

        name = task_run.name
        if name:
            return str(name)
    except Exception:
        pass
    return fallback


class _ChioClientOwner:
    """Lazy :class:`ChioClient` owner; only closes clients it created itself."""

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
    """Evaluate via the sidecar; emit receipt event; raise PermissionError on deny.

    Kernel / transport errors propagate as :class:`ChioError` so Prefect
    can apply its retry policy (a transport failure is not a deny).
    """
    try:
        receipt = await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        # HTTP 403: no receipt body; synthesise a deny event.
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
    """Build the deny :class:`PermissionError`; full context rides on ``__cause__``."""
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


def _resolve_task_context(
    *,
    task_scope: ChioScope | None,
    task_capability_id: str | None,
    task_tool_server: str | None,
    task_name: str,
    chio_client_override: ChioClientLike | None,
    sidecar_url_override: str | None,
) -> tuple[_FlowContext | None, str, ChioScope, str]:
    """Resolve ``(flow_context, capability_id, scope, tool_server)`` for a task call."""
    flow_ctx = _current_flow.get()
    if flow_ctx is not None:
        # Attenuation: a declared task scope must be a subset of the flow scope.
        if task_scope is not None and not task_scope.is_subset_of(flow_ctx.scope):
            raise ChioPrefectConfigError(
                f"chio_task scope for {task_name!r} is not a subset of the "
                "enclosing chio_flow scope"
            )
        resolved_scope = task_scope if task_scope is not None else flow_ctx.scope
        capability_id = task_capability_id or flow_ctx.capability_id
        tool_server = task_tool_server or flow_ctx.tool_server
        return flow_ctx, capability_id, resolved_scope, tool_server

    # Standalone task call requires its own capability id.
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
    """Wrap ``fn`` as a Chio-governed Prefect task.

    A task running inside an :func:`chio_flow` inherits the flow's
    scope / capability_id when its own are unset, and any declared
    ``scope`` must be a subset of the flow scope. Standalone tasks (no
    enclosing flow) require their own ``capability_id``.

    ``redaction_policy`` controls which kwargs are stubbed before
    reaching the sidecar; defaults to the enclosing flow's policy or
    :meth:`RedactionPolicy.chio_default`. The wrapped body always sees
    the original arguments. ``**task_options`` pass straight through to
    :func:`prefect.task`.
    """
    # Lazy import: keeps unit tests that do not exercise Prefect importable.
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
            # Run the async evaluation plumbing on a throwaway loop so
            # the sync task body stays synchronous.
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
    """Resolve scope, evaluate via the sidecar, then invoke the wrapped function."""
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

    # Policy resolution: per-task override > flow policy > chio default.
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
                args, kwargs, tool_name_override, resolved_policy, fn=fn
            ),
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
        )
    finally:
        await owner.close()

    _ = resolved_task_name  # reserved for future metadata on receipts
    if is_async:
        return await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
    # Sync body offloaded so we never block the loop on a long-running task.
    return await asyncio.to_thread(fn, *args, **kwargs)


# Tool-arity table for forwarding wrappers that have no fixed-signature
# parameter names to bind positional values against. Tools listed here
# get their positional bodies redacted via these declared names; tools
# absent from the table fall back to kwargs-only redaction.
_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES: dict[str, tuple[str, ...]] = {
    "chio_file_write": ("path", "content"),
    "chio_file_edit": ("path", "patch"),
}


def _forwarding_table_or_passthrough(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
) -> dict[str, Any]:
    """Redact a forwarding-style call via :data:`_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES`.

    Used by the pure-forwarding wrapper branch and by the
    non-introspectable fallback (C-extension callables and
    ``inspect.signature``-failing builtins). Tools listed in the
    arity table get their first N positional values bound to declared
    names and redacted; positional extras past the table cardinality
    stay positional and pass through unredacted (no parameter name to
    bind them to). Tools absent from the table fall back to
    kwargs-only redaction.

    The positional and keyword buckets are redacted INDEPENDENTLY: a
    pathological caller passing both a positional AND a keyword for
    the same field (``write('/tmp/x', path='/etc/passwd')``) would
    otherwise let the kwarg overwrite the positional value before
    redaction, leaking the kwarg-side payload. The wrapped function
    will raise ``TypeError`` for the duplicate parameter; we do not
    try to repair caller error.
    """
    positional_names = _CHIO_DEFAULT_TOOL_POSITIONAL_NAMES.get(tool_name)
    if positional_names is None or not args:
        return {
            "args": list(args),
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }
    named_positional = {
        n: a for n, a in zip(positional_names, args, strict=False)
    }
    redacted_named = redact_args(tool_name, named_positional, policy=policy)
    redacted_kwargs = redact_args(tool_name, dict(kwargs), policy=policy)
    bound_count = min(len(args), len(positional_names))
    new_args: list[Any] = [
        redacted_named[positional_names[i]] for i in range(bound_count)
    ]
    if len(args) > bound_count:
        # Extras past the tool-arity table have no declared name to bind
        # against; they stay positional and pass through unredacted.
        new_args.extend(args[bound_count:])
    return {"args": new_args, "kwargs": redacted_kwargs}


def _task_parameters(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Canonicalise call arguments for the sidecar payload.

    ``redact_args`` keys on parameter names. Positional callers would
    otherwise leave body fields in ``parameters["args"]`` unredacted, so
    we bind positional values to declared parameter names via
    :func:`inspect.signature` before redaction. Crucially, the wire
    shape is preserved: positional values re-emit under
    ``parameters["args"]`` (after redaction) and keyword values stay
    under ``parameters["kwargs"]``. Values are NOT moved between the
    two buckets.

    ``inspect.Signature.bind_partial`` does NOT raise for functions
    accepting ``**kwargs`` or ``*args``; it absorbs extras into the
    variadic parameter (``def f(**kw)`` called with
    ``content="SECRET"`` binds to ``{"kw": {"content": "SECRET"}}``).
    That nests the protected field one level deeper than the redactor
    looks. We branch on signature shape:

    * Pure forwarding wrappers (only ``*args``/``**kwargs``, no fixed
      named params): consult ``_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES`` to
      map positional values onto declared field names, redact, then
      split back into the caller's positional / keyword buckets. Tools
      absent from the table fall back to kwargs-only redaction so
      positional values pass through raw.
    * Fixed-signature functions: redact named values, but keep
      positional values positional and keyword values keyword.
      ``VAR_POSITIONAL`` extras (positional values past the fixed
      slots) remain in ``args`` because no parameter name binds to
      them. ``VAR_KEYWORD`` spillover is re-redacted on the dict.

    Falls back to kwargs-only redaction when ``fn`` is ``None`` or when
    introspection raises. When ``bind_partial`` raises (duplicate
    keyword, unexpected arg) we drop positional args so a failing call
    cannot leak the secret we are trying to scrub.
    """
    if fn is None:
        return _forwarding_table_or_passthrough(
            args, kwargs, tool_name, policy
        )
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        # Non-introspectable callables (C extensions, builtins,
        # functools.partial wrapping a C builtin, etc.) cannot expose a
        # parameter list. Fall back to the forwarding-wrapper path so
        # chio-default tools listed in
        # ``_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES`` still get their
        # positional bodies redacted via the tool-arity table. Tools
        # absent from that table still pass positional values through
        # raw because we have no name to bind them against; this is the
        # documented limitation of fallback-path redaction.
        return _forwarding_table_or_passthrough(
            args, kwargs, tool_name, policy
        )

    params = sig.parameters
    has_var_keyword = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )
    has_var_positional = any(
        p.kind == inspect.Parameter.VAR_POSITIONAL for p in params.values()
    )
    fixed_positional_names = [
        p.name
        for p in params.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    has_fixed_named = any(
        p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for p in params.values()
    )

    # Pure forwarding wrapper: ``def fn(*args, **kwargs)``-shape. No
    # fixed parameter names; consult the tool-arity table so chio
    # default tools still get positional bodies scrubbed.
    if not has_fixed_named:
        return _forwarding_table_or_passthrough(
            args, kwargs, tool_name, policy
        )

    try:
        bound = sig.bind_partial(*args, **kwargs).arguments
    except TypeError:
        # Duplicate keyword, unexpected arg, etc. The downstream fn()
        # call will raise; do NOT forward raw positional args because
        # they may carry the secret we are trying to redact.
        return {
            "args": [],
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }

    var_keys = {
        name
        for name, p in params.items()
        if p.kind
        in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
    }
    flat = {k: v for k, v in bound.items() if k not in var_keys}
    redacted_flat = redact_args(tool_name, flat, policy=policy)
    if has_var_keyword:
        for vk in var_keys:
            v = bound.get(vk)
            if isinstance(v, dict):
                for kk, vv in redact_args(
                    tool_name, dict(v), policy=policy
                ).items():
                    redacted_flat[kk] = vv

    # Rebuild original wire shape: positional values stay positional,
    # keyword values stay keyword. The first ``bound_positional_count``
    # fixed names were supplied positionally, so they re-emit as args.
    bound_positional_count = min(len(args), len(fixed_positional_names))
    new_args = []
    for i in range(bound_positional_count):
        n = fixed_positional_names[i]
        if n in redacted_flat:
            new_args.append(redacted_flat[n])
        else:
            new_args.append(args[i])
    # VAR_POSITIONAL extras have no name to bind to; surface them in
    # args so the wire shape matches the caller's invocation.
    if has_var_positional and len(args) > bound_positional_count:
        new_args.extend(args[bound_positional_count:])
    new_kwargs = {
        k: v
        for k, v in redacted_flat.items()
        if k not in fixed_positional_names[:bound_positional_count]
    }
    return {"args": new_args, "kwargs": new_kwargs}


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
    """Wrap ``fn`` as a Chio-governed Prefect flow.

    The flow's ``scope`` becomes the ceiling for every enclosed
    :func:`chio_task`; broader task scopes are rejected at call time
    with :class:`ChioPrefectConfigError`. ``redaction_policy`` is the
    default policy for enclosed tasks (otherwise
    :meth:`RedactionPolicy.chio_default`). ``**flow_options`` pass
    straight through to :func:`prefect.flow`.
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
