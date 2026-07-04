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

from chio_adapter_base.redact import (
    RedactionPolicy,
    bind_and_redact,
    redact_args,
)
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

    if not receipt.is_allowed:
        decision = receipt.decision
        reason = (
            decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt"
        )
        guard = decision.guard if decision is not None else None
        decision_payload = (
            decision.model_dump(exclude_none=True) if decision is not None else None
        )
        emit_deny_event(
            receipt=receipt,
            task_name=tool_name,
            reason=reason,
            guard=guard,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
        )
        raise _denied_permission_error(
            task_name=tool_name,
            flow_run_id=flow_run_id,
            task_run_id=task_run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=reason,
            guard=guard,
            receipt_id=receipt.id,
            decision=decision_payload,
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

    if is_async:
        return await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
    # Sync body offloaded so we never block the loop on a long-running task.
    return await asyncio.to_thread(fn, *args, **kwargs)


def _prefect_envelope(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None,
) -> dict[str, Any]:
    """Wrap ``bind_and_redact`` output in prefect's wire-shape envelope.

    Two prefect-specific contracts the bare ``bind_and_redact`` output
    does not encode:

    1. The sidecar payload shape is a single
       ``{"args": [...], "kwargs": {...}}`` envelope. ``bind_and_redact``
       returns ``(redacted_args, redacted_kwargs)``; this helper packs
       them into the envelope.
    2. When a caller-supplied kwarg name collides with a positional-only
       parameter that already received a value, prefect emits the
       spillover under a synthetic ``<name>__var_kw_spillover__`` key
       so neither bucket overwrites the other. ``bind_and_redact``
       preserves both values under the canonical/wrapper names; this
       helper detects the positional-only-spillover collision and
       re-routes the kwarg value to the synthetic key (matching the
       v0.2 wire shape).
    """
    redacted_args, redacted_kwargs = bind_and_redact(
        fn,
        args,
        kwargs,
        tool_name=tool_name,
        policy=policy,
    )
    # Arity-overflow fail-closed redaction. The bare ``bind_and_redact``
    # fallback table forwards positional values past the wrapper's last
    # named slot raw (``# Extras beyond the table entry stay positional
    # and raw.``). An arity-invalid call such as
    # ``write('/tmp', 'SECRET1', 'SECRET2')`` against
    # ``def write(path, content)`` must not leak ``SECRET2`` on the
    # wire. Enforce that fail-closed contract here, but redact the
    # overflow values under each protected canonical instead of dropping
    # them (preserves the audit trail: a receipt consumer can see
    # "a secret was attempted at position N" without the raw bytes
    # crossing the wire).
    redacted_arg_list = list(redacted_args)
    if fn is not None and len(redacted_arg_list) > 0:
        try:
            overflow_sig = inspect.signature(fn)
        except (TypeError, ValueError):
            overflow_sig = None
        if overflow_sig is not None:
            has_var_positional = any(
                p.kind is inspect.Parameter.VAR_POSITIONAL
                for p in overflow_sig.parameters.values()
            )
            if not has_var_positional:
                fixed_positional_arity = sum(
                    1
                    for p in overflow_sig.parameters.values()
                    if p.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                )
                protected_for_tool = policy.body_fields.get(tool_name) or ()
                if (
                    protected_for_tool
                    and len(redacted_arg_list) > fixed_positional_arity
                ):
                    # Redact each overflow position under the first
                    # protected canonical so arity-invalid calls fail
                    # closed. The exact field identity is unknowable
                    # once the caller supplied too many positional
                    # values, but a redacted audit marker is strictly
                    # safer than forwarding the raw overflow value.
                    for overflow_idx in range(
                        fixed_positional_arity, len(redacted_arg_list)
                    ):
                        overflow_value = redacted_arg_list[overflow_idx]
                        # Skip if ``bind_and_redact`` already turned this
                        # overflow positional into a redaction marker (e.g.
                        # the kwonly-protected path covers
                        # ``def write(path, *, content)`` overflows by
                        # redacting under the kwonly canonical). Re-running
                        # ``redact_args`` on the marker dict would treat its
                        # ``repr()`` as the new "value" and overwrite
                        # ``byte_count`` with the length of the marker repr,
                        # corrupting the audit trail.
                        #
                        # Match the exact redaction-marker fingerprint
                        # ``{"omitted": True, "byte_count": int}`` (no
                        # other keys) rather than just ``omitted is True``
                        # so a user dict that happens to carry an
                        # ``omitted`` flag plus real secrets does NOT slip
                        # through unredacted.
                        if (
                            isinstance(overflow_value, dict)
                            and len(overflow_value) == 2
                            and overflow_value.get("omitted") is True
                            and isinstance(
                                overflow_value.get("byte_count"), int
                            )
                        ):
                            continue
                        canonical = protected_for_tool[0]
                        single = redact_args(
                            tool_name,
                            {canonical: overflow_value},
                            policy=policy,
                        )
                        redacted_arg_list[overflow_idx] = single[canonical]
    redacted_args = tuple(redacted_arg_list)
    # Detect the positional-only-spillover collision: the fn signature
    # has a positional-only param whose name appears as a kwarg AND
    # there is a VAR_KEYWORD spillover param. In that case prefect's
    # wire shape moves the kwarg's redacted value to a synthetic
    # ``<name>__var_kw_spillover__`` key so neither bucket overwrites
    # the other.
    spillover_keys: set[str] = set()
    if fn is not None:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            sig = None
        if sig is not None:
            has_var_keyword = any(
                p.kind is inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )
            if has_var_keyword:
                positional_only_names = {
                    p.name
                    for p in sig.parameters.values()
                    if p.kind is inspect.Parameter.POSITIONAL_ONLY
                }
                # bind_partial logic mirror: a kwarg whose name matches
                # a positional-only param that was supplied positionally
                # lands in the VAR_KEYWORD spillover. The rebuilt
                # kwargs already carry both values; route the kwarg
                # value to the synthetic key.
                for name in positional_only_names:
                    # The kwarg is a spillover collision when the same
                    # name was supplied both positionally (within the
                    # positional-only cardinality) and as a kwarg.
                    pos_only_idx = next(
                        (
                            i
                            for i, p in enumerate(sig.parameters.values())
                            if p.name == name
                        ),
                        None,
                    )
                    if (
                        pos_only_idx is not None
                        and pos_only_idx < len(args)
                        and name in kwargs
                    ):
                        spillover_keys.add(name)

    new_kwargs: dict[str, Any] = {}
    for k, v in redacted_kwargs.items():
        if k in spillover_keys:
            # Positional-only params that also appear in **kwargs spill over
            # under a synthetic key so the wire payload keeps the redacted
            # value distinct from the positional slot.
            new_kwargs[f"{k}__var_kw_spillover__"] = v
        else:
            new_kwargs[k] = v

    return {"args": list(redacted_args), "kwargs": new_kwargs}


def _task_parameters(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Canonicalise call arguments for the sidecar payload.

    Thin wrapper around ``chio_adapter_base.redact.bind_and_redact``
    plus the prefect ``_prefect_envelope`` shim. The shim's two jobs:

    1. Pack ``(args, kwargs)`` into prefect's
       ``{"args": [...], "kwargs": {...}}`` envelope.
    2. Re-emit the synthetic ``__var_kw_spillover__`` keys when a
       kwarg name collides with a positional-only parameter that was
       already supplied positionally.

    The helper redaction logic itself lives in
    ``chio_adapter_base.redact.bind_and_redact``. The prefect-local
    contracts (variadic-named-after-protected, pure-forwarder kwarg
    precedence, alias-rename redaction, TypeError fallback) are
    expressed there; the prefect canary verifies the helper API
    subsumes the bespoke shape.
    """
    return _prefect_envelope(args, kwargs, tool_name, policy, fn)


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
