"""Chio-governed ``ray.remote`` decorator.

:func:`chio_remote` wraps :func:`ray.remote` so every remote-task
invocation hits the Chio sidecar before the body runs. The check fires
inside the worker so the receipt comes from the node-local sidecar.
Denied tasks raise ``PermissionError``; Ray propagates it through
``ray.get`` as a ``RayTaskError``. Sync and async bodies are supported.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_ray.errors import ChioRayConfigError, ChioRayError
from chio_ray.grants import scope_from_spec

# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


async def _evaluate_with_sidecar(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ChioReceipt:
    """Call the sidecar; translate HTTP-403 deny to PermissionError.

    Receipt-path denies (``is_denied``) are translated in the caller so
    the caller can record actor / method context in the error.
    """
    try:
        return await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        err = ChioRayError(
            exc.message,
            task_name=tool_name,
            capability_id=capability_id,
            tool_server=tool_server,
            guard=exc.guard,
            reason=exc.reason or exc.message,
            receipt_id=exc.receipt_id,
        )
        raise _permission_error(err) from exc
    except ChioError:
        # Transport / sidecar failure; let Ray's retry logic see it.
        raise


def _permission_error(err: ChioRayError) -> PermissionError:
    """Wrap an :class:`ChioRayError` in :class:`PermissionError` for Ray."""
    pe = PermissionError(f"Chio capability denied: {err.reason or err.message}")
    pe.chio_error = err  # type: ignore[attr-defined]
    return pe


async def _evaluate_allow_or_raise(
    *,
    chio_client: ChioClientLike | None,
    sidecar_url: str,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    actor_class: str | None = None,
    method_name: str | None = None,
) -> ChioReceipt:
    """Shared allow/deny path for :func:`chio_remote` and :class:`ChioActor`.

    When ``chio_client`` is ``None`` a fresh client is minted, used,
    and closed inside this call.
    """
    if not capability_id:
        raise _permission_error(
            ChioRayError(
                "missing capability_id",
                task_name=tool_name,
                actor_class=actor_class,
                method_name=method_name,
                reason="missing_capability",
            )
        )

    owned = False
    client = chio_client
    if client is None:
        client = ChioClient(sidecar_url)
        owned = True

    try:
        receipt = await _evaluate_with_sidecar(
            chio_client=client,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    finally:
        if owned:
            await client.close()

    if receipt.is_denied:
        decision = receipt.decision
        err = ChioRayError(
            decision.reason or "denied by Chio kernel",
            task_name=tool_name,
            actor_class=actor_class,
            method_name=method_name,
            capability_id=capability_id,
            tool_server=tool_server,
            guard=decision.guard,
            reason=decision.reason or "denied by Chio kernel",
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )
        raise _permission_error(err)

    return receipt


def chio_remote(
    __fn: F | None = None,
    *,
    scope: str | ChioScope,
    capability_id: str | None = None,
    tool_server: str = "",
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str = "http://127.0.0.1:9090",
    redaction_policy: RedactionPolicy | None = None,
    **ray_options: Any,
) -> Any:
    """Wrap ``fn`` as a Chio-governed Ray remote task.

    ``capability_id`` is required (raises :class:`ChioRayConfigError`
    otherwise). ``redaction_policy`` only governs receipt-log
    parameters; Ray's object store still holds the pickled originals.
    ``**ray_options`` pass straight through to :func:`ray.remote`.
    """
    import ray  # lazy: ray is heavy

    resolved_scope: ChioScope = scope_from_spec(scope)
    scope_spec_for_intro: str | None = scope if isinstance(scope, str) else None

    def decorator(fn: F) -> Any:
        if not capability_id:
            raise ChioRayConfigError(
                f"chio_remote requires a non-empty 'capability_id' for task "
                f"{fn.__name__!r}; mint a token via chio_sdk.ChioClient.create_capability "
                "and pass its id on the decorator."
            )

        resolved_tool_name = tool_name or fn.__name__
        is_coro = inspect.iscoroutinefunction(fn)

        # Capture in locals so the wrapper closure stays Ray-serialisable.
        bound_capability_id = capability_id
        bound_tool_server = tool_server
        bound_sidecar_url = sidecar_url
        bound_chio_client = chio_client
        bound_redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )

        if is_coro:

            @functools.wraps(fn)
            async def async_body(*args: Any, **kwargs: Any) -> Any:
                await _evaluate_allow_or_raise(
                    chio_client=bound_chio_client,
                    sidecar_url=bound_sidecar_url,
                    capability_id=bound_capability_id,
                    tool_server=bound_tool_server,
                    tool_name=resolved_tool_name,
                    parameters=_task_parameters(
                        resolved_tool_name,
                        args,
                        kwargs,
                        policy=bound_redaction_policy,
                        fn=fn,
                    ),
                )
                return await cast(Callable[..., Awaitable[Any]], fn)(
                    *args, **kwargs
                )

            wrapper = async_body
        else:

            @functools.wraps(fn)
            def sync_body(*args: Any, **kwargs: Any) -> Any:
                asyncio.run(
                    _evaluate_allow_or_raise(
                        chio_client=bound_chio_client,
                        sidecar_url=bound_sidecar_url,
                        capability_id=bound_capability_id,
                        tool_server=bound_tool_server,
                        tool_name=resolved_tool_name,
                        parameters=_task_parameters(
                            resolved_tool_name,
                            args,
                            kwargs,
                            policy=bound_redaction_policy,
                            fn=fn,
                        ),
                    )
                )
                return fn(*args, **kwargs)

            wrapper = sync_body

        wrapper._chio_scope = resolved_scope  # type: ignore[attr-defined]
        wrapper._chio_scope_spec = scope_spec_for_intro  # type: ignore[attr-defined]
        wrapper._chio_capability_id = bound_capability_id  # type: ignore[attr-defined]
        wrapper._chio_tool_server = bound_tool_server  # type: ignore[attr-defined]
        wrapper._chio_tool_name = resolved_tool_name  # type: ignore[attr-defined]

        if ray_options:
            remote_handle = ray.remote(**ray_options)(wrapper)
        else:
            remote_handle = ray.remote(wrapper)

        # Mirror introspection attrs onto the remote handle when it accepts them.
        for attr in (
            "_chio_scope",
            "_chio_scope_spec",
            "_chio_capability_id",
            "_chio_tool_server",
            "_chio_tool_name",
        ):
            try:
                setattr(remote_handle, attr, getattr(wrapper, attr))
            except (AttributeError, TypeError):
                # Frozen handle; callers can still read the wrapper attrs.
                pass
        return remote_handle

    if __fn is not None:
        return decorator(__fn)
    return decorator


# Tool-arity table for forwarding wrappers that have no fixed-signature
# parameter names to bind positional args against. When the tool name
# matches, positional values are mapped onto these declared positional
# names so they can be redacted before scrubbing. Tools not in this
# table cannot have positional payloads redacted by name.
_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES: dict[str, tuple[str, ...]] = {
    "chio_file_write": ("path", "content"),
    "chio_file_edit": ("path", "patch"),
}


def _build_redacted_call(
    fn: Callable[..., Any] | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
    *,
    drop_self: bool = False,
) -> tuple[list[Any], dict[str, Any]]:
    """Bind args to declared names, redact protected fields, preserve wire shape.

    Returns ``(redacted_positional_list, redacted_keyword_dict)`` for
    embedding under ``parameters = {"args": ..., "kwargs": ...}``. The
    returned positional list mirrors what the caller supplied
    positionally (with chio-default body fields stubbed); the keyword
    dict mirrors what they supplied as kwargs (with body fields stubbed
    and any VAR_KEYWORD spillover scrubbed). Values are NOT migrated
    between the positional and keyword buckets.

    ``inspect.Signature.bind_partial`` does NOT raise for callables
    accepting ``**kwargs`` or ``*args``; it absorbs extras into the
    variadic parameter (``def f(**kw)`` called with ``content="SECRET"``
    binds to ``{"kw": {"content": "SECRET"}}``). That nests the
    protected field one level deeper than ``redact_args`` looks. We
    therefore branch on signature shape:

    * Pure forwarding wrappers (only ``*args``/``**kwargs``, no fixed
      named params): consult ``_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES`` to
      map positional values onto declared field names so they can be
      redacted, then split the redacted dict back into the caller's
      positional / keyword buckets. Tools absent from the table fall
      back to kwargs-only redaction (positional values pass through
      raw).
    * Fixed-signature callables: redact named values, but keep
      positional values positional and keyword values keyword.
      ``VAR_POSITIONAL`` extras (positional values past the fixed
      positional slots) remain in ``args`` because there is no
      parameter name to bind them to.

    Falls back to kwargs-only redaction when ``fn`` is ``None`` or when
    introspection raises. ``drop_self=True`` strips the implicit ``self``
    parameter for bound-method signatures.
    """
    if fn is None:
        return list(args), redact_args(tool_name, dict(kwargs), policy=policy)
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return list(args), redact_args(tool_name, dict(kwargs), policy=policy)

    if drop_self:
        params_list = list(sig.parameters.values())
        if params_list and params_list[0].name == "self":
            sig = sig.replace(parameters=params_list[1:])

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

    # Pure forwarding wrapper: ``def fn(*args, **kwargs)`` style. No
    # fixed parameter names to bind positional values against; consult
    # the tool-arity table so chio-default tools still get their
    # positional bodies redacted.
    if not has_fixed_named:
        positional_names = _CHIO_DEFAULT_TOOL_POSITIONAL_NAMES.get(tool_name)
        if positional_names is None or not args:
            return list(args), redact_args(
                tool_name, dict(kwargs), policy=policy
            )
        named_positional = {
            n: a for n, a in zip(positional_names, args, strict=False)
        }
        merged = {**named_positional, **kwargs}
        redacted_merged = redact_args(tool_name, merged, policy=policy)
        bound_count = min(len(args), len(positional_names))
        new_args: list[Any] = [
            redacted_merged[positional_names[i]] for i in range(bound_count)
        ]
        if len(args) > bound_count:
            new_args.extend(args[bound_count:])
        bound_names = set(positional_names[:bound_count])
        new_kwargs = {
            k: v for k, v in redacted_merged.items() if k not in bound_names
        }
        return new_args, new_kwargs

    try:
        bound = sig.bind_partial(*args, **kwargs).arguments
    except TypeError:
        # Duplicate keyword / unexpected arg. Do NOT forward raw
        # positional args; they may carry the secret we are scrubbing.
        return [], redact_args(tool_name, dict(kwargs), policy=policy)

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

    bound_positional_count = min(len(args), len(fixed_positional_names))
    new_args = []
    for i in range(bound_positional_count):
        n = fixed_positional_names[i]
        if n in redacted_flat:
            new_args.append(redacted_flat[n])
        else:
            new_args.append(args[i])
    if has_var_positional and len(args) > bound_positional_count:
        new_args.extend(args[bound_positional_count:])
    new_kwargs = {
        k: v
        for k, v in redacted_flat.items()
        if k not in fixed_positional_names[:bound_positional_count]
    }
    return new_args, new_kwargs


def _task_parameters(
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Canonicalise call args for the sidecar.

    Positional values are bound to declared parameter names via
    :func:`inspect.signature` so :func:`redact_args` (which keys on
    field name) can scrub protected bodies. The original wire shape is
    preserved: positional values stay in ``parameters["args"]``,
    keyword values stay in ``parameters["kwargs"]``. See
    :func:`_build_redacted_call` for the full signature-shape handling.
    """
    new_args, new_kwargs = _build_redacted_call(
        fn, args, kwargs, tool_name, policy
    )
    return {"args": new_args, "kwargs": new_kwargs}


__all__ = [
    "ChioClientLike",
    "chio_remote",
]
