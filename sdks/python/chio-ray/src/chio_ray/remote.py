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

from chio_adapter_base.redact import RedactionPolicy, bind_and_redact
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_ray.errors import ChioRayConfigError, ChioRayError
from chio_ray.grants import scope_from_spec

# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])

# Module-level singleton so each chio_remote decoration does not allocate
# a fresh policy when the caller did not pass one.
_DEFAULT_REDACTION_POLICY: RedactionPolicy = RedactionPolicy.chio_default()


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

    if not receipt.is_allowed:
        decision = receipt.decision
        err = ChioRayError(
            decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt",
            task_name=tool_name,
            actor_class=actor_class,
            method_name=method_name,
            capability_id=capability_id,
            tool_server=tool_server,
            guard=decision.guard if decision is not None else None,
            reason=decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt",
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True)
            if decision is not None
            else None,
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
            else _DEFAULT_REDACTION_POLICY
        )

        # Ray pickles args into the object store before this wrapper fires.
        # The sidecar payload below is redacted for receipt safety, but
        # callers that need object-store secrecy must pass already-redacted
        # values to Ray.
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


def _build_redacted_call(
    fn: Callable[..., Any] | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: RedactionPolicy,
    *,
    drop_self: bool = False,
) -> tuple[list[Any], dict[str, Any]]:
    """Bind args to declared names, redact protected fields, preserve wire shape."""
    return bind_and_redact(
        fn,
        args,
        kwargs,
        tool_name=tool_name,
        policy=policy,
        drop_self=drop_self,
    )


def _task_parameters(
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Canonicalise call args for the sidecar (positional stays positional)."""
    new_args, new_kwargs = _build_redacted_call(
        fn, args, kwargs, tool_name, policy
    )
    return {"args": new_args, "kwargs": new_kwargs}


__all__ = [
    "ChioClientLike",
    "chio_remote",
]
