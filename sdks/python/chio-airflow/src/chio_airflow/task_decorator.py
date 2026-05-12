"""Chio-governed Airflow TaskFlow decorator.

``@chio_task`` evaluates each invocation through the Chio sidecar
before running the body. Deny raises ``AirflowException`` with a
``PermissionError`` on ``__cause__``. Allow pushes the receipt id /
scope / capability into XCom so DAG listeners can aggregate receipts.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast, overload

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope

from chio_airflow._evaluation import (
    ChioClientLike,
    _ChioClientOwner,
    _evaluate,
    evaluate_sync,
)
from chio_airflow.errors import ChioAirflowConfigError
from chio_airflow.operator import (
    XCOM_CAPABILITY_KEY,
    XCOM_RECEIPT_ID_KEY,
    XCOM_SCOPE_KEY,
)

F = TypeVar("F", bound=Callable[..., Any])


@overload
def chio_task(__fn: F) -> F: ...


@overload
def chio_task(
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str = "",
    tool_name: str | None = None,
    sidecar_url: str | None = None,
    chio_client: ChioClientLike | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **task_kwargs: Any,
) -> Callable[[F], F]: ...


def chio_task(
    __fn: F | None = None,
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str = "",
    tool_name: str | None = None,
    sidecar_url: str | None = None,
    chio_client: ChioClientLike | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **task_kwargs: Any,
) -> Any:
    """Decorator for Chio-governed Airflow TaskFlow tasks.

    ``capability_id`` is required (raises :class:`ChioAirflowConfigError`
    at decoration time when omitted). ``redaction_policy`` defaults to
    :meth:`RedactionPolicy.chio_default`. ``**task_kwargs`` pass straight
    through to :func:`airflow.sdk.task`. Async TaskFlow bodies are
    supported.
    """
    # Lazy import keeps this module mypy-importable without Airflow.
    from airflow.sdk import task as airflow_task

    def decorator(fn: F) -> F:
        if capability_id is None or not capability_id:
            raise ChioAirflowConfigError(
                "chio_task requires a capability_id; either pass "
                "capability_id=... or wrap the function in an @chio_task "
                "invocation that supplies one"
            )

        resolved_tool_name = tool_name or fn.__name__
        resolved_sidecar = sidecar_url or ChioClient.DEFAULT_BASE_URL
        resolved_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )
        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                await _evaluate_and_push_async(
                    args=args,
                    kwargs=kwargs,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    sidecar_url=resolved_sidecar,
                    chio_client=chio_client,
                    redaction_policy=resolved_policy,
                    fn=fn,
                )
                return await cast(Callable[..., Awaitable[Any]], fn)(
                    *args, **kwargs
                )

            body: Callable[..., Any] = async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                _evaluate_and_push(
                    args=args,
                    kwargs=kwargs,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    sidecar_url=resolved_sidecar,
                    chio_client=chio_client,
                    redaction_policy=resolved_policy,
                    fn=fn,
                )
                return fn(*args, **kwargs)

            body = sync_wrapper

        decorated = airflow_task(**task_kwargs)(body) if task_kwargs else airflow_task(body)
        return cast(F, decorated)

    if __fn is not None:
        return decorator(__fn)
    return decorator


def _evaluate_and_push(
    *,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    capability_id: str,
    tool_server: str,
    tool_name: str,
    scope: ChioScope | None,
    sidecar_url: str,
    chio_client: ChioClientLike | None,
    redaction_policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> None:
    """Sync evaluation; deny -> AirflowException; XCom push is best-effort."""
    from airflow.exceptions import AirflowException

    ti, dag_id, run_id = _resolve_airflow_runtime()
    parameters = _build_redacted_parameters(
        tool_name=tool_name,
        args=args,
        kwargs=kwargs,
        policy=redaction_policy,
        fn=fn,
    )
    try:
        receipt = evaluate_sync(
            chio_client=chio_client,
            sidecar_url=sidecar_url,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
            task_id=tool_name,
            dag_id=dag_id,
            run_id=run_id,
        )
    except PermissionError as exc:
        raise AirflowException(str(exc)) from exc

    _push_receipt(
        ti=ti,
        receipt_id=receipt.id,
        scope=scope,
        capability_id=capability_id,
    )


async def _evaluate_and_push_async(
    *,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    capability_id: str,
    tool_server: str,
    tool_name: str,
    scope: ChioScope | None,
    sidecar_url: str,
    chio_client: ChioClientLike | None,
    redaction_policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> None:
    """Async evaluation; cannot call :func:`asyncio.run` under Airflow 3's loop."""
    from airflow.exceptions import AirflowException

    ti, dag_id, run_id = _resolve_airflow_runtime()
    parameters = _build_redacted_parameters(
        tool_name=tool_name,
        args=args,
        kwargs=kwargs,
        policy=redaction_policy,
        fn=fn,
    )
    owner = _ChioClientOwner(client=chio_client, sidecar_url=sidecar_url)
    try:
        try:
            receipt = await _evaluate(
                chio_client=owner.get(),
                capability_id=capability_id,
                tool_server=tool_server,
                tool_name=tool_name,
                parameters=parameters,
                task_id=tool_name,
                dag_id=dag_id,
                run_id=run_id,
            )
        except PermissionError as exc:
            raise AirflowException(str(exc)) from exc
    finally:
        await owner.close()

    _push_receipt(
        ti=ti,
        receipt_id=receipt.id,
        scope=scope,
        capability_id=capability_id,
    )


def _push_receipt(
    *,
    ti: Any | None,
    receipt_id: str,
    scope: ChioScope | None,
    capability_id: str,
) -> None:
    """Publish receipt id / scope / capability to XCom; XCom errors are swallowed."""
    if ti is None:
        return
    try:
        ti.xcom_push(key=XCOM_RECEIPT_ID_KEY, value=receipt_id)
        if scope is not None:
            ti.xcom_push(
                key=XCOM_SCOPE_KEY, value=scope.model_dump(exclude_none=True)
            )
        ti.xcom_push(key=XCOM_CAPABILITY_KEY, value=capability_id)
    except Exception:  # noqa: BLE001 -- XCom push must not fail the task
        pass


def _build_redacted_parameters(
    *,
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    policy: RedactionPolicy,
    fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Build sidecar payload with positional args bound to parameter names.

    ``redact_args`` keys on parameter names. Positional callers
    (``write_file("/tmp/x", "PROD_SECRET")``) would otherwise bypass
    redaction because the body field would land in ``parameters["args"]``
    untouched. We bind positional args to their declared names via
    :func:`inspect.signature` before redaction, then surface the result
    under ``kwargs`` so the sidecar / receipt both see the redacted form.

    ``inspect.Signature.bind_partial`` does NOT raise for functions that
    accept ``**kwargs`` or ``*args``; it absorbs extras into the variadic
    parameter (e.g. ``def f(**kw)`` called with ``content="SECRET"``
    binds to ``{"kw": {"content": "SECRET"}}``). That would leave the
    protected field nested one level deep where ``redact_args`` cannot
    find it. We therefore inspect the signature for VAR_KEYWORD /
    VAR_POSITIONAL parameters up-front and pick the redaction shape that
    keeps protected fields at the top level of the dict ``redact_args``
    inspects.

    Falls back to kwargs-only redaction when ``fn`` is ``None`` or when
    introspection raises (positional bodies remain raw, matching the
    pre-bind behaviour).
    """
    if fn is None:
        return {
            "args": list(args),
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {
            "args": list(args),
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }

    params = sig.parameters
    has_var_keyword = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )
    has_named_param = any(
        p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for p in params.values()
    )

    # Pure ``**kwargs`` (and optionally ``*args``) function: bind_partial
    # would nest user kwargs under the variadic name. Redact the merged
    # kwargs dict directly; positional bodies (if any) cannot be named.
    if has_var_keyword and not has_named_param:
        return {
            "args": list(args),
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }

    try:
        bound = sig.bind_partial(*args, **kwargs).arguments
    except TypeError:
        # Duplicate keyword, unexpected arg, missing required-positional,
        # etc. Do NOT forward raw positional args; they may carry the
        # very secret we're trying to redact and the call is about to
        # blow up at fn() anyway.
        return {
            "args": [],
            "kwargs": redact_args(tool_name, dict(kwargs), policy=policy),
        }

    # Drop VAR_KEYWORD / VAR_POSITIONAL placeholders before policy lookup
    # (they hold a dict/tuple, not a target-field value), then re-redact
    # the VAR_KEYWORD spillover so kwargs-style calls with protected
    # fields also get scrubbed.
    var_keys = {
        name
        for name, p in params.items()
        if p.kind
        in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
    }
    flat = {k: v for k, v in bound.items() if k not in var_keys}
    redacted = redact_args(tool_name, flat, policy=policy)
    for vk in var_keys:
        v = bound.get(vk)
        if isinstance(v, dict):
            for kk, vv in redact_args(tool_name, dict(v), policy=policy).items():
                redacted[kk] = vv
    return {
        "args": [],
        "kwargs": redacted,
    }


def _resolve_airflow_runtime() -> tuple[Any | None, str | None, str | None]:
    """Resolve ``(ti, dag_id, run_id)``; all ``None`` outside a live TaskFlow execute."""
    try:
        from airflow.sdk import get_current_context
    except Exception:  # pragma: no cover -- import guard for older airflow
        return None, None, None

    try:
        context = get_current_context()
    except Exception:  # noqa: BLE001 -- no live context
        return None, None, None

    ti = None
    try:
        ti = context["ti"]
    except Exception:  # noqa: BLE001
        try:
            ti = context.get("task_instance")
        except Exception:  # noqa: BLE001
            ti = None

    dag_id: str | None = None
    try:
        dag = context["dag"]
        dag_id = getattr(dag, "dag_id", None)
    except Exception:  # noqa: BLE001
        dag_id = None

    run_id: str | None = None
    try:
        run_id = context["run_id"]
    except Exception:  # noqa: BLE001
        run_id = None

    return ti, dag_id, run_id


__all__ = [
    "chio_task",
]
