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

from chio_adapter_base.redact import RedactionPolicy, bind_and_redact
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
    """Build the sidecar payload via the canonical ``bind_and_redact`` helper.

    Wire shape is preserved: positional values re-emit under
    ``parameters["args"]`` (redacted where their declared parameter
    name matches the policy) and keyword values stay under
    ``parameters["kwargs"]``. Behaviour for forwarding wrappers,
    ``VAR_POSITIONAL`` extras, ``VAR_KEYWORD`` spillover, and
    non-introspectable callables is documented on
    :func:`chio_adapter_base.redact.bind_and_redact`.
    """
    redacted_args, redacted_kwargs = bind_and_redact(
        fn,
        args,
        kwargs,
        tool_name=tool_name,
        policy=policy,
    )
    return {"args": redacted_args, "kwargs": redacted_kwargs}


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
