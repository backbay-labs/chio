"""Chio-governed Airflow TaskFlow decorator.

:func:`chio_task` wraps a Python function so, when Airflow's TaskFlow
engine runs the task, the body only executes after an Chio capability
evaluation. Deny verdicts raise
:class:`airflow.exceptions.AirflowException` with a
:class:`PermissionError` chained on ``__cause__`` so both the
scheduler and the roadmap's ``except PermissionError`` idiom work.

On allow, the decorator pushes the kernel receipt id into XCom under
``chio_receipt_id`` via the running task instance, so downstream tasks
and the DAG listener can aggregate receipts without needing the inner
operator to opt in.

The decorator is deliberately callable in two forms so it reads the
same way as Airflow's own ``@task``:

* ``@chio_task`` -- no parentheses; inherits every default.
* ``@chio_task(scope=..., capability_id=..., ...)`` -- options form.
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

    Parameters
    ----------
    scope:
        Optional :class:`ChioScope` declared for the task. The kernel
        enforces; the wrapper also publishes it to XCom so downstream
        tasks can introspect the allowed surface.
    capability_id:
        Pre-minted Chio capability id for the evaluation. Required when
        the decorator is called in options form; omitting it raises
        :class:`ChioAirflowConfigError` at decoration time.
    tool_server:
        Chio tool server id. Defaults to the empty string so bare
        decorator usage (``@chio_task``) stays legal; operators should
        pass it in real deployments.
    tool_name:
        Overrides the kernel-facing tool name. Defaults to the wrapped
        function's ``__name__``.
    sidecar_url:
        Sidecar URL used when ``chio_client`` is unset. Defaults to
        :attr:`ChioClient.DEFAULT_BASE_URL`.
    chio_client:
        Optional :class:`chio_sdk.client.ChioClient` or
        :class:`chio_sdk.testing.MockChioClient`.
    redaction_policy:
        Optional :class:`chio_adapter_base.redact.RedactionPolicy` used
        to scrub body-bearing argument fields (e.g. ``content`` for
        ``chio_file_write``) before they are forwarded to the sidecar
        and recorded in the receipt log. Defaults to
        :meth:`RedactionPolicy.chio_default`. The user function still
        receives the original (unredacted) arguments; only the
        parameters that cross into the sidecar are redacted.
    **task_kwargs:
        Forwarded verbatim to :func:`airflow.sdk.task` (e.g.
        ``retries``, ``retry_delay``, ``task_id``, ``queue``). Airflow
        TaskFlow options pass through untouched.

    Behaviour
    ---------
    The decorator wraps the user function so the wrapper:

    1. Resolves the live Airflow execute-context via
       :func:`airflow.sdk.get_current_context` so it can pull the TI,
       DAG id, and run id without the user having to thread them
       through.
    2. Calls the sidecar under ``capability_id`` / ``tool_server`` /
       ``tool_name``, with the task's positional + keyword arguments
       canonicalised under ``{"args": [...], "kwargs": {...}}``.
    3. On deny, raises :class:`AirflowException` (``__cause__`` =
       :class:`PermissionError`).
    4. On allow, runs the user function, pushes the receipt id into
       XCom on the live TI under ``chio_receipt_id``, and returns the
       user function's value.

    Async functions are supported: the wrapper runs the async body on
    the event loop the decorator created for the sidecar call, so
    ``@chio_task`` works with ``async def`` TaskFlow bodies in Airflow
    3.x.
    """
    # Lazy import: the Airflow TaskFlow decorator pulls in a large
    # configuration subsystem. Keeping it lazy means this module stays
    # importable in a type-check-only context (e.g. mypy) without
    # Airflow installed.
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
                )
                return fn(*args, **kwargs)

            body = sync_wrapper

        # ``@task`` exposes a ``TaskDecoratorCollection``; calling it
        # with kwargs produces the concrete decorator. When the user
        # passed e.g. ``task_id``, respect it; otherwise Airflow uses
        # the function name.
        decorated = airflow_task(**task_kwargs)(body) if task_kwargs else airflow_task(body)
        return cast(F, decorated)

    if __fn is not None:
        # Bare ``@chio_task`` with no parens -- require capability_id to
        # have been threaded via a higher-level wrapper (e.g. partial).
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
) -> None:
    """Sync evaluation helper used by ``def`` TaskFlow bodies.

    Raises :class:`AirflowException` on deny (``__cause__`` is the
    :class:`PermissionError` the evaluator produced). On allow the
    receipt id is pushed via the current task instance; the push is
    best-effort and wrapped in a try / except so XCom failures never
    mask a successful evaluation.
    """
    from airflow.exceptions import AirflowException

    ti, dag_id, run_id = _resolve_airflow_runtime()
    parameters = _build_redacted_parameters(
        tool_name=tool_name,
        args=args,
        kwargs=kwargs,
        policy=redaction_policy,
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
) -> None:
    """Async evaluation helper used by ``async def`` TaskFlow bodies.

    Airflow 3's TaskFlow engine drives async tasks on its own event
    loop, so we cannot call :func:`asyncio.run` here (that would
    collide with the running loop). The async path therefore reaches
    past the sync wrapper and calls the coroutine :func:`_evaluate`
    directly.
    """
    from airflow.exceptions import AirflowException

    ti, dag_id, run_id = _resolve_airflow_runtime()
    parameters = _build_redacted_parameters(
        tool_name=tool_name,
        args=args,
        kwargs=kwargs,
        policy=redaction_policy,
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
    """Publish the allow-path receipt id / scope / capability to XCom.

    Best-effort: a failing XCom backend must not undo a successful
    evaluation, so all exceptions are swallowed here.
    """
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
) -> dict[str, Any]:
    """Build the sidecar-bound parameters payload with redacted body fields.

    The TaskFlow decorator forwards a ``{"args": [...], "kwargs": {...}}``
    payload to the sidecar so the kernel can hash the inputs into the
    receipt. Body-bearing kwargs (e.g. ``content`` for
    ``chio_file_write``) are scrubbed via
    :func:`chio_adapter_base.redact.redact_args` before they cross the
    boundary, preventing raw secret bytes from landing in the receipt
    log. Positional args are not touched: kwarg names are how the
    redaction policy targets fields, and the user function still
    receives the original ``args`` / ``kwargs`` so behaviour is
    unchanged.
    """
    return {
        "args": list(args),
        "kwargs": redact_args(tool_name, kwargs, policy=policy),
    }


def _resolve_airflow_runtime() -> tuple[Any | None, str | None, str | None]:
    """Resolve ``(task_instance, dag_id, run_id)`` from the live Airflow context.

    When the wrapper runs outside a TaskFlow execute (e.g. a unit test
    that calls the decorated function directly), all three values are
    ``None``. The evaluator still runs; the XCom push simply no-ops.
    """
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
