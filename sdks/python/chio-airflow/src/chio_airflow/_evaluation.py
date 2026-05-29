"""Shared Chio evaluation plumbing for the Airflow integration.

Both :class:`chio_airflow.ChioOperator` and :func:`chio_airflow.chio_task`
take the same pre-dispatch path: resolve a :class:`ChioClient`, call
``evaluate_tool_call``, translate denies into an
:class:`airflow.exceptions.AirflowException` whose ``__cause__`` is a
:class:`PermissionError`, and return the allow-path receipt so the
caller can push its id into XCom.

The kernel / transport error path deliberately does *not* translate to
``PermissionError``. A sidecar that is down is not a denial; Airflow's
retry policy should apply.
"""

from __future__ import annotations

import asyncio
from typing import Any

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt

from chio_airflow.errors import ChioAirflowError

# Anything that quacks like an :class:`chio_sdk.ChioClient` -- the real
# async client plus :class:`chio_sdk.testing.MockChioClient` are both
# accepted.
ChioClientLike = Any


class _ChioClientOwner:
    """Owns a lazily-constructed :class:`ChioClient` for one dispatch.

    If the caller supplied their own client (operator kwarg, test
    fixture), we do not close it. If we had to mint one pointing at
    ``sidecar_url``, we close it after the evaluation to avoid leaking
    httpx connections between task invocations.
    """

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(self, *, client: ChioClientLike | None, sidecar_url: str) -> None:
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


async def _evaluate(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
) -> ChioReceipt:
    """Call the sidecar, raising on deny.

    Returns the allow-path :class:`ChioReceipt` so the caller can push
    ``receipt.id`` into XCom. Raises :class:`PermissionError` on both
    the receipt-path deny (``receipt.is_denied``) and the HTTP-403
    ``ChioDeniedError`` path; the original :class:`ChioAirflowError`
    rides along on ``PermissionError.chio_error`` so structured-log
    consumers see the full context.

    Kernel / transport errors propagate as :class:`ChioError` so the
    Airflow retry policy can apply.
    """
    try:
        receipt = await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        raise _denied_permission_error(
            task_id=task_id,
            dag_id=dag_id,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=exc.reason or exc.message,
            guard=exc.guard,
            receipt_id=exc.receipt_id,
        ) from exc
    except ChioError:
        # Transport / sidecar outage -- let the Airflow retry policy
        # apply. Deliberately NOT translated to PermissionError.
        raise

    if not receipt.is_allowed:
        decision = receipt.decision
        raise _denied_permission_error(
            task_id=task_id,
            dag_id=dag_id,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt",
            guard=decision.guard if decision is not None else None,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True)
            if decision is not None
            else None,
        )

    return receipt


def _denied_permission_error(
    *,
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
    capability_id: str | None,
    tool_server: str | None,
    reason: str,
    guard: str | None,
    receipt_id: str | None,
    decision: dict[str, Any] | None = None,
) -> PermissionError:
    """Build the :class:`PermissionError` that denies raise.

    The :class:`ChioAirflowError` rides along on
    :attr:`PermissionError.chio_error` so structured-log consumers can
    inspect the full deny context. The surface type is
    :class:`PermissionError` so callers can ``except PermissionError``
    naturally.
    """
    err = ChioAirflowError(
        reason,
        task_id=task_id,
        dag_id=dag_id,
        run_id=run_id,
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


def evaluate_sync(
    *,
    chio_client: ChioClientLike | None,
    sidecar_url: str,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
) -> ChioReceipt:
    """Synchronous wrapper around :func:`_evaluate`.

    Airflow's :meth:`BaseOperator.execute` signature is synchronous so
    this function hides the async evaluation plumbing behind a blocking
    call. A throwaway event loop is spun up per call because Airflow
    worker processes do not own a persistent loop we can schedule onto
    safely. The per-call cost is dominated by the sidecar round-trip,
    not loop creation.
    """
    owner = _ChioClientOwner(client=chio_client, sidecar_url=sidecar_url)

    async def _run() -> ChioReceipt:
        try:
            return await _evaluate(
                chio_client=owner.get(),
                capability_id=capability_id,
                tool_server=tool_server,
                tool_name=tool_name,
                parameters=parameters,
                task_id=task_id,
                dag_id=dag_id,
                run_id=run_id,
            )
        finally:
            await owner.close()

    return asyncio.run(_run())


__all__ = [
    "ChioClientLike",
    "evaluate_sync",
]
