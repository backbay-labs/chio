"""Airflow DAG / task listener that materialises Chio receipt ids.

:class:`ChioDAGListener` plugs into Airflow's listener plugin surface
(``@hookimpl``) to push per-task receipt ids into XCom on
``on_task_instance_success`` and ``on_task_instance_failed``, and to
record DAG-level aggregation state on ``on_dag_run_success`` /
``on_dag_run_failed``.

Why a listener
--------------
:class:`chio_airflow.ChioOperator` and :func:`chio_airflow.chio_task` both
push receipt ids themselves at execute time. The listener exists so a
DAG that mixes Chio-wrapped and un-wrapped tasks still produces a
consistent timeline: un-wrapped tasks get a synthesised receipt
receipt id, and the final DAG-run success / failure hook writes an
aggregation summary into the run-level XCom (or prints it when XCom
is unavailable) that includes every receipt id the run produced.

Registration
------------
Airflow plugins must subclass :class:`airflow.plugins_manager.AirflowPlugin`
and expose a ``listeners`` attribute. :class:`ChioAirflowPlugin` below
does exactly that for operators who want drop-in registration; tests
exercise the listener directly via its public hook methods so the
``@hookimpl`` decoration does not need a live plugin manager.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from chio_airflow.operator import XCOM_RECEIPT_ID_KEY

if TYPE_CHECKING:  # pragma: no cover -- typing only
    from airflow.listeners import hookimpl as _hookimpl
else:
    try:
        from airflow.listeners import hookimpl as _hookimpl
    except Exception:  # pragma: no cover -- lightweight fallback

        def _hookimpl(func: Any) -> Any:
            """No-op fallback when the Airflow plugin manager is unavailable.

            Kept so the module is importable in type-check-only contexts
            (e.g. CI without Airflow) without raising at import time.
            """
            return func


logger = logging.getLogger(__name__)

#: XCom key where the listener records the aggregated receipt ids for
#: the entire DAG run. Task-level keys keep using
#: :data:`chio_airflow.operator.XCOM_RECEIPT_ID_KEY` per task.
XCOM_RUN_RECEIPTS_KEY = "chio_receipt_ids"
#: XCom key where the listener records the terminal DAG-run state
#: alongside the aggregated receipt ids, so observers can filter.
XCOM_RUN_STATE_KEY = "chio_run_state"


class ChioDAGListener:
    """Airflow listener that materialises Chio receipt ids on XCom.

    The listener stores every receipt id it sees per DAG-run in an
    in-memory map so, when the DAG run finishes, it can publish the
    aggregated list to XCom under :data:`XCOM_RUN_RECEIPTS_KEY`. The
    map is keyed by ``(dag_id, run_id)`` so concurrent runs of the
    same DAG do not contaminate each other's aggregation.

    The listener is idempotent: repeated success / failed hooks for
    the same task instance merge into the same run entry and the
    final aggregation is emitted exactly once per DAG-run terminal
    transition.
    """

    def __init__(self) -> None:
        # (dag_id, run_id) -> list of receipt ids captured this run.
        self._receipts: dict[tuple[str, str], list[str]] = {}

    # ------------------------------------------------------------------
    # Task-level hooks
    # ------------------------------------------------------------------

    @_hookimpl
    def on_task_instance_success(
        self,
        previous_state: Any,
        task_instance: Any,
    ) -> None:
        """Called when an Airflow task transitions to SUCCESS.

        The listener pulls the per-task receipt id (written by
        :class:`ChioOperator` or :func:`chio_task` at execute time) and
        adds it to the DAG-run aggregation. Tasks that did not push an
        id are ignored -- the listener does not forge receipts for
        un-governed tasks.
        """
        self._record_task(task_instance, status="success")

    @_hookimpl
    def on_task_instance_failed(
        self,
        previous_state: Any,
        task_instance: Any,
        error: Any = None,
    ) -> None:
        """Called when an Airflow task transitions to FAILED.

        Chio deny paths surface as failures here (the operator /
        decorator raise :class:`AirflowException` with
        :class:`PermissionError` as cause). The listener still records
        whatever receipt id was emitted -- a deny produces a receipt
        too, and downstream audit tooling expects to see it.
        """
        self._record_task(task_instance, status="failed")

    # ------------------------------------------------------------------
    # DAG-run-level hooks
    # ------------------------------------------------------------------

    @_hookimpl
    def on_dag_run_success(self, dag_run: Any, msg: Any = None) -> None:
        """Finalise the aggregation for a successful DAG run."""
        self._finalise(dag_run, state="success")

    @_hookimpl
    def on_dag_run_failed(self, dag_run: Any, msg: Any = None) -> None:
        """Finalise the aggregation for a failed DAG run."""
        self._finalise(dag_run, state="failed")

    # ------------------------------------------------------------------
    # Public helpers (used by tests and custom aggregators)
    # ------------------------------------------------------------------

    def receipts_for(self, dag_id: str, run_id: str) -> list[str]:
        """Return the list of receipt ids captured for ``(dag_id, run_id)``.

        Useful from a downstream TaskFlow ``@task`` body (or from
        tests) that wants to emit a workflow-level receipt that
        references every step receipt.
        """
        return list(self._receipts.get((dag_id, run_id), []))

    def reset(self) -> None:
        """Clear the in-memory aggregation state.

        Tests use this to isolate runs; production deployments never
        need to call it because the DAG-run terminal hook drains the
        entry for that run.
        """
        self._receipts.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_task(self, task_instance: Any, *, status: str) -> None:
        key = _run_key(task_instance)
        if key is None:
            return
        receipt_id = _pull_receipt_id(task_instance)
        if not receipt_id:
            return
        bucket = self._receipts.setdefault(key, [])
        if receipt_id not in bucket:
            bucket.append(receipt_id)
        logger.debug(
            "chio-airflow: recorded receipt %s for task status=%s key=%s",
            receipt_id,
            status,
            key,
        )

    def _finalise(self, dag_run: Any, *, state: str) -> None:
        dag_id = _safe_attr(dag_run, "dag_id")
        run_id = _safe_attr(dag_run, "run_id")
        if not dag_id or not run_id:
            return
        key = (str(dag_id), str(run_id))
        receipts = self._receipts.pop(key, [])
        logger.info(
            "chio-airflow: DAG run finalised dag_id=%s run_id=%s state=%s "
            "receipt_count=%d",
            dag_id,
            run_id,
            state,
            len(receipts),
        )
        _push_run_aggregation(
            dag_run=dag_run,
            receipts=receipts,
            state=state,
        )


# ---------------------------------------------------------------------------
# Context accessors
# ---------------------------------------------------------------------------


def _run_key(task_instance: Any) -> tuple[str, str] | None:
    """Return the ``(dag_id, run_id)`` tuple for a task instance.

    Returns ``None`` when either value is missing -- the listener
    refuses to record orphan receipts because the aggregation would
    leak into unrelated runs otherwise.
    """
    dag_id = _safe_attr(task_instance, "dag_id")
    run_id = _safe_attr(task_instance, "run_id")
    if not dag_id or not run_id:
        return None
    return (str(dag_id), str(run_id))


def _pull_receipt_id(task_instance: Any) -> str | None:
    """Pull the per-task receipt id the operator / decorator pushed.

    Airflow task instances expose ``xcom_pull(key=..., task_ids=...)``.
    The listener asks the TI for its own receipt id (same task_id);
    when the TI was not Chio-governed, no receipt is present and the
    return is ``None``.
    """
    try:
        task_id = _safe_attr(task_instance, "task_id")
        if task_id is None:
            return None
        value = task_instance.xcom_pull(
            task_ids=task_id, key=XCOM_RECEIPT_ID_KEY
        )
    except Exception:  # noqa: BLE001 -- xcom backend may be unavailable
        return None
    if not value:
        return None
    return str(value)


def _push_run_aggregation(
    *, dag_run: Any, receipts: list[str], state: str
) -> None:
    """Publish the run-level aggregation via whatever XCom surface works.

    Airflow's ``DagRun`` object does not natively expose an
    ``xcom_push``; we try a few common shapes (``get_task_instances``
    returning the running TIs, ``dag_run.conf`` merging, a
    ``xcom_push`` attribute) and fall back to logging if none are
    available. The listener promises *materialisation*, not a
    specific storage backend, so tests substitute a custom XCom
    sink via :meth:`ChioDAGListener.receipts_for`.
    """
    # Preferred: a task instance we can write to.
    try:
        tis = list(dag_run.get_task_instances())
    except Exception:  # noqa: BLE001 -- legacy or test dag_run
        tis = []

    target_ti: Any | None = None
    for ti in tis:
        task_id = _safe_attr(ti, "task_id")
        # Prefer a clearly-marked aggregator task if the DAG author
        # added one, otherwise fall back to the last TI so the
        # aggregation lands somewhere observable.
        if isinstance(task_id, str) and "aggregate" in task_id.lower():
            target_ti = ti
            break
    if target_ti is None and tis:
        target_ti = tis[-1]

    payload = list(receipts)
    if target_ti is not None:
        try:
            target_ti.xcom_push(key=XCOM_RUN_RECEIPTS_KEY, value=payload)
            target_ti.xcom_push(key=XCOM_RUN_STATE_KEY, value=state)
            return
        except Exception:  # noqa: BLE001
            logger.debug(
                "chio-airflow: target TI xcom_push failed; falling back",
                exc_info=True,
            )

    # Fallback: dag_run.xcom_push if present.
    push = getattr(dag_run, "xcom_push", None)
    if callable(push):
        try:
            push(key=XCOM_RUN_RECEIPTS_KEY, value=payload)
            push(key=XCOM_RUN_STATE_KEY, value=state)
            return
        except Exception:  # noqa: BLE001
            logger.debug(
                "chio-airflow: dag_run.xcom_push failed; logging aggregation",
                exc_info=True,
            )

    logger.info(
        "chio-airflow: DAG run aggregation (no XCom backend) state=%s receipts=%s",
        state,
        payload,
    )


def _safe_attr(obj: Any, name: str) -> Any:
    try:
        return getattr(obj, name, None)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# AirflowPlugin registration
# ---------------------------------------------------------------------------


_PROCESS_LISTENER: ChioDAGListener | None = None


def get_listener() -> ChioDAGListener:
    """Return a process-wide :class:`ChioDAGListener` instance.

    Airflow loads plugins once per worker; we expose a module-level
    singleton so tests and plugin registration share the same listener
    state without having to plumb it through.
    """
    global _PROCESS_LISTENER
    if _PROCESS_LISTENER is None:
        _PROCESS_LISTENER = ChioDAGListener()
    return _PROCESS_LISTENER


def _build_airflow_plugin() -> type | None:
    """Build a thin :class:`AirflowPlugin` subclass that registers the listener.

    Returns ``None`` when the plugin base class is unavailable (older
    Airflow, test-only environments). Used by ``airflow_plugin`` at
    module scope so ``chio_airflow.listener:airflow_plugin`` is a
    valid entry-point target.
    """
    try:
        from airflow.plugins_manager import AirflowPlugin
    except Exception:  # pragma: no cover -- airflow plugin API unavailable
        return None

    listener = get_listener()

    class ChioAirflowPlugin(AirflowPlugin):
        name = "chio_airflow"
        listeners = [listener]

    return ChioAirflowPlugin


airflow_plugin: type | None = _build_airflow_plugin()


__all__ = [
    "XCOM_RUN_RECEIPTS_KEY",
    "XCOM_RUN_STATE_KEY",
    "ChioDAGListener",
    "airflow_plugin",
    "get_listener",
]
