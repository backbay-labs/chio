"""Chio Airflow integration.

Wraps Apache Airflow's operator and TaskFlow surfaces so every task
run flows through the Chio sidecar for capability-scoped authorisation,
denied tasks fail with an :class:`airflow.exceptions.AirflowException`
whose ``__cause__`` is a :class:`PermissionError`, and receipt ids are
pushed into XCom on the current task instance so downstream tasks and
audit consumers can build a DAG-level receipt timeline.

Public surface:

* :class:`ChioOperator` -- drop-in wrapper around any existing
  :class:`airflow.models.BaseOperator`. Calls the Chio sidecar before
  handing control to the inner operator's ``execute()`` and pushes the
  receipt id into XCom on allow.
* :func:`chio_task` -- TaskFlow API decorator that gates an ``@task``
  on a Chio capability evaluation.
* :class:`ChioDAGListener` -- Airflow listener (``@hookimpl``) that
  records per-task receipt ids and publishes a DAG-run aggregation at
  terminal transitions.
* :class:`ChioAirflowError` / :class:`ChioAirflowConfigError` -- error
  types.
"""

from chio_airflow.errors import ChioAirflowConfigError, ChioAirflowError
from chio_airflow.listener import (
    XCOM_RUN_RECEIPTS_KEY,
    XCOM_RUN_STATE_KEY,
    ChioDAGListener,
    airflow_plugin,
    get_listener,
)
from chio_airflow.operator import (
    XCOM_CAPABILITY_KEY,
    XCOM_RECEIPT_ID_KEY,
    XCOM_SCOPE_KEY,
    ChioOperator,
)
from chio_airflow.task_decorator import chio_task

__all__ = [
    "XCOM_CAPABILITY_KEY",
    "XCOM_RECEIPT_ID_KEY",
    "XCOM_RUN_RECEIPTS_KEY",
    "XCOM_RUN_STATE_KEY",
    "XCOM_SCOPE_KEY",
    "ChioAirflowConfigError",
    "ChioAirflowError",
    "ChioDAGListener",
    "ChioOperator",
    "airflow_plugin",
    "chio_task",
    "get_listener",
]
