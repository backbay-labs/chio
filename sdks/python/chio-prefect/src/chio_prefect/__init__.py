"""Chio Prefect integration.

Wraps Prefect's Python SDK (:mod:`prefect`) so every ``@chio_task``
invocation flows through the Chio sidecar for capability-scoped
authorisation, denied tasks raise :class:`PermissionError` (which
Prefect routes to a failed task-run state), and every allow / deny
verdict is emitted as a Prefect Event so the UI renders receipts on
the flow-run timeline.

Public surface:

* :func:`chio_task` -- decorator that wraps a Python function as a
  Prefect :func:`prefect.task` gated on a Chio capability check.
* :func:`chio_flow` -- decorator that wraps a Python function as a
  Prefect :func:`prefect.flow` with a flow-level capability that
  bounds every enclosed task's scope via attenuation.
* :class:`ChioPrefectError` / :class:`ChioPrefectConfigError` -- error
  types.

The decorators mirror the signatures of :func:`prefect.task` and
:func:`prefect.flow` so Prefect options (``retries``,
``retry_delay_seconds``, ``tags``, ``timeout_seconds``, ``task_runner``,
...) pass through verbatim. Sync and async functions are both
supported; the wrapper preserves Prefect's sync / async contract.
"""

from chio_prefect.decorators import chio_flow, chio_task
from chio_prefect.errors import ChioPrefectConfigError, ChioPrefectError
from chio_prefect.events import EVENT_ALLOW, EVENT_DENY

__all__ = [
    "EVENT_ALLOW",
    "EVENT_DENY",
    "ChioPrefectConfigError",
    "ChioPrefectError",
    "chio_flow",
    "chio_task",
]
