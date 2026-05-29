"""Chio-governed Airflow operator wrapper.

:class:`ChioOperator` is the primary integration surface for brownfield
Airflow DAGs: wrap any existing :class:`airflow.models.BaseOperator`
with a pre-``execute()`` Chio capability evaluation. Allow verdicts let
the inner operator's ``execute()`` run unchanged and push the receipt
id into XCom under the ``chio_receipt_id`` key. Deny verdicts raise
:class:`airflow.exceptions.AirflowException` with a
:class:`PermissionError` as ``__cause__`` so Airflow's scheduler marks
the task as failed while preserving the ``except PermissionError``
contract for callers inspecting the cause chain.

The wrapper deliberately does not try to deep-merge inner-operator
arguments into its own :meth:`BaseOperator.__init__` signature.
Airflow's operator surface is too wide for that, so we keep the
ownership boundary clean: the caller constructs the inner operator
with whatever kwargs it needs, hands the instance to
``ChioOperator(inner_operator=...)``, and sets the Chio-facing options
(``scope``, ``tool_name``, ``capability_id``, ``tool_server``) on the
wrapper itself.

Redaction scope
---------------
Argument redaction (``chio_adapter_base.redact.redact_args``) is wired
only on the TaskFlow path (``chio_airflow.task_decorator.chio_task``).
``ChioOperator`` records DAG / task / capability context fields in the
sidecar payload rather than per-tool argument bodies because the
wrapper does not introspect the inner operator's parameter signature;
the inner operator's templated fields and ``op_kwargs`` are owned by
the caller and remain outside the redaction surface here.
"""

from __future__ import annotations

from typing import Any

from airflow.exceptions import AirflowException
from airflow.models import BaseOperator
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope

from chio_airflow._evaluation import ChioClientLike, evaluate_sync
from chio_airflow.errors import ChioAirflowConfigError

#: XCom key under which the allow-path receipt id is published.
XCOM_RECEIPT_ID_KEY = "chio_receipt_id"
#: XCom key under which the scope declared by the wrapper is published.
XCOM_SCOPE_KEY = "chio_scope"
#: XCom key under which the capability id is published.
XCOM_CAPABILITY_KEY = "chio_capability_id"


class ChioOperator(BaseOperator):
    """Wraps another operator with a Chio capability evaluation.

    Parameters
    ----------
    inner_operator:
        An already-constructed :class:`BaseOperator`. Its
        ``execute(context)`` method runs only if the Chio sidecar returns
        an allow verdict for this wrapper's declared scope. We do not
        forward ``inner_operator``'s scheduling options (``retries``,
        ``queue``, etc.); those belong to the ChioOperator itself, which
        is the scheduler-visible task.
    capability_id:
        Pre-minted capability id for the sidecar evaluation. Required:
        the Chio kernel refuses to evaluate without one.
    scope:
        Optional :class:`ChioScope` describing what the task is allowed
        to do. Declarative: the kernel side enforces. Published to
        XCom so downstream tasks can reason about the allowed surface.
    tool_server:
        Chio tool server id. When unset, the sidecar evaluates against
        the implicit empty server; teams with a real server topology
        should always pass it.
    tool_name:
        Chio tool name to use for evaluation. Defaults to the
        operator's ``task_id`` so the sidecar can correlate verdicts
        to the DAG node that produced them.
    sidecar_url:
        Base URL of the Chio sidecar when the wrapper has to mint its
        own :class:`ChioClient`. Ignored when ``chio_client`` is
        supplied.
    chio_client:
        Optional :class:`chio_sdk.client.ChioClient` or
        :class:`chio_sdk.testing.MockChioClient`. Tests inject a mock;
        production deployments usually let the wrapper mint a default
        client against ``sidecar_url``.
    task_id:
        Forwarded to :class:`BaseOperator`. If omitted, defaults to
        ``f"chio_{inner_operator.task_id}"`` so the wrapper does not
        collide with the inner operator's own id.
    **operator_kwargs:
        Forwarded verbatim to :class:`BaseOperator.__init__`
        (``retries``, ``retry_delay``, ``trigger_rule``, ``dag``, etc.).

    XCom contract
    -------------
    On allow, three keys are pushed on the current task instance:

    * ``chio_receipt_id`` -- the receipt id returned by the kernel.
    * ``chio_scope`` -- the canonicalised scope (as a dict) the
      wrapper declared.
    * ``chio_capability_id`` -- the capability id used for evaluation.

    The inner operator's own return value is returned unchanged so
    downstream tasks that ``xcom_pull`` on the standard ``return_value``
    key keep working.
    """

    template_fields = ("tool_name",)
    ui_color = "#f4d35e"

    def __init__(
        self,
        *,
        inner_operator: BaseOperator,
        capability_id: str,
        scope: ChioScope | None = None,
        tool_server: str = "",
        tool_name: str | None = None,
        sidecar_url: str | None = None,
        chio_client: ChioClientLike | None = None,
        task_id: str | None = None,
        **operator_kwargs: Any,
    ) -> None:
        if inner_operator is None:
            raise ChioAirflowConfigError(
                "ChioOperator requires an inner_operator; pass an already-"
                "constructed BaseOperator instance"
            )
        if not capability_id:
            raise ChioAirflowConfigError(
                "ChioOperator requires a capability_id for sidecar evaluation"
            )

        resolved_task_id = task_id or f"chio_{inner_operator.task_id}"
        # Airflow's operator metaclass injects ``default_args`` into the
        # constructor keyword set at DAG-attachment time; drop it so our
        # named kwargs aren't mistaken for defaults we're meant to
        # forward verbatim.
        operator_kwargs.pop("default_args", None)
        super().__init__(task_id=resolved_task_id, **operator_kwargs)

        self.inner_operator = inner_operator
        self.capability_id = capability_id
        self.scope = scope
        self.tool_server = tool_server
        self.tool_name = tool_name or inner_operator.task_id
        self.sidecar_url = sidecar_url or ChioClient.DEFAULT_BASE_URL
        self.chio_client = chio_client

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, context: Any) -> Any:
        """Evaluate the capability, run the inner operator, push receipt id.

        Deny path: translates the inner :class:`PermissionError` into
        an :class:`AirflowException` whose ``__cause__`` is the
        original :class:`PermissionError`. This preserves the
        :class:`PermissionError` cause while surfacing an Airflow-native
        failure type to the scheduler so retry rules apply uniformly.
        """
        dag_id = _context_dag_id(context)
        run_id = _context_run_id(context)
        parameters = _context_parameters(context)

        try:
            receipt = evaluate_sync(
                chio_client=self.chio_client,
                sidecar_url=self.sidecar_url,
                capability_id=self.capability_id,
                tool_server=self.tool_server,
                tool_name=self.tool_name,
                parameters=parameters,
                task_id=self.task_id,
                dag_id=dag_id,
                run_id=run_id,
            )
        except PermissionError as exc:
            self.log.error(
                "Chio denied %s (dag=%s run=%s): %s",
                self.tool_name,
                dag_id,
                run_id,
                exc,
            )
            raise AirflowException(str(exc)) from exc

        # Allow path: run the inner operator. Any exception raised by
        # the inner operator propagates to the scheduler as-is so
        # Airflow can apply its normal retry / alerting policy; the
        # capability was granted, the task body just failed.
        result = self.inner_operator.execute(context)

        self._publish_receipt_xcom(context, receipt_id=receipt.id)

        return result

    # ------------------------------------------------------------------
    # XCom helpers
    # ------------------------------------------------------------------

    def _publish_receipt_xcom(self, context: Any, *, receipt_id: str) -> None:
        """Push receipt id / scope / capability into XCom on the current TI.

        Swallows any :class:`Exception` from the XCom backend: failing
        to persist the receipt id must not undo a successful inner
        execute. The receipt id is also logged at ``INFO`` so operators
        always have a trail even if XCom is misbehaving.
        """
        ti = _context_task_instance(context)
        self.log.info(
            "Chio allow receipt=%s scope=%s capability=%s",
            receipt_id,
            _scope_dict(self.scope),
            self.capability_id,
        )
        if ti is None:
            return
        try:
            ti.xcom_push(key=XCOM_RECEIPT_ID_KEY, value=receipt_id)
            ti.xcom_push(key=XCOM_SCOPE_KEY, value=_scope_dict(self.scope))
            ti.xcom_push(key=XCOM_CAPABILITY_KEY, value=self.capability_id)
        except Exception:  # noqa: BLE001 -- XCom failure must not fail the task
            self.log.warning(
                "failed to push Chio receipt id to XCom", exc_info=True
            )


# ---------------------------------------------------------------------------
# Context accessors (resilient to the thin context dicts tests pass in)
# ---------------------------------------------------------------------------


def _context_dag_id(context: Any) -> str | None:
    dag = _safe_get(context, "dag")
    if dag is not None:
        dag_id = getattr(dag, "dag_id", None)
        if dag_id:
            return str(dag_id)
    return _safe_get(context, "dag_id")


def _context_run_id(context: Any) -> str | None:
    run_id = _safe_get(context, "run_id")
    if run_id:
        return str(run_id)
    dag_run = _safe_get(context, "dag_run")
    if dag_run is not None:
        rid = getattr(dag_run, "run_id", None)
        if rid:
            return str(rid)
    return None


def _context_task_instance(context: Any) -> Any | None:
    """Return the task instance from the Airflow execute-context dict.

    Airflow exposes the running TI under the ``ti`` key (and, as a
    legacy alias, ``task_instance``). We try both so tests can inject
    whichever they like.
    """
    ti = _safe_get(context, "ti")
    if ti is not None:
        return ti
    return _safe_get(context, "task_instance")


def _context_parameters(context: Any) -> dict[str, Any]:
    """Build the sidecar-bound parameters dict from the Airflow context.

    The kernel hashes this payload into the receipt for replay
    detection, so it must be deterministic for identical inputs.
    """
    payload: dict[str, Any] = {}
    dag_id = _context_dag_id(context)
    if dag_id:
        payload["dag_id"] = dag_id
    run_id = _context_run_id(context)
    if run_id:
        payload["run_id"] = run_id
    execution_date = _safe_get(context, "execution_date")
    if execution_date is not None:
        payload["execution_date"] = str(execution_date)
    logical_date = _safe_get(context, "logical_date")
    if logical_date is not None:
        payload["logical_date"] = str(logical_date)
    return payload


def _safe_get(context: Any, key: str) -> Any:
    """Return ``context[key]`` when ``context`` supports ``__getitem__``.

    Airflow passes a dict, but the rendered-context proxy also accepts
    ``.get`` / ``__getitem__``. Tests sometimes pass a bare dict. Any
    :class:`Exception` (including :class:`KeyError`) yields ``None`` so
    our accessors are best-effort and never blow up the operator.
    """
    if context is None:
        return None
    try:
        return context[key]
    except Exception:  # noqa: BLE001 -- context access is best-effort
        try:
            return context.get(key)
        except Exception:  # noqa: BLE001
            return None


def _scope_dict(scope: ChioScope | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    return scope.model_dump(exclude_none=True)


__all__ = [
    "XCOM_CAPABILITY_KEY",
    "XCOM_RECEIPT_ID_KEY",
    "XCOM_SCOPE_KEY",
    "ChioOperator",
]
