"""Apache Flink (PyFlink) operator for Chio-governed streams.

Flink owns exactly-once end-to-end via aligned checkpoints and 2PC
sinks, so this module does not emulate that plumbing. Instead it runs
the same per-event Chio evaluation the broker middlewares do and
emits canonical receipts / DLQ envelopes to Flink side outputs. The
two output tags (``chio-receipt`` and ``chio-dlq``) carry bytes that
are byte-identical to every other middleware's receipt / DLQ so a
single downstream consumer can audit all ingress regardless of
source.

Three operators are exported:

* :class:`ChioAsyncEvaluateFunction` is an ``AsyncFunction`` subclass
  that calls the sidecar concurrently under ``AsyncDataStream``'s
  ordered / unordered wait. ``AsyncFunction`` cannot emit to side
  outputs (PyFlink limitation), so it returns a single
  :class:`EvaluationResult` which is split downstream by
  :class:`ChioVerdictSplitFunction`.
* :class:`ChioVerdictSplitFunction` is a ``ProcessFunction`` that
  takes the async outputs and fans them out to main / receipt / DLQ.
  Chained after the async operator it costs nothing at runtime (same
  task thread).
* :class:`ChioEvaluateFunction` is a single-operator synchronous
  alternative: a ``ProcessFunction`` that blocks the task thread on
  every sidecar call. Acceptable only for low-throughput or co-located
  sidecar deployments.

Importing this module does not require PyFlink to be installed; the
subclasses of PyFlink types degrade to fallback bases that raise
:class:`ChioStreamingConfigError` at construction. Install
``chio-streaming[flink]`` to use the real operators.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from chio_streaming.core import (
    BaseProcessingOutcome,
    ChioClientLike,
    Slots,
    evaluate_with_chio,
    hash_body,
    new_request_id,
    resolve_scope,
    synthesize_deny_receipt,
)
from chio_streaming.dlq import DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import build_envelope

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from pyflink.datastream import (
        OutputTag as _PyFlinkOutputTag,
    )
    from pyflink.datastream import (
        RuntimeContext as _PyFlinkRuntimeContext,
    )
    from pyflink.datastream import (
        StreamExecutionEnvironment as _PyFlinkEnv,
    )

logger = logging.getLogger(__name__)


SidecarErrorBehaviour = Literal["raise", "deny"]


#: Name of the side output tag carrying canonical receipt envelopes.
RECEIPT_TAG_NAME = "chio-receipt"

#: Name of the side output tag carrying canonical DLQ envelopes.
DLQ_TAG_NAME = "chio-dlq"

# PyFlink is an optional dependency. Import the symbols we subclass or
# construct at module import time when available; otherwise define
# fallback bases so the module still imports. The real operators guard
# __init__ with a friendly error instructing users to install the
# [flink] extra.
try:
    from pyflink.datastream import (
        AsyncFunction as _AsyncFunctionBase,
    )
    from pyflink.datastream import (
        ProcessFunction as _ProcessFunctionBase,
    )

    _HAVE_PYFLINK = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAVE_PYFLINK = False

    class _AsyncFunctionBase:  # type: ignore[no-redef]
        """Fallback base used when PyFlink is not installed."""

        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)

    class _ProcessFunctionBase:  # type: ignore[no-redef]
        """Fallback base used when PyFlink is not installed."""

        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)


def _require_pyflink(operator_name: str) -> None:
    if _HAVE_PYFLINK:
        return
    raise ChioStreamingConfigError(
        f"{operator_name} requires PyFlink. Install with: pip install 'chio-streaming[flink]'"
    )


def _receipt_tag() -> _PyFlinkOutputTag:
    """Return the receipt ``OutputTag`` (bytes), built lazily.

    ``OutputTag`` construction needs ``Types`` which only loads when
    PyFlink is installed, so this helper is called from operator code
    (not at import time).
    """
    _require_pyflink("_receipt_tag")
    from pyflink.common.typeinfo import Types
    from pyflink.datastream import OutputTag

    return OutputTag(RECEIPT_TAG_NAME, Types.PICKLED_BYTE_ARRAY())


def _dlq_tag() -> _PyFlinkOutputTag:
    """Return the DLQ ``OutputTag`` (bytes), built lazily."""
    _require_pyflink("_dlq_tag")
    from pyflink.common.typeinfo import Types
    from pyflink.datastream import OutputTag

    return OutputTag(DLQ_TAG_NAME, Types.PICKLED_BYTE_ARRAY())


@dataclass
class ChioFlinkConfig:
    """Configuration for the Chio Flink operators.

    Attributes
    ----------
    capability_id:
        Capability token id every evaluation is bound to. Same shape as
        every other middleware.
    tool_server:
        Chio tool-server id for the source (e.g. ``"kafka://prod"`` or
        ``"flink://fraud-job"``).
    scope_map:
        Optional map from subject (topic / logical event type) to Chio
        ``tool_name``. Falls back to ``events:consume:{subject}``.
    receipt_topic:
        Logical receipt topic carried in the envelope payload. Not a
        Flink sink name; users attach their own sink to the receipt
        side output. ``None`` disables receipt emission (denies still
        flow through the DLQ side output).
    max_in_flight:
        Per-subtask ceiling for concurrent sidecar evaluations. The
        synchronous operator uses it as a simple semaphore; the async
        operator uses it to size the internal slots gauge. Flink's
        ``AsyncDataStream.unordered_wait(capacity=...)`` is the true
        async backpressure knob; size it to match.
    on_sidecar_error:
        ``"raise"`` (default) propagates sidecar unavailability so Flink
        restarts the task and the source rewinds. ``"deny"`` synthesises
        a deny receipt, emits it to the DLQ, and lets processing
        continue.
    subject_extractor:
        Pure function ``(element) -> str``. Defaults to reading
        ``"topic"`` off the ``ctx`` when present, otherwise the empty
        string (which :func:`resolve_scope` rejects). Non-string events
        should supply one.
    parameters_extractor:
        Pure function ``(element) -> dict``. Defaults to a dict with
        ``request_id``, ``subject``, ``body_length``, ``body_hash``
        (mirroring the broker middlewares). ``body_hash`` is the SHA-256
        of canonical-JSON bytes for dicts or ``str(element).encode()``
        otherwise. Custom extractors should include ``body_length`` and
        ``body_hash`` themselves; the operator only back-fills
        ``request_id`` / ``subject``, not the body-derived fields.
        Missing body-hash weakens replay determinism for downstream
        receipt verifiers.
    client_factory:
        Required. Factory that builds a :class:`ChioClientLike` once per
        Flink subtask inside ``open()``. ``ChioClient`` holds a
        connection pool that cannot survive cloudpickle across the
        JobManager -> TaskManager boundary, so factories are the only
        safe shape.
    dlq_router_factory:
        Required. Factory that builds a :class:`DLQRouter` once per
        Flink subtask inside ``open()``. Same rationale as
        ``client_factory``.
    request_id_prefix:
        Prefix for synthesised request ids. Default ``"chio-flink"``
        matches the other middlewares' conventions
        (``chio-pulsar``, ``chio-pubsub``, ...).

    Raises
    ------
    ChioStreamingConfigError:
        If ``capability_id`` / ``tool_server`` are empty, ``max_in_flight``
        is below 1, ``on_sidecar_error`` is not one of the two literals,
        or either factory is missing.
    """

    capability_id: str
    tool_server: str
    client_factory: Callable[[], ChioClientLike]
    dlq_router_factory: Callable[[], DLQRouter]
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None
    max_in_flight: int = 64
    on_sidecar_error: SidecarErrorBehaviour = "raise"
    subject_extractor: Callable[[Any], str] | None = None
    parameters_extractor: Callable[[Any], dict[str, Any]] | None = None
    request_id_prefix: str = "chio-flink"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError("ChioFlinkConfig.capability_id must be non-empty")
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioFlinkConfig.tool_server must be non-empty")
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioFlinkConfig.max_in_flight must be >= 1")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError(
                "ChioFlinkConfig.on_sidecar_error must be 'raise' or 'deny'"
            )
        if self.client_factory is None:
            raise ChioStreamingConfigError(
                "ChioFlinkConfig.client_factory is required (Flink workers "
                "cannot hydrate a ChioClient from ambient DI)"
            )
        if self.dlq_router_factory is None:
            raise ChioStreamingConfigError(
                "ChioFlinkConfig.dlq_router_factory is required (same "
                "serialization constraint as client_factory)"
            )
        if not self.request_id_prefix:
            raise ChioStreamingConfigError("ChioFlinkConfig.request_id_prefix must be non-empty")
        if self.subject_extractor is None:
            # PyFlink ProcessFunction.Context / AsyncFunction do not expose
            # a topic, so there is no sensible generic default. Without an
            # extractor the default would return "" and resolve_scope would
            # raise on every record. Fail at config time so operators never
            # hit a restart loop in production with default settings.
            raise ChioStreamingConfigError(
                "ChioFlinkConfig.subject_extractor is required: Flink "
                "elements have no broker-provided subject, and an empty "
                "subject would make resolve_scope reject every record. "
                "Supply a Callable[[Any], str] that pulls the scope subject "
                "from your event shape (e.g. `lambda e: e['type']`)."
            )


@dataclass
class FlinkProcessingOutcome(BaseProcessingOutcome):
    """Outcome of evaluating a single Flink record.

    ``acked`` on this outcome means "emitted to main output." The
    source-side commit rides Flink's checkpoint barrier, not the
    operator; ``checkpoint_id`` is only populated when a hook actually
    observes it.

    Attributes
    ----------
    element:
        The original input element, preserved for introspection.
    subtask_index:
        Value of ``RuntimeContext.get_index_of_this_subtask()`` at
        evaluation time.
    attempt_number:
        Value of ``RuntimeContext.get_attempt_number()`` at evaluation
        time. Useful for forensics after partial restarts.
    checkpoint_id:
        Populated only when the outcome is observed during a
        ``CheckpointedFunction`` hook.
    receipt_bytes:
        Canonical-JSON envelope bytes when a receipt is emitted. Lets
        downstream splitters avoid re-serialising.
    dlq_bytes:
        Canonical-JSON DLQ record bytes when a denial is emitted.
    """

    element: Any | None = None
    subtask_index: int | None = None
    attempt_number: int | None = None
    checkpoint_id: int | None = None
    receipt_bytes: bytes | None = None
    dlq_bytes: bytes | None = None


@dataclass
class EvaluationResult:
    """Intermediate record returned by :class:`ChioAsyncEvaluateFunction`.

    Used to bridge the ``AsyncFunction`` (main-output-only) -> split
    ``ProcessFunction`` (side outputs) pipeline. Consumers should not
    rely on its exact shape beyond "pass it to
    :class:`ChioVerdictSplitFunction`".

    Attributes
    ----------
    allowed:
        ``True`` when the original element should flow downstream.
    element:
        The original input element.
    receipt_bytes:
        Canonical-JSON envelope bytes, or ``None`` when
        ``receipt_topic`` is not configured.
    dlq_bytes:
        Canonical-JSON DLQ bytes when the verdict was deny (including
        synthesised denies under ``on_sidecar_error="deny"``).
    """

    allowed: bool
    element: Any
    receipt_bytes: bytes | None = None
    dlq_bytes: bytes | None = None


def _canonical_body_bytes(element: Any) -> bytes:
    """Coerce an arbitrary element to stable bytes for ``hash_body``."""
    if isinstance(element, bytes | bytearray):
        return bytes(element)
    if isinstance(element, str):
        return element.encode("utf-8")
    if isinstance(element, Mapping):
        try:
            return json.dumps(
                dict(element),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        except TypeError:
            return str(dict(element)).encode("utf-8")
    return str(element).encode("utf-8")


def _default_parameters_extractor(
    element: Any,
    *,
    request_id: str,
    subject: str,
) -> dict[str, Any]:
    body = _canonical_body_bytes(element)
    return {
        "request_id": request_id,
        "subject": subject,
        "body_length": len(body),
        "body_hash": hash_body(body),
    }


def _register_metrics(metrics_group: Any, slots: Slots) -> dict[str, Any]:
    """Register counters / gauges; log and continue if the API shape differs.

    PyFlink's metrics API has been stable across 1.16+ but the wrapper
    surface differs subtly between releases, so fall back to a
    no-op dict rather than crash the operator.
    """
    metrics: dict[str, Any] = {}
    try:
        metrics["evaluations_total"] = metrics_group.counter("evaluations_total")
        metrics["allow_total"] = metrics_group.counter("allow_total")
        metrics["deny_total"] = metrics_group.counter("deny_total")
        metrics["sidecar_errors_total"] = metrics_group.counter("sidecar_errors_total")
    except Exception as exc:  # pragma: no cover - PyFlink version dependent
        logger.warning("chio-flink: failed to register counter metrics: %s", exc)
    try:
        metrics["in_flight"] = metrics_group.gauge("in_flight", lambda: slots.in_flight)
    except Exception as exc:  # pragma: no cover - PyFlink version dependent
        logger.warning("chio-flink: failed to register in_flight gauge: %s", exc)
    return metrics


def _bump(metrics: dict[str, Any], name: str) -> None:
    counter = metrics.get(name)
    if counter is None:
        return
    try:
        counter.inc()
    except Exception:  # pragma: no cover - metrics should never raise
        logger.debug("chio-flink: counter %s.inc() raised; ignoring", name)


async def _maybe_close(client: Any) -> None:
    """Call ``.close()`` on the client if available, awaiting if async."""
    closer = getattr(client, "close", None)
    if closer is None:
        return
    try:
        result = closer()
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("chio-flink: client.close() raised: %s", exc)
        return
    if hasattr(result, "__await__"):
        try:
            await result
        except Exception as exc:  # pragma: no cover - best effort
            logger.warning("chio-flink: awaiting client.close() raised: %s", exc)


class _ChioFlinkEvaluator:
    """Shared evaluation core used by the sync and async operators.

    Not a PyFlink type: plain Python state plus an async method the
    operator drives. Keeps the sync / async operators byte-equivalent
    (same request-id prefix, same envelope, same DLQ shape).
    """

    def __init__(self, config: ChioFlinkConfig) -> None:
        self._config = config
        self._chio_client: ChioClientLike | None = None
        self._dlq_router: DLQRouter | None = None
        self._slots = Slots(config.max_in_flight)
        self._subtask: int | None = None
        self._attempt: int | None = None
        self._metrics: dict[str, Any] = {}

    @property
    def slots(self) -> Slots:
        return self._slots

    @property
    def subtask_index(self) -> int | None:
        return self._subtask

    @property
    def attempt_number(self) -> int | None:
        return self._attempt

    def bind(self, runtime_context: _PyFlinkRuntimeContext) -> None:
        self._chio_client = self._config.client_factory()
        self._dlq_router = self._config.dlq_router_factory()
        try:
            self._subtask = runtime_context.get_index_of_this_subtask()
        except Exception:  # pragma: no cover - older PyFlink shape
            self._subtask = None
        try:
            self._attempt = runtime_context.get_attempt_number()
        except Exception:  # pragma: no cover - older PyFlink shape
            self._attempt = None
        try:
            metrics_group = runtime_context.get_metrics_group()
        except Exception:  # pragma: no cover - PyFlink version dependent
            metrics_group = None
        if metrics_group is not None:
            self._metrics = _register_metrics(metrics_group, self._slots)

    async def shutdown(self) -> None:
        if self._chio_client is not None:
            await _maybe_close(self._chio_client)
        self._chio_client = None
        self._dlq_router = None

    def _subject_for(self, element: Any, ctx: Any | None) -> str:
        # subject_extractor is required by __post_init__; the call site
        # cannot be reached with extractor=None.
        return str(self._config.subject_extractor(element))  # type: ignore[misc]

    def _parameters_for(
        self,
        element: Any,
        *,
        request_id: str,
        subject: str,
    ) -> dict[str, Any]:
        extractor = self._config.parameters_extractor
        if extractor is not None:
            params = dict(extractor(element))
            params.setdefault("request_id", request_id)
            params.setdefault("subject", subject)
            return params
        return _default_parameters_extractor(element, request_id=request_id, subject=subject)

    async def evaluate(
        self,
        element: Any,
        *,
        ctx: Any | None,
    ) -> FlinkProcessingOutcome:
        """Evaluate ``element`` and return a fully populated outcome."""
        if self._chio_client is None or self._dlq_router is None:
            raise ChioStreamingConfigError(
                "Chio Flink operator used before open() initialised its "
                "collaborators (client / DLQ router)"
            )
        await self._slots.acquire()
        try:
            return await self._evaluate_locked(element, ctx=ctx)
        finally:
            self._slots.release()

    async def _evaluate_locked(
        self,
        element: Any,
        *,
        ctx: Any | None,
    ) -> FlinkProcessingOutcome:
        request_id = new_request_id(self._config.request_id_prefix)
        subject = self._subject_for(element, ctx)
        tool_name = resolve_scope(
            scope_map=self._config.scope_map,
            subject=subject,
        )
        parameters = self._parameters_for(element, request_id=request_id, subject=subject)

        _bump(self._metrics, "evaluations_total")
        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,  # type: ignore[arg-type]
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": subject,
                    "request_id": request_id,
                },
            )
        except ChioStreamingError:
            _bump(self._metrics, "sidecar_errors_total")
            if self._config.on_sidecar_error != "deny":
                raise
            receipt = synthesize_deny_receipt(
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                reason="sidecar unavailable; failing closed",
                guard="chio-streaming-sidecar",
            )

        if not receipt.is_allowed:
            _bump(self._metrics, "deny_total")
            dlq_record = self._dlq_router.build_record(  # type: ignore[union-attr]
                source_topic=subject or "unknown",
                source_partition=None,
                source_offset=None,
                original_key=None,
                original_value=_canonical_body_bytes(element),
                request_id=request_id,
                receipt=receipt,
            )
            # Match every other broker: the receipt envelope is an
            # allow-path signal. The DLQ record carries the deny receipt
            # inside its payload for audit; emitting a separate deny
            # receipt to the allow stream would break the "single
            # receipt consumer" wire-compat guarantee.
            return FlinkProcessingOutcome(
                allowed=False,
                receipt=receipt,
                request_id=request_id,
                element=element,
                subtask_index=self._subtask,
                attempt_number=self._attempt,
                dlq_bytes=dlq_record.value,
                dlq_record=dlq_record,
            )

        receipt_bytes: bytes | None = None
        if self._config.receipt_topic is not None:
            # source_topic is the origin of the event (matching pulsar /
            # pubsub semantics); receipt_topic is a sink target and must
            # not leak into the envelope payload.
            envelope = build_envelope(
                request_id=request_id,
                receipt=receipt,
                source_topic=subject,
            )
            receipt_bytes = envelope.value

        _bump(self._metrics, "allow_total")
        return FlinkProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            element=element,
            subtask_index=self._subtask,
            attempt_number=self._attempt,
            receipt_bytes=receipt_bytes,
            acked=True,
        )


class ChioEvaluateFunction(_ProcessFunctionBase):
    """Synchronous ``ProcessFunction`` variant.

    Latency floor equals the sidecar RTT times the per-element
    processing cost; no pipelining. Use only when the sidecar is
    co-located and RTT is <1ms, or when the source is low-throughput.
    Prefer the async pair (:class:`ChioAsyncEvaluateFunction` +
    :class:`ChioVerdictSplitFunction`) everywhere else.

    ``process_element`` yields the original element on allow, plus
    side outputs to ``RECEIPT_TAG_NAME`` / ``DLQ_TAG_NAME`` as
    appropriate.
    """

    def __init__(self, config: ChioFlinkConfig) -> None:
        _require_pyflink("ChioEvaluateFunction")
        super().__init__()
        self._config = config
        self._evaluator = _ChioFlinkEvaluator(config)
        self._loop: asyncio.AbstractEventLoop | None = None
        # PyFlink is confirmed available by _require_pyflink, so the
        # tags can be constructed once at operator-build time. Avoids
        # per-element OutputTag allocation in the hot path.
        self._receipt_tag: _PyFlinkOutputTag = _receipt_tag()
        self._dlq_tag: _PyFlinkOutputTag = _dlq_tag()

    @property
    def config(self) -> ChioFlinkConfig:
        return self._config

    def open(self, runtime_context: _PyFlinkRuntimeContext) -> None:
        self._evaluator.bind(runtime_context)
        self._loop = asyncio.new_event_loop()

    def close(self) -> None:
        if self._loop is None:
            return
        try:
            self._loop.run_until_complete(self._evaluator.shutdown())
        finally:
            self._loop.close()
            self._loop = None

    def process_element(self, value: Any, ctx: Any) -> Any:
        if self._loop is None:
            raise ChioStreamingConfigError(
                "ChioEvaluateFunction.process_element called before open()"
            )
        outcome = self._loop.run_until_complete(self._evaluator.evaluate(value, ctx=ctx))
        yield from _yield_outcome(outcome, self._receipt_tag, self._dlq_tag)


class ChioAsyncEvaluateFunction(_AsyncFunctionBase):
    """Asynchronous ``AsyncFunction`` variant.

    Wire with ``AsyncDataStream.unordered_wait(..., capacity=N)`` and
    chain into :class:`ChioVerdictSplitFunction` to recover the
    receipt / DLQ side outputs. PyFlink's ``AsyncFunction`` has no
    ``Context`` parameter, so side outputs are unavailable at this
    operator; the downstream split is the documented workaround.
    """

    def __init__(self, config: ChioFlinkConfig) -> None:
        _require_pyflink("ChioAsyncEvaluateFunction")
        super().__init__()
        self._config = config
        self._evaluator = _ChioFlinkEvaluator(config)

    @property
    def config(self) -> ChioFlinkConfig:
        return self._config

    def open(self, runtime_context: _PyFlinkRuntimeContext) -> None:
        self._evaluator.bind(runtime_context)

    def close(self) -> None:
        # Production PyFlink drives close() from the worker thread with
        # no running loop, so the one-shot loop below is the common path.
        # Calling close() from inside a running loop cannot be handled
        # without either deadlocking (sync wait on the loop's own
        # thread) or leaking the HTTP pool (fire-and-forget task). The
        # correct invocation pattern is to dispatch close() off the
        # loop thread (e.g. `await loop.run_in_executor(None, fn.close)`).
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            raise ChioStreamingConfigError(
                "ChioAsyncEvaluateFunction.close() was called from inside "
                "a running event loop. close() is synchronous and cannot "
                "await the HTTP client shutdown without either deadlocking "
                "or leaking the pool. Dispatch close() to a worker thread, "
                "e.g. `await loop.run_in_executor(None, fn.close)`."
            )
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self._evaluator.shutdown())
        finally:
            loop.close()

    async def async_invoke(self, value: Any) -> list[EvaluationResult]:
        outcome = await self._evaluator.evaluate(value, ctx=None)
        return [
            EvaluationResult(
                allowed=outcome.allowed,
                element=outcome.element,
                receipt_bytes=outcome.receipt_bytes,
                dlq_bytes=outcome.dlq_bytes,
            )
        ]


class ChioVerdictSplitFunction(_ProcessFunctionBase):
    """Split :class:`EvaluationResult` from the async evaluator.

    Emits the original element to the main output on allow, the
    receipt bytes (when present) to the receipt side output, and the
    DLQ bytes (when present) to the DLQ side output. Runtime cost is
    negligible when chained to the async operator (same task thread,
    no serialisation).
    """

    def __init__(self) -> None:
        _require_pyflink("ChioVerdictSplitFunction")
        super().__init__()
        # PyFlink is confirmed available by _require_pyflink, so the
        # tags can be constructed once at operator-build time. Avoids
        # per-element OutputTag allocation in the hot path.
        self._receipt_tag: _PyFlinkOutputTag = _receipt_tag()
        self._dlq_tag: _PyFlinkOutputTag = _dlq_tag()

    def process_element(self, value: EvaluationResult, ctx: Any) -> Any:
        if value.allowed:
            yield value.element
        if value.receipt_bytes is not None:
            yield self._receipt_tag, value.receipt_bytes
        if value.dlq_bytes is not None:
            yield self._dlq_tag, value.dlq_bytes


def _yield_outcome(
    outcome: FlinkProcessingOutcome,
    receipt_tag: _PyFlinkOutputTag,
    dlq_tag: _PyFlinkOutputTag,
) -> Any:
    """Generator helper shared by the sync operator."""
    if outcome.allowed:
        yield outcome.element
    if outcome.receipt_bytes is not None:
        yield receipt_tag, outcome.receipt_bytes
    if outcome.dlq_bytes is not None:
        yield dlq_tag, outcome.dlq_bytes


def register_dependencies(
    env: _PyFlinkEnv,
    *,
    requirements_path: str | None = None,
    python_files: list[str] | None = None,
) -> None:
    """Register Python files and requirements with a Flink environment.

    Wraps ``env.add_python_file(path)`` for each entry in
    ``python_files`` plus ``env.set_python_requirements(path)`` when
    supplied. Keeps the call site free of PyFlink incantations. Safe
    to call with both arguments omitted; it becomes a no-op.

    Parameters
    ----------
    env:
        A ``StreamExecutionEnvironment`` instance. Typed loosely
        because PyFlink may not be installed at type-check time.
    requirements_path:
        Path to a ``requirements.txt`` shipped to workers. Typically
        contains ``chio-streaming[flink]`` plus the user's Chio SDK
        and any HTTP client (e.g. ``aiohttp``, ``httpx``).
    python_files:
        Additional ``.py`` / package / ``.zip`` paths to prepend to
        each worker's ``PYTHONPATH``.
    """
    if python_files:
        for path in python_files:
            env.add_python_file(path)
    if requirements_path is not None:
        env.set_python_requirements(requirements_path)


__all__ = [
    "DLQ_TAG_NAME",
    "RECEIPT_TAG_NAME",
    "ChioAsyncEvaluateFunction",
    "ChioEvaluateFunction",
    "ChioFlinkConfig",
    "ChioVerdictSplitFunction",
    "EvaluationResult",
    "FlinkProcessingOutcome",
    "SidecarErrorBehaviour",
    "register_dependencies",
]
