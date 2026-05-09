# Flink Operator Design for Chio Streaming

## Purpose

Resolve the four open questions from `docs/research/chio-streaming-flink-integration.md` and specify `ChioEvaluateFunction`. Grounded in the existing middleware patterns (`pulsar.py`, `pubsub.py`, `nats.py`, `redis_streams.py`, `core.py`).

## Part 1: Four open questions

### Q1. Transform-mode only, or callback mode from day one?

**Recommendation:** Transform mode only in v1. Callback mode is a thin adapter we can add later without API breakage.

**Reasoning.** Broker middlewares take a `MessageHandler` because the broker loop is synchronous and has no downstream operator. Flink inverts that: the dataflow graph is the handler, and side outputs split allow / deny idiomatically. Forcing a callback inside a `ProcessFunction` blocks downstream parallelism, forfeits keyed state in the next operator, and fights Flink's scheduler. A `ChioEvaluateCallbackFunction` adapter (invoke user fn inline, emit receipt) is a later-additive change; transform-first keeps the base class clean. Reverse migration (callback-first -> transform) forces users to restructure their job graph, so we pay the composition cost once at the wrong end.

**If we decide the other way:** We duplicate `MessageHandler` inside PyFlink, fight cloudpickle serialization of closures across the Beam portable runner, and still have to add transform mode later.

### Q2. Keyed-state-aware variant now or later?

**Recommendation:** Ship `ChioEvaluateFunction` (stateless, operates on `DataStream`) in v1. Defer `KeyedChioEvaluateFunction` (operates on `KeyedStream`, can read keyed state in its parameter builder) to v1.1.

**Reasoning.** Keyed state needs `KeyedProcessFunction`, an explicit `StateDescriptor` surface, and checkpoint-aware access -- all additional API surface to learn and test. The stateless operator already composes downstream of `keyBy().window().aggregate()` (see the `SpendSummary` example in the design doc), which covers "Chio-evaluate the aggregate" without keyed state inside the operator itself. The truly stateful case ("deny if this user was flagged in the last hour") is a v1.1 feature whose design depends on unvalidated choices about state population (CDC join? side input? prior Chio evaluation?). Shipping v1 stateless keeps the test surface tractable; checkpoint semantics alone are enough.

**If we decide the other way:** Doubles the operator surface (two classes, two sets of lifecycle hooks, two test matrices) and forces an API decision on state population we haven't validated with a user.

### Q3. Minimum PyFlink / Flink version?

**Recommendation:** `apache-flink >= 1.18, < 2.0`. Document-tested on 1.18 and 1.19; do not block 1.20.

**Reasoning.** The design doc notes "1.18 has stable async I/O in Python, 1.17 doesn't." Python `AsyncFunction` stabilized in 1.18 and is required for `ChioAsyncEvaluateFunction`. 1.18 is also the first release where DataStream side-output ergonomics stopped drifting between minor versions. The API surface we depend on (`ProcessFunction`, `OutputTag`, `RuntimeContext.get_metrics_group`) is stable across 1.18-1.20. Pinning `< 2.0` defends against the 2.0 rework of the Python API.

**If we decide the other way:** Pinning 1.19 excludes enterprise Kubernetes deployments still on 1.18; 1.17 loses async I/O and forces blocking `asyncio.run(...)` per element.

### Q4. Example job?

**Recommendation:** Ship a minimal runnable example: `examples/flink_fraud_scoring.py` -- Kafka source -> `ChioEvaluateFunction` -> Kafka sink (allow) + Kafka DLQ sink (deny) + Kafka receipt sink (2PC). Keep it under 150 lines. No synthetic infrastructure.

**Reasoning.** Other middlewares ship examples in `examples/` or docstrings; the Flink wiring (side outputs, 2PC sinks, checkpoint config, parallelism) is materially more complex and will not be guessed from the class docstring. Fraud-scoring is the canonical "why keyed windows + Chio" story and doubles as the integration-test harness we need anyway. The example does not need Docker Compose -- a `FileSource` suffices, with Kafka as a documented swap. Cost: ~150 lines plus one CI test against the mini-cluster.

**If we decide the other way:** Users hit the side-output + 2PC complexity with no reference and file issues that are really "how do I use Flink."

## Part 2: Operator shape specification

### Module layout

`sdks/python/chio-streaming/src/chio_streaming/flink.py`, with `[flink]` extra in `pyproject.toml` pinning `apache-flink >= 1.18, < 2.0`.

### Config dataclass

```python
@dataclass
class ChioFlinkConfig:
    # Shared with every other middleware
    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None        # logical tag, not a Flink sink name
    max_in_flight: int = 64
    handler_error_strategy: HandlerErrorStrategy = "nack"
    on_sidecar_error: SidecarErrorBehaviour = "raise"

    # Flink-specific
    subject_extractor: Callable[[Any], str] | None = None
    #   Pure function (IN -> str). Lets users pull subject from event
    #   fields rather than relying on headers. Default uses repr or
    #   raises if scope_map has no default.
    parameters_extractor: Callable[[Any], dict[str, Any]] | None = None
    #   Same pattern: pure IN -> parameters dict. Default mirrors the
    #   broker middlewares: request_id, subject, body_hash, body_length.
    client_factory: Callable[[], ChioClientLike] | None = None
    #   Required: constructs a ChioClient inside open() on each worker.
    #   See "Constructor signature" below.
    dlq_router_factory: Callable[[], DLQRouter] | None = None
    #   Required: constructs a DLQRouter on each worker (default topic or
    #   topic_map). Same serialization story as client_factory.
    async_evaluate: bool = False
    #   Selects AsyncFunction path vs ProcessFunction path (see "Lifecycle").
    request_id_prefix: str = "chio-flink"
    #   Matches convention: chio-pulsar / chio-pubsub / chio-nats / chio-flink.

    def __post_init__(self) -> None:
        # Same validations as ChioPulsarConsumerConfig: non-empty
        # capability_id / tool_server, max_in_flight >= 1, strategy
        # enums in range. Additionally: client_factory and
        # dlq_router_factory are required (no way to hydrate them
        # from ambient DI across a Flink worker boundary).
        ...
```

Shared fields (top block) match `ChioPulsarConsumerConfig` / `ChioPubSubConfig` / `ChioNatsConsumerConfig` byte-for-byte. `handler_error_strategy` is retained for v1.1 callback mode; transform mode never reads it. `SidecarErrorBehaviour` is the same `"raise" | "deny"` literal.

Flink-specific fields handle two problems broker middlewares don't: (a) Flink events are not broker messages with headers, so the operator needs a pure function to pull `subject` / `parameters` from arbitrary `IN`; (b) DI-constructed collaborators (`ChioClient`, `DLQRouter`) do not survive serialization across the JobManager -> TaskManager boundary, so we pass factory callables rather than instances.

### Outcome type

```python
@dataclass
class FlinkProcessingOutcome(BaseProcessingOutcome):
    # Inherited: allowed, receipt, request_id, acked, dlq_record, handler_error
    element: Any | None = None              # original IN, for introspection
    subtask_index: int | None = None        # RuntimeContext.index_of_this_subtask
    attempt_number: int | None = None       # RuntimeContext.attempt_number
    checkpoint_id: int | None = None        # Populated when emitted during snapshotState
    key: Any | None = None                  # Present only for KeyedChioEvaluateFunction (v1.1)
```

`acked` shifts meaning: in brokers it means "source-side commit complete"; in Flink it means "emitted to main output." The real commit is the checkpoint barrier, which the operator does not own -- so `checkpoint_id` is only populated when a `CheckpointedFunction` hook actually observes the outcome. `subtask_index` + `attempt_number` are cheap to populate and worth it for partial-failure forensics; broker middlewares have no equivalent because the broker owns partition / offset.

### Side output tags

```python
RECEIPT_TAG: OutputTag[bytes]  = OutputTag("chio-receipt", type_info=Types.BYTE())
DLQ_TAG:     OutputTag[bytes]  = OutputTag("chio-dlq",     type_info=Types.BYTE())
```

Both emit the canonical-JSON bytes produced by `build_envelope` / `DLQRouter.build_record`. Users attach their own sinks to these tagged streams. The byte format is shared with every other middleware so the same receipt consumer works regardless of the upstream broker (the "Wire compatibility" guarantee from the design doc).

### Constructor signature

```python
class ChioEvaluateFunction(ProcessFunction):  # PyFlink ProcessFunction
    def __init__(self, config: ChioFlinkConfig) -> None:
        self._config = config
        # No ChioClient, no DLQRouter stored here. They are not
        # serializable across the JobManager -> TaskManager boundary.
        # Everything stored on self must pickle. config is a dataclass
        # of primitives + pure callables (which cloudpickle handles).
```

The operator does not take `chio_client` / `dlq_router` in its constructor (the broker pattern). PyFlink serializes the function on the JobManager and ships bytes to each Python worker; a `ChioClient` holds an `httpx.AsyncClient` / connection pool that will not survive pickle. Factories are passed through `config` and invoked inside `open()` on each worker -- the same constraint every PyFlink user function imposes on collaborators.

### Lifecycle methods

```python
class ChioEvaluateFunction(ProcessFunction):

    def open(self, runtime_context: RuntimeContext) -> None:
        # Called once per subtask on worker startup.
        self._chio_client = self._config.client_factory()
        self._dlq_router  = self._config.dlq_router_factory()
        self._slots       = Slots(self._config.max_in_flight)
        self._subtask     = runtime_context.get_index_of_this_subtask()
        self._attempt     = runtime_context.get_attempt_number()
        self._loop        = asyncio.new_event_loop()
        # Registered metrics groups: in_flight, evaluations_total,
        # allow_total, deny_total, handler_errors_total, sidecar_errors_total.
        self._metrics     = _register_metrics(runtime_context.get_metrics_group())

    def process_element(self, value: IN, ctx: ProcessFunction.Context) -> Iterable[OUT]:
        # Sync shim over the async core. For the async_evaluate=True path,
        # see ChioAsyncEvaluateFunction below.
        outcome = self._loop.run_until_complete(
            self._dispatch_async(value, ctx.timestamp())
        )
        if outcome.allowed:
            yield value                                    # main output
        # Side outputs via ctx.output(tag, bytes):
        if outcome.receipt is not None and self._config.receipt_topic is not None:
            envelope = build_envelope(
                request_id=outcome.request_id,
                receipt=outcome.receipt,
                source_topic=self._config.receipt_topic,
            )
            ctx.output(RECEIPT_TAG, envelope.value)
        if outcome.dlq_record is not None:
            ctx.output(DLQ_TAG, outcome.dlq_record.value)

    def close(self) -> None:
        # Drain loop, close ChioClient's HTTP session if it has one.
        try:
            self._loop.run_until_complete(
                _maybe_close(self._chio_client)
            )
        finally:
            self._loop.close()

    # Optional: CheckpointedFunction hook (added by mixing in
    # CheckpointedFunction). No operator state to snapshot for v1 -- the
    # receipt side output rides the checkpoint via the sink's 2PC. We
    # implement the hook as a no-op for forward compatibility.
    def snapshot_state(self, context: FunctionSnapshotContext) -> None:
        pass

    def initialize_state(self, context: FunctionInitializationContext) -> None:
        pass
```

The async path (`async_evaluate=True`) uses `AsyncFunction` instead and does not run its own event loop per element -- PyFlink drives the coroutine. Sketch:

```python
class ChioAsyncEvaluateFunction(AsyncFunction):
    def open(self, runtime_context): ...  # as above
    async def async_invoke(self, value: IN, result_future: ResultFuture[OUT]) -> None:
        outcome = await self._dispatch_async(value, timestamp=None)
        result_future.complete([value] if outcome.allowed else [])
        # NOTE: Flink AsyncFunction cannot emit to side outputs directly;
        # the workaround is to emit a wrapped (value, envelope_bytes,
        # dlq_bytes) tuple and split in a downstream ProcessFunction.
        # Documented as a known caveat; not blocking for v1.
```

### Error semantics (fail-closed, matching the other middlewares)

Three failure classes, same taxonomy as pulsar / pubsub / nats:

1. **Sidecar error** (`ChioStreamingError` from `evaluate_with_chio`). If `config.on_sidecar_error == "raise"`, re-raise and let Flink restart the task (replay from source). If `"deny"`, synthesize a deny receipt via `synthesize_deny_receipt`, route to `DLQ_TAG`. Default `"raise"` so the operator fails closed (nothing passes main output).
2. **DLQ publish error** (side output emission to a full buffer or checkpoint-barrier backpressure stall). Propagate; Flink's own backpressure handles it, and on checkpoint failure the source rewinds. Never swallow.
3. **Handler error.** Not applicable in transform mode (there is no handler). Kept on the outcome type (`handler_error: Exception | None = None`) so v1.1's callback wrapper has a field to populate.

The broker invariant -- "every element produces a main-output or DLQ emission" -- holds as long as (a) `on_sidecar_error="deny"` in production, or (b) the user accepts task restarts on sidecar outages.

### Request-id prefix

`new_request_id("chio-flink")`. Matches the convention (`chio-pulsar` / `chio-pubsub` / `chio-nats` / `chio-redis-streams`).

## Part 3: New open questions

1. **Non-Kafka receipt sinks.** The 2PC story assumes a transactional Kafka sink. File / HTTP / other sinks either need `TwoPhaseCommitSinkFunction` or accept at-least-once with `request_id` dedupe. Ship a reference `ChioReceiptKafkaSink`, document the 2PC contract, or both?
2. **Side outputs + `AsyncFunction` do not mix.** `async_invoke` cannot call `ctx.output(tag, ...)` -- there is no `Context`. Workaround: emit a wrapped tuple and split downstream. Is that acceptable friction, or should v1 ship only the sync `ProcessFunction` variant?
3. **Mini-cluster testing in CI.** PyFlink's mini-cluster boots a JVM; slow / flaky on macOS ARM and some runners. Gate integration tests behind `FLINK_INTEGRATION=1` and run in a dedicated lane?
4. **Extractor serialization.** Arbitrary callables go through cloudpickle; closures over unpicklable handles fail at `open()`-time. Document "pure function, no closures," or provide a named-field default that covers 80% of cases?
5. **Metrics naming.** Broker middlewares expose `in_flight` as a property. Flink has a metrics group. Match OpenTelemetry conventions (`chio.evaluations.total{verdict}`) or mirror broker names verbatim?
6. **JVM milestone.** PyFlink-first is resolved, but should JVM be v1.1 or v2.0? Deciding now prevents PyFlink-only API choices that Java will have to mirror awkwardly.

## Evidence trail

- Config conventions: `pulsar.py:86-153`, `pubsub.py:81-148`, `nats.py:80-145`, `redis_streams.py:68-120`.
- Outcome type: `core.py:46-55` (`BaseProcessingOutcome`).
- Request-id prefix: `new_request_id` callsites in each middleware.
- Fail-closed path: `core.py:71-111` plus each `_process`'s `except ChioStreamingError`.
- Wire format: `receipt.py:83-149`, `ENVELOPE_VERSION = "chio-streaming/v1"`.
