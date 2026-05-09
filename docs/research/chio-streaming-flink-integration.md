# Flink Integration for Chio Streaming

## Status

Ready for implementation. Supporting research under `docs/research/flink/`:

- `flink/01-flink-internals.md` -- 2PC contract, side outputs, failure scenarios, AsyncFunction limits, checkpoint backpressure.
- `flink/02-pyflink-api.md` -- PyFlink ProcessFunction / AsyncFunction / keyed state / KafkaSink / dependency management / testing. Versions: Flink 2.2.0 (Dec 2025) stable.
- `flink/03-operator-design.md` -- config / outcome / lifecycle spec grounded in existing middleware conventions.

## Goal

Ship a PyFlink-native operator that evaluates each event against a Chio capability, emits signed receipts, and routes denials to a DLQ -- with the same semantics and byte-compatible envelope the other broker middlewares emit.

## Why native, not a shim over the Kafka middleware

Summarised from the prior draft, unchanged:

- The Kafka middleware drives its own Kafka transactions; Flink also manages exactly-once via aligned barriers and 2PC sinks. Two transaction coordinators on the same offsets fight.
- Per-event ack in the middleware is coarser than Flink's checkpoint granularity.
- A middleware in `ProcessFunction` has no access to keyed state, windows, or joins. Chio can only see raw event fields, not derived state.
- Two competing backpressure systems (`Slots(max_in_flight)` vs credit-based flow control) produce pathological stalls.

Running the Kafka middleware inside a Flink job works as a stopgap. A native operator does strictly more.

## Architecture (revised after research)

The preliminary design said "ProcessFunction + AsyncFunction pair" as if they were interchangeable. Research 01 §4 corrects this: **`AsyncFunction` cannot emit to side outputs.** Its interface is `async def async_invoke(value) -> list`, with no `Context` parameter. So the async path has to be a two-operator chain:

```
source
  └─ AsyncDataStream.unordered_wait(ChioAsyncEvaluateFunction)      # sidecar call
       └─ ProcessFunction(ChioVerdictSplitFunction)                  # split by verdict
            ├─ main output ──── allowed events → downstream
            ├─ RECEIPT_TAG ──── receipt envelopes (bytes) → KafkaSink EXACTLY_ONCE
            └─ DLQ_TAG ──────── DLQ envelopes (bytes) → KafkaSink EXACTLY_ONCE
```

Chained operators run in the same task thread with no serialization cost; the two-operator split is free at runtime.

For teams that accept a throughput cap in exchange for simpler topology, we also ship a single-operator `ChioEvaluateFunction(ProcessFunction)` that runs the sidecar call synchronously on the task thread. Fine for low-throughput / low-latency sidecar deployments; not the primary path.

### Checkpoint semantics

- `KafkaSink` with `DeliveryGuarantee.EXACTLY_ONCE` implements `TwoPhaseCommitSinkFunction` internally. We do NOT write our own 2PC sink for Kafka -- we configure Flink's.
- Side outputs flow through the same barrier mechanism as the main output. A receipt emitted during `process_element` of an event before barrier N is part of checkpoint N. On success, the sink commits atomically. On failure, the source rewinds and the sink's prepared transaction aborts -- so the first run's receipts are never visible (research 01 §3).
- Sidecar determinism (Chio evaluates deterministically on `(policy_hash, input)`) is a correctness requirement, not a nice-to-have: re-evaluation after replay must produce byte-identical receipts or the aborted-and-redone sink writes could diverge.
- Non-Kafka receipt sinks (HTTP receipt store, JDBC, etc.) have **no Python `TwoPhaseCommitSinkFunction` base class** (research 02 §4). Users who need non-Kafka sinks either write Java 2PC sinks, accept at-least-once with `request_id` dedupe, or write to an intermediate Kafka topic and bridge.

## Decisions on the four open questions

All four are now answered (research 03 §Part 1).

### 1. Transform mode or callback mode?

**Transform mode only in v1.** The Flink dataflow graph already *is* the handler; forcing a callback inside `ProcessFunction` blocks downstream parallelism and forfeits keyed state. A callback adapter is trivially additive later; reverse migration would force users to restructure their job graph.

### 2. Keyed-state-aware variant?

**Stateless `ChioEvaluateFunction` only in v1.** The stateless operator already composes *after* `keyBy().window().aggregate()`, which covers "Chio-evaluate the aggregate." A `KeyedChioEvaluateFunction` that reads state *inside* the operator depends on unvalidated design choices about state population (CDC join? side input? prior Chio evaluation?). v1.1 material.

### 3. Minimum Flink version?

**`apache-flink >= 2.2.0, < 3.0`.** Research 02 §7 is authoritative: PyFlink `AsyncFunction` shipped in Flink 2.2.0 (Dec 2025) via FLINK-38560 / 38561 / 38563 / 38591. Prior researcher claims that AsyncFunction "stabilized in 1.18" were wrong -- 1.18 has Python async I/O for a different shape. We want the 2.2 `async def async_invoke` interface + `AsyncDataStream.unordered_wait_with_retry` + `AsyncRetryStrategy`.

Consequence: we drop the prior doc's "1.18" floor. Users on older Flink can still use `chio_streaming.middleware` (the Kafka middleware) as an interim.

Confirm before shipping: that `flink-connector-kafka` has a 2.2-compatible Python wheel release (research 02 §Remaining uncertainty 4).

### 4. Example job?

**Ship `examples/flink_fraud_scoring.py` (under ~150 lines).** Doubles as the integration-test harness. Side outputs + 2PC sink wiring will not be guessed from a docstring.

## Operator spec (v1)

Full spec in `flink/03-operator-design.md`. Summary:

### Module

`sdks/python/chio-streaming/src/chio_streaming/flink.py`. `[flink]` extra in `pyproject.toml`: `apache-flink >= 2.2.0, < 3.0`; `aiohttp` optional (users supply their own `ChioClient`).

### Exports

- `ChioAsyncEvaluateFunction(AsyncFunction)` -- primary path; calls the sidecar; emits a wrapped `EvaluationResult` tuple.
- `ChioVerdictSplitFunction(ProcessFunction)` -- chained after the async one; splits by verdict into main / RECEIPT_TAG / DLQ_TAG.
- `ChioEvaluateFunction(ProcessFunction)` -- single-operator sync alternative for low-throughput cases.
- `ChioFlinkConfig` -- dataclass mirroring `ChioPulsarConsumerConfig` / `ChioPubSubConfig` conventions, with Flink-specific `subject_extractor`, `parameters_extractor`, `client_factory`, `dlq_router_factory`.
- `FlinkProcessingOutcome` -- `BaseProcessingOutcome` subclass; adds `element`, `subtask_index`, `attempt_number`, `checkpoint_id`.
- `RECEIPT_TAG`, `DLQ_TAG` -- `OutputTag("chio-receipt" / "chio-dlq", Types.PICKLED_BYTE_ARRAY())`.
- `register_dependencies(env, *, requirements_path=None)` -- helper that wraps `add_python_file` + `set_python_requirements` so users don't have to remember the incantation.

### Config (abbreviated)

```python
@dataclass
class ChioFlinkConfig:
    # Shared with every other middleware (byte-compatible semantics)
    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None               # logical name carried in envelope
    max_in_flight: int = 64
    on_sidecar_error: Literal["raise", "deny"] = "raise"

    # Flink-specific (events have no broker headers)
    subject_extractor: Callable[[Any], str] | None = None
    parameters_extractor: Callable[[Any], dict[str, Any]] | None = None

    # Non-serializable collaborators: built in open() on each worker
    client_factory: Callable[[], ChioClientLike]
    dlq_router_factory: Callable[[], DLQRouter]

    request_id_prefix: str = "chio-flink"          # matches chio-pulsar / chio-nats / ...
```

Factories (not instances) are required because `ChioClient` holds a connection pool that will not survive cloudpickle across the JobManager → TaskManager boundary. Every PyFlink user function imposes the same constraint.

### Side output tags

```python
RECEIPT_TAG = OutputTag("chio-receipt", Types.PICKLED_BYTE_ARRAY())
DLQ_TAG     = OutputTag("chio-dlq",     Types.PICKLED_BYTE_ARRAY())
```

Carry the canonical-JSON bytes from `build_envelope` / `DLQRouter.build_record`. Byte-identical to every other middleware so a single receipt consumer works across all sources.

### Lifecycle

- `open(runtime_context)`: build `ChioClient`, `DLQRouter`, `Slots(max_in_flight)`, event loop (sync variant only), metrics group. Capture `subtask_index` / `attempt_number`.
- `async_invoke(value)` (async variant) OR `process_element(value, ctx)` (sync variant): resolve scope, call sidecar via `evaluate_with_chio`, handle `ChioStreamingError` per `on_sidecar_error`, build envelope, emit.
- `close()`: drain loop and close HTTP session.
- `snapshot_state` / `initialize_state`: no-ops in v1. No operator state -- the receipt side output rides the sink's 2PC.

### Error taxonomy

- `on_sidecar_error="raise"` (default): sidecar unavailability re-raises → Flink restarts the task → source rewinds → replay. Matches fail-closed.
- `on_sidecar_error="deny"`: synthesize a deny receipt via `synthesize_deny_receipt` and route to DLQ. Structural `SYNTHETIC_RECEIPT_MARKER` so verifiers reject them without string-matching.
- DLQ publish error: propagate. Flink's backpressure handles buffer pressure; on checkpoint failure the source rewinds.

## Scope estimate

- `src/chio_streaming/flink.py`: ~400-500 lines. ChioAsyncEvaluateFunction + ChioVerdictSplitFunction + ChioEvaluateFunction (sync) + config + outcome + helpers.
- `tests/test_flink.py`: ~300 lines on top of `PyFlinkStreamingTestCase` (research 02 §6). Covers allow, deny, sidecar error paths, fail-closed synthesis, side-output routing. No receipt-sink 2PC replay test in v1 (requires broker + orchestration; deferred to integration lane).
- `examples/flink_fraud_scoring.py`: ~150 lines. FileSource for local runs, KafkaSource swap documented.
- `pyproject.toml`: `[flink]` extra pinning `apache-flink >= 2.2, < 3.0`.
- README section: quickstart + wire compatibility note + dependency packaging (research 02 §5).

## Known limitations (document in README)

1. **Non-Kafka 2PC sinks**: no Python `TwoPhaseCommitSinkFunction`. For non-Kafka receipt sinks, users get at-least-once unless they write Java.
2. **AsyncFunction + side outputs**: must chain through `ChioVerdictSplitFunction`. Extra operator, no cost at runtime (chained), but extra mental model.
3. **Kafka `transaction.timeout.ms`**: must exceed checkpoint interval + commit latency or receipts are lost on transaction expiry. Document.
4. **Sidecar capacity**: total in-flight against the sidecar is `capacity * parallelism`. Size the sidecar pool accordingly (research 02 §Remaining uncertainty 5).

## Open questions before implementation

Mostly closed, but worth the user's attention:

1. **Kafka connector wheel availability on 2.2.** Research 02 flagged this. Confirm `flink-connector-kafka` ships a 2.2-compatible Python wheel before committing to the 2.2 floor. If not, the interim is to ship the sync `ChioEvaluateFunction` only (1.18+) and add async in a follow-up when 2.2 connectors land.
2. **Metrics naming convention.** Mirror broker names (`in_flight`, `allow_total`) or adopt OpenTelemetry-ish (`chio.evaluations.total{verdict}`)? The existing middlewares expose a property; Flink has a typed metrics group. Small decision with long tail.
3. **JVM milestone timing.** Still deferred; decide now whether it's v1.1 or v2.0 to prevent PyFlink-only choices that Java has to mirror awkwardly.

## Risks

1. **PyFlink 2.2 connector churn.** Flink connectors ship on separate cadences post-1.17. If `flink-connector-kafka` lags, our 2.2 floor bites. Mitigation above.
2. **Mini-cluster flakiness on macOS ARM / CI.** Gate integration tests behind `FLINK_INTEGRATION=1` and run in a dedicated lane.
3. **Cloudpickle + closures.** `subject_extractor` / `parameters_extractor` callables serialize via cloudpickle. Closures over unpicklable handles fail at `open()`-time. Document "pure function, no closures."

## Recommendation

Proceed to implementation. PyFlink-first, `AsyncFunction → ProcessFunction(split)` as the primary topology, single-operator sync as a simpler fallback. 2PC via `KafkaSink EXACTLY_ONCE`; non-Kafka 2PC documented as a limitation. Example job doubles as the integration test. Defer JVM and keyed-state operator to later milestones.

## Post-implementation review notes

Three review agents (correctness, PyFlink-API, tests) audited the
initial implementation (commit 84c1dd8e). Cleanup pass findings:

- **source_topic fix (P2)**: initial implementation passed the receipt
  *destination* topic as `build_envelope(..., source_topic=...)`, which
  drifted from Pulsar / Pub/Sub (which pass the resolved subject). Fixed
  to pass the event origin subject so audit queries correlate receipts
  back to source.
- **Async `close()` fallback (P2)**: the running-loop branch scheduled
  `shutdown()` as a fire-and-forget task, leaking the HTTP connection
  pool. Resolved by bounding the wait via
  `asyncio.run_coroutine_threadsafe(...).result(timeout=5s)`. Production
  PyFlink invokes close synchronously (no running loop), so this branch
  is only exercised by in-process test harnesses.
- **Example timeout (P1)**: `AsyncDataStream.unordered_wait` takes a
  `pyflink.common.Time`, not an int. Fixed in the example and the README
  snippet.
- **Coverage gaps**: backpressure, DLQ-router-failure, running-loop
  close(), counter verification, subtask/attempt/dlq_record assertions,
  and byte parity for async + DLQ paths were all added in the cleanup
  pass.

No new coverage gaps remain open.
