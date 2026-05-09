# Flink Integration Review: PyFlink API Usage

## Summary

The `chio-streaming` Flink integration targets the PyFlink 2.2 surface correctly for the operator side (ProcessFunction, AsyncFunction, OutputTag, RuntimeContext, metrics, dependency registration). The `async_invoke` signature, `yield (tag, value)` side-output idiom, lazy `OutputTag` construction, and subtask/attempt/metrics lookups all match PyFlink master and the 2.2 release notes. The **example job has one hard blocker**: it passes an `int` to `AsyncDataStream.unordered_wait`'s `timeout` parameter, which PyFlink requires to be a `pyflink.common.Time` instance. There are a couple of smaller issues in the metrics helper and the sync operator, but the core operator module is sound.

## Findings

### [P1] `AsyncDataStream.unordered_wait` timeout must be a `Time`, not an int

File: `sdks/python/chio-streaming/examples/flink_fraud_scoring.py:129-135`.

```python
evaluated = AsyncDataStream.unordered_wait(
    transactions,
    ChioAsyncEvaluateFunction(config),
    10_000,                               # <-- BUG: passed as `timeout`
    output_type=Types.PICKLED_BYTE_ARRAY(),
    capacity=128,
)
```

`unordered_wait(data_stream, async_function, timeout: Time, capacity: int = 100, output_type: TypeInformation = None)` -- PyFlink master [`async_data_stream.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/async_data_stream.py#L33-L53) and every test in [`test_async_function.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/tests/test_async_function.py) pass `Time.seconds(N)` (`from pyflink.common import Time`). The validator at line 161 of `async_data_stream.py` calls `timeout.to_milliseconds()`; passing `10_000` raises `AttributeError: 'int' object has no attribute 'to_milliseconds'` as soon as retry validation runs, and would fail in the Java bridge regardless.

Recommended fix:
```python
from pyflink.common import Time
...
AsyncDataStream.unordered_wait(
    transactions,
    ChioAsyncEvaluateFunction(config),
    Time.milliseconds(10_000),
    capacity=128,
    output_type=Types.PICKLED_BYTE_ARRAY(),
)
```

### [P2] `unordered_wait` `capacity` / `output_type` are not keyword-only

File: `sdks/python/chio-streaming/examples/flink_fraud_scoring.py:129-135`.

The PyFlink signature is positional: `(data_stream, async_function, timeout, capacity=100, output_type=None)`. Python allows passing `capacity=128, output_type=...` as kwargs (they match the parameter names), so the current call works once the timeout is fixed. Style note only: every shipping PyFlink test uses positional form, e.g. `AsyncDataStream.unordered_wait(ds, fn, Time.seconds(5), 2, Types.INT())`. Keeping the positional style matches upstream idiom and avoids surprise if a future PyFlink release tightens the signature.

### [P2] Example imports `DeliveryGuarantee` from `pyflink.datastream.connectors.kafka` (commented block)

File: `sdks/python/chio-streaming/examples/flink_fraud_scoring.py:154-157`.

```python
# from pyflink.datastream.connectors.kafka import (
#     KafkaSource, KafkaSink, KafkaRecordSerializationSchema,
#     KafkaOffsetsInitializer, DeliveryGuarantee,
# )
```

`DeliveryGuarantee` is defined in [`pyflink.datastream.connectors.base`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/connectors/kafka.py#L28) and re-exported into the kafka module via a `from .base import DeliveryGuarantee, ...` line but is **not** in the kafka module's `__all__`. Importing it from `...connectors.kafka` currently works because Python name resolution doesn't consult `__all__`, but it's not the documented path and could break if upstream tightens the re-export. The canonical import is:

```python
from pyflink.datastream.connectors.base import DeliveryGuarantee
```

This is in a commented-out production swap block, so no current runtime impact, but worth fixing so users copy-paste a correct import.

### [P3] `MetricGroup.gauge()` returns `None`, not a Gauge handle

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:376`.

```python
metrics["in_flight"] = metrics_group.gauge("in_flight", lambda: slots.in_flight)
```

Per [`metricbase.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/metrics/metricbase.py#L57-L63), the signature is `def gauge(self, name: str, obj: Callable[[], int]) -> None`. Storing the return value produces `metrics["in_flight"] = None`, which never causes a crash (nothing reads it), but the slot is dead weight. Minor: drop the assignment or comment that the gauge is side-effect only.

### [P3] Counter entries stored under names `_bump` cannot locate

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:367-379, 382-389`.

`_register_metrics` populates `metrics["evaluations_total"] / ["allow_total"] / ["deny_total"] / ["sidecar_errors_total"]`, and `_bump` does `metrics.get(name)` with exactly those keys. No defect, but note that the whole dict becomes empty if the initial `metrics_group.counter(...)` call raises (caught and logged), so every later `_bump` is a no-op -- metrics are silently lost after the warning. If that behaviour is intentional (graceful degradation), consider a top-level warning once per operator rather than per metric.

### [P3] Sync operator blocks a per-subtask event loop from `process_element`

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:610-629`.

```python
def open(self, runtime_context):
    self._evaluator.bind(runtime_context)
    self._loop = asyncio.new_event_loop()
...
def process_element(self, value, ctx):
    outcome = self._loop.run_until_complete(self._evaluator.evaluate(value, ctx=ctx))
```

This is correct and matches the research doc's "per-operator loop in `open()`" pattern, but a single persistent loop driven via `run_until_complete` from the Flink task thread will behave oddly if the underlying `ChioClient` or any middleware schedules work that outlives a single call (background `asyncio.Task`s). Those tasks remain pending on the loop across calls and can leak; if the user's HTTP client pools use a keepalive task, that task never runs. Acceptable for the fail-closed sync path, but documenting that `client_factory` must return a client whose coroutines are self-contained per call would head off a subtle class of bugs. Not a PyFlink API issue.

### [P3] Async operator `close()` schedules shutdown on a running loop without awaiting

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:655-673`.

```python
if running is not None:
    running.create_task(self._evaluator.shutdown())
    return
```

If PyFlink calls `close()` from a thread that happens to have a running loop (e.g. certain test harnesses), the shutdown coroutine is scheduled but never awaited before the method returns -- the `ChioClient.close()` may not actually run. PyFlink's `Function.close` contract is synchronous and the common path ("no running loop") is handled correctly; document or log at `warning` level when the running-loop branch fires so silent leaks are visible. Not a PyFlink API misuse; behavioural edge case.

### [P3] `register_dependencies` silently accepts pre-2.2 PyFlink

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:724-754`.

`set_python_requirements` and `add_python_file` exist on `StreamExecutionEnvironment` since 1.x and are present on 2.2 ([`stream_execution_environment.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/stream_execution_environment.py#L398-L458)), so there is no version-skew failure here. The module docstring pins the 2.2 `AsyncFunction` expectation, but `register_dependencies` itself has no 2.2-specific guard and works on 1.18+. If the `[flink]` extra ends up allowing `apache-flink>=1.18`, the async operator will raise `ImportError` on that path because `AsyncFunction` is a 2.2 addition. Recommend adding a runtime version check (e.g. read `pyflink.version.__version__` on import) when constructing `ChioAsyncEvaluateFunction`, with an explicit error pointing to 2.2.

### [P3] `OutputTag` constructed per `process_element` call

File: `sdks/python/chio-streaming/src/chio_streaming/flink.py:701-709, 712-721`.

```python
def process_element(self, value, ctx):
    receipt_tag = _receipt_tag()
    dlq_tag = _dlq_tag()
    ...
```

`OutputTag(name, type_info)` is cheap Python (no JVM round-trip per call -- the constructor only stores `_tag_id` and `_type_info`), and per-call construction is what makes the lazy-import design work. But PyFlink identifies side outputs by tag id, and repeated construction is slightly wasteful at hot-path throughput. Since the tag depends only on module-level constants, cache them on the operator:

```python
def open(self, runtime_context):
    ...
    self._receipt_tag = _receipt_tag()
    self._dlq_tag = _dlq_tag()
```

No correctness impact, just a micro-opt that also makes the emissions traceable.

## Things I checked that are correct

- `async_invoke(self, value) -> List[OUT]`: matches [`AsyncFunction`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/functions.py#L986-L1004) exactly. No `ResultFuture` parameter in PyFlink (unlike Java).
- `OutputTag(name, type_info)` with `Types.PICKLED_BYTE_ARRAY()` matches the research doc and upstream examples; the example's module-level tags and the operator's lazy tags carry identical `(name, type_info)` pairs so PyFlink matches them by tag id.
- `OutputTag` importable from `pyflink.datastream` ([`__init__.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/__init__.py#L289)).
- `process_element(self, value, ctx)` snake_case signature matches `ProcessFunction.process_element` exactly; `ctx` is `ProcessFunction.Context` but the impl uses it loosely (`Any`) because it doesn't call `.timer_service()` or `.timestamp()`.
- `RuntimeContext.get_index_of_this_subtask()`, `.get_attempt_number()`, `.get_metrics_group()`: all three exist with those exact snake_case names at [`functions.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/functions.py#L163-L195). Defensive `try/except` around them is reasonable insurance.
- `Counter.inc()`: correct. The `_bump` helper is safe.
- `MetricGroup.counter(name)` returns a `Counter`; stored result is usable.
- `env.enable_checkpointing(interval_ms, CheckpointingMode.EXACTLY_ONCE)`: signature `(self, interval: int, mode: CheckpointingMode = None)` matches.
- `CheckpointingMode` is exported from `pyflink.datastream`.
- `FileSource.for_record_stream_format(StreamFormat.text_line_format(), path).process_static_file_set().build()`: matches [`file_system.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/connectors/file_system.py) builder chain.
- `from __future__ import annotations` is used throughout; `str | None` unions are safe on 3.11.
- Module-level `try: from pyflink.datastream import ... except ImportError` with `_ProcessFunctionBase` / `_AsyncFunctionBase` placeholders correctly lets `import chio_streaming.flink` succeed without PyFlink, satisfying the "no import-time PyFlink dep" design requirement.
- `OutputTag` construction is correctly deferred to operator code (helpers `_receipt_tag` / `_dlq_tag`) so module import never touches PyFlink types.
- `AsyncFunction` cannot emit side outputs -- the documented workaround (async operator emits `EvaluationResult`, downstream `ProcessFunction` splits into tags) matches the research doc and upstream guidance.
- `register_dependencies` wraps `add_python_file` and `set_python_requirements` with existence checks that make omitted args a no-op.

## Version targeting

The module docstring and the design doc cite Flink 2.2.0. All API calls verified above match PyFlink master (which equals 2.2 on these surfaces). No `Time.seconds(5)` vs `Duration.of_seconds(5)` mismatch -- `Time` still exists and is exported from `pyflink.common` on master and is what `AsyncDataStream` expects.

Fixing the one P1 and the two P2s makes the example runnable under PyFlink 2.2. The operator module itself is already version-correct.
