# chio-streaming-flink

Apache Flink operators that evaluate every record against a Chio
capability and emit canonical receipt / DLQ envelopes to side outputs.
JVM companion to `chio_streaming.flink` in Python; the bytes on the
receipt and DLQ streams are byte-identical across both implementations.

## Overview

Flink owns exactly-once end-to-end via aligned checkpoints and 2PC
sinks. This module does not drive transactions itself; it chains
`ChioAsyncEvaluateFunction` (primary) or `ChioEvaluateFunction` (sync)
into your pipeline and fans the verdicts out through
`ChioVerdictSplitFunction` into `main`, `chio-receipt`, and
`chio-dlq` side outputs. Sinks are the user's responsibility.

Included:

- `ChioAsyncEvaluateFunction` - `RichAsyncFunction` driven by
  `AsyncDataStream.unorderedWait(capacity=...)`. Use this unless you
  need a ProcessFunction for side outputs on the same operator.
- `ChioEvaluateFunction` - synchronous `ProcessFunction` variant with
  native side-output emission.
- `ChioVerdictSplitFunction` - fans `EvaluationResult` into main /
  receipt / DLQ side outputs; tag names are the wire-stable
  `chio-receipt` and `chio-dlq`.
- `ChioFlinkConfig` - serializable, builder-based configuration.
  Client and DLQ router are supplied as `SerializableSupplier` factories
  so connection pools rebuild per TaskManager.
- `DefaultParametersExtractor` / `BodyCoercion` - default body hash and
  body length extraction matching `_canonical_body_bytes` in Python.

## Install

Requires Java 21 or newer (Flink 2.2's minimum) and a running Chio
sidecar (defaults to `http://127.0.0.1:9090`). Publishing coordinates
are pending.

```kotlin
dependencies {
    implementation("world.chio:chio-streaming-flink:0.1.0")
    compileOnly("org.apache.flink:flink-streaming-java:2.2.0")
}
```

`flink-streaming-java` is `compileOnly` so the artifact does not
double-pull Flink into a Flink cluster. Your pipeline build owns its
Flink version.

## Quickstart

```kotlin
import world.chio.flink.ChioAsyncEvaluateFunction
import world.chio.flink.ChioFlinkConfig
import world.chio.flink.ChioOutputTags
import world.chio.flink.ChioVerdictSplitFunction
import world.chio.flink.SidecarErrorBehaviour
import world.chio.sdk.ChioClient
import world.chio.sdk.DlqRouter
import org.apache.flink.api.common.typeinfo.Types
import org.apache.flink.streaming.api.datastream.AsyncDataStream
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment
import org.apache.flink.util.OutputTag
import java.util.concurrent.TimeUnit

val env = StreamExecutionEnvironment.getExecutionEnvironment()
env.enableCheckpointing(60_000)

val config =
    ChioFlinkConfig
        .builder<Transaction>()
        .capabilityId("cap-fraud")
        .toolServer("flink://fraud-job")
        .subjectExtractor { "transactions" }
        .clientFactory { ChioClient("http://127.0.0.1:9090") }
        .dlqRouterFactory { DlqRouter(defaultTopic = "chio-fraud-dlq") }
        .scopeMap(mapOf("transactions" to "events:consume:transactions"))
        .receiptTopic("chio-fraud-receipts")
        .maxInFlight(64)
        .onSidecarError(SidecarErrorBehaviour.DENY)
        .build()

val evaluated =
    AsyncDataStream.unorderedWait(
        transactions,
        ChioAsyncEvaluateFunction(config),
        10_000L,
        TimeUnit.MILLISECONDS,
        128,
    )

val split = evaluated.process(ChioVerdictSplitFunction<Transaction>())
val receiptTag = OutputTag(ChioOutputTags.RECEIPT_TAG_NAME, Types.PRIMITIVE_ARRAY(Types.BYTE))
val dlqTag = OutputTag(ChioOutputTags.DLQ_TAG_NAME, Types.PRIMITIVE_ARRAY(Types.BYTE))

split.sinkTo(downstream)
split.getSideOutput(receiptTag).sinkTo(kafkaReceiptEos) // 2PC receipt sink
split.getSideOutput(dlqTag).sinkTo(kafkaDlqEos)         // 2PC DLQ sink
```

Prefer `ChioAsyncEvaluateFunction` paired with
`ChioVerdictSplitFunction` (chained, no serialisation cost between
the two operators). `ChioEvaluateFunction` is available if you need
the sync path.

## Fail-closed semantics

`SidecarErrorBehaviour.DENY` (default in most deployments) synthesises
a deny receipt carrying the `chio-streaming/synthetic-deny/v1`
marker, routes it to the DLQ, and keeps the pipeline flowing.
`SidecarErrorBehaviour.RAISE` propagates a `ChioStreamingError` so
Flink restarts the task and the source rewinds.

Only `ChioError` subtypes are treated as sidecar failures. Any other
`RuntimeException` (bug in a user-supplied extractor, Jackson crash,
etc.) propagates unchanged to match Python's
`chio_streaming.core.evaluate_with_chio` semantics.

## Parity

The Flink tests that pin wire invariants carry `@Tag("parity")`.
`MiniClusterSyncJobIT` / `MiniClusterAsyncJobIT` (integration, `@Tag("integration")`)
drive a full allow + deny + sidecar-error scenario through a real
MiniCluster; they are excluded from default `check` but runnable via
`./gradlew :chio-streaming-flink:integrationTest`.

## Integration testing

`./gradlew :chio-streaming-flink:integrationTest` runs the end-to-end
Kafka suite (`ChioFlinkKafkaIntegrationTest`): a Flink MiniCluster job
with a real `KafkaSource` -> `ChioAsyncEvaluateFunction` ->
`ChioVerdictSplitFunction` -> two `KafkaSink`s, against a Testcontainers-
managed Redpanda broker (image `redpandadata/redpanda:v24.2.7`,
matching `deploy/compose/streaming-flink-compose.yml`).

The task is self-contained: only a running Docker daemon is required;
no `docker compose up` step. It is deliberately NOT wired to `check`,
so default CI (`./gradlew check`) skips it. The suite is the JVM
counterpart to
`sdks/python/chio-streaming/tests/integration/test_flink_kafka_integration.py`
and asserts the same allow + deny envelope shapes are produced
byte-for-byte across both languages.

## Status

Version `0.1.0`, pre-1.0. Flink 2.2+ required. Wire formats track
the Chio `0.1.x` sidecar contract and PyFlink reference operator.
