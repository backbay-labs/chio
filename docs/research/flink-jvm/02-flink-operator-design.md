# Chio Flink JVM Operator Design

Target module: `chio-streaming-flink-jvm`. Mirror of the PyFlink module in
`sdks/python/chio-streaming/src/chio_streaming/flink.py` (the spec of record;
cited throughout as `flink.py:N`). Supporting research:
`docs/research/flink/01-flink-internals.md` (2PC / side outputs / AsyncFunction
limits), `docs/research/flink/02-pyflink-api.md`, `docs/research/flink/03-operator-design.md`.

## Summary recommendation

Ship a pure-Java module `chio-streaming-flink-jvm` that re-exports the three
operators defined in the PyFlink version (`ChioAsyncEvaluateFunction`,
`ChioVerdictSplitFunction`, `ChioEvaluateFunction`) with byte-identical receipt
and DLQ envelopes, plus a public `ChioFlinkConfig<IN>` builder, two public
`OutputTag<byte[]>` constants, and `FlinkProcessingOutcome<IN>` / `EvaluationResult<IN>`
records. For v1 do not ship bespoke receipt/DLQ sinks: users wire Flink's native
`KafkaSink(DeliveryGuarantee.EXACTLY_ONCE)` and the module's documentation /
example code demonstrates that wiring. Java 21, Flink 2.2.0, pure Java (not
Kotlin) for API ergonomics to Scala / Java / Kotlin downstream, Gradle with a
new `sdks/jvm/settings.gradle.kts` multi-project root that includes both
`chio-spring-boot` and `chio-streaming-flink`. Depend on `chio-sdk-jvm` via
`implementation(project(":chio-sdk-jvm"))`. JDK `java.net.http.HttpClient`
remains the default transport (matches `chio-spring-boot` at
`sdks/jvm/chio-spring-boot/src/main/kotlin/world/chio/ChioSidecarClient.kt:35-38`).

## API sketch

Public surface only. Package `world.chio.streaming.flink`.

```java
// Configuration. Immutable record + static builder. Subject/parameter
// extractors are serializable functional interfaces because Flink
// serializes the operator to the TaskManager (same constraint as
// cloudpickle in PyFlink; see flink.py:189-197 "client_factory" rationale).

public final class ChioFlinkConfig<IN> implements Serializable {
    public String capabilityId();
    public String toolServer();
    public Map<String, String> scopeMap();               // default: empty
    public Optional<String> receiptTopic();              // null = no receipts
    public int maxInFlight();                            // default: 64
    public SidecarErrorBehaviour onSidecarError();       // default: RAISE
    public SerializableFunction<IN, String> subjectExtractor();        // REQUIRED
    public SerializableFunction<IN, Map<String, Object>> parametersExtractor();
    public SerializableSupplier<ChioClient> clientFactory();           // REQUIRED
    public SerializableSupplier<DlqRouter> dlqRouterFactory();         // REQUIRED
    public String requestIdPrefix();                      // default: "chio-flink"

    public static <IN> Builder<IN> builder();
    public enum SidecarErrorBehaviour { RAISE, DENY }

    public static final class Builder<IN> {
        public Builder<IN> capabilityId(String id);
        public Builder<IN> toolServer(String server);
        public Builder<IN> scopeMap(Map<String, String> map);
        public Builder<IN> receiptTopic(String topic);
        public Builder<IN> maxInFlight(int n);
        public Builder<IN> onSidecarError(SidecarErrorBehaviour b);
        public Builder<IN> subjectExtractor(SerializableFunction<IN, String> f);
        public Builder<IN> parametersExtractor(SerializableFunction<IN, Map<String, Object>> f);
        public Builder<IN> clientFactory(SerializableSupplier<ChioClient> s);
        public Builder<IN> dlqRouterFactory(SerializableSupplier<DlqRouter> s);
        public Builder<IN> requestIdPrefix(String p);
        public ChioFlinkConfig<IN> build();              // validates, matches flink.py:223-258
    }
}

// Side-output tag constants. byte[] payloads, canonical-JSON envelopes.
// Names are wire-stable across ecosystems and match flink.py:76-79.
public final class ChioOutputTags {
    public static final String RECEIPT_TAG_NAME = "chio-receipt";
    public static final String DLQ_TAG_NAME     = "chio-dlq";
    public static OutputTag<byte[]> receiptTag();        // lazy, typed once
    public static OutputTag<byte[]> dlqTag();
}

// Intermediate record from the async operator.
public record EvaluationResult<IN>(
    boolean allowed,
    IN element,
    byte[] receiptBytes,   // nullable
    byte[] dlqBytes        // nullable
) implements Serializable {}

// Full outcome. Parallel to FlinkProcessingOutcome in flink.py:262-295.
public record FlinkProcessingOutcome<IN>(
    boolean allowed,
    ChioReceipt receipt,
    String requestId,
    IN element,
    Integer subtaskIndex,
    Integer attemptNumber,
    Long checkpointId,
    byte[] receiptBytes,
    byte[] dlqBytes,
    DlqRecord dlqRecord
) implements Serializable {}

// Async operator: sidecar call concurrency under AsyncDataStream.
// Emits exactly one EvaluationResult per input. Wire with:
//   AsyncDataStream.unorderedWait(stream, new ChioAsyncEvaluateFunction<>(cfg),
//       Duration.ofSeconds(10), cfg.maxInFlight())
public class ChioAsyncEvaluateFunction<IN>
        extends RichAsyncFunction<IN, EvaluationResult<IN>> {
    public ChioAsyncEvaluateFunction(ChioFlinkConfig<IN> config);
    @Override public void open(OpenContext ctx);          // Flink 2.0+ shape
    @Override public void asyncInvoke(IN value, ResultFuture<EvaluationResult<IN>> fut);
    @Override public void close();
}

// Split operator: trailing ProcessFunction that recovers side outputs.
// Chain after the async op; costs nothing at runtime (same task thread).
public class ChioVerdictSplitFunction<IN>
        extends ProcessFunction<EvaluationResult<IN>, IN> {
    public ChioVerdictSplitFunction();
    @Override public void processElement(
        EvaluationResult<IN> value,
        Context ctx,
        Collector<IN> out);
}

// Sync single-operator variant. Blocks the task thread on each sidecar
// call. Acceptable only for co-located, sub-ms-RTT sidecars, same caveat
// as flink.py:592-604.
public class ChioEvaluateFunction<IN> extends KeyedProcessFunction<Object, IN, IN> {
    public ChioEvaluateFunction(ChioFlinkConfig<IN> config);
    @Override public void open(OpenContext ctx);
    @Override public void processElement(IN value, Context ctx, Collector<IN> out);
    @Override public void close();
}

// Serializable functional interfaces. Flink requires Serializable
// lambdas/closures at the operator boundary, plain java.util.function
// interfaces are not Serializable by default.
@FunctionalInterface public interface SerializableFunction<T, R>
        extends Function<T, R>, Serializable {}
@FunctionalInterface public interface SerializableSupplier<T>
        extends Supplier<T>, Serializable {}
```

## Detailed answers

### 1. Operator class design

Four shapes matching PyFlink one-to-one:

- `ChioAsyncEvaluateFunction<IN> extends RichAsyncFunction<IN, EvaluationResult<IN>>`.
  Primary path. `RichAsyncFunction` (not bare `AsyncFunction`) to get
  `open(OpenContext)` and `getRuntimeContext()` for metrics group and
  subtask index, same info PyFlink pulls at `flink.py:439-455`.
- `ChioVerdictSplitFunction<IN> extends ProcessFunction<EvaluationResult<IN>, IN>`.
  Side outputs via `ctx.output(tag, bytes)`, main output via
  `out.collect(element)`. Matches `flink.py:707-732`.
- `ChioEvaluateFunction<IN> extends KeyedProcessFunction<Object, IN, IN>`
  sync variant. Choosing `KeyedProcessFunction` over plain `ProcessFunction`
  gives users on a `KeyedStream` keyed-state access for free and degrades
  cleanly on non-keyed streams. (Reconsidered in open questions: v1 may
  ship on plain `ProcessFunction` for exact parity; see below.)
- `ChioFlinkConfig<IN>` is a typed builder, not Lombok or a record:
  records cannot validate cheaply, Lombok is a transitive dep we should not
  force, and a builder lets us add optional fields without API breakage.
  Validation mirrors `flink.py:223-258`.
- `FlinkProcessingOutcome<IN>` / `EvaluationResult<IN>` are records.
  Records are `Serializable` when components are; call out to the SDK
  researcher that `ChioReceipt` and `DlqRecord` must implement
  `Serializable` with stable `serialVersionUID`.
- `OutputTag<byte[]>` constants exposed via factory methods
  (`ChioOutputTags.receiptTag()`) because the constructor needs a live
  `TypeInformation`. Same rationale as `_receipt_tag()` at
  `flink.py:119-139`.

### 2. Async HTTP client choice

JDK `java.net.http.HttpClient`. Zero extra deps, already used in
`chio-spring-boot` (`ChioSidecarClient.kt:14-35`). `sendAsync` returns
`CompletableFuture<HttpResponse<T>>` which composes directly with
`ResultFuture`; `RichAsyncFunction.asyncInvoke` must not block, and
`sendAsync` never does. OkHttp and Reactor Netty also work but add deps;
Reactor Netty is overkill outside Spring WebFlux.

The operator is transport-agnostic so long as the SDK exposes
`CompletionStage<ChioReceipt> evaluateToolCallAsync(...)`. If the SDK
ships only a blocking `evaluateToolCall`, we wrap in
`CompletableFuture.supplyAsync(..., executor)`, which defeats the
purpose of `AsyncFunction`. Flag this contract to the SDK researcher.

### 3. 2PC capability story

Ship v1 with only the three operators and config: no bespoke
receipt / DLQ sinks, no `TwoPhaseCommitSinkFunction` reference.
Rationale:

- `01-flink-internals.md` §1: `KafkaSink(DeliveryGuarantee.EXACTLY_ONCE)`
  already handles 2PC. A `ChioReceiptKafkaSink` wrapper would hide the
  `transactionalIdPrefix` control users need to set per-job
  (`01-flink-internals.md:27`) and duplicate
  `KafkaRecordSerializationSchema` configuration.
- A reference `TwoPhaseCommitSinkFunction` for JDBC / HTTP locks us into
  specific drivers and has subtle 2PC traps (idempotent commit, txn-id
  fencing). Users with those sinks are going to customize anyway.
- Deliverable: `examples/KafkaReceiptSinkExample.java` wiring
  `KafkaSink` end-to-end plus README notes on the
  `transaction.timeout.ms` gotcha.

Revisit v1.1 when we have real user pressure for non-Kafka 2PC.

### 4. Exactly-once semantics

Confirmed against `01-flink-internals.md` §1-3. Canonical topology:

```
KafkaSource (checkpointed offsets)
  -> AsyncDataStream.unorderedWait(ChioAsyncEvaluateFunction<IN>, ..., capacity=N)
  -> ChioVerdictSplitFunction<IN>
     main        out.collect(element) -> downstream
     RECEIPT_TAG ctx.output(tag, bytes) -> KafkaSink(EOS, txnPrefix="chio-recv-<job>")
     DLQ_TAG     ctx.output(tag, bytes) -> KafkaSink(EOS, txnPrefix="chio-dlq-<job>")
```

Documented preconditions (README + example assertions):

- `env.enableCheckpointing(ms)` plus production state backend (RocksDB).
  Without this, EOS silently downgrades.
- Broker `transaction.max.timeout.ms > checkpointInterval + maxRestart`
  (`01-flink-internals.md:27`).
- Unique `transactionalIdPrefix` per `(job, sink)`; collisions fence each
  other silently.
- `env.getCheckpointConfig().enableUnalignedCheckpoints()` recommended for
  sync-operator users (unnecessary on the async path because the task
  thread returns immediately, `01-flink-internals.md:88`).

### 5. Build target and compatibility

Follow `chio-spring-boot` with one bump:

- Java 21 (vs 17 on `chio-spring-boot/build.gradle.kts:11`). Flink 2.2
  supports both; virtual threads / pattern-matching `switch` are useful
  in the split function. If `chio-sdk-jvm` pins 17, drop back.
- Pure Java, not Kotlin. Larger Flink user base is on Java, Kotlin stdlib
  would be a transitive dep on pure-Java consumers, and we want Scala /
  Clojure compatibility without classpath friction. (Spring Boot already
  implies a classpath, so Kotlin is fine there.)
- `org.apache.flink:flink-streaming-java:2.2.0` as `compileOnly` so
  consumers bring their own Flink bundle. No transitive
  `flink-connector-kafka`.
- Gradle `java-library` + `maven-publish`. Coordinates
  `world.chio:chio-streaming-flink:0.1.0`.

### 6. Module layout

Create `sdks/jvm/settings.gradle.kts` as a multi-project root. Absorb
`chio-spring-boot/settings.gradle.kts` or keep it as a proxy.

```
sdks/jvm/
  settings.gradle.kts           # includes all subprojects
  build.gradle.kts              # common plugins / repos
  chio-sdk-jvm/                 # from the SDK researcher
  chio-spring-boot/             # existing
  chio-streaming-flink/
    build.gradle.kts
    src/main/java/world/chio/streaming/flink/
      ChioFlinkConfig.java
      ChioOutputTags.java
      ChioAsyncEvaluateFunction.java
      ChioVerdictSplitFunction.java
      ChioEvaluateFunction.java
      EvaluationResult.java
      FlinkProcessingOutcome.java
      internal/ChioFlinkEvaluator.java   # sync/async core, parallels _ChioFlinkEvaluator flink.py:410-589
    src/test/java/...
    examples/KafkaReceiptSinkExample.java
```

Dependencies:

```kotlin
dependencies {
    api(project(":chio-sdk-jvm"))               // types appear in public signatures
    compileOnly("org.apache.flink:flink-streaming-java:2.2.0")
    testImplementation("org.apache.flink:flink-streaming-java:2.2.0")
    testImplementation("org.apache.flink:flink-test-utils:2.2.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("org.mockito:mockito-core:5.14.1")
}
```

`api(...)` (not `implementation`) because `ChioReceipt` / `DlqRouter`
appear in `FlinkProcessingOutcome` / public builder methods.

### 7. Testing strategy

Three layers:

- **Unit tests** (always on). Mock `ChioClient` and `DlqRouter` via
  `SerializableSupplier`; drive
  `ProcessFunctionTestHarnesses.forProcessFunction(...)` from
  `flink-test-utils` for sync operator and split function. For the async
  operator, feed records directly and capture `ResultFuture.complete()`.
  Mirrors the Python in-process surrogate pattern at `tests/test_flink.py`.
- **Integration tests** (tagged `@Tag("integration")`, Gradle task
  `integrationTest`). `MiniClusterWithClientResource` from
  `flink-test-utils`, fake sidecar via JDK `HttpServer`; assert main
  output is allow-only, receipt bytes are byte-identical to the Python
  reference, DLQ bytes carry `SYNTHETIC_RECEIPT_MARKER` on synthetic
  denies, checkpoint replay produces byte-identical receipts.

  ```kotlin
  val integrationTest = tasks.register<Test>("integrationTest") {
      useJUnitPlatform { includeTags("integration") }
      shouldRunAfter(tasks.test)
  }
  ```

- **Wire-parity tests** (tagged `parity`). Golden files under
  `testFixtures/` captured from PyFlink; assert byte-equality. Protects
  the "byte-identical across middlewares" invariant at `flink.py:5-10`.

### 8. Parity with Python semantics

See checklist below; every bullet maps to a `flink.py` line range.

## Parity checklist

Every invariant maps to a `flink.py` cite; the JVM operator must preserve each.

- **Canonical JSON byte-equality** across Python and JVM for
  `(receipt, request_id, source_topic)` triples. Matches
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
  at `flink.py:335-340`, `receipt.py:47-54`. Jackson needs
  `ORDER_MAP_ENTRIES_BY_KEYS` plus ASCII escaping; reuse the
  `chio-sdk-jvm` helper if it exists rather than duplicating.
- **Wire-stable tag names** `"chio-receipt"` / `"chio-dlq"`
  (`flink.py:76-79`). These are wire contracts; no renaming.
- **Deny emits only to DLQ.** The DLQ record carries the deny receipt in
  its payload; emitting a deny receipt to the allow stream would break
  the "single receipt consumer" guarantee (`flink.py:553-566`).
- **Allow emits main + optional receipt.** Receipt only when
  `receiptTopic` is set (`flink.py:568-589`).
- **`RAISE` propagates, `DENY` synthesizes.** On `RAISE`, re-throw a
  `ChioStreamingException` out of `asyncInvoke` / `processElement` so
  Flink restarts and the source rewinds (`flink.py:528-531`). On `DENY`,
  build a synthetic deny receipt carrying
  `SYNTHETIC_RECEIPT_MARKER = "chio-streaming/synthetic-deny/v1"` in
  metadata key `chio_streaming_synthetic_marker`, with reason prefixed
  `"[unsigned]"` (`core.py:116`, `flink.py:532-539`).
- **`subjectExtractor` required at config time.** Empty subject makes
  `resolve_scope` reject every record (`flink.py:246-258`). The builder
  must throw on `build()`.
- **`parametersExtractor` default** yields
  `{request_id, subject, body_length, body_hash}` where `body_hash` is
  hex SHA-256 of canonical body bytes (`flink.py:327-358`). Encoding
  rules: `byte[]` passthrough, `String` UTF-8, `Map` canonical JSON,
  otherwise `toString().getBytes(UTF_8)`.
- **Factories, not instances.** `clientFactory` / `dlqRouterFactory` are
  `SerializableSupplier<T>` invoked in `open()` per-TaskManager.
  `HttpClient` connection pools cannot survive Kryo / `writeObject`
  (`flink.py:187-197`).
- **`maxInFlight`** sizes the sync-operator semaphore and matches
  `AsyncDataStream.unorderedWait(..., capacity=...)` on the async path
  (`flink.py:162-167`).
- **Metrics** `evaluations_total`, `allow_total`, `deny_total`,
  `sidecar_errors_total` counters plus `in_flight` gauge on
  `getMetricGroup().addGroup("chio")`. Log-and-continue on registration
  failure (`flink.py:361-380`).
- **`request_id` derivation** is `prefix + "-" + UUID.randomUUID()`
  matching `core.py:228-230`. Flink has no broker message identity;
  deterministic-replay IDs from `(topic, partition, offset)` land in v1.1
  via a `requestIdExtractor` hook if demanded.
- **`close()` drains the client.** Python has asyncio loop-lifecycle
  gymnastics (`flink.py:667-693`); Java calls `ChioClient.close()`
  synchronously with no analogue.
- **`FlinkProcessingOutcome` fields** are `element`, `subtaskIndex`,
  `attemptNumber`, `checkpointId`, `receiptBytes`, `dlqBytes` plus
  inherited `allowed`, `receipt`, `requestId`, `acked`. `acked` means
  "emitted to main output" in Flink (`flink.py:265-268`).
- **`receiptTopic` is a metadata tag, not a sink name.** Document on
  the builder method (`flink.py:568-572`).
- **`register_dependencies` has no JVM analogue.** JVM Flink jobs ship
  fat jars; omit the helper.

## Open questions

- **`ChioReceipt` / `DlqRecord` serialization.** Must be `Serializable`
  with stable `serialVersionUID` if they travel through `EvaluationResult`,
  or we declare operator state empty (PyFlink v1 does this at
  `03-operator-design.md:180-184`). Defer to the SDK researcher.
- **Canonical JSON helper location.** Ideally in `chio-sdk-jvm` for reuse;
  if not, ship a dedicated helper here and guard byte-equality via the
  golden-file test.
- **Retry in the builder?** Flink 2.2 ships `AsyncRetryStrategy`.
  PyFlink v1 does not expose retry. Adding
  `ChioFlinkConfig.retryStrategy(...)` is cheap but raises v1 surface;
  decide during implementation.
- **Sync operator base: keyed or plain `ProcessFunction`?** Parity
  argues plain; ergonomics argue `KeyedProcessFunction<Object, IN, IN>`.
  Recommend plain for v1, add `ChioKeyedEvaluateFunction<K, IN>` in v1.1
  aligned with PyFlink.
- **SDK async return type.** Prefer `CompletionStage<ChioReceipt>` for
  loose coupling over `CompletableFuture<ChioReceipt>`.
- **`OpenContext` vs deprecated `Configuration`.** Use the 2.0 shape;
  confirm `RichAsyncFunction` in 2.2 exposes `open(OpenContext)`.
- **Examples module layout.** Ship as a separate Gradle subproject wired
  as an integration test so runnability is CI-enforced without polluting
  the publishable jar.
