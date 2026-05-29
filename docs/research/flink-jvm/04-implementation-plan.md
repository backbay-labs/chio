# 04 - Phase 3 Implementation Plan (chio-sdk-jvm + chio-streaming-flink)

This plan synthesises the three Phase 1 research documents (01, 02, 03) into a
file-by-file executable spec for Phase 3. Reconciled decisions from the user
steer are treated as final: Kotlin 2.3 for both new modules, JDK 17 for
`chio-sdk-jvm` / `chio-spring-boot`, JDK 21 for `chio-streaming-flink`, JDK
`java.net.http.HttpClient`, Jackson canonical mapper, multi-project Gradle at
`sdks/jvm/`, JUnit 5 with tag-gated integration tests, no `flink-connector-kafka`
dependency, Spotless + ktlint 1.5.0, no publishing, minimal CI job.

The Python module `sdks/python/chio-streaming/src/chio_streaming/flink.py` is
the reference; every JVM operator must preserve its wire-level invariants.

## 1. Module layout

Final tree after Phase 3 lands. Every directory / file the implementer must
create or touch is listed.

```
sdks/jvm/
├── build.gradle.kts                         # root aggregate
├── settings.gradle.kts                      # multi-project includes
├── gradle.properties                        # org.gradle.jvmargs
├── gradlew                                  # moved up from chio-spring-boot
├── gradlew.bat                              # moved up from chio-spring-boot
├── gradle/
│   ├── libs.versions.toml                   # version catalog
│   └── wrapper/
│       ├── gradle-wrapper.jar               # moved up
│       └── gradle-wrapper.properties        # moved up, stays at 8.7
├── chio-sdk-jvm/
│   ├── build.gradle.kts
│   └── src/
│       ├── main/kotlin/world/chio/sdk/
│       │   ├── ChioClient.kt
│       │   ├── ChioTypes.kt
│       │   ├── ChioReceipt.kt
│       │   ├── Decision.kt
│       │   ├── ToolCallAction.kt
│       │   ├── CanonicalJson.kt
│       │   ├── Hashing.kt
│       │   ├── DlqRouter.kt
│       │   ├── DlqRecord.kt
│       │   ├── ReceiptEnvelope.kt
│       │   ├── SyntheticDenyReceipt.kt
│       │   ├── SidecarPaths.kt
│       │   └── errors/
│       │       ├── ChioError.kt
│       │       ├── ChioConnectionError.kt
│       │       ├── ChioTimeoutError.kt
│       │       ├── ChioDeniedError.kt
│       │       └── ChioValidationError.kt
│       └── test/kotlin/world/chio/sdk/
│           ├── CanonicalJsonTest.kt
│           ├── HashingTest.kt
│           ├── ChioClientHttpTest.kt
│           ├── ChioDeniedErrorTest.kt
│           ├── ChioReceiptParseTest.kt
│           ├── ChioTypesTest.kt            # moved from chio-spring-boot
│           ├── DlqRouterTest.kt
│           ├── ReceiptEnvelopeTest.kt
│           └── SyntheticDenyReceiptTest.kt
├── chio-spring-boot/
│   ├── build.gradle.kts                     # refactored, depends on :chio-sdk-jvm
│   ├── settings.gradle.kts                  # DELETED (subproject)
│   ├── README.md
│   └── src/
│       ├── main/kotlin/world/chio/
│       │   ├── CachedBodyHttpServletRequest.kt   # unchanged
│       │   ├── ChioAutoConfiguration.kt          # unchanged
│       │   ├── ChioFilter.kt                     # import updates only
│       │   ├── ChioIdentityExtractor.kt          # strip sha256Hex; import from sdk
│       │   ├── ChioSidecarClient.kt              # DELETED, typealias shim added
│       │   ├── ChioTypes.kt                      # DELETED, typealiases added
│       │   └── compat/
│       │       ├── ChioSdkAliases.kt             # typealiases for one-release compat
│       │       └── ChioSidecarClient.kt          # thin shim around sdk.ChioClient
│       ├── main/resources/META-INF/spring.factories    # unchanged
│       └── test/kotlin/world/chio/
│           ├── ChioFilterBodyTest.kt             # unchanged
│           └── ChioFilterCapabilityTransportTest.kt # unchanged
│                                                 # ChioTypesTest.kt moved
└── chio-streaming-flink/
    ├── build.gradle.kts
    └── src/
        ├── main/kotlin/world/chio/flink/
        │   ├── ChioFlinkConfig.kt
        │   ├── ChioFlinkEvaluator.kt             # internal shared core
        │   ├── ChioAsyncEvaluateFunction.kt
        │   ├── ChioVerdictSplitFunction.kt
        │   ├── ChioEvaluateFunction.kt
        │   ├── ChioOutputTags.kt
        │   ├── EvaluationResult.kt
        │   ├── FlinkProcessingOutcome.kt
        │   ├── SidecarErrorBehaviour.kt
        │   ├── SerializableFunction.kt
        │   ├── SerializableSupplier.kt
        │   ├── Slots.kt
        │   ├── ScopeResolver.kt
        │   ├── BodyCoercion.kt                   # canonical body bytes helper
        │   └── DefaultParametersExtractor.kt
        ├── test/kotlin/world/chio/flink/
        │   ├── ChioFlinkConfigTest.kt
        │   ├── ChioFlinkEvaluatorTest.kt
        │   ├── ChioAsyncEvaluateFunctionTest.kt
        │   ├── ChioVerdictSplitFunctionTest.kt
        │   ├── ChioEvaluateFunctionTest.kt
        │   ├── ScopeResolverTest.kt
        │   ├── DefaultParametersExtractorTest.kt
        │   └── support/
        │       ├── FakeChioClient.kt
        │       ├── FakeDlqRouter.kt
        │       └── FakeRuntimeContext.kt
        └── integrationTest/kotlin/world/chio/flink/
            ├── MiniClusterAsyncJobIT.kt
            └── MiniClusterSyncJobIT.kt
```

Notes:

- Wrapper migration: existing wrapper under `sdks/jvm/chio-spring-boot/gradle/wrapper/`
  is moved up one level. `gradlew` / `gradlew.bat` move with it. Example
  project's `settings.gradle.kts` flips from `includeBuild("../../sdks/jvm/chio-spring-boot")`
  to `includeBuild("../../sdks/jvm")` as a separate non-blocking commit.
- `chio-spring-boot/settings.gradle.kts` is deleted; root `settings.gradle.kts`
  owns inclusion.

## 2. File-by-file API specification

Every file lists purpose, public types, public signatures, and the Python
reference that fixes semantics. Kotlin signatures only; no bodies.

### 2.1 `chio-sdk-jvm` / `world.chio.sdk`

#### `CanonicalJson.kt`

Purpose: single place that owns the canonical `ObjectMapper` plus a
`writeCanonicalBytes(Any)` helper. Mirrors `_canonical_json` in
`chio_sdk/client.py:38-48` and `canonical_json` in
`chio_streaming/receipt.py:47-54`.

```kotlin
object CanonicalJson {
    /** Mapper configured for byte-identical output vs Python's
     *  json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True). */
    @JvmStatic
    val MAPPER: ObjectMapper

    /** Serialize `value` to canonical JSON bytes. Sorts map keys,
     *  alphabetises POJO properties, escapes non-ASCII. */
    @JvmStatic
    fun writeBytes(value: Any?): ByteArray

    /** Same as [writeBytes] but returns a `String`. Prefer bytes where
     *  the consumer hashes. */
    @JvmStatic
    fun writeString(value: Any?): String
}
```

Mirrors: `chio_sdk.client._canonical_json` (client.py:38-48),
`chio_streaming.receipt.canonical_json` (receipt.py:47-54).

#### `Hashing.kt`

Purpose: SHA-256 hex helpers. Replaces `sha256Hex` currently in
`ChioIdentityExtractor.kt:13-22`.

```kotlin
object Hashing {
    @JvmStatic fun sha256Hex(input: String): String
    @JvmStatic fun sha256Hex(input: ByteArray): String
    /** Hex SHA-256 or null if input is null/empty. Mirrors
     *  chio_streaming.core.hash_body (core.py:183-187). */
    @JvmStatic fun hashBody(input: ByteArray?): String?
}
```

#### `ChioTypes.kt`

Purpose: HTTP-side types carried by the sidecar (AuthMethod, CallerIdentity,
Verdict, GuardEvidence, HttpReceipt, ChioHttpRequest, EvaluateResponse,
ChioPassthrough, ChioErrorResponse, ChioErrorCodes). Moves verbatim from
`sdks/jvm/chio-spring-boot/src/main/kotlin/world/chio/ChioTypes.kt`
with a package change to `world.chio.sdk`. All Jackson `@JsonProperty`
annotations stay.

Public types (Kotlin data classes with `@JsonInclude(NON_NULL)`; copy current
signatures unchanged except for package and the one `toDecision()` convenience
added to `Verdict` mirroring `Verdict.to_decision` in `models.py:375-386`):

```kotlin
data class AuthMethod(method: String, tokenHash: String? = null, ...) {
    companion object {
        @JvmStatic fun anonymous(): AuthMethod
        @JvmStatic fun bearer(tokenHash: String): AuthMethod
        @JvmStatic fun apiKey(keyName: String, keyHash: String): AuthMethod
        @JvmStatic fun cookie(cookieName: String, cookieHash: String): AuthMethod
    }
}

data class CallerIdentity(subject: String, authMethod: AuthMethod, ...) {
    companion object { @JvmStatic fun anonymous(): CallerIdentity }
}

data class Verdict(verdict: String, reason: String? = null,
                   guard: String? = null, httpStatus: Int? = null) {
    @JsonIgnore fun isAllowed(): Boolean
    @JsonIgnore fun isDenied(): Boolean
    fun toDecision(): Decision   // mirrors models.py:375-386
    companion object {
        @JvmStatic fun allow(): Verdict
        @JvmOverloads @JvmStatic
        fun deny(reason: String, guard: String, httpStatus: Int = 403): Verdict
    }
}

data class GuardEvidence(guardName: String, verdict: Boolean, details: String? = null)
data class HttpReceipt(...)                    // unchanged shape
data class ChioHttpRequest(...)                // unchanged shape
data class EvaluateResponse(verdict: Verdict, receipt: HttpReceipt,
                            evidence: List<GuardEvidence> = emptyList())
data class ChioPassthrough(mode: String = "allow_without_receipt", ...)
data class ChioErrorResponse(error: String, message: String,
                             receiptId: String? = null, suggestion: String? = null)

object ChioErrorCodes {
    const val ACCESS_DENIED = "chio_access_denied"
    const val SIDECAR_UNREACHABLE = "chio_sidecar_unreachable"
    const val EVALUATION_FAILED = "chio_evaluation_failed"
    const val INVALID_RECEIPT = "chio_invalid_receipt"
    const val TIMEOUT = "chio_timeout"
}
```

Mirrors: `chio_sdk.models` (models.py).

#### `Decision.kt`

Purpose: tool-call verdict (allow / deny / cancelled / incomplete) used inside
`ChioReceipt`. Mirrors `Decision` in `models.py:313-346`.

```kotlin
@JsonInclude(JsonInclude.Include.NON_NULL)
data class Decision(
    @JsonProperty("verdict") val verdict: String,
    @JsonProperty("reason") val reason: String? = null,
    @JsonProperty("guard") val guard: String? = null,
) {
    @JsonIgnore fun isAllowed(): Boolean
    @JsonIgnore fun isDenied(): Boolean

    companion object {
        @JvmStatic fun allow(): Decision
        @JvmStatic fun deny(reason: String, guard: String): Decision
        @JvmStatic fun cancelled(reason: String): Decision
        @JvmStatic fun incomplete(reason: String): Decision
    }
}
```

#### `ToolCallAction.kt`

Purpose: the action block inside a `ChioReceipt`. Mirrors
`ToolCallAction` in `models.py:407-411`.

```kotlin
data class ToolCallAction(
    @JsonProperty("parameters") val parameters: Map<String, Any?> = emptyMap(),
    @JsonProperty("parameter_hash") val parameterHash: String,
)
```

Note: `Map<String, Any?>` is the Java-friendly choice resolved from Phase 1
open question 4. `null` map values must round-trip through the canonical
mapper.

#### `ChioReceipt.kt`

Purpose: signed tool-call receipt. Mirrors `ChioReceipt` in `models.py:419-442`.

```kotlin
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioReceipt(
    @JsonProperty("id") val id: String,
    @JsonProperty("timestamp") val timestamp: Long,
    @JsonProperty("capability_id") val capabilityId: String,
    @JsonProperty("tool_server") val toolServer: String,
    @JsonProperty("tool_name") val toolName: String,
    @JsonProperty("action") val action: ToolCallAction,
    @JsonProperty("decision") val decision: Decision,
    @JsonProperty("content_hash") val contentHash: String,
    @JsonProperty("policy_hash") val policyHash: String,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
    @JsonProperty("metadata") val metadata: Map<String, Any?>? = null,
    @JsonProperty("kernel_key") val kernelKey: String,
    @JsonProperty("signature") val signature: String,
) : Serializable {
    @JsonIgnore fun isAllowed(): Boolean
    @JsonIgnore fun isDenied(): Boolean

    companion object { private const val serialVersionUID: Long = 1L }
}
```

Implements `Serializable` with stable `serialVersionUID` because this type
travels inside `EvaluationResult` and `FlinkProcessingOutcome` which Flink
serialises.

#### `SidecarPaths.kt`

Purpose: string constants for sidecar endpoints. Mirrors the bare paths used
throughout `chio_sdk/client.py`.

```kotlin
object SidecarPaths {
    const val DEFAULT_BASE_URL = "http://127.0.0.1:9090"
    const val HEALTH = "/chio/health"
    const val EVALUATE_HTTP = "/chio/evaluate"
    const val VERIFY_HTTP_RECEIPT = "/chio/verify"
    const val EVALUATE_TOOL_CALL = "/v1/evaluate"
    const val VERIFY_RECEIPT = "/v1/receipts/verify"
}
```

#### `errors/ChioError.kt`

Purpose: base exception; mirrors `chio_sdk.errors.ChioError`
(errors.py:8-13).

```kotlin
open class ChioError @JvmOverloads constructor(
    message: String,
    val code: String? = null,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
```

#### `errors/ChioConnectionError.kt`

Purpose: sidecar unreachable. Mirrors `ChioConnectionError` (errors.py:16-20).

```kotlin
class ChioConnectionError(message: String, cause: Throwable? = null)
    : ChioError(message, "CONNECTION_ERROR", cause)
```

#### `errors/ChioTimeoutError.kt`

Purpose: HTTP timeout. Mirrors `ChioTimeoutError` (errors.py:23-27).

```kotlin
class ChioTimeoutError(message: String, cause: Throwable? = null)
    : ChioError(message, "TIMEOUT", cause)
```

#### `errors/ChioDeniedError.kt`

Purpose: structured 403 from the sidecar. Mirrors `ChioDeniedError`
(errors.py:30-175) exactly; all 11 optional fields, `fromWire(JsonNode)`,
`toWire()` helpers. Deferred parity item: the multi-line `toString()` shape
is OPTIONAL for v1; a single-line message is acceptable. The `fromWire`
payload decoding MUST accept the same field names Python accepts.

```kotlin
class ChioDeniedError @JvmOverloads constructor(
    message: String,
    val guard: String? = null,
    val reason: String? = null,
    val toolName: String? = null,
    val toolServer: String? = null,
    val requestedAction: String? = null,
    val requiredScope: String? = null,
    val grantedScope: String? = null,
    val reasonCode: String? = null,
    val receiptId: String? = null,
    val hint: String? = null,
    val docsUrl: String? = null,
) : ChioError(message, "DENIED") {
    fun toWire(): Map<String, Any?>
    companion object {
        @JvmStatic fun fromWire(node: JsonNode): ChioDeniedError
        @JvmStatic fun fromWire(data: Map<String, Any?>): ChioDeniedError
    }
}
```

#### `errors/ChioValidationError.kt`

Purpose: local validation failure. Mirrors `ChioValidationError`
(errors.py:178-182).

```kotlin
class ChioValidationError(message: String)
    : ChioError(message, "VALIDATION_ERROR")
```

#### `SyntheticDenyReceipt.kt`

Purpose: builder for the synthetic deny receipt emitted when `on_sidecar_error=DENY`.
Mirrors `synthesize_deny_receipt` in `chio_streaming/core.py:119-160`.

```kotlin
object SyntheticDenyReceipt {
    /** Marker string written into receipt.metadata for synthetic denies. */
    const val MARKER: String = "chio-streaming/synthetic-deny/v1"

    @JvmStatic
    fun synthesize(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
        reason: String,
        guard: String,
        clock: () -> Long = { System.currentTimeMillis() / 1000L },
        idSupplier: () -> String = { "chio-streaming-synth-" + UUID.randomUUID().toString().replace("-", "").take(10) },
    ): ChioReceipt
}
```

Invariants (all from `core.py:139-160`):
- Reason is prefixed `"[unsigned] "` unless already prefixed.
- `kernelKey = ""`, `signature = ""`.
- `metadata` contains `"chio_streaming_synthetic": true` and
  `"chio_streaming_synthetic_marker": MARKER`.
- `parameterHash` = SHA-256 hex of canonical JSON of `parameters`.
- `contentHash` = same as `parameterHash`.
- `policyHash = ""`.
- `evidence = []`.

#### `ReceiptEnvelope.kt`

Purpose: canonical envelope emitted to the receipt side output. Mirrors
`build_envelope` + `ReceiptEnvelope` in `chio_streaming/receipt.py:57-149`.

```kotlin
data class ReceiptEnvelope(
    val key: ByteArray,                          // request_id UTF-8
    val value: ByteArray,                        // canonical JSON payload
    val headers: List<Pair<String, ByteArray>>,
    val requestId: String,
    val receiptId: String,
) : Serializable {
    companion object {
        const val ENVELOPE_VERSION: String = "chio-streaming/v1"
        const val RECEIPT_HEADER: String = "X-Chio-Receipt"
        const val VERDICT_HEADER: String = "X-Chio-Verdict"

        @JvmOverloads
        @JvmStatic
        fun build(
            requestId: String,
            receipt: ChioReceipt,
            sourceTopic: String? = null,
            sourcePartition: Int? = null,
            sourceOffset: Long? = null,
            extraMetadata: Map<String, Any?>? = null,
        ): ReceiptEnvelope
        private const val serialVersionUID: Long = 1L
    }
}
```

Note: `key` / `value` are `ByteArray` (JVM idiomatic, mirrors Python `bytes`).
Tests must ignore Kotlin data-class `equals` on arrays; use content equality.

#### `DlqRecord.kt`

Purpose: DLQ wire record. Mirrors `DLQRecord` in `chio_streaming/dlq.py:37-59`.

```kotlin
data class DlqRecord(
    val topic: String,
    val key: ByteArray,
    val value: ByteArray,
    val headers: List<Pair<String, ByteArray>>,
) : Serializable {
    companion object { private const val serialVersionUID: Long = 1L }
}
```

#### `DlqRouter.kt`

Purpose: build DLQ records for denied evaluations. Mirrors `DLQRouter` in
`chio_streaming/dlq.py:62-197`.

```kotlin
class DlqRouter @JvmOverloads constructor(
    private val defaultTopic: String? = null,
    private val topicMap: Map<String, String> = emptyMap(),
    private val includeOriginalValue: Boolean = true,
) {
    /** Resolve the DLQ topic for a source topic. */
    fun route(sourceTopic: String): String

    @JvmOverloads
    fun buildRecord(
        sourceTopic: String,
        sourcePartition: Int? = null,
        sourceOffset: Long? = null,
        originalKey: ByteArray? = null,
        originalValue: ByteArray? = null,
        requestId: String,
        receipt: ChioReceipt,
        extraMetadata: Map<String, Any?>? = null,
    ): DlqRecord

    fun topicFor(sourceTopic: String): String?
    fun defaultTopic(): String?
}
```

Invariants (all from `dlq.py:118-184`):
- Input receipt MUST be a deny; otherwise throws `ChioValidationError`.
- Payload version: `"chio-streaming/dlq/v1"`.
- Payload keys in fixed order after canonicalisation:
  `version, request_id, verdict, reason, guard, receipt_id, receipt, source, metadata?, original_value?`.
- `source.partition` / `source.offset` are `null` when not supplied, not omitted.
- Headers: `X-Chio-Receipt`, `X-Chio-Verdict` (= `"deny"`),
  `X-Chio-Deny-Guard`, `X-Chio-Deny-Reason`.
- `key` = `originalKey` ?: `requestId.toByteArray(UTF_8)`.
- `original_value` encoded as `{"utf8": ...}` if decodes, else `{"hex": ...}`.

#### `ChioClient.kt`

Purpose: typed blocking HTTP client; drop-in replacement for
`ChioSidecarClient`. Mirrors `ChioClient` in `chio_sdk/client.py:66-364`.
Only blocking methods in v1; async method pair added in v1.1 when the Flink
async operator is rewired to the SDK layer (Phase 2 open question 2).

```kotlin
class ChioClient @JvmOverloads constructor(
    baseUrl: String = SidecarPaths.DEFAULT_BASE_URL,
    timeout: Duration = Duration.ofSeconds(5),
) : AutoCloseable {

    /** POST /chio/evaluate. Mirrors evaluate_http_request (client.py:249-294). */
    @JvmOverloads
    fun evaluateHttpRequest(
        request: ChioHttpRequest,
        capabilityToken: String? = null,
    ): EvaluateResponse

    /** Field-taking overload for Java callers (no model pre-built). */
    @JvmOverloads
    fun evaluateHttpRequest(
        requestId: String,
        method: String,
        routePattern: String,
        path: String,
        caller: CallerIdentity,
        query: Map<String, String> = emptyMap(),
        headers: Map<String, String> = emptyMap(),
        bodyHash: String? = null,
        bodyLength: Long = 0L,
        sessionId: String? = null,
        capabilityId: String? = null,
        capabilityToken: String? = null,
        timestamp: Long? = null,
    ): EvaluateResponse

    /** POST /v1/evaluate. Mirrors evaluate_tool_call (client.py:224-247). */
    fun evaluateToolCall(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt

    /** POST /v1/receipts/verify. Mirrors verify_receipt (client.py:182-191). */
    fun verifyReceipt(receipt: ChioReceipt): Boolean

    /** POST /chio/verify. Mirrors verify_http_receipt (client.py:193-199). */
    fun verifyHttpReceipt(receipt: HttpReceipt): Boolean

    /** Deprecated single-name alias for one-release compat. */
    @Deprecated("Use verifyHttpReceipt", ReplaceWith("verifyHttpReceipt(receipt)"))
    fun verifyReceipt(receipt: HttpReceipt): Boolean

    /** Pure client-side Merkle chain walk. Mirrors
     *  verify_receipt_chain (client.py:201-218). Byte-identical hashes. */
    fun verifyReceiptChain(receipts: List<ChioReceipt>): Boolean

    /** GET /chio/health. Returns parsed map. Mirrors health (client.py:109-111). */
    fun health(): Map<String, Any?>

    /** Boolean shim kept for chio-spring-boot parity with old healthCheck(). */
    fun isHealthy(): Boolean

    override fun close()

    companion object {
        @JvmStatic
        fun collectEvidence(receipts: List<ChioReceipt>): List<GuardEvidence>
    }
}
```

Capability mint (`create_capability`, `validate_capability`,
`attenuate_capability`) is NOT included in v1; see section 9.

### 2.2 `chio-streaming-flink` / `world.chio.flink`

#### `SidecarErrorBehaviour.kt`

```kotlin
enum class SidecarErrorBehaviour { RAISE, DENY }
```

Mirrors the Python `Literal["raise", "deny"]` (flink.py:72).

#### `SerializableFunction.kt` / `SerializableSupplier.kt`

```kotlin
fun interface SerializableFunction<T, R> : Function<T, R>, Serializable
fun interface SerializableSupplier<T> : Supplier<T>, Serializable
```

Flink serialises operator closures; plain `java.util.function` interfaces are
not `Serializable`. Same rationale as `client_factory` in `flink.py:189-197`.

#### `Slots.kt`

Purpose: lazy bounded semaphore gauge carrier. Mirrors
`chio_streaming.core.Slots` (core.py:233-268).

```kotlin
class Slots(private val limit: Int) : Serializable {
    init { require(limit >= 1) { "Slots(limit) must be >= 1" } }
    val inFlight: Int
    /** Blocking acquire. Throws InterruptedException. */
    fun acquire()
    fun release()
    companion object { private const val serialVersionUID: Long = 1L }
}
```

Implementation note for the implementer: JVM-side Slots uses
`java.util.concurrent.Semaphore` because there is no asyncio loop-binding
concern; inFlight is a plain `AtomicInteger`.

#### `ScopeResolver.kt`

Purpose: `resolve_scope` port. Mirrors `core.py:163-180`.

```kotlin
object ScopeResolver {
    @JvmOverloads @JvmStatic
    fun resolve(
        scopeMap: Map<String, String>,
        subject: String,
        defaultPrefix: String = "events:consume",
    ): String
}
```

Throws `ChioValidationError` for empty subject.

#### `BodyCoercion.kt`

Purpose: canonical body bytes for default parameter extractor. Mirrors
`_canonical_body_bytes` in `flink.py:327-343`.

```kotlin
internal object BodyCoercion {
    @JvmStatic
    fun canonicalBodyBytes(element: Any?): ByteArray
}
```

Encoding rules (exact order, match `flink.py:329-343`):
1. `ByteArray` / `ByteBuffer` passthrough.
2. `String` encodes as UTF-8.
3. `Map<*, *>` canonical JSON via `CanonicalJson.writeBytes`.
4. Fallback: `element.toString().toByteArray(UTF_8)`.

#### `DefaultParametersExtractor.kt`

Purpose: extractor returning `{request_id, subject, body_length, body_hash}`.
Mirrors `_default_parameters_extractor` in `flink.py:346-358`.

```kotlin
object DefaultParametersExtractor {
    @JvmStatic
    fun extract(element: Any?, requestId: String, subject: String): Map<String, Any?>
}
```

#### `EvaluationResult.kt`

Purpose: the per-element record the async operator emits. Mirrors
`EvaluationResult` in `flink.py:298-324`.

```kotlin
data class EvaluationResult<IN>(
    val allowed: Boolean,
    val element: IN,
    val receiptBytes: ByteArray? = null,
    val dlqBytes: ByteArray? = null,
) : Serializable {
    companion object { private const val serialVersionUID: Long = 1L }
}
```

#### `FlinkProcessingOutcome.kt`

Purpose: full evaluation outcome (sync operator + tests). Mirrors
`FlinkProcessingOutcome` in `flink.py:261-295`.

```kotlin
data class FlinkProcessingOutcome<IN>(
    val allowed: Boolean,
    val receipt: ChioReceipt,
    val requestId: String,
    val element: IN,
    val subtaskIndex: Int? = null,
    val attemptNumber: Int? = null,
    val checkpointId: Long? = null,
    val receiptBytes: ByteArray? = null,
    val dlqBytes: ByteArray? = null,
    val dlqRecord: DlqRecord? = null,
    val acked: Boolean = false,
    val handlerError: Throwable? = null,
) : Serializable {
    companion object { private const val serialVersionUID: Long = 1L }
}
```

#### `ChioOutputTags.kt`

Purpose: receipt / DLQ side output tag constants and lazy factories. Mirrors
`RECEIPT_TAG_NAME` / `DLQ_TAG_NAME` / `_receipt_tag` / `_dlq_tag` in
`flink.py:75-139`.

```kotlin
object ChioOutputTags {
    const val RECEIPT_TAG_NAME: String = "chio-receipt"
    const val DLQ_TAG_NAME: String = "chio-dlq"

    @JvmStatic fun receiptTag(): OutputTag<ByteArray>
    @JvmStatic fun dlqTag(): OutputTag<ByteArray>
}
```

Names MUST be wire-stable.

#### `ChioFlinkConfig.kt`

Purpose: immutable builder. Mirrors the `@dataclass ChioFlinkConfig` plus
`__post_init__` validation in `flink.py:142-258`. Implements `Serializable`;
closures must be serialisable via the `SerializableFunction` / `SerializableSupplier`
interfaces.

```kotlin
class ChioFlinkConfig<IN> private constructor(
    val capabilityId: String,
    val toolServer: String,
    val scopeMap: Map<String, String>,
    val receiptTopic: String?,
    val maxInFlight: Int,
    val onSidecarError: SidecarErrorBehaviour,
    val subjectExtractor: SerializableFunction<IN, String>,
    val parametersExtractor: SerializableFunction<IN, Map<String, Any?>>?,
    val clientFactory: SerializableSupplier<ChioClient>,
    val dlqRouterFactory: SerializableSupplier<DlqRouter>,
    val requestIdPrefix: String,
) : Serializable {
    companion object {
        @JvmStatic fun <IN> builder(): Builder<IN>
        private const val serialVersionUID: Long = 1L
    }

    class Builder<IN> {
        fun capabilityId(id: String): Builder<IN>
        fun toolServer(server: String): Builder<IN>
        fun scopeMap(map: Map<String, String>): Builder<IN>
        fun receiptTopic(topic: String?): Builder<IN>
        fun maxInFlight(n: Int): Builder<IN>
        fun onSidecarError(b: SidecarErrorBehaviour): Builder<IN>
        fun subjectExtractor(f: SerializableFunction<IN, String>): Builder<IN>
        fun parametersExtractor(f: SerializableFunction<IN, Map<String, Any?>>?): Builder<IN>
        fun clientFactory(s: SerializableSupplier<ChioClient>): Builder<IN>
        fun dlqRouterFactory(s: SerializableSupplier<DlqRouter>): Builder<IN>
        fun requestIdPrefix(p: String): Builder<IN>
        fun build(): ChioFlinkConfig<IN>   // throws ChioValidationError
    }
}
```

Validation (all must throw `ChioValidationError` in `build()`, matching
`flink.py:223-258`):
- `capabilityId` non-empty.
- `toolServer` non-empty.
- `maxInFlight >= 1`.
- `onSidecarError` non-null (Kotlin enforces at call site).
- `subjectExtractor` non-null (REQUIRED, no default).
- `clientFactory` non-null.
- `dlqRouterFactory` non-null.
- `requestIdPrefix` non-empty (default `"chio-flink"`).

Defaults: `scopeMap = emptyMap()`, `receiptTopic = null`, `maxInFlight = 64`,
`onSidecarError = RAISE`, `parametersExtractor = null` (means use default),
`requestIdPrefix = "chio-flink"`.

#### `ChioFlinkEvaluator.kt`

Purpose: shared sync/async core. Mirrors `_ChioFlinkEvaluator` in
`flink.py:410-589`. Internal to the module (`internal` visibility); not
exposed to users. One instance per operator instance.

```kotlin
internal class ChioFlinkEvaluator<IN>(private val config: ChioFlinkConfig<IN>) {
    val slots: Slots
    var subtaskIndex: Int?
    var attemptNumber: Int?

    /** Populate per-subtask state (client, DLQ router, metrics). Called
     *  from operator open(). */
    fun bind(runtimeContext: RuntimeContext)

    /** Release resources. Called from operator close(). */
    fun shutdown()

    /** Evaluate one element. Thread-safe; blocking on semaphore. */
    fun evaluate(element: IN): FlinkProcessingOutcome<IN>
}
```

Metric names registered on `getMetricGroup().addGroup("chio")` (matches
`flink.py:361-380`): `evaluations_total`, `allow_total`, `deny_total`,
`sidecar_errors_total` counters; `in_flight` gauge returning `slots.inFlight`.

#### `ChioAsyncEvaluateFunction.kt`

Purpose: RichAsyncFunction primary path. Mirrors `ChioAsyncEvaluateFunction`
in `flink.py:644-704`.

```kotlin
class ChioAsyncEvaluateFunction<IN>(
    private val config: ChioFlinkConfig<IN>,
) : RichAsyncFunction<IN, EvaluationResult<IN>>() {
    override fun open(openContext: OpenContext)
    override fun asyncInvoke(value: IN, resultFuture: ResultFuture<EvaluationResult<IN>>)
    override fun close()
}
```

Implementation notes for Phase 3:
- Use `ChioClient` blocking methods on an internal per-subtask
  `Executor` (sized to `config.maxInFlight`). Delegate to `evaluator.evaluate`;
  on completion call `resultFuture.complete(listOf(EvaluationResult(...)))`.
  This satisfies the Flink "never block the task thread" rule without
  requiring an async SDK method.
- On `RAISE` behaviour with sidecar error: `resultFuture.completeExceptionally(err)`.

#### `ChioVerdictSplitFunction.kt`

Purpose: trailing `ProcessFunction` that splits async outputs to side outputs.
Mirrors `ChioVerdictSplitFunction` in `flink.py:707-732`.

```kotlin
class ChioVerdictSplitFunction<IN> : ProcessFunction<EvaluationResult<IN>, IN>() {
    override fun processElement(
        value: EvaluationResult<IN>,
        ctx: Context,
        out: Collector<IN>,
    )
}
```

Emits `value.element` to main only when allowed, `receiptTag` bytes when
non-null, `dlqTag` bytes when non-null. Tags come from `ChioOutputTags`.

#### `ChioEvaluateFunction.kt`

Purpose: synchronous `ProcessFunction` variant. Mirrors `ChioEvaluateFunction`
in `flink.py:592-641`. Chosen shape: plain `ProcessFunction<IN, IN>` (not
`KeyedProcessFunction`) per the Phase 1 open question resolution favouring
parity.

```kotlin
class ChioEvaluateFunction<IN>(
    private val config: ChioFlinkConfig<IN>,
) : ProcessFunction<IN, IN>() {
    override fun open(openContext: OpenContext)
    override fun processElement(value: IN, ctx: Context, out: Collector<IN>)
    override fun close()
}
```

Emits: `value` to main on allow, receipt bytes to `receiptTag` when non-null,
DLQ bytes to `dlqTag` when non-null.

### 2.3 chio-spring-boot compat files

#### `compat/ChioSdkAliases.kt`

Purpose: typealias re-exports so existing chio-spring-boot users import
`world.chio.AuthMethod` without churn. One-release compat; removed in
0.2.0.

```kotlin
@file:JvmName("ChioSdkAliases")
package world.chio

typealias AuthMethod = world.chio.sdk.AuthMethod
typealias CallerIdentity = world.chio.sdk.CallerIdentity
typealias Verdict = world.chio.sdk.Verdict
typealias GuardEvidence = world.chio.sdk.GuardEvidence
typealias HttpReceipt = world.chio.sdk.HttpReceipt
typealias ChioHttpRequest = world.chio.sdk.ChioHttpRequest
typealias EvaluateResponse = world.chio.sdk.EvaluateResponse
typealias ChioPassthrough = world.chio.sdk.ChioPassthrough
typealias ChioErrorResponse = world.chio.sdk.ChioErrorResponse
typealias ChioErrorCodes = world.chio.sdk.ChioErrorCodes
```

#### `compat/ChioSidecarClient.kt`

Purpose: thin deprecated shim so `ChioFilter` keeps working without
re-importing. Delegates to `world.chio.sdk.ChioClient`.

```kotlin
package world.chio

import world.chio.sdk.ChioClient
import java.time.Duration

@Deprecated(
    "Use world.chio.sdk.ChioClient directly",
    ReplaceWith("world.chio.sdk.ChioClient(baseUrl, java.time.Duration.ofSeconds(timeoutSeconds))"),
)
class ChioSidecarClient @JvmOverloads constructor(
    baseUrl: String = ChioClient.DEFAULT_BASE_URL,
    timeoutSeconds: Long = 5,
) {
    private val delegate: ChioClient

    fun evaluate(request: ChioHttpRequest, capabilityToken: String? = null): EvaluateResponse
    fun verifyReceipt(receipt: HttpReceipt): Boolean
    fun healthCheck(): Boolean

    companion object { const val DEFAULT_SIDECAR_URL = ChioClient.DEFAULT_BASE_URL }
}

// Legacy exception name kept as alias:
typealias ChioSidecarException = world.chio.sdk.errors.ChioError
```

## 3. Canonical JSON contract

Jackson mapper configuration (exact; implementer must produce this):

```kotlin
val MAPPER: ObjectMapper = ObjectMapper(
    JsonFactory().enable(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature())
)
    .registerModule(KotlinModule.Builder().build())
    .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
    .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
    .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true)
    .configure(SerializationFeature.INDENT_OUTPUT, false)
    .setDefaultPropertyInclusion(
        JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL)
    )
```

Post-configuration: `writeBytes` returns `mapper.writeValueAsBytes(value)`.

Test vectors (all MUST pass byte-identically with Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`):

Vector 1 - nested map with unicode:
- Input: `mapOf("b" to 2, "a" to mapOf("cafe" to "café", "xyz" to 1))`
- Expected bytes (string form): `{"a":{"cafe":"café","xyz":1},"b":2}`.
- Python reference: `json.dumps({"b":2,"a":{"cafe":"café","xyz":1}}, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.

Vector 2 - emoji + sort order:
- Input: `mapOf("z" to "a", "Z" to "b", "0" to "💡")`
  (the surrogate pair encodes U+1F4A1, light bulb).
- Expected bytes: `{"0":"💡","Z":"b","z":"a"}`.
- Edge case: uppercase sorts before lowercase (ASCII code-point order),
  and surrogate pairs are emitted as two `\uXXXX` escapes in lowercase hex,
  matching Python.

Vector 3 - null value and nested array with mixed types:
- Input: `mapOf("null_field" to null, "arr" to listOf(1, "two", mapOf("k" to 3L)), "flag" to true)`
- Expected bytes: `{"arr":[1,"two",{"k":3}],"flag":true,"null_field":null}`.
- Edge case: `NON_NULL` inclusion is property-level, not map-value-level; map
  values that are `null` MUST serialise as `null` (mirroring Python
  `json.dumps({"a": None}) -> '{"a":null}'`). The implementer MUST NOT
  drop null map values via a bad inclusion default.

All three vectors become assertions in `CanonicalJsonTest.kt`.

Number semantics caveat (Phase 1 open question 1): floats are not exercised
by these vectors because the Rust kernel does not round-trip float receipt
fields. If that changes, add a float vector; for v1 the test suite
restricts inputs to `Int`, `Long`, `Boolean`, `String`, `null`, `Map`, `List`.

## 4. Migration of chio-spring-boot

Files that MOVE to `chio-sdk-jvm` (`world.chio.sdk`):
- `ChioSidecarClient.kt` -> widened and renamed to `ChioClient.kt`.
- `ChioTypes.kt` -> split into `ChioTypes.kt` (HTTP types) +
  `Decision.kt` + `ToolCallAction.kt` + `ChioReceipt.kt`.
- `sha256Hex` (from `ChioIdentityExtractor.kt:13-22`) -> `Hashing.kt`.

Files that STAY in chio-spring-boot (unchanged logic, import updates only):
- `ChioFilter.kt`: change imports from `world.chio.ChioSidecarClient` to
  `world.chio.sdk.ChioClient`; call `evaluateHttpRequest` instead of
  `evaluate`. Typealias shim means no churn if keeping `ChioSidecarClient` name.
- `CachedBodyHttpServletRequest.kt`: unchanged.
- `ChioAutoConfiguration.kt`: unchanged.
- `ChioIdentityExtractor.kt`: delete the top-level `sha256Hex` functions
  (callers import `world.chio.sdk.Hashing.sha256Hex`). Keep
  `defaultIdentityExtractor` and `IdentityExtractorFn`.
- `spring.factories` resource: unchanged.
- Tests `ChioFilterBodyTest.kt`, `ChioFilterCapabilityTransportTest.kt`:
  unchanged; typealiases keep imports working.
- `ChioTypesTest.kt`: MOVES to `chio-sdk-jvm/src/test/kotlin/...`.

New files added to chio-spring-boot:
- `compat/ChioSdkAliases.kt` (typealiases).
- `compat/ChioSidecarClient.kt` (deprecated delegating shim).

`build.gradle.kts` diff:
- Adopt version catalog (plugin + dep refs use `libs.*`).
- Add `api(project(":chio-sdk-jvm"))`.
- Remove `implementation("com.fasterxml.jackson.module:jackson-module-kotlin")`
  (now transitive via `api` on chio-sdk-jvm).
- `settings.gradle.kts` DELETED (root owns inclusion).

## 5. Gradle skeletons

### `sdks/jvm/settings.gradle.kts`

```kotlin
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories { mavenCentral() }
    versionCatalogs {
        create("libs") { from(files("gradle/libs.versions.toml")) }
    }
}

rootProject.name = "chio-jvm"

include(":chio-sdk-jvm")
include(":chio-spring-boot")
include(":chio-streaming-flink")
```

### `sdks/jvm/build.gradle.kts`

```kotlin
plugins {
    alias(libs.plugins.spotless) apply false
}

allprojects {
    group = "world.chio"
    version = "0.1.0"
    repositories { mavenCentral() }
}

subprojects {
    apply(plugin = "com.diffplug.spotless")
    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        kotlin {
            ktlint(rootProject.libs.versions.ktlint.get())
            target("src/**/*.kt")
        }
        kotlinGradle {
            ktlint(rootProject.libs.versions.ktlint.get())
            target("*.gradle.kts")
        }
    }
}
```

### `sdks/jvm/gradle/libs.versions.toml`

```toml
[versions]
kotlin = "2.3.0"
springBoot = "3.2.2"
flink = "2.2.0"
jackson = "2.17.2"
junit = "5.11.4"
spotless = "7.0.2"
ktlint = "1.5.0"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
kotlin-test-junit5 = { module = "org.jetbrains.kotlin:kotlin-test-junit5", version.ref = "kotlin" }

jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
jackson-module-kotlin = { module = "com.fasterxml.jackson.module:jackson-module-kotlin", version.ref = "jackson" }

springBoot-bom = { module = "org.springframework.boot:spring-boot-dependencies", version.ref = "springBoot" }
springBoot-starter-web = { module = "org.springframework.boot:spring-boot-starter-web" }
springBoot-starter-test = { module = "org.springframework.boot:spring-boot-starter-test" }

flink-streaming-java = { module = "org.apache.flink:flink-streaming-java", version.ref = "flink" }
flink-clients = { module = "org.apache.flink:flink-clients", version.ref = "flink" }
flink-test-utils = { module = "org.apache.flink:flink-test-utils", version.ref = "flink" }

junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version.ref = "junit" }

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
kotlin-spring = { id = "org.jetbrains.kotlin.plugin.spring", version.ref = "kotlin" }
springBoot = { id = "org.springframework.boot", version.ref = "springBoot" }
spotless = { id = "com.diffplug.spotless", version.ref = "spotless" }
```

### `sdks/jvm/chio-sdk-jvm/build.gradle.kts`

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api(libs.kotlin.stdlib)
    api(libs.jackson.databind)
    api(libs.jackson.module.kotlin)
    implementation(libs.kotlin.reflect)

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit.jupiter)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.withType<Test> { useJUnitPlatform() }
```

### `sdks/jvm/chio-streaming-flink/build.gradle.kts`

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

sourceSets {
    create("integrationTest") {
        compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
        runtimeClasspath += output + compileClasspath
    }
}

val integrationTestImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.testImplementation.get())
}

dependencies {
    api(project(":chio-sdk-jvm"))
    compileOnly(libs.flink.streaming.java)

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.flink.streaming.java)

    integrationTestImplementation(libs.flink.test.utils)
    integrationTestImplementation(libs.flink.clients)
    integrationTestImplementation(libs.flink.streaming.java)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        excludeTags("integration")
    }
}

val integrationTest by tasks.registering(Test::class) {
    description = "Runs Flink MiniCluster integration tests."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform { includeTags("integration") }
    shouldRunAfter("test")
    systemProperty("junit.jupiter.execution.parallel.enabled", "false")
}
// Deliberately NOT wiring check -> integrationTest; CI skips integration tests.
```

### `sdks/jvm/chio-spring-boot/build.gradle.kts` (refactored)

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.springBoot) apply false
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api(project(":chio-sdk-jvm"))
    implementation(platform(libs.springBoot.bom))
    implementation(libs.springBoot.starter.web)
    implementation(libs.kotlin.reflect)

    testImplementation(platform(libs.springBoot.bom))
    testImplementation(libs.springBoot.starter.test)
    testImplementation(libs.kotlin.test.junit5)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.withType<Test> { useJUnitPlatform() }
```

## 6. Test plan

### `chio-sdk-jvm` tests

- `CanonicalJsonTest.kt` - the three canonical vectors from section 3 byte-for-byte;
  additional null-map-value, empty-list, deep-nesting cases.
- `HashingTest.kt` - known-answer SHA-256 (hex lowercase) for `""`, `"abc"`,
  round-trip with `hashBody(null)` returning null.
- `ChioClientHttpTest.kt` - stand up `com.sun.net.httpserver.HttpServer` on a
  free port (pattern from `ChioFilterCapabilityTransportTest.kt:6`). Covers:
  `evaluateToolCall` payload shape includes `parameter_hash`; `verifyReceipt`
  POSTs to `/v1/receipts/verify`; `verifyHttpReceipt` POSTs to `/chio/verify`;
  `health()` returns parsed map; 403 maps to `ChioDeniedError` with populated
  fields; connection failure maps to `ChioConnectionError`; timeout maps to
  `ChioTimeoutError`; `verifyReceiptChain` returns false when
  `receipts[i].contentHash != sha256(canonical(receipts[i-1]))`.
- `ChioDeniedErrorTest.kt` - `fromWire` accepts all 11 fields; `toWire`
  round-trips; `fromWire` falls back to `reason` then `"denied"` for empty
  message.
- `ChioReceiptParseTest.kt` - Jackson deserialises a canonical receipt JSON
  fixture; `isAllowed` / `isDenied` match; `null` metadata round-trips;
  `evidence = []` deserialises as empty list.
- `ChioTypesTest.kt` - existing snake_case wire tests (moved verbatim).
- `DlqRouterTest.kt` - routing precedence (explicit > default > error);
  non-deny receipt rejected; header ordering matches Python
  (`X-Chio-Receipt` first); `original_value` utf8 vs hex branches.
- `ReceiptEnvelopeTest.kt` - `build` produces `ENVELOPE_VERSION`-tagged
  payload; headers `X-Chio-Receipt` and `X-Chio-Verdict`; key is `requestId`
  UTF-8 bytes; `source_*` fields absent when null.
- `SyntheticDenyReceiptTest.kt` - `MARKER` value wire-stable; `[unsigned]`
  prefix applied once (idempotent); `kernelKey == ""`, `signature == ""`;
  `parameterHash == sha256(canonical(parameters))`.

### `chio-streaming-flink` unit tests

- `ChioFlinkConfigTest.kt` - builder validation: empty capabilityId / toolServer /
  requestIdPrefix throws; maxInFlight < 1 throws; missing subjectExtractor
  throws; missing clientFactory / dlqRouterFactory throws.
- `ScopeResolverTest.kt` - explicit map hit; default prefix fallback; empty
  subject throws.
- `DefaultParametersExtractorTest.kt` - dict, string, bytes, and fallback
  `toString()` coercion produce the same `body_hash` Python would.
- `ChioFlinkEvaluatorTest.kt` - allow path populates `receiptBytes` only when
  `receiptTopic` set; deny path populates `dlqBytes` + `dlqRecord`, leaves
  `receiptBytes = null`; `RAISE` behaviour throws `ChioError` subclass on
  sidecar error; `DENY` behaviour synthesises marker receipt + DLQ record;
  metrics `evaluations_total`, `allow_total`, `deny_total`,
  `sidecar_errors_total` increment on the right branches.
- `ChioAsyncEvaluateFunctionTest.kt` - given a fake `RuntimeContext` and a
  fake `ResultFuture`, assert exactly one `EvaluationResult` completed per
  element; exception on `RAISE` sidecar failure reaches
  `completeExceptionally`.
- `ChioVerdictSplitFunctionTest.kt` - main output receives `element` only on
  allow; receipt side output receives bytes when non-null; DLQ side output
  receives bytes when non-null; tag names are `"chio-receipt"` and
  `"chio-dlq"`.
- `ChioEvaluateFunctionTest.kt` - parity of side-output emissions with async
  pair; covers the parity invariants in section 8.

Support fakes live under `support/` and are in-test only:
- `FakeChioClient` implements `ChioClient`-compatible methods returning
  pre-seeded responses (allow / deny / throw).
- `FakeDlqRouter` records every `buildRecord` call.
- `FakeRuntimeContext` stubs `getIndexOfThisSubtask`, `getAttemptNumber`,
  `getMetricGroup` with a minimal `MetricGroup` mock.

### Integration tests (`@Tag("integration")`)

- `MiniClusterAsyncJobIT.kt` - stand up `MiniClusterWithClientResource`, a
  JDK `HttpServer` fake sidecar, and a four-element source (allow, deny,
  allow, sidecar-error with `DENY`). Assert main output = 2 allowed
  elements, DLQ side output = 2 records (1 real deny, 1 synthetic), receipt
  side output = 2 allow envelopes.
- `MiniClusterSyncJobIT.kt` - same but wired via `ChioEvaluateFunction`.

## 7. CI diff

Add to `.github/workflows/ci.yml`, parallel to existing `check` job:

```yaml
  jvm-build:
    name: JVM build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
      - uses: gradle/actions/setup-gradle@v4
      - name: Build JVM modules
        working-directory: sdks/jvm
        run: ./gradlew build --no-daemon
```

Notes: `build` runs compile + unit tests + spotlessCheck; it does NOT run
`integrationTest` because `integrationTest` is not wired into `check`. JDK 21
is installed because `chio-streaming-flink` requires it; the other modules
compile cleanly against 21's javac targeting 17 bytecode.

## 8. Parity invariants to test

Every row is an invariant from `chio_streaming/flink.py` or the Python SDK
and the JVM test that pins it.

| Invariant | Source | JVM test |
| --- | --- | --- |
| Canonical JSON byte-identical across map key ordering | `flink.py:335-340` | `CanonicalJsonTest.matchesPythonVectorMapSorted` |
| Canonical JSON escapes non-ASCII as `\uXXXX` lowercase hex | `client.py:46-47` | `CanonicalJsonTest.matchesPythonVectorUnicodeEscapes` |
| Canonical JSON preserves null map values | Python `json.dumps({"a":None})` | `CanonicalJsonTest.nullMapValueRoundTrips` |
| Wire-stable tag names `"chio-receipt"` / `"chio-dlq"` | `flink.py:76-79` | `ChioVerdictSplitFunctionTest.tagNamesAreWireStable` |
| Deny emits only DLQ, no receipt envelope | `flink.py:552-566` | `ChioEvaluateFunctionTest.denyYieldsDlqOnlyNoReceipt` |
| Allow emits main + optional receipt | `flink.py:568-589` | `ChioEvaluateFunctionTest.allowYieldsMainAndReceiptWhenTopicSet` |
| Allow without `receiptTopic` emits main only | `flink.py:569-570` | `ChioEvaluateFunctionTest.allowWithoutTopicYieldsMainOnly` |
| `RAISE` propagates sidecar errors upward | `flink.py:528-531` | `ChioEvaluateFunctionTest.sidecarErrorRaiseThrows` |
| `DENY` synthesises receipt with `SYNTHETIC_RECEIPT_MARKER` | `core.py:116, flink.py:532-539` | `ChioEvaluateFunctionTest.sidecarErrorDenySynthesisesReceiptWithMarker` |
| Synthetic deny reason prefixed `"[unsigned]"` | `core.py:139` | `SyntheticDenyReceiptTest.reasonPrefixAppliedOnce` |
| Synthetic deny has empty `kernelKey` / `signature` | `core.py:158-159` | `SyntheticDenyReceiptTest.kernelKeyAndSignatureEmpty` |
| `subjectExtractor` required at config build time | `flink.py:246-258` | `ChioFlinkConfigTest.missingSubjectExtractorThrows` |
| Default parameters extractor fields = `{request_id, subject, body_length, body_hash}` | `flink.py:346-358` | `DefaultParametersExtractorTest.defaultFieldsMatch` |
| `body_hash` = hex SHA-256 of canonical body bytes | `flink.py:327-358` | `DefaultParametersExtractorTest.bodyHashMatchesCanonicalSha256` |
| Factories (not instances) serialisable across operator boundary | `flink.py:187-197` | `ChioFlinkConfigTest.configRoundTripsThroughJavaSerialization` |
| `maxInFlight` enforces per-subtask semaphore | `flink.py:162-167` | `ChioFlinkEvaluatorTest.maxInFlightLimitsConcurrency` |
| Metrics group `chio` + 4 counters + 1 gauge | `flink.py:361-380` | `ChioFlinkEvaluatorTest.metricsRegisteredUnderChioGroup` |
| `request_id` = `prefix + "-" + uuidHex` | `core.py:228-230` | `ChioFlinkEvaluatorTest.requestIdFormat` |
| `close()` calls `ChioClient.close()` | `flink.py:667-693` Java analogue | `ChioEvaluateFunctionTest.closeInvokesClientClose` |
| DLQ payload version `"chio-streaming/dlq/v1"` | `dlq.py:154` | `DlqRouterTest.payloadVersionPinned` |
| DLQ headers ordered `X-Chio-Receipt, X-Chio-Verdict, X-Chio-Deny-Guard, X-Chio-Deny-Reason` | `dlq.py:172-177` | `DlqRouterTest.headerOrderPinned` |
| DLQ `key = original_key ?: request_id.utf8` | `dlq.py:178` | `DlqRouterTest.keyFallsBackToRequestId` |
| DLQ `original_value` utf8 vs hex branch | `dlq.py:200-205` | `DlqRouterTest.originalValueEncoding` |
| Receipt envelope version `"chio-streaming/v1"` | `receipt.py:35` | `ReceiptEnvelopeTest.versionPinned` |
| `evaluate_tool_call` sends `parameter_hash` canonical SHA-256 | `client.py:236-245` | `ChioClientHttpTest.evaluateToolCallSendsParameterHash` |
| `verify_receipt_chain` Merkle walk byte-identical | `client.py:201-218` | `ChioClientHttpTest.verifyReceiptChainUsesCanonicalHash` |
| 403 body maps to `ChioDeniedError.fromWire` | `client.py:348-354, errors.py:98-124` | `ChioClientHttpTest.deny403MapsToStructuredError` |

## 9. Known gaps and explicit deferrals

- **Capability mint flow** (`create_capability`, `validate_capability`,
  `attenuate_capability`, capability token models, `is_subset_of`, the whole
  `chio_sdk.models` capability stack from `models.py:21-305`). Deferred
  post-v1. Stub constants / reserved package `world.chio.sdk.capabilities`
  may be pre-created empty, but no code is required. Revisit before 0.2.0.
- **Kafka connector version skew**. We intentionally do not depend on
  `flink-connector-kafka`; users bring their own sink. Document in the
  `chio-streaming-flink` README (not in this plan) the 4.0.1-2.0 vs 2.2 gap
  and the workaround (pass `transactionalIdPrefix`, match to Flink 2.2
  via the Flink externalised-connector compatibility guarantee).
- **Publishing setup** (`maven-publish`, `signing`, Sonatype). Out of scope.
- **Golden wire-parity tests against Python output**. Deferred. The approach
  when we wire this up: a fixture-generating Python test dumps canonical
  receipt envelopes + DLQ records into
  `sdks/jvm/chio-streaming-flink/src/test/resources/parity/*.json`; a JVM
  `parity`-tagged test rebuilds the same inputs, asserts byte equality.
  Until it lands, `CanonicalJsonTest` vectors plus the per-field invariants
  in section 8 are the pin.
- **`ChioDeniedError` multi-line `toString()` pretty-print** (errors.py:126-175).
  Deferred. The v1 error still carries all 11 fields and a `toWire()` dict;
  the pretty-print is a cosmetic Python-side niceity.
- **Async SDK method** (`evaluateToolCallAsync` returning `CompletionStage`).
  Deferred. `ChioAsyncEvaluateFunction` wraps the blocking client on an
  executor; an async method pair lands in v1.1 once the Flink async path is
  proven.
- **`KeyedProcessFunction` sync operator variant** (Phase 1 operator-design
  open question). Deferred to v1.1 (`ChioKeyedEvaluateFunction<K, IN>`).
- **`register_dependencies` helper** (flink.py:749-779). No JVM analogue
  shipped; JVM users build fat jars.

## 10. Execution order for Phase 3

Each step leaves the repo with `(cd sdks/jvm && ./gradlew build --no-daemon)`
passing. Do not reorder without re-validating that invariant.

1. **Create multi-project Gradle skeleton.** Move wrapper up one level, write
   root `settings.gradle.kts`, `build.gradle.kts`, `gradle.properties`, and
   `gradle/libs.versions.toml` (section 5). Delete
   `chio-spring-boot/settings.gradle.kts`. Refactor
   `chio-spring-boot/build.gradle.kts` to use the version catalog BUT do not
   yet add `api(project(":chio-sdk-jvm"))` (the SDK project is still empty).
   Verify: `./gradlew build` still compiles chio-spring-boot unchanged.

2. **Scaffold empty `chio-sdk-jvm` and `chio-streaming-flink` subprojects.**
   `build.gradle.kts` files per section 5; empty `src/main/kotlin/...`
   directories so Gradle does not complain. Verify: `./gradlew build`.

3. **Build `chio-sdk-jvm` errors + canonical JSON + hashing.** `errors/*.kt`,
   `CanonicalJson.kt`, `Hashing.kt`. Unit tests `CanonicalJsonTest.kt`,
   `HashingTest.kt`, `ChioDeniedErrorTest.kt`. This is the load-bearing
   foundation; nothing else is useful until the canonical mapper matches
   Python byte-for-byte.

4. **Port types.** `ChioTypes.kt` (HTTP types), `Decision.kt`,
   `ToolCallAction.kt`, `ChioReceipt.kt`. Move `ChioTypesTest.kt` from
   chio-spring-boot into the new module. Add `ChioReceiptParseTest.kt`.

5. **Port `ChioClient.kt`.** Depend on the mapper from step 3. Tests in
   `ChioClientHttpTest.kt` (HttpServer-backed). `SidecarPaths.kt`.

6. **Port receipt/DLQ helpers.** `SyntheticDenyReceipt.kt`,
   `ReceiptEnvelope.kt`, `DlqRecord.kt`, `DlqRouter.kt` plus tests.

7. **Wire chio-spring-boot compat layer.** Add `api(project(":chio-sdk-jvm"))`
   to the Spring build file. Delete old `ChioSidecarClient.kt` and
   `ChioTypes.kt`. Add `compat/ChioSdkAliases.kt` and
   `compat/ChioSidecarClient.kt`. Strip `sha256Hex` from
   `ChioIdentityExtractor.kt`; update its imports. Run existing tests;
   they should pass unchanged. Verify: `./gradlew :chio-spring-boot:test`.

8. **Build `chio-streaming-flink` non-operator primitives.**
   `SidecarErrorBehaviour.kt`, `SerializableFunction.kt`,
   `SerializableSupplier.kt`, `Slots.kt`, `ScopeResolver.kt`,
   `BodyCoercion.kt`, `DefaultParametersExtractor.kt`, `ChioOutputTags.kt`,
   `EvaluationResult.kt`, `FlinkProcessingOutcome.kt`. Unit tests for scope
   resolver, default parameters extractor, Slots concurrency.

9. **Build `ChioFlinkConfig` + builder.** Validation tests
   (`ChioFlinkConfigTest.kt`).

10. **Build `ChioFlinkEvaluator`** (internal shared core). Tests with fakes.

11. **Build the three operators.** `ChioAsyncEvaluateFunction.kt`,
    `ChioVerdictSplitFunction.kt`, `ChioEvaluateFunction.kt`. Unit tests
    with `FakeRuntimeContext` / `FakeChioClient` / `FakeDlqRouter`.
    Every parity invariant in section 8 becomes a test here.

12. **Integration tests.** `MiniClusterAsyncJobIT.kt` and
    `MiniClusterSyncJobIT.kt` under `integrationTest` source set. Gated
    `@Tag("integration")`; run locally with `./gradlew integrationTest`,
    skipped in CI.

13. **CI job.** Add the `jvm-build` block from section 7 to
    `.github/workflows/ci.yml`. Confirm `(cd sdks/jvm && ./gradlew build --no-daemon)`
    passes on a fresh checkout.

14. **Example project settings update (optional).** Flip
    `examples/hello-spring-boot/settings.gradle.kts` from
    `includeBuild("../../sdks/jvm/chio-spring-boot")` to
    `includeBuild("../../sdks/jvm")`. Safe under Gradle composite build
    substitution (the `world.chio:chio-spring-boot:0.1.0` coordinate
    resolves to the `:chio-spring-boot` subproject). Non-blocking for the
    Phase 3 gate.

Phase 3 is complete when steps 1-13 are merged and
`(cd sdks/jvm && ./gradlew build --no-daemon)` is green in CI on main.
