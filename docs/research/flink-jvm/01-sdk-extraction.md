# 01 - Chio JVM SDK extraction

## Summary recommendation

Extract. `chio-spring-boot` already isolates its Spring-free core
(`ChioSidecarClient.kt`, `ChioTypes.kt`, `ChioIdentityExtractor.kt::sha256Hex`)
from its Spring-specific filter/auto-config; moving the non-Spring files
into a new `sdks/jvm/chio-sdk-jvm/` Gradle subproject and widening the
surface to match `chio_sdk.client.ChioClient` unblocks Flink without
regressing the Spring starter. Stack: **Kotlin 2.3** on **JDK 21**,
**`java.net.http.HttpClient`** (no OkHttp/Ktor), **Jackson** with
`ORDER_MAP_ENTRIES_BY_KEYS` + `ESCAPE_NON_ASCII` for canonical JSON,
**JUnit 5 + `kotlin-test-junit5`**, package `world.chio.sdk`, and
a **multi-project Gradle** root at `sdks/jvm/` where `chio-spring-boot`
declares `api(project(":chio-sdk-jvm"))`.

## 1. Should we extract?

Yes. A file-by-file read of `sdks/jvm/chio-spring-boot/src/main/kotlin/world/chio/`
shows the seam is already drawn:

- `ChioSidecarClient.kt` lines 9-17 import only `com.fasterxml.jackson.*`
  and `java.net.http.*`. `ChioSidecarException` (line 20) is a plain
  `RuntimeException`. Moves verbatim.
- `ChioTypes.kt` lines 9-11: only Jackson annotations. All data classes,
  companion factories (`Verdict.allow()` line 63, `AuthMethod.bearer`
  line 27), and `ChioErrorCodes` move verbatim.
- `ChioIdentityExtractor.kt` lines 13-22 (`sha256Hex` overloads): pure
  JDK `MessageDigest`. Move; leave `defaultIdentityExtractor`
  (lines 34-75, depends on `HttpServletRequest`) in chio-spring-boot.
- `ChioFilter.kt`, `CachedBodyHttpServletRequest.kt`,
  `ChioAutoConfiguration.kt`, `spring.factories`: import
  `jakarta.servlet.*` / `org.springframework.*`. Stay in chio-spring-boot
  and pick up `api project(":chio-sdk-jvm")`.

`ChioFilter.kt` line 62 constructs the client with just `sidecarUrl` +
`timeoutSeconds` and line 129 calls `client.evaluate(chioRequest,
capabilityToken)`. No Spring or Servlet type crosses that boundary, and
`ChioTypesTest.kt` lines 21-188 already asserts snake_case wire
compatibility, so extraction preserves conformance guarantees instead of
rebuilding them.

## 2. Language choice

**Kotlin 2.3** targeting JDK 21. Pure Java would regress current Spring
users who already consume Kotlin artifacts (`build.gradle.kts` line 2)
and would force static-factory classes to replace the companion-object
pattern that mirrors Python's `@classmethod` factories 1:1 (e.g.
`Verdict.allow()` at `ChioTypes.kt` line 63 vs `models.py` line 358).
Flink Java developers lose nothing - every Kotlin class compiles to a
Java-callable JAR; add `@JvmOverloads` and `@JvmStatic` where Python
uses keyword-only params. Scala is out of scope: Flink's Scala API is
in maintenance, and a Scala SDK would fork the canonical-JSON code,
which MUST stay byte-identical.

## 3. API surface to mirror

Method-level comparison, `chio_sdk.client.ChioClient` vs
`ChioSidecarClient`:

| Python (`client.py`) | JVM today (`ChioSidecarClient.kt`) | Gap |
| --- | --- | --- |
| `evaluate_tool_call` (224-247), POST `/v1/evaluate` | absent | **Missing.** Core Flink use case - `chio_streaming/core.py` line 88 calls it via `ChioClientLike`. Must add, with canonical-JSON + SHA-256 `parameter_hash`. |
| `evaluate_http_request` (249-294) | `evaluate(ChioHttpRequest, ...)` (43-73) | Shape matches; JVM takes a pre-built model. Add a field-taking overload for Java callers. |
| `verify_receipt(ChioReceipt)` (182-191) POST `/v1/receipts/verify` | absent | **Missing.** Different endpoint from HTTP verify. |
| `verify_http_receipt(HttpReceipt)` (193-199) POST `/chio/verify` | `verifyReceipt(HttpReceipt)` (76-93) | Same endpoint. Rename to `verifyHttpReceipt`, keep deprecated alias. |
| `verify_receipt_chain(list[ChioReceipt])` (201-218) | absent | **Missing.** Pure-client canonical-JSON + SHA-256 chain walk; MUST be byte-identical. |
| `health()` -> dict (109-111) | `healthCheck()` -> Boolean (96-109) | Widen JVM to `Map<String, Any>`; keep `isHealthy()` boolean shim. |
| `create_capability` / `validate_capability` / `attenuate_capability` (117-176) | absent | **Missing.** `/v1/capabilities*`. Lower priority for Flink first cut but add stubs so 0.1.0 surface is not later broken. `attenuate` carries a local `is_subset_of` precheck that must port unchanged. |
| `collect_evidence` staticmethod (301-308) | absent | Trivial; port as top-level `@JvmStatic`. |

Type gaps, `chio_sdk.models` vs `ChioTypes.kt`:

- **`ChioReceipt`** (Python 419-442) - absent on JVM; today's module has
  only `HttpReceipt` (79-96). This is the Flink operator's primary
  return type and the biggest single blocker. Needs `id`, `timestamp`,
  `capability_id`, `tool_server`, `tool_name`, `action: ToolCallAction`,
  `decision: Decision`, `content_hash`, `policy_hash`, `evidence`,
  `metadata`, `kernel_key`, `signature`.
- **`Decision`** (313-346) and **`ToolCallAction`** (407-411) - absent.
  `Decision` is like `Verdict` but adds `cancelled`/`incomplete` and
  drops `http_status`. Python's `Verdict.to_decision` (375) bridges
  them; port once both exist.
- **Capability-token stack** - `CapabilityToken`, `CapabilityTokenBody`,
  `ChioScope`, `ToolGrant`, `ResourceGrant`, `PromptGrant`, `Operation`,
  `Constraint`, `MonetaryAmount`, `DelegationLink`, `Attenuation`,
  `RuntimeAssuranceTier`, `GovernedAutonomyTier` (Python 21-305) - all
  absent. Match Python's flat discriminator shape (e.g. `Constraint`
  with a string `type` + optional `value` at `models.py` line 73)
  rather than Jackson's polymorphic `@JsonTypeInfo`; the flat shape is
  simpler and matches what the Rust `#[serde(tag, content)]` emits.
- `AuthMethod`, `CallerIdentity`, `GuardEvidence`, `HttpReceipt`,
  `ChioHttpRequest`, `EvaluateResponse`, `ChioPassthrough`,
  `ChioErrorResponse` already match on both sides.

Error-hierarchy gap, `chio_sdk.errors` vs JVM: Python has
`ChioError` (base, line 8), `ChioConnectionError` (16),
`ChioTimeoutError` (23), `ChioDeniedError` (30-175) with 10+ structured
fields plus `from_wire` / `to_dict`, and `ChioValidationError` (178).
JVM today collapses connection and timeout into a single
`ChioSidecarException` (`ChioSidecarClient.kt` line 20) and has no
`ChioDeniedError` equivalent - `ChioFilter` surfaces denies as JSON
response bodies, never exceptions. The Flink operator needs a thrown
`ChioDeniedError` so the `except ChioDeniedError` branch in
`chio_streaming/core.py` line 94 has a JVM analogue; add the full
hierarchy plus `fromWire(JsonNode)` and `toWire()` helpers.

Net: today's JVM surface is roughly 30% of Python's. Extraction without
widening ships a crippled SDK. The extraction PR MUST add `ChioReceipt`,
`Decision`, `ToolCallAction`, `evaluate_tool_call`,
`verify_receipt_chain`, the error hierarchy, and the canonical-JSON
helper. Capability-mint endpoints can trail behind but should be
scoped so the 0.1.0 public surface isn't a subset of what 0.2.0 needs.

## 4. Dependency story

**HTTP: `java.net.http.HttpClient`.** Zero third-party deps; already in
use at `ChioSidecarClient.kt` lines 14-17. Sidecar is on localhost, so
OkHttp's connection-pool story buys nothing. Every Flink TaskManager
ships the user-code JAR, so avoiding OkHttp's ~5 MB transitive closure
matters. JDK 21 supports HTTP/1.1 + HTTP/2 and `sendAsync` for when we
later add a non-blocking client. Ktor would force a Kotlin-only
consumption story and drag in `kotlinx-coroutines` - bad for Java-only
Flink users.

**JSON: Jackson.** `jackson-databind` + `jackson-module-kotlin`. Already
used (`ChioSidecarClient.kt` lines 9-11, `ChioTypes.kt` line 9) and
tested end-to-end (`ChioTypesTest.kt` lines 21-188). Gson and
kotlinx.serialization would each require re-annotating every type and
provide no canonicalisation features Jackson lacks. `kotlin-reflect`
stays because `jackson-module-kotlin` needs it.

## 5. Serialization compatibility (canonical JSON)

Python emits canonical JSON via `json.dumps(obj, sort_keys=True,
separators=(",", ":"), ensure_ascii=True).encode("utf-8")` at
`chio_sdk/client.py` line 46, `chio_sdk/testing.py` line 138, and
`chio_streaming/core.py` line 135, `chio_streaming/receipt.py` line 54.
Byte-identical output is required for `content_hash`, `parameter_hash`,
`caller_identity_hash`, and the receipt chain check in
`verify_receipt_chain`.

Jackson produces this shape with a dedicated `ObjectMapper` (separate
from the wire mapper):

1. `SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS` - sorts `Map`
   entries at emit time.
2. `MapperFeature.SORT_PROPERTIES_ALPHABETICALLY` - sorts POJO fields,
   matching Python's `sort_keys=True` behaviour for model dicts.
3. Default `JsonFactory` (no `INDENT_OUTPUT`) gives Jackson's compact
   `,`/`:` separators.
4. Set `JsonWriteFeature.ESCAPE_NON_ASCII` on the factory to match
   Python's `ensure_ascii=True` (`\uXXXX` for all non-ASCII).
5. Use `writeValueAsBytes` - emits UTF-8 directly.

Alternatives rejected: Gson needs a custom `TypeAdapterFactory` to sort
properties, Moshi does not sort map keys, and a hand-rolled
`JsonNode`-walker reimplements features Jackson already ships. See open
question 1 for float-formatting risk and open question 4 for
`parameters` typing.

## 6. Module layout

Concrete recommendation:

```
sdks/jvm/
  settings.gradle.kts                    # new: include both subprojects
  build.gradle.kts                       # new: empty root
  chio-sdk-jvm/                          # new subproject
    src/main/kotlin/world/chio/sdk/
      ChioClient.kt                      # widened from ChioSidecarClient.kt
      ChioTypes.kt                       # moved verbatim
      ChioReceipt.kt, Decision.kt, ToolCallAction.kt  # new
      CanonicalJson.kt                   # sorted-keys mapper + sha256Hex
      errors/{ChioError,Connection,Timeout,Denied,Validation}.kt   # new
      capabilities/{CapabilityToken,ChioScope,*Grant,...}.kt       # new
    src/test/kotlin/world/chio/sdk/
      ChioTypesTest.kt (moved), CanonicalJsonTest.kt, ChioClientTest.kt
  chio-spring-boot/                      # existing module, thinned
    build.gradle.kts                     # api(project(":chio-sdk-jvm"))
    src/main/kotlin/world/chio/
      ChioFilter.kt, CachedBodyHttpServletRequest.kt,
      ChioAutoConfiguration.kt, ChioIdentityExtractor.kt (filter-specific)
    src/main/resources/META-INF/spring.factories
```

- **Location**: `sdks/jvm/chio-sdk-jvm/` alongside `chio-spring-boot/`;
  a future `chio-flink/` sits next to them under the same root build.
- **Package**: `world.chio.sdk`. Spring types keep `world.chio`
  so chio-spring-boot users see no class-name churn; moved types get
  `typealias` re-exports in the old package for one release cycle. The
  `.sdk` suffix mirrors Python's `chio_sdk` and leaves
  `world.chio.flink` / `.spring` as peer namespaces.
- **Gradle topology**: multi-project with a single settings file at
  `sdks/jvm/settings.gradle.kts` (`include("chio-sdk-jvm",
  "chio-spring-boot")`). Today's `chio-spring-boot/settings.gradle.kts`
  (line 1: `rootProject.name = "chio-spring-boot"`) is a standalone
  build; promoting it is a one-line change. The existing
  `build.gradle.kts` becomes the subproject file largely unchanged.
- **Dependency arrow**: `chio-spring-boot` gets
  `api(project(":chio-sdk-jvm"))`. The `spring-boot-starter-web` on
  today's `build.gradle.kts` line 20 stays on the Spring subproject;
  `chio-sdk-jvm` has zero Spring deps.
- **Artifact coords**: `world.chio:chio-sdk-jvm:0.1.0`, and
  `world.chio:chio-spring-boot:0.1.0` continues to point at the
  thinned Spring starter.

## 7. Testing library

Confirmed: today's module uses JUnit 5 + `kotlin-test-junit5`
(`build.gradle.kts` line 26, `useJUnitPlatform()` at line 37). The three
existing tests (`ChioTypesTest`, `ChioFilterBodyTest`,
`ChioFilterCapabilityTransportTest`) use `org.junit.jupiter.api.Test` +
`kotlin.test.assertEquals`. `ChioFilterCapabilityTransportTest` line 6
already uses `com.sun.net.httpserver.HttpServer` to stand up a loopback
sidecar - port that pattern into `ChioClientTest` instead of adding
WireMock. MockK is not needed; seams are small. Keep
`spring-boot-starter-test` on `chio-spring-boot` only.

## Open questions

1. **Canonical JSON number semantics.** Does the Rust kernel hash any
   receipt field carrying a JSON float? If yes, Python's `json.dumps`
   (`1.0`) vs Jackson's default (`1.0` or `1` depending on value type)
   becomes a conformance bug. Audit `spec/PROTOCOL.md` plus the Rust
   `serde_canonical` equivalent before cutting 0.1.0.
2. **Async first cut?** Python's client is `async`; JVM can expose
   `CompletionStage` via `HttpClient.sendAsync`. The Flink operator
   choice (`ProcessFunction` vs `RichAsyncFunction`) will decide.
   Blocking vs non-blocking leaks into every method signature - settle
   before freezing the API.
3. **Kotlin 2.3 vs 2.0.** Today's module pins 2.3.0
   (`build.gradle.kts` line 2). Flink user-code JARs historically lag;
   confirm Flink 1.19/2.0 TaskManager classloaders accept Kotlin 2.3
   stdlib, or down-target the SDK to 2.0 while Spring stays on 2.3.
4. **`parameters` typing for `evaluateToolCall`.** Options:
   `Map<String, Any?>`, `Map<String, JsonNode>`, sealed
   `ChioJsonValue`. `JsonNode` gives the tightest canonical-hash
   contract; `Map<String, Any?>` is Java-friendlier. Decide before
   freezing.
5. **Publishing coords.** README (`chio-spring-boot/README.md` lines 24,
   34) already advertises `world.chio:chio-spring-boot:0.1.0`. If
   SDK 0.1.0 ships first, does Spring bump to 0.2.0 alongside or stay
   at 0.1.0 with a bumped dependency?
6. **Deny-body wire shape.** Python's `ChioDeniedError.from_wire`
   (`errors.py` lines 98-124) accepts 11 fields; `ChioFilter.kt` line
   166 currently emits 4. Confirm which fields the sidecar actually
   sends so the JVM `fromWire` is not wishful thinking.
