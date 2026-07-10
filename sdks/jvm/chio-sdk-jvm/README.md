# chio-sdk-jvm

Pure Kotlin/JDK implementation of the Chio client SDK, mirroring
`chio-sdk` in Python. Provides the blocking HTTP client, receipt
primitives, canonical JSON, and DLQ envelope builders used by all JVM
middlewares (`chio-spring-boot`, `chio-streaming-flink`).

## Overview

`chio-sdk-jvm` is the transport-agnostic core of Chio on the JVM. It
carries no Spring or Flink dependencies so it can be consumed from any
JDK 17+ service. Every public type is byte-compatible with the Python
reference wherever the Chio protocol pins a wire shape.

Included:

- `ChioClient` - blocking HTTP client against the Chio sidecar
  (`/v1/evaluate/advisory`, `/v1/receipts/verify`, `/chio/health`).
  Implements `AutoCloseable` for use-resource parity with Python's async
  client.
- `CanonicalJson` - Jackson-backed canonicalizer that matches
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
  byte-for-byte.
- `ChioReceipt`, `Decision`, `ToolCallAction`, `GuardEvidence` - the
  signed-receipt object graph. Serializable across Flink operator
  boundaries and JSON-round-trippable against the sidecar.
- `SyntheticDenyReceipt` - stamps a deny receipt carrying the
  `chio-streaming/synthetic-deny/v1` marker when the sidecar is
  unreachable in fail-closed mode.
- `DlqRouter` - builds the canonical dead-letter queue record
  (`chio-streaming/dlq/v1`) with pinned header order.
- `ReceiptEnvelope` - the `chio-streaming/receipt/v1` envelope used by
  the receipt side output.
- `errors.*` - `ChioError`, `ChioDeniedError`, `ChioConnectionError`,
  `ChioTimeoutError`, `ChioValidationError`, and `ChioStreamingError`.

## Install

Requires Java 17 or newer and a running Chio sidecar (defaults to
`http://127.0.0.1:9090`). Publishing coordinates are pending; for now
consume via composite build or a local `mavenLocal()` publish from
this repository.

```kotlin
dependencies {
    implementation("world.chio:chio-sdk-jvm:0.1.0")
}
```

## Quickstart

```kotlin
import world.chio.sdk.CallerIdentity
import world.chio.sdk.ChioClient
import world.chio.sdk.ChioHttpRequest
import world.chio.sdk.errors.ChioDeniedError

val client = ChioClient("http://127.0.0.1:9090")

val advisory =
    client.evaluateToolCallAdvisory(
        capabilityId = "cap-fraud",
        toolServer = "flink://fraud-job",
        toolName = "events:consume:transactions",
        parameters = mapOf("body_length" to 42L, "body_hash" to "..."),
    )
println("advisory receipt: ${advisory.id}")

try {
    client.evaluateToolCall(
        capabilityId = "cap-fraud",
        toolServer = "flink://fraud-job",
        toolName = "events:consume:transactions",
        parameters = mapOf("body_length" to 42L, "body_hash" to "..."),
    )
} catch (error: ChioDeniedError) {
    println("not authorized: ${error.message}")
}
```

`evaluateToolCall` returns only for authoritative mediated tool-call
authorization receipts. With the current advisory-only sidecar route, it
fails closed after integrity-checking the advisory receipt. The sidecar
advisory routes
`POST /v1/evaluate/advisory` and deprecated `POST /v1/evaluate` return
`authorization: false`, `authorizationBasis: "advisory_only"`, and an
advisory receipt.

For HTTP request evaluation (used by `chio-spring-boot`):

```kotlin
val response =
    client.evaluateHttpRequest(
        ChioHttpRequest(
            requestId = "req-1",
            method = "GET",
            routePattern = "/pets",
            path = "/pets",
            caller = CallerIdentity(id = "alice", roles = setOf("user")),
            timestamp = System.currentTimeMillis() / 1000,
        ),
    )
```

## Parity

`CanonicalJsonTest`, `SyntheticDenyReceiptTest`, and `DlqRouterTest`
each carry `@Tag("parity")` and assert byte-equality against
hand-computed Python vectors.

## Status

Version `0.1.0`, pre-1.0. Wire formats track the Chio `0.1.x` sidecar
contract.
