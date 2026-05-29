# chio-spring-boot

Spring Boot starter and servlet filter for the
[Chio protocol](../../../spec/PROTOCOL.md). Protects any Spring Boot 3
service with capability validation and receipt-signed responses served
by the Chio sidecar kernel.

## Overview

`chio-spring-boot` is the drop-in JVM adapter for Chio. It is aimed at
Spring Boot service authors who want every inbound HTTP request gated
by a capability token plus a policy-evaluated verdict, without
restructuring their controllers or security config. The filter is
fail-closed by default: if the sidecar is unreachable the request is
denied, and allowed requests carry an `X-Chio-Receipt-Id` response
header pointing at the signed receipt.

## Install

Add the dependency to `build.gradle.kts`:

```kotlin
dependencies {
    implementation("world.chio:chio-spring-boot:0.1.0")
}
```

Or to `pom.xml`:

```xml
<dependency>
  <groupId>world.chio</groupId>
  <artifactId>chio-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

Requires Java 17 or newer, Spring Boot 3.2+, and a running Chio sidecar
(defaults to `http://127.0.0.1:9090`).

## Quickstart

The starter auto-configures a servlet filter as soon as it is on the
classpath. A minimal application needs no extra wiring:

```kotlin
@SpringBootApplication
class DemoApplication

fun main(args: Array<String>) {
    runApplication<DemoApplication>(*args)
}

@RestController
class PetsController {
    @GetMapping("/pets")
    fun pets(): Map<String, Any> = mapOf("pets" to emptyList<Any>())
}
```

Denied requests receive a structured JSON error body; allowed requests
flow through the filter chain with the receipt id attached to the
response headers.

## Configuration

Configure the filter through `application.yaml` under the `chio` prefix:

```yaml
chio:
  sidecar-url: http://127.0.0.1:9090
  timeout-seconds: 5
  on-sidecar-error: deny   # or "allow" for fail-open
  enabled: true
  url-patterns:
    - "/*"
  filter-order: 1
```

Or programmatically by supplying a `ChioFilterConfig` bean with custom
`identityExtractor` and `routeResolver` functions for header-driven
caller lookup and pattern-based route resolution. The `CHIO_SIDECAR_URL`
environment variable is honoured when no explicit URL is configured.

## Example

A richer end-to-end example with a Spring Boot controller and a smoke
harness lives in
[`examples/hello-spring-boot`](../../../examples/hello-spring-boot/). It
drives traffic through the sidecar and prints the returned receipts.

## Status

Version `0.1.0`, pre-1.0. Wire formats track the Chio `0.1.x` sidecar
contract. The API surface may evolve in minor versions before the `1.0`
stability freeze.
