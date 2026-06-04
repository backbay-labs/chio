# hello-spring-boot Architecture

## Owning Boundary

`hello-spring-boot` owns the JVM Spring Boot HTTP example for Chio. It uses the
local Gradle composite build for `sdks/jvm/chio-spring-boot` and demonstrates
the servlet-filter path without modifying the SDK package itself.

This package owns:

- `src/main/kotlin/example/hello/HelloSpringBootApplication.kt`: application
  startup and Chio servlet-filter registration.
- `src/main/kotlin/example/hello/HelloController.kt`: HTTP route handlers and
  request payload validation.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher through the JVM SDK Gradle wrapper.
- `smoke.sh`: the end-to-end trust authority, sidecar, Spring app,
  capability, and receipt-persistence flow.
- `build.gradle.kts` and `settings.gradle.kts`: the package-local Gradle build
  and composite-build link to the JVM SDK workspace.

## Runtime Shape

The app has three routes:

- `GET /healthz` is an app readiness check and must not call the sidecar.
- `GET /hello` is governed by the Chio servlet filter and returns the greeting
  body with the receipt id on `X-Chio-Receipt-Id`.
- `POST /echo` is governed by the Chio servlet filter, requires a capability
  token, and returns the validated JSON echo payload.

The Spring filter calls the sidecar over `/chio/evaluate`, verifies accepted
receipts, and attaches `X-Chio-Receipt-Id` to accepted responses. Denied
requests return the structured Chio denial body before the controller runs.

## Architectural Constraints

- Health checks must remain outside Chio evaluation so readiness does not
  depend on the sidecar.
- The app must keep fail-closed servlet-filter behavior for governed routes.
- Controllers must not issue or validate Chio capability tokens directly.
- The `/echo` request schema in `HelloController.kt` and `openapi.yaml` must
  stay aligned.
- Smoke evidence must prove all three HTTP decisions and persisted sidecar
  receipts.
- Route tests must exercise controller behavior without a live sidecar.
- The Gradle composite must continue resolving `world.chio:chio-spring-boot`
  through `../../sdks/jvm`.

## Current Improvement Target

The example currently keeps application wiring, filter registration, route
handlers, and payload types in one source file. The filter protects every path,
including `/healthz`, even though readiness should not depend on sidecar
availability. The echo route accepts only a typed Kotlin DTO but does not
enforce the stricter OpenAPI contract around unknown fields, nonempty
messages, and positive counts. The smoke flow also uses an outdated capability
grant and a receipt-list path that does not match the sidecar HTTP receipt
store.
