# hello-drogon Architecture

## Module Boundaries

- `main.cpp` should only configure Chio, register the app routes, bind the local
  listener, and start Drogon.
- `src/hello_app.hpp` and `src/hello_app.cpp` own the example route contract:
  health, hello, echo validation, response shapes, receipt-id projection, and
  route registration.
- `CMakeLists.txt` owns optional Drogon discovery, the example app library, the
  executable, and local contract tests. Missing Drogon must keep producing a
  clear skip rather than a false failure.
- `smoke.sh` owns the live trust service, app process, sidecar, capability,
  receipt-store, and content-hash proof loop.

## Pain Points

- The previous single `main.cpp` mixed environment parsing, Chio middleware
  configuration, Drogon route registration, JSON payload parsing, response
  construction, and validation.
- Echo accepted missing, empty, non-string, or non-positive payload fields even
  though the OpenAPI contract described a structured JSON body.
- The smoke script still used an older demo capability tool name and CLI receipt
  listing path instead of the current HTTP authority capability and direct
  receipt-store evidence used by the hardened HTTP examples.
- Local contract behavior had no focused test target; only the live smoke could
  notice a route-contract regression, and that smoke may skip on machines
  without Drogon.

## Security And API Constraints

- `GET /hello` and `POST /echo` must remain protected by
  `chio::drogon::ChioMiddleware`.
- `/healthz` may stay sidecar-independent for readiness, but it must not imply
  bypass for governed business routes.
- Denied governed requests must stay fail-closed and receipt-backed.
- Allowed governed requests must require the trust-issued HTTP authority
  capability token and preserve handler access to `chio::drogon::receipt_id`.
- The example must not change the `sdks/cpp/chio-drogon` public API.

## Affected Dependents

- `scripts/check-chio-drogon.sh` is the C++ Drogon qualification gate and should
  run the example contract tests when Drogon is available.
- `examples/README.md` and `examples/EXAMPLE_SURFACE_MATRIX.md` already point to
  the example smoke path, so the example README is enough for local test
  documentation.
- `sdks/cpp/chio-drogon` stays the dependency. Its own package tests prove the
  middleware type and configuration surface; this example proves route contracts
  and live receipt flow.

## Planned Improvement

Split route-contract ownership out of `main.cpp`, add focused C++ contract
tests for readiness, hello, and echo validation, tighten the OpenAPI schema, and
update the live smoke to use current HTTP authority capability issuance plus
direct SQLite receipt verification.
