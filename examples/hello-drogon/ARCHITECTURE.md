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
