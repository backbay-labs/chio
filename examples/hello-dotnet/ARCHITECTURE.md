# hello-dotnet Architecture

## Module Boundaries

- `Program.cs` is only executable bootstrap. It should not own route contracts,
  validation, or response shapes.
- `HelloApp.cs` owns ASP.NET pipeline composition, Chio middleware placement,
  route registration, and the small request/response contract used by the
  example.
- `HelloChio.csproj` owns the project reference to
  `sdks/dotnet/ChioMiddleware` and exposes internals only to the local tests.
- `smoke.sh` owns the live trust service, app, sidecar, capability, receipt,
  and artifact proof loop.

## Pain Points

- The previous top-level `Program.cs` mixed bootstrap, middleware wiring,
  route registration, request payloads, and response construction in one file.
- `/healthz` was inside the same middleware path as governed routes, which made
  a liveness endpoint depend on a sidecar that the smoke flow starts later.
- The OpenAPI echo schema did not describe the runtime contract tightly enough.
- The smoke script used an older demo capability target and CLI receipt listing
  path that no longer matches the hardened HTTP sidecar examples.

## Security And API Constraints

- `GET /hello` and `POST /echo` must stay governed by `ChioMiddleware`.
- `/healthz` may be used for local readiness and must not bypass any governed
  business route.
- Denied governed requests must remain fail-closed and receipt-backed.
- Allowed governed requests must require the trust-issued HTTP authority
  capability token and return a sidecar receipt id.
- The example must not weaken `sdks/dotnet/ChioMiddleware`; route-specific
  composition belongs in the app.

## Affected Dependents

- `examples/run-hello-smokes.sh` already includes `hello-dotnet`; the local
  smoke script must keep that aggregate runner working.
- `examples/README.md` points users to `run.sh` and `smoke.sh`; new local tests
  need to be documented in this example README only.
- `sdks/dotnet/ChioMiddleware` stays the referenced adapter package. Its tests
  prove middleware fail-closed behavior and receipt verification, while this
  example proves app-specific contracts and sidecar integration.

## Planned Improvement

Split bootstrap from the app contract, make `/healthz` sidecar-independent while
leaving `/hello` and `/echo` governed, add focused .NET tests for route contract
validation, tighten the OpenAPI echo schema, and update the smoke script to use
the current HTTP authority capability plus direct receipt-store evidence.
