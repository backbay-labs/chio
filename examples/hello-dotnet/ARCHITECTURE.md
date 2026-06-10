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
