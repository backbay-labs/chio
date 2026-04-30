# dotnet SDK Verdict Matrix Driver

This .NET 8 project is the dotnet deployment-shape driver for the Chio
verdict matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as `dotnet-sdk` with
`status = "prepared"` and `matrix_role = "deployment-shape"`. The trajectory-1
`sdks/dotnet/ChioMiddleware` package provides the host kernel bindings the
driver invokes through a Chio sidecar.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts the
dotnet driver is registered, scaffolded, and returns the same verdict tuples
as the Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver mirrors the trajectory-1 `typescript-node-http` driver contract:
the dotnet SDK does not embed kernel evaluation. Active execution against a
live Chio sidecar is operator-supplied via the
`CHIO_VERDICT_MATRIX_SIDECAR_URL` environment variable (or the
`CHIO_SIDECAR_URL` fallback). When the variable is absent, every scenario is
reported as `unsupported` with a diagnostic that names the missing variable.

## Run

```bash
cd crates/chio-conformance/verdict_matrix/drivers/dotnet
dotnet test --nologo --verbosity quiet
```

`dotnet` is operator-supplied; the project targets net8.0 and uses xUnit for
the smoke tests.

## D07 closure

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s) that close the M02 D07 deferral. The combined registration is
audited in `.planning/audits/M07-adoption-beachhead.md` under "M07 P6
closure".
