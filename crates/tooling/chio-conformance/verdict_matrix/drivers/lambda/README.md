# Lambda Deployment-Shape Verdict Matrix Driver

This Rust crate is the Lambda deployment-shape driver for the Chio verdict
matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as
`lambda-deployment-shape` with `status = "transport-client"` and
`matrix_role = "deployment-shape"`. The
`sdks/lambda/chio-lambda-extension` runtime provides the host kernel
bindings the driver invokes through a Chio sidecar.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
on stdout shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts
the Lambda driver is registered, wired, and returns the same verdict tuples
as the Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver is a wired transport client mirroring the `typescript-node-http`
driver contract: the Lambda extension does not embed kernel evaluation. When
`CHIO_VERDICT_MATRIX_SIDECAR_URL` (or the `CHIO_SIDECAR_URL` fallback) names a
sidecar, the driver issues a real blocking `POST /chio/evaluate` per scenario
through `reqwest`, parses the verdict and the `verdict_matrix` receipt
metadata, and emits a pass/fail tuple against the expected tuple. A sidecar
that is set-but-unreachable surfaces as a failure, never a silent skip. When no
sidecar URL is set, every scenario is reported as `unsupported` with a
diagnostic that names the missing variable, because the Lambda extension has no
in-process kernel and therefore no verdict it can honestly emit on its own.

## Run

```bash
cargo test -p chio-verdict-matrix-driver-lambda --quiet
cargo run -p chio-verdict-matrix-driver-lambda --quiet
```

## Deployment-shape coverage

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s). The four register together to cover the supported
deployment shapes.
