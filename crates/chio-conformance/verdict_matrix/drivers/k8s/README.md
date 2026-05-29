# k8s Admission-Webhook Verdict Matrix Driver

This Go module is the k8s admission-webhook deployment-shape driver for the
Chio verdict matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as
`k8s-admission-webhook` with `status = "transport-client"` and
`matrix_role = "deployment-shape"`. The `sdks/k8s/webhooks`
admission surface and `sdks/k8s/controller` provide the host kernel
bindings the driver invokes through a Chio sidecar.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
on stdout shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts
the k8s driver is registered, wired, and returns the same verdict tuples as
the Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver is a wired transport client mirroring the `typescript-node-http`
driver contract: the k8s admission-webhook controller does not embed kernel
evaluation. When `CHIO_VERDICT_MATRIX_SIDECAR_URL` (or the `CHIO_SIDECAR_URL`
fallback) names a sidecar, the driver issues a real `POST /chio/evaluate` per
scenario through the Go `net/http` client, parses the verdict and the
`verdict_matrix` receipt metadata, and emits a pass/fail tuple against the
expected tuple. A sidecar that is set-but-unreachable surfaces as a failure,
never a silent skip. When no sidecar URL is set, every scenario is reported as
`unsupported` with a diagnostic that names the missing variable, because the
controller has no in-process kernel and therefore no verdict it can honestly
emit on its own.

## Run

```bash
cd crates/chio-conformance/verdict_matrix/drivers/k8s
go test ./... -count=1
```

## Deployment-shape coverage

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s). The four register together to cover the supported
deployment shapes.
