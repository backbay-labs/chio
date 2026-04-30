# k8s Admission-Webhook Verdict Matrix Driver

This Go module is the k8s admission-webhook deployment-shape driver for the
Chio verdict matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as
`k8s-admission-webhook` with `status = "prepared"` and
`matrix_role = "deployment-shape"`. The trajectory-1 `sdks/k8s/webhooks`
admission surface and `sdks/k8s/controller` provide the host kernel
bindings the driver invokes through the controller test harness.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
on stdout shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts
the k8s driver is registered, scaffolded, and returns the same verdict
tuples as the Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver mirrors the trajectory-1 `typescript-node-http` driver contract:
the k8s admission-webhook controller does not embed kernel evaluation.
Active execution against a live Chio sidecar through the controller test
harness is operator-supplied via the `CHIO_VERDICT_MATRIX_SIDECAR_URL`
environment variable (or the `CHIO_SIDECAR_URL` fallback). When the
variable is absent, every scenario is reported as `unsupported` with a
diagnostic that names the missing variable.

## Run

```bash
cd crates/chio-conformance/verdict_matrix/drivers/k8s
go test ./... -count=1
```

## D07 closure

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s) that close the M02 D07 deferral. The combined registration is
audited in `.planning/audits/M07-adoption-beachhead.md` under "M07 P6
closure".
