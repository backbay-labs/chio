# JVM SDK Verdict Matrix Driver

This Gradle project is the JVM deployment-shape driver for the Chio verdict
matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as `jvm-sdk` with
`status = "prepared"` and `matrix_role = "deployment-shape"`. The trajectory-1
`sdks/jvm/chio-sdk-jvm` package provides the host kernel bindings the driver
invokes through a Chio sidecar.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
on stdout shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts the
JVM driver is registered, scaffolded, and returns the same verdict tuples as
the Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver mirrors the trajectory-1 `typescript-node-http` driver contract:
the JVM SDK does not embed kernel evaluation. Active execution against a
live Chio sidecar is operator-supplied via the
`CHIO_VERDICT_MATRIX_SIDECAR_URL` environment variable (or the
`CHIO_SIDECAR_URL` fallback). When the variable is absent, every scenario is
reported as `unsupported` with a diagnostic that names the missing variable.

## Run

```bash
cd crates/chio-conformance/verdict_matrix/drivers/jvm
./gradlew --quiet test
./gradlew --quiet run
```

The `gradlew` wrapper is operator-supplied; on hosts without Gradle Wrapper
binaries committed under this driver, the parent repository's
`sdks/jvm/gradlew` may be used by passing
`-p crates/chio-conformance/verdict_matrix/drivers/jvm`.

## D07 closure

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s) that close the M02 D07 deferral. The combined registration is
audited in `.planning/audits/M07-adoption-beachhead.md` under "M07 P6
closure".
