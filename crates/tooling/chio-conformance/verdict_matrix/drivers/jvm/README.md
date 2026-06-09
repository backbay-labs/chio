# JVM SDK Verdict Matrix Driver

This Gradle project is the JVM deployment-shape driver for the Chio verdict
matrix. It is registered in
`crates/chio-conformance/verdict_matrix/manifest.toml` as `jvm-sdk` with
`status = "transport-client"` and `matrix_role = "deployment-shape"`. The
`sdks/jvm/chio-sdk-jvm` package provides the host kernel bindings the driver
invokes through a Chio sidecar.

## Contract

The driver loads the canonical scenario corpus from
`crates/chio-conformance/verdict_matrix/scenarios/` and emits a JSON report
on stdout shaped as `(verdict, reason_code, scope_set)` per scenario. The
`verdict_matrix.deployment_shape_smoke` integration test in
`crates/chio-conformance` is the cross-deployment smoke gate that asserts the
JVM driver is registered, wired, and returns the same verdict tuples as the
Rust kernel reference for the canonical scenario subset.

## Sidecar wiring

The driver is a wired transport client mirroring the `typescript-node-http`
driver contract: the JVM SDK does not embed kernel evaluation. When
`CHIO_VERDICT_MATRIX_SIDECAR_URL` (or the `CHIO_SIDECAR_URL` fallback) names a
sidecar, the driver issues a real `POST /chio/evaluate` per scenario through
the JDK HttpClient, parses the verdict and the `verdict_matrix` receipt
metadata, and emits a pass/fail tuple against the expected tuple. A sidecar
that is set-but-unreachable surfaces as a failure, never a silent skip. When no
sidecar URL is set, every scenario is reported as `unsupported` with a
diagnostic that names the missing variable, because the JVM SDK has no
in-process kernel and therefore no verdict it can honestly emit on its own.

## Run

```bash
cd crates/chio-conformance/verdict_matrix/drivers/jvm
./gradlew --quiet test
./gradlew --quiet run
```

The build pins a JDK 17 toolchain (`jvmToolchain(17)`), matching the
`sdks/jvm` source compatibility. On hosts where JDK 17 is keg-only or not on
the default PATH, point Gradle at it explicitly, for example
`-Porg.gradle.java.installations.paths=/path/to/jdk-17`. The `gradlew` wrapper
is operator-supplied; on hosts without Gradle Wrapper binaries committed under
this driver, a system `gradle` invocation works against this `build.gradle.kts`.

## Deployment-shape coverage

This driver is one of four deployment-shape SDK drivers (JVM, dotnet,
Lambda, k8s). The four register together to cover the supported
deployment shapes.
