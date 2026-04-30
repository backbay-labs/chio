# M07 SDK-Matrix Pre-Flight Research

Coordinator: R07 layer-1 researcher coordinator
Milestone: M07 adoption beachhead pack
Bundle: research
Date: 2026-04-30

## Objective

M07 P6 closes D07 by adding deployment-shape SDK drivers for JVM, dotnet,
Lambda, and k8s to the M02 cross-SDK verdict matrix. This is research only.
No implementation PRs are proposed here.

The halt trigger for later execution is:

```text
cross-SDK verdict-matrix divergence in M07
```

## Canonical State

- `EXECUTION-STATE.json` currently has M07 as `ticket files authored`,
  `ready_for_p0`, and Wave 3, not active implementation.
- D07 says the primary verdict matrix covers Rust, Python, TypeScript
  node-http, WASM browser, and Go. JVM, dotnet, Lambda, and k8s are deferred
  to M07. See `.planning/trajectory-2/decisions.yml:111`.
- M07 P6 says these four SDK trees are deployment shapes that re-host a
  primary kernel while exposing distinct wire surfaces. See
  `.planning/trajectory-2/07-adoption-beachhead-pack.md:374`.
- The live verdict-matrix manifest is active with 48 scenarios and only
  `rust-kernel` required. JVM, dotnet, Lambda, and k8s are not registered.
  See `crates/chio-conformance/verdict_matrix/manifest.toml:5`.
- The live workflow only watches Rust kernel, Python SDK, TypeScript packages,
  Go SDK, the error registry, the workflow, and the verdict-matrix docs. It
  does not yet watch `sdks/jvm/**`, `sdks/dotnet/**`, `sdks/lambda/**`, or
  `sdks/k8s/**`. See `.github/workflows/verdict-matrix.yml:3`.

## Verdict Tuple Contract

Every M07 P6 driver must emit only this tuple:

```text
(verdict, reason_code, scope_set)
```

The diff oracle sorts scope order before comparison and treats missing required
driver output as divergence. See
`crates/chio-conformance/verdict_matrix/src/diff_oracle.rs:207` and
`crates/chio-conformance/verdict_matrix/src/diff_oracle.rs:250`.

The driver contract is not raw SDK payload equality. Existing SDKs expose
different local verdict surfaces:

- The matrix tuple allows `allow`, `deny`, or `error`; see
  `crates/chio-conformance/verdict_matrix/src/lib.rs:6` and
  `docs/conformance/verdict-matrix.md:28`.
- HTTP verdict schemas allow `allow`, `deny`, `cancel`, and `incomplete`; see
  `spec/schemas/chio-http/v1/verdict.schema.json:5`.
- Python and JVM map HTTP `cancel` to core `cancelled`; see
  `sdks/python/chio-sdk-python/src/chio_sdk/models_legacy.py:400` and
  `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioTypes.kt:88`.
- TypeScript and Go expose HTTP `cancel` directly; see
  `sdks/typescript/packages/node-http/src/types.ts:51` and
  `sdks/go/chio-go-http/types_helpers.go:74`.

Pre-flight verdict: M07 drivers must explicitly map `cancel` and `incomplete`
to `error`, or exclude those scenarios from the P6 smoke subset until the
tuple schema is widened. Comparing raw SDK verdict strings would be a false
divergence generator.

## Existing Primary SDK Surfaces

These are the cite-pointers M07 P6 should use as the baseline shape.

### chio-py and Python SDK

- `packages/sdk/chio-py` receipt invariant helpers verify canonical receipt
  bodies and return the receipt decision verdict. See
  `packages/sdk/chio-py/src/chio/invariants/receipt.py:23`.
- `sdks/python/chio-sdk-python` re-exports legacy hand-typed SDK models while
  generated Pydantic models settle. See
  `sdks/python/chio-sdk-python/src/chio_sdk/models.py:1`.
- Python HTTP models expose `Decision`, `Verdict`, `HttpReceipt`, and
  `EvaluateResponse`; see
  `sdks/python/chio-sdk-python/src/chio_sdk/models_legacy.py:338` and
  `sdks/python/chio-sdk-python/src/chio_sdk/models_legacy.py:532`.
- Python client sends typed sidecar calls and validates capabilities. See
  `sdks/python/chio-sdk-python/src/chio_sdk/client.py:66`.

### chio-ts and TypeScript SDK

- `packages/sdk/chio-ts` receipt invariant helpers return
  `ReceiptDecisionKind` from a signed receipt. See
  `packages/sdk/chio-ts/src/invariants/receipt.ts:5` and
  `packages/sdk/chio-ts/src/invariants/receipt.ts:55`.
- TypeScript node-http exposes the current HTTP verdict union and
  `EvaluateResponse`. See `sdks/typescript/packages/node-http/src/types.ts:51`
  and `sdks/typescript/packages/node-http/src/types.ts:116`.
- TypeScript sidecar client posts to `/chio/evaluate`. See
  `sdks/typescript/packages/node-http/src/sidecar-client.ts:59`.
- WASM browser, edge, and workers packages expose wasm evaluation and receipt
  verification surfaces rather than the node-http sidecar payload. See
  `sdks/typescript/packages/browser/src/index.ts:1`,
  `sdks/typescript/packages/edge/src/index.ts:40`, and
  `sdks/typescript/packages/workers/src/index.ts:38`.

### chio-go and Go SDK

- `packages/sdk/chio-go` receipt invariant helpers return a decision string
  plus signature and parameter-hash validity. See
  `packages/sdk/chio-go/invariants/receipt.go:25`.
- Go HTTP SDK exposes `ChioHTTPRequest`, `Verdict`, `HTTPReceipt`, and
  `EvaluateResponse`. See `sdks/go/chio-go-http/types_helpers.go:59`.
- Go sidecar client posts to `/chio/evaluate`. See
  `sdks/go/chio-go-http/sidecar.go:49`.

## Driver Research

### JVM Driver

Readiness: ready as a driver candidate, not registered.

Recommended driver boundary:

- Use `sdks/jvm/chio-sdk-jvm` over its existing blocking JDK HTTP client.
  Do not assume JNI is already present. M07 narrative says `JNI/HTTP`, but
  live code provides HTTP client methods. See
  `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioClient.kt:28`.
- Prefer `evaluateHttpRequest` for HTTP-substrate scenarios and
  `evaluateToolCall` only when the scenario is explicitly tool-call shaped.
  See `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioClient.kt:83`
  and `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioClient.kt:104`.
- Normalize JVM `EvaluateResponse.verdict` into the matrix tuple, not raw
  `Verdict.verdict`.

Pre-flight positives:

- JVM SDK has verdict serialization and conversion coverage. See
  `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioTypes.kt:74`.
- JVM tool-call evaluation canonicalizes parameters and hashes them before
  posting. See
  `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/ChioClient.kt:90`.
- Spring/Flink paths provide additional integration precedent, but P6 should
  not use those as the base driver unless the scenario specifically targets
  middleware behavior.

Pre-flight risks:

- The P6 ticket gate says to run `./gradlew` from the future driver directory,
  but the existing Gradle wrapper lives under `sdks/jvm/`. See
  `.planning/trajectory-2/tickets/M07/P6.yml:46` and
  `sdks/jvm/settings.gradle.kts:18`.
- If driver code is placed under
  `crates/chio-conformance/verdict_matrix/drivers/jvm/`, it should either call
  the workspace Gradle wrapper by relative path or ship a local wrapper
  intentionally. Do not assume one exists.

### dotnet Driver

Readiness: ready as a driver candidate, not registered.

Recommended driver boundary:

- Wrap `sdks/dotnet/ChioMiddleware` and use
  `ChioSidecarClient.EvaluateAsync`. See
  `sdks/dotnet/ChioMiddleware/src/ChioSidecarClient.cs:56`.
- Normalize `EvaluateResponse.Verdict` and `HttpReceipt` into the matrix
  tuple. See `sdks/dotnet/ChioMiddleware/src/ChioTypes.cs:84` and
  `sdks/dotnet/ChioMiddleware/src/ChioTypes.cs:233`.
- Use ASP.NET middleware semantics for raw-byte request hashing scenarios only
  when the scenario is HTTP-substrate shaped. See
  `sdks/dotnet/ChioMiddleware/src/ChioMiddlewareExtensions.cs:112`.

Pre-flight positives:

- dotnet preserves body bytes for hashing, forwards capability tokens, records
  receipt IDs, and has explicit fail-open passthrough behavior. See
  `sdks/dotnet/ChioMiddleware/src/ChioMiddlewareExtensions.cs:129` and
  `sdks/dotnet/ChioMiddleware/src/ChioMiddlewareExtensions.cs:208`.
- The .NET sidecar client has a narrow, testable `EvaluateAsync` boundary.

Pre-flight risks:

- Current main verdict-matrix workflow does not include `sdks/dotnet/**`.
- The driver should not convert sidecar transport failures into `allow`.
  Fail-open passthrough is middleware runtime behavior, not a passing matrix
  tuple. For matrix purposes, sidecar failure should be `error` with a stable
  `reason_code`.

### Lambda Driver

Readiness: present runtime surface, not matrix-ready without normalization.

Recommended driver boundary:

- Invoke `sdks/lambda/chio-lambda-extension` through a local invoke shim, as
  planned in P6, but normalize the response into the matrix tuple.
- Lambda serves `POST /v1/evaluate` and returns `decision`, `reason`, and
  receipt metadata, not the HTTP-substrate `/chio/evaluate` payload with
  `{verdict, receipt, evidence}`. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:261` and
  `sdks/lambda/chio-lambda-extension/src/main.rs:314`.
- Lambda request fields accept `scope` and `arguments`, and `parameters` is an
  alias for `arguments`. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:232`.

Pre-flight positives:

- Lambda performs real capability evaluation with deployment-configured
  trusted issuers. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:422` and
  `sdks/lambda/chio-lambda-extension/src/main.rs:497`.
- Request-supplied trusted issuers are ignored, which is the right trust
  boundary for a deployment-shape driver. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:497`.

Pre-flight risks:

- Lambda uses an empty guard slice in this path. That can produce parity gaps
  for redaction or guard scenarios. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:458`.
- Receipt buffer overflow logs a warning while still returning an OK
  evaluation response. That is not acceptable as a matrix pass condition. See
  `sdks/lambda/chio-lambda-extension/src/main.rs:411`.
- Lambda docs describe a broader package layout than live code currently
  provides. See `docs/protocols/AWS-LAMBDA-INTEGRATION.md:352`.

### k8s Driver

Readiness: present runtime surfaces, but split into admission and Job
lifecycle paths. Treating it as one opaque driver would hide divergence.

Recommended driver boundary:

- For M07.P6.T4, name the driver `k8s-admission-webhook` internally unless the
  ticket is deliberately widened. P6 says to use `sdks/k8s/webhooks` through
  the controller test harness. See `.planning/trajectory-2/tickets/M07/P6.yml:116`.
- Admission-webhook scenarios should assert Kubernetes `allowed` boolean,
  status messages, and capability validation outcomes, then normalize to the
  matrix tuple.
- Job lifecycle scenarios should be separate or explicitly out of the first
  driver. The Job controller mints grants, annotates pod templates, releases
  grants, aggregates pod receipt annotations, and submits a `JobReceipt`. See
  `sdks/k8s/controller/internal/reconciler/job_reconciler.go:240` and
  `sdks/k8s/controller/internal/reconciler/job_reconciler.go:301`.

Pre-flight positives:

- k8s has canonical capability token handling for controller flows. See
  `sdks/k8s/controller/internal/chio/types.go:16`.
- The controller client has narrow sidecar calls for mint, release, and
  receipt submission. See `sdks/k8s/controller/internal/chio/client.go:14`.

Pre-flight risks:

- k8s admission semantics are boolean admission decisions, not the matrix tuple
  shape. The driver must map admission denial into `deny` and unsupported
  lifecycle cases into `error`.
- K8s docs describe proposed ChioJobGrant, CronJob, Helm, and Secret flows
  that are not all present in live code. See
  `docs/protocols/K8S-JOBS-INTEGRATION.md:383`.
- There is also an Istio ext_authz path in examples, which is a distinct
  runtime shape and should not be conflated with M07.P6.T4.

## Cross-SDK Divergence Risks

Known risk: cross-SDK verdict-matrix divergence in M07.

Specific risk classes:

1. Verdict vocabulary drift. Matrix uses `allow|deny|error`; HTTP SDKs use
   `allow|deny|cancel|incomplete`; core receipts use `cancelled`; k8s uses
   admission `allowed`; Lambda uses `decision`.
2. Reason-code drift. Several SDK surfaces expose human `reason` or guard name
   fields, while the matrix expects `reason_code` from `spec/errors/registry.yaml`
   or `urn:chio:error:none`.
3. Scope-set drift. M02 tuple compares sorted `scope_set`; some deployment
   shapes expose capability scopes only indirectly through token JSON or
   admission annotations.
4. Unsupported scenario masking. `unsupported` must not count as pass. Missing
   required-driver output is divergence in the oracle.
5. Runtime path conflation. k8s admission, k8s Job lifecycle, Lambda extension,
   JVM HTTP client, and dotnet ASP.NET middleware are different deployment
   shapes even when they call the same local sidecar.
6. Fail-open masking. TS, JVM, dotnet, and Go middleware include explicit
   fail-open passthrough modes. Matrix drivers must treat fail-open passthrough
   as `error`, not `allow`.
7. Workflow coverage gap. The live verdict-matrix workflow does not yet include
   `sdks/jvm/**`, `sdks/dotnet/**`, `sdks/lambda/**`, or `sdks/k8s/**`.

## Required Pre-Flight Conditions Before M07 P6 Starts

1. M02 P5.T5 and P5.T6 must be merged so the diff oracle and hash-pinned
   manifest are required-CI.
2. M07 P6 driver specs must require each driver to emit only
   `(verdict, reason_code, scope_set)`.
3. The cancel/incomplete mapping rule must be explicit: map to `error` or
   exclude those scenarios from M07 P6 smoke.
4. JVM gate path must be corrected to use the existing Gradle wrapper location
   or ship a deliberate local wrapper.
5. dotnet gate must run `dotnet test` against the new driver plus
   `sdks/dotnet/ChioMiddleware` coverage.
6. Lambda gate must assert `/v1/evaluate` response normalization and reject
   receipt-drop paths as pass.
7. k8s gate must state whether it is admission-only or split into admission
   and Job lifecycle drivers.
8. `.github/workflows/verdict-matrix.yml` must include the four deployment
   SDK paths before the drivers are marked required.

## Recommended P6 Execution Shape

- M07.P6.T1 JVM: add driver shim under
  `crates/chio-conformance/verdict_matrix/drivers/jvm/`, call
  `sdks/jvm/gradlew`, emit tuple JSON, and test tuple normalization.
- M07.P6.T2 dotnet: add driver shim under
  `crates/chio-conformance/verdict_matrix/drivers/dotnet/`, call
  `dotnet test`, and test fail-open as `error`.
- M07.P6.T3 Lambda: add Rust driver crate or binary that local-invokes
  `chio-lambda-extension`, normalizes `decision` to tuple verdict, and
  treats empty guard coverage as unsupported for guard-only scenarios.
- M07.P6.T4 k8s: add Go driver over the controller test harness, scope it to
  admission-webhook semantics unless a separate Job lifecycle driver is added.
- M07.P6.T5 manifest/workflow: register `jvm`, `dotnet`, `lambda`, and `k8s`
  in the manifest and workflow only after the drivers produce tuple reports.
- M07.P6.T6 smoke: run a small canonical subset across all four drivers and
  Rust reference. Any tuple mismatch, missing tuple, unsupported required
  scenario, or fail-open passthrough is divergence and should halt.

## Bottom Line

JVM and dotnet are ready as driver candidates. Lambda and k8s have real
runtime surfaces but need stricter normalization and scoping before they can be
required drivers. The main pre-flight risk is not missing code; it is treating
heterogeneous local verdict payloads as if they already match the M02 semantic
tuple.
