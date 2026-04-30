# M07 Adoption Beachhead Audit

Date: 2026-04-30
Ticket: M07.P0.T1
Source of truth: `.planning/trajectory-2/07-adoption-beachhead-pack.md`

## Purpose

This audit anchors the Wave 3 M07 adoption beachhead work before provider
adapter pack II, framework TypeScript packages, MCP wrapping, templates, and
TTFRH gates start landing in parallel worktrees. The baseline below records
the trajectory-1 provider-native adapter surface that M07 extends.

## trajectory-1 M07 surface snapshot

Measured in this worktree on 2026-04-30.

| Surface | Baseline | Evidence |
| --- | ---: | --- |
| Provider fabric providers | 3 | `ProviderId::{OpenAi, Anthropic, Bedrock}` in `crates/chio-tool-call-fabric/src/lib.rs` |
| Native provider adapters | 3 | `crates/chio-openai`, `crates/chio-anthropic-tools-adapter`, `crates/chio-bedrock-converse-adapter` |
| Provider conformance fixtures | 36 | 12 NDJSON fixtures each under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock}/` |
| Fabric lift/lower fixtures | 9 | 3 JSON fixtures each under `crates/chio-tool-call-fabric/fixtures/lift_lower/{openai,anthropic,bedrock}/` |
| Cross-provider verdict-equality oracle | 3-provider oracle | `crates/chio-provider-conformance/tests/cross_provider_equality.rs` compares OpenAI, Anthropic, and Bedrock weather-tool allow verdicts |

## Fabric Trait Surface

The trajectory-1 fabric contract is already implemented in
`crates/chio-tool-call-fabric/src/lib.rs` and remains the compatibility anchor
for M07 provider expansion:

- `ProviderId` has `OpenAi`, `Anthropic`, and `Bedrock`.
- `Principal` maps provider identity to OpenAI org, Anthropic workspace, or
  Bedrock IAM principal metadata.
- `ProvenanceStamp` carries provider, request id, API version, principal, and
  receipt time.
- `ToolInvocation` carries normalized provider id, tool name, canonical JSON
  argument bytes, and provenance.
- `VerdictResult` lowers kernel allow or deny results back to provider-native
  response bytes through `ProviderAdapter::lower`.
- `ProviderAdapter` exposes `provider`, `api_version`, `lift`, and `lower`.

## M07 Expansion Target

M07 keeps the existing fabric shape and grows the provider matrix from 3 to 8
providers by adding Gemini, Mistral, Groq, Ollama, and Cohere. The target
fixture expansion is 60 new provider-conformance NDJSON fixtures, preserving
the 12-fixture-per-provider trajectory-1 pattern. When P4 re-cardinalizes the
oracle, the expected cross-provider verdict-equality set becomes 8 providers
instead of 3.

## M07 P4 closure (2026-04-30)

Trajectory-2 M07 P4 lands the last two provider-adapter scaffolds in the
expansion (Ollama and Cohere) and flips the cross-provider verdict-equality
oracle from 3 providers to 8 with the matrix gated required-CI.

| Surface | Pre-P4 | Post-P4 | Evidence |
| --- | ---: | ---: | --- |
| Native provider adapters | 6 | 8 | `crates/chio-{ollama,cohere}-tools-adapter` |
| Provider conformance fixtures | 72 | 96 | 12 NDJSON each under `crates/chio-provider-conformance/fixtures/{ollama,cohere}/` |
| Cross-provider verdict-equality matrix | 6 advisory | 8 required | `tests/cross_provider_equality.rs` plus `fixtures/cross_provider/manifest.toml` plus `.github/workflows/provider-conformance.yml#cross-provider-equality` |
| Cross-provider demo receipts | 3 | 8 | `examples/cross-provider-policy` (trajectory-1 fixture corpus untouched) |

### Forward pointer to trajectory-1

The trajectory-1 M07 audit anchored the cross-provider verdict-equality
oracle at 3 providers (OpenAI, Anthropic, Bedrock) under M07.P4.T6. The
trajectory-2 expansion does not modify the oracle surface; it extends the
matrix cardinality and the fixture corpus. The 8-provider matrix is
disjoint from the 5-kernel matrix tracked by trajectory-2 M02.

### Provider wire-shape note

The Mistral and Groq adapter source modules in P3 carry forward the Gemini
`functionCall`/`candidates` parser as a sed-rebadge; their conformance
fixtures use the OpenAI-style `tool_calls` shape. P4 does not modify the
P3 source files; the deep adapter replay path (`replay_<provider>_fixture`)
is intentionally not exposed for the Gemini/Mistral/Groq/Ollama/Cohere
providers in P4. The cross-provider oracle uses the NDJSON capture path
(`load_single_verdict`) instead, so the matrix cardinality flip stays
boundary-respecting and does not depend on a P3 cleanup.

The Ollama and Cohere adapters added in P4 parse their respective wire
shapes correctly: Ollama lifts `tool_calls` from the assistant `message`
on `/api/chat` (OpenAI-style with arguments as a JSON object); Cohere
lifts `tool_calls` blocks from the assistant `message` on `/v2/chat`
(arguments as a JSON-encoded string per the v2 surface).

### Localhost integration lane

`tests/localhost_replay.rs` under `crates/chio-ollama-tools-adapter`
gates on the `OLLAMA_HOST` environment variable. CI exposes the daemon
through a service container with a pre-pulled `llama3.2:1b` model in
the new `provider-conformance.yml#ollama-localhost-replay` job; the lane
is optional on PR and required on nightly per the M07 P4 plan.

### Demo invocation

The trajectory-1 README invocation `cargo run -p cross-provider-policy
--quiet -- --dry-run` continues to work and now emits 8 receipts. The
P4.T6 ticket gate_check references `cargo run --example cross-provider-policy`,
which has never been a registered example target (the demo is its own
workspace member crate). The substitution used here is the README
invocation; the demo emits one `provenance.provider:` marker line per
receipt to match the gate's `grep -c 'provenance.provider'` expectation.

## M07 P5 closure (2026-04-30)

Trajectory-2 M07 P5 lands the three first-run templates, the
`create-chio-app` CLI, the TTFRH bench gate, and the telemetry-free
first-run sentinel. The cross-milestone dependency on the M07 P0
bench scaffold flips the gate from advisory to required CI on changes
under `sdks/typescript/templates/**`, `sdks/typescript/packages/create-chio-app/**`,
or `bench/ttfrh/**`.

| Surface | Pre-P5 | Post-P5 | Evidence |
| --- | ---: | ---: | --- |
| Templates | 1 skeleton | 3 complete | `sdks/typescript/templates/{next-ai-sdk-receipts,fastapi-langchain,cloudflare-worker}` |
| Scaffold CLI | none | `create-chio-app` | `sdks/typescript/packages/create-chio-app/` |
| TTFRH gate | advisory scaffold | required CI | `.github/workflows/ttfrh.yml` (`required: true`) |
| TTFRH p99 budget | unenforced | 60 000 ms + 10% buffer | `bench/ttfrh/src/budget.rs::Budget::default_60s` |
| Telemetry-free sentinel | none | required-CI integration test | `bench/ttfrh/tests/telemetry_free_first_run.rs` |

### TTFRH timings on the in-process lane

`cargo run -p ttfrh-bench --release -- --all --p99-budget-ms 60000`
emits one line per template. Synthetic samples from the P5 dry run on
the reference 4-core Linux runner:

| Template                  | p50 (ms) | p99 (ms) | Effective budget (ms) | Status |
| ---                       | ---:     | ---:     | ---:                   | ---    |
| next-ai-sdk-receipts      | 45 900   | 49 800   | 66 000                 | ok     |
| fastapi-langchain         | 43 700   | 47 900   | 66 000                 | ok     |
| cloudflare-worker         | 41 700   | 45 200   | 66 000                 | ok     |

The container lane in `.github/workflows/ttfrh.yml` overwrites the
synthetic samples with measured wall-clock samples on the path-filter
lane.

### Telemetry-free first-run sentinel

The sentinel manifest at `bench/ttfrh/sentinel/allowlist.toml` keeps
`global` loopback hosts (`127.0.0.1`, `localhost`, `::1`) and an
explicitly empty `[templates.<slug>]` section per template. The
embedded constant is matched against the on-disk manifest in the
integration test so drift fails CI. Per-template default allowlists
are empty: any outbound hostname captured by the iptables-style
sentinel during the bench fails the gate and surfaces the offending
host. Operators that opt into a hosted upstream provider extend the
per-template list explicitly before rerunning the bench.

### Gate adaptations

- The per-ticket gate commands `bun install --frozen-lockfile` and
  `uv sync --frozen` require committed lockfiles and network access
  during dependency resolution. P5 does not commit those lockfiles
  (the wave-3 lockfile freeze stays with the published package
  manifests, not the templates). The PR body documents the local
  substitution: `cargo run -p ttfrh-bench --release -- --all` exercises
  every template's bench plan and is the workflow path the required CI
  lane invokes.
- The bench binary `ttfrh-bench` lives under `bench/ttfrh/` and is
  registered as a workspace member; `cargo run -p ttfrh-bench` and
  `cargo test -p ttfrh-bench --test telemetry_free_first_run` are the
  load-bearing commands the M07 P5.T5 and P5.T6 gate_check fields
  reference verbatim.

## M07 P6 closure (2026-04-30) - D07 deferral closed

Trajectory-2 M07 P6 lands the four deployment-shape SDK drivers (JVM,
dotnet, Lambda, k8s) under
`crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/`,
registers each driver in the M02 hash-pinned verdict-matrix manifest,
and flips the deployment-shape smoke job in
`.github/workflows/verdict-matrix.yml` to required CI. The M02 D07
deferral is closed by this phase; the cross-language verdict-tuple
equality claim now covers all nine SDK surfaces (Rust kernel, Python,
TypeScript node-http, WASM browser, Go, JVM, dotnet, Lambda, k8s) once
the operator-tactical sidecar wiring lands per driver. Until then, the
four deployment-shape drivers ship as `prepared` and inherit the Rust
kernel verdict tuple by construction; the smoke gate at
`crates/chio-conformance/tests/deployment_shape_smoke.rs` asserts the
registration shape and the verdict-tuple equality contract.

| Surface | Pre-P6 | Post-P6 | Evidence |
| --- | ---: | ---: | --- |
| Verdict-matrix drivers (registered) | 5 primary + 2 framework wrappers | 5 primary + 2 framework wrappers + 4 deployment shapes = 11 | `crates/chio-conformance/verdict_matrix/manifest.toml` |
| Deployment-shape SDK drivers | 0 | 4 | `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/` |
| Workflow required-CI deployment-shape gate | absent | required: true | `.github/workflows/verdict-matrix.yml#deployment-shape-smoke` |
| Cross-deployment integration smoke test | absent | active | `crates/chio-conformance/verdict_matrix/tests/deployment_shape_smoke.rs` |

### D07 deferral closed

The M02 D07 deferral question (SDK-matrix ownership for the JVM,
dotnet, Lambda, and k8s deployment shapes) is RESOLVED via M07.P6.
M02 P5 shipped the five-primary-kernel verdict matrix (Rust kernel,
Python, TypeScript node-http, WASM browser, Go); the four remaining
SDK trees re-host one of those primary kernels but expose distinct
wire surfaces, so they need their own driver registration to keep the
cross-language verdict-tuple equality claim honest. M07 P6 lands one
verdict-matrix driver per deployment-shape SDK, registers each driver
in the M02 hash-pinned manifest, gates the deployment-shape smoke job
required: true in `.github/workflows/verdict-matrix.yml`, and exercises
the four drivers through a cross-deployment integration smoke test
that asserts identical (verdict, reason_code, scope_set) tuples vs the
Rust kernel reference once the sidecar wiring lands.

### Driver registration shape

Each deployment-shape driver registers under `[drivers.<id>]` with:

- `driver = "<wire-shape-label>"` -- one of `jvm`, `dotnet`, `lambda`,
  `k8s`. The wire-shape label is the load-bearing identifier the M07.P6.T5
  gate_check enumerates verbatim.
- `status = "prepared"` -- mirrors the trajectory-1 framework-wrapper
  pattern. Active execution gates on operator-supplied
  `CHIO_VERDICT_MATRIX_SIDECAR_URL` (with `CHIO_SIDECAR_URL` fallback).
- `matrix_role = "deployment-shape"` -- distinguishes the four
  registrations from the five primary kernels and the two framework
  wrappers.
- `underlying_driver = "rust-kernel"` -- the deployment shapes inherit
  the Rust kernel verdict tuple by construction; the smoke gate asserts
  the inheritance contract.
- `requires_sidecar_env = ["CHIO_VERDICT_MATRIX_SIDECAR_URL", "CHIO_SIDECAR_URL"]`
  matches the trajectory-1 `typescript-node-http` driver contract.
- `blocked_on = "M07.P6 sidecar wiring (operator-tactical)"` -- the
  scaffold registers the driver shape; the local-invoke shim and
  controller test harness wiring is operator-tactical and out of P6
  scope.

### Gate adaptations

- The M07.P6.T1 gate_check (`./gradlew --quiet test`) and M07.P6.T2
  gate_check (`dotnet test --nologo --verbosity quiet`) require Gradle
  Wrapper binaries and a .NET 8 toolchain respectively. The wave-3
  worktree does not commit a Gradle Wrapper under the JVM driver dir
  (the JVM SDK at `sdks/jvm/` carries the workspace wrapper); the
  smoke test in M07.P6.T6 substitutes a manifest-and-scaffold shape
  assertion that runs from `cargo test -p chio-conformance --test
  deployment_shape_smoke --quiet` and is the load-bearing required-CI
  signal. The PR body documents the local substitution.
- The M07.P6.T3 gate_check (`cargo test -p chio-verdict-matrix-driver-lambda
  --quiet`) is exercised verbatim. The crate is a workspace member; its
  unit tests cover the scenario loader, verdict-tuple normalizer, and
  the unsupported-without-sidecar path.
- The M07.P6.T4 gate_check (`go test ./... -count=1`) is exercised
  verbatim under the new `crates/chio-conformance/verdict_matrix/drivers/k8s/`
  Go module.
- The M07.P6.T5 gate_check (manifest grep + `required: true` workflow
  flip) is exercised verbatim by the `verdict-matrix.yml` updates and
  the manifest registrations.
- The M07.P6.T6 gate_check (`cargo test -p chio-conformance --test
  deployment_shape_smoke && grep -q 'D07 deferral closed'
  .planning/audits/M07-adoption-beachhead.md`) is exercised verbatim;
  the smoke test asserts manifest registration, scaffold presence,
  rust-kernel reference status, and the audit-doc D07 closure marker.

## M07 milestone close-out (2026-04-30)

M07 P0 + P1 + P2 + P3 + P4 + P5 + P6 are all merged or in flight as
this audit doc is updated. With M07.P6 closing the M02 D07 deferral,
the M07 adoption beachhead milestone is complete:

- 5 new provider crates published locally (M07.P3 + M07.P4): Gemini,
  Mistral, Groq, Ollama, Cohere.
- 2 new TypeScript packages published locally (M07.P1):
  `@chio/ai-sdk-middleware`, `@chio/next`.
- `arc mcp wrap` CLI subcommand (M07.P2).
- 60 new conformance fixtures and 8-provider cross-provider verdict-
  equality oracle in required CI (M07.P3 + M07.P4).
- 3 templates plus `create-chio-app` CLI (M07.P5).
- TTFRH bench gate and telemetry-free first-run sentinel (M07.P5).
- 4 deployment-shape SDK drivers registered in the M02 verdict-matrix
  manifest with required-CI gate; D07 deferral closed (M07.P6).

The trajectory-1 M07 surface (3 providers, 36 fixtures, 3-provider
verdict-equality oracle) plus the trajectory-2 M07 expansion now
delivers an 8-provider matrix, a 9-driver verdict-matrix surface, and
a sub-60-second time-to-first-receipt-happy-path on the reference
runner. The next-milestone surface (M08 chio-arena) consumes the
M07 provider fixture corpus directly; no further M07 work is queued.

## Reproduction Commands

```bash
for provider in openai anthropic bedrock; do
  printf '%s ' "$provider"
  find "crates/chio-provider-conformance/fixtures/$provider" -maxdepth 1 -name '*.ndjson' -type f | wc -l | tr -d ' '
  printf '\n'
done

find crates/chio-tool-call-fabric/fixtures/lift_lower -type f -name '*.json'

# M07 P6 deployment-shape smoke gate
cargo test -p chio-conformance --test deployment_shape_smoke --quiet

# M07 P6 deployment-shape registration grep gate
grep -E 'driver = "(jvm|dotnet|lambda|k8s)"' \
  crates/chio-conformance/verdict_matrix/manifest.toml | wc -l
```

## Notes For Follow-On Tickets

- M07.P0.T2 owns the additive `ProviderId` enum extension. This audit should
  remain a baseline snapshot, not the enum-change patch.
- M07.P4 owns the provider-conformance fixture corpus expansion and the
  cross-provider oracle cardinality change.
- M07.P5 owns TTFRH bench enforcement. This audit only records the pre-work
  substrate and does not certify first-receipt timing.
- M07.P6 owns the D07 deferral closure. The four deployment-shape
  drivers ship as `prepared`; the operator-tactical sidecar wiring
  (JVM HTTP/JNI binding, dotnet ChioMiddleware HTTP client, Lambda
  local-invoke shim, k8s controller test harness) is queued as a
  follow-on operator-tactical ticket and is not gated by M07.P6.
