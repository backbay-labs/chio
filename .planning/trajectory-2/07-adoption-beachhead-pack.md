# Milestone 07: Adoption Beachhead Pack

## Lens

Single lens: adoption / SDK ergonomics. Three integration surfaces the
trajectory-1 substrate already enables but never delivered as a paste-and-go
product. This milestone is not about new kernel features; it is about cutting
the path from `npm i` (or `arc mcp wrap`) to a signed receipt under sixty
seconds on a clean machine. Every ticket is judged against time-to-first-
receipt-happy-path (TTFRH) and the count of net new lines a target user has
to write.

## Why this is on the trajectory

trajectory-1 closed the substrate. M07 (trajectory-1)
(`.planning/trajectory/07-provider-native-adapters.md`) shipped the
`chio-tool-call-fabric` `ProviderAdapter` trait and three provider crates
(OpenAI extension, Anthropic, Bedrock) with conformance fixtures and the
M07.P4.T6 cross-provider verdict-equality oracle. M08 (trajectory-1)
(`.planning/trajectory/08-browser-edge-sdk.md`) shipped four runtime
TS packages (`@chio-protocol/{browser,workers,edge,deno}`) and the
`crates/chio-kernel-browser/` wasm-bindgen artifact. The kernel
`verdict_for_provider_invocation` shim landed at trajectory-1 M07.P1.T4 and
the wasm bytes are publishable today.

What did NOT ship: the framework adapters that production agent code
actually imports (Vercel AI SDK middleware, Next.js Route Handler), the
one-line operator path for IDE / desktop MCP clients (Cursor, Claude Desktop,
Continue, Zed), and the second wave of provider adapters (Gemini, Mistral,
Groq, Ollama, Cohere) that round out cross-provider verdict equality from
three providers to eight. Without those three surfaces, the substrate is
load-bearing only for engineers who already read the workspace; this
milestone closes the import-then-verify loop for everyone else.

M07 also owns the SDK-matrix expansion D07 (in M02) deferred. M02 ships
the five-primary-kernel verdict matrix (Rust + Python + TypeScript
node-http + WASM browser + Go); the four remaining SDK trees (JVM,
dotnet, Lambda, k8s) are deployment shapes that re-host one of the
primary kernels but expose distinct wire surfaces, so they need their
own driver registration to keep the cross-language verdict-tuple
equality claim honest. P6 closes the D07 deferral by landing one
verdict-matrix driver per deployment-shape SDK and flipping the
extended manifest to required-CI.

## Prior-art reckoning

What trajectory-1 already shipped that overlaps with this milestone:

- **trajectory-1 M07 fabric and three adapters**: shipped at
  `crates/chio-tool-call-fabric/`, `crates/chio-openai/` (extended in-place),
  `crates/chio-anthropic-tools-adapter/`, `crates/chio-bedrock-converse-adapter/`.
  Preserved verbatim. trajectory-2 M07 adds five more adapters under the
  same fabric trait; it does not refactor the fabric, the three existing
  adapters, or the conformance harness shape. New providers register
  against the existing `ProviderId` enum (extended) and reuse the
  `chio-provider-conformance` replay format.
- **trajectory-1 M07 cross-provider verdict-equality oracle (M07.P4.T6)**:
  shipped. Reused. The matrix grows from 3 providers (OpenAI, Anthropic,
  Bedrock) to 8 (adds Gemini, Mistral, Groq, Ollama, Cohere). The oracle
  itself does not change; only the fixture corpus and the expected matrix
  cardinality.
- **trajectory-1 M08 four runtime packages**: shipped at
  `sdks/typescript/packages/{browser,workers,edge,deno}/`. Preserved.
  trajectory-2 M07 does NOT republish or re-namespace these packages; the
  new `@chio/ai-sdk-middleware` and `@chio/next` packages consume the
  existing wasm artifact through `@chio-protocol/edge` for Edge runtime
  paths and through Node-native bindings for the Server runtime path.
- **trajectory-1 `crates/chio-mcp-adapter/` and `crates/chio-hosted-mcp/`**:
  shipped (`crates/chio-mcp-adapter/src/{lib.rs,native.rs,transport.rs,fuzz.rs}`,
  `crates/chio-hosted-mcp/src/lib.rs`). Preserved. trajectory-2 M07
  promotes these into a `chio-cli mcp wrap` subcommand; the underlying
  crates do not change shape, the CLI gains a thin orchestration layer.
- **trajectory-1 M01 `urn:chio:error:*` registry plan**: trajectory-2 M01
  is the source of truth for error codes consumed by every new adapter's
  per-error-variant doctest. Cross-trajectory soft dep.

What is NOT preserved (deliberate change):

- The trajectory-1 M07 `ProviderId` enum is extended with five variants
  (`Gemini`, `Mistral`, `Groq`, `Ollama`, `Cohere`). This is an additive
  enum bump; serde `rename_all = "snake_case"` keeps wire compatibility.
  The bump is one chunk in a single ticket so the diff reads cleanly.
- The trajectory-1 M07 fixture matrix is re-cardinalized: the cross-
  provider verdict-equality assertion now expects 8 providers per family,
  not 3. The harness signature does not change; the corpus does.

This milestone is NOT a re-attack of a v3.18-style bounded retreat. It is
straight extension of a deliberately bounded trajectory-1 surface.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses; update the date and numbers on
re-run.

- TypeScript SDK packages already published:
  `sdks/typescript/packages/{ai-sdk,browser,conformance,deno,edge,elysia,
  express,fastify,node-http,workers}` (10 packages).
  (`ls sdks/typescript/packages/`)
- Existing `ai-sdk` package shape: present but a thin shell, not the
  middleware shape this milestone requires; the `@chio/ai-sdk-middleware`
  surface is new and lives in a new package directory rather than
  rewriting the existing `ai-sdk` package, to keep the shell intact for
  consumers that already imported it.
- Provider adapter crates today (count and names):
  `crates/chio-anthropic-tools-adapter`, `crates/chio-tool-call-fabric`,
  plus the in-place `crates/chio-openai/` extension and
  `crates/chio-bedrock-converse-adapter/` per trajectory-1 M07. Five
  adapter crates in scope today.
  (`ls crates/ | grep -E 'tools-adapter|tool-call-fabric'`)
- MCP-related crates today: `crates/chio-mcp-adapter`,
  `crates/chio-mcp-edge`, `crates/chio-hosted-mcp`,
  `crates/chio-openapi-mcp-bridge`. Four crates.
  (`ls crates/ | grep mcp`)
- chio-cli subcommand modules today:
  `crates/chio-cli/src/cli/{conformance,dispatch,replay,runtime,session,
  trust_commands,types}.rs` plus a `replay/` subdir. No `mcp` subcommand
  exists yet; this milestone adds one.
  (`ls crates/chio-cli/src/cli/`)
- New crates this milestone adds: 5 (one per provider in pack II).
- New TS packages this milestone adds: 2 (`@chio/ai-sdk-middleware`,
  `@chio/next`) plus 3 templates (Next.js + AI SDK + receipts viewer,
  FastAPI + LangChain, Cloudflare Worker) under
  `sdks/typescript/templates/`.

## Workspace dependency state

Pinned by trajectory-1 and reused (do not re-pin):

- `serde = { workspace = true }`, `serde_json = { workspace = true }`,
  `tokio = { workspace = true }`, `thiserror = { workspace = true }`,
  `async-trait = "0.1"` for fabric crate consumers.
- `aws-sdk-bedrockruntime` workspace pin (Bedrock adapter). New
  provider adapters do NOT add their own AWS SDK; Gemini/Mistral/Groq/
  Ollama/Cohere are HTTP-native and ride `reqwest` (already pinned).
- `wasm-pack` and `wasm-bindgen-cli` versions in `.tooling/wasm-pack.version`
  and `.tooling/wasm-bindgen.version` per trajectory-1 M08.

Not pinned anywhere; this milestone adds them and pins versions on Wave-3
open day (re-check crates.io / npm / PyPI / Ollama for then-current latest
patch):

- (Rust, per provider) `reqwest` SSE features as needed; rely on workspace
  pin and tighten features per crate.
- (TypeScript) `ai` (Vercel AI SDK) peer-dep range; pin a minor band, not
  a single patch. The middleware ships against the `wrapLanguageModel`
  surface that has been GA since `ai@4.x`.
- (TypeScript) `next` peer-dep range for `@chio/next`. App Router only;
  the package documents its supported Next.js minor band in the README
  and refuses to install against unsupported versions via `peerDependencies`.
- (Tooling) `create-chio-app` template scaffold uses `degit` (or
  equivalent) to clone the template directory; pin the tool in the CLI
  metadata, not at the workspace root.

## Scope

In:

- `sdks/typescript/packages/chio-ai-sdk-middleware/` (`@chio/ai-sdk-middleware`):
  exports a `wrapLanguageModel`-compatible middleware that wraps any AI
  SDK language model and runs `verdict_for_provider_invocation` (the
  trajectory-1 M07.P1.T4 shim) before/after stream yield. Edge-runtime-
  friendly via `@chio-protocol/edge`; Node-runtime-friendly via the same
  wasm artifact mediated by `@chio-protocol/browser` glue.
- `sdks/typescript/packages/chio-next/` (`@chio/next`): Route Handler and
  Server Action wrappers for App Router. Streaming-friendly (returns the
  AI SDK stream untouched on Allow; emits a denial response on Deny).
  No Pages Router support in v1.
- `arc mcp wrap` CLI subcommand at `crates/chio-cli/src/cli/mcp.rs`
  (and a `mcp/` subdir matching the `replay/` precedent): wraps a stdio
  MCP server with verdict gating, generates ready-to-paste config blobs
  for Cursor (`~/.cursor/mcp.json`), Claude Desktop
  (`claude_desktop_config.json`), Continue, and Zed. Per-tool capability
  scope inferred from MCP `tools/list`. Local-trust-edge defaults; no
  hosted control plane required for first run.
- Provider adapter pack II (5 new crates):
  - `crates/chio-gemini-tools-adapter/`
  - `crates/chio-mistral-tools-adapter/`
  - `crates/chio-groq-tools-adapter/`
  - `crates/chio-ollama-tools-adapter/`
  - `crates/chio-cohere-tools-adapter/`
  Each follows the trajectory-1 M07.P1-P4 ladder: scaffold -> SSE state
  machine -> 12 conformance fixtures -> error-taxonomy doctest consuming
  the trajectory-2 M01 error registry -> verdict latency budget bench.
- `chio-provider-conformance` corpus extension: 12 fixtures per new
  provider (60 fixtures), and the cross-provider verdict-equality oracle
  is re-cardinalized to 8 providers.
- Ollama localhost integration test: a `cargo test -p
  chio-ollama-tools-adapter --test localhost_replay` lane that boots an
  Ollama daemon via a CI service container and asserts an offline replay
  end to end. Skipped if `OLLAMA_HOST` is unset; required when set.
- `sdks/typescript/templates/` directory with three first-run templates:
  - `next-ai-sdk-receipts/` (Next.js + Vercel AI SDK + receipts viewer)
  - `fastapi-langchain/` (Python FastAPI + LangChain)
  - `cloudflare-worker/` (Cloudflare Worker + `@chio-protocol/workers`)
  Each ships a `README.md` with a single `npx create-chio-app <template>`
  invocation and a TTFRH stopwatch the bench job runs.
- TTFRH bench: `bench/ttfrh/` with one harness per template that
  measures end-to-end clean-machine time (Docker image -> first signed
  receipt). Target: < 60 s on the reference 4-core Linux runner. Lane
  is required CI on changes touching `sdks/typescript/templates/**` or
  `bench/ttfrh/**`. Reference runner image is the trajectory-1 M05
  P3.T4 inherited pin (`ubuntu-24.04`); M07 P5.T5 records the inherited
  pin in the audit doc so the comparison is reproducible.
- Telemetry-free first run: every template defaults to a local-only
  receipt sink. No network call to a hosted control plane unless the
  user opts in via `chio config set control_plane <url>`.
- Deployment-shape SDK drivers for the M02 verdict matrix (closes D07
  deferral): one driver per SDK tree at
  `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/`,
  registered in the M02 P5.T6 hash-pinned manifest, gated required-CI
  in `.github/workflows/verdict-matrix.yml`, and exercised by a
  cross-deployment smoke test that asserts identical verdict tuples
  against the Rust kernel reference. No new kernel logic; the drivers
  are adapters over the trajectory-1 SDK trees at
  `sdks/{jvm,dotnet,lambda,k8s}/`.

Out:

- LangGraph / CrewAI / AutoGen scaffold fillin (cut as tactical by the
  trajectory-2 synthesis; revisit only if a downstream consumer
  requests it with concrete usage evidence). The fastapi-langchain
  template uses LangChain itself, not LangGraph, and the synthesis
  cut was specifically the `chio-langchain` SDK SCAFFOLD-FILLIN
  package, not the LangChain framework as a starter-template
  primitive. D18 explicitly names FastAPI + LangChain as one of the
  three in-scope templates; the template is a usage example of the
  existing Python SDK, not a new framework adapter.
- GitHub Action verifier (cut as low-blocking by the trajectory-2
  synthesis; community-tactical, not milestone-grade).
- Kong / Envoy gateway adapter pack (cut as enterprise-sales work, not
  engineering output).
- JetBrains plugin (folded into trajectory-2 M01 LSP work; revisit only
  if M01 LSP closes and a JetBrains-specific gap remains).
- Receipt viewer browser playground as a separate item (folds into the
  `next-ai-sdk-receipts` template; the viewer is one route in that
  template, not a standalone package).
- Vertex AI adapter (deferred per trajectory-1 M07 "Out of scope" note;
  revisit when Google IAM provenance shape stabilizes against the
  Bedrock adapter precedent).
- Pages Router support in `@chio/next` (v1 is App Router only).
- Republishing or renaming any trajectory-1 TS package.
- A separate `arc init --profile` milestone (folded into the
  `create-chio-app` template surface in P5).
- Single-binary install / packaging pipeline (tactical packaging work,
  not milestone-grade).

## Phases

### P0: Wave-opener Cargo.lock bump and audit doc

- M07.P0.T1: Open milestone audit doc and snapshot trajectory-1 M07
  surface (provider count, fixture corpus size, fabric trait surface).
- M07.P0.T2: Cargo.lock bump and `ProviderId` enum extension (5 new
  variants; serde wire compat preserved).
- M07.P0.T3: Reserve npm package names (`@chio/ai-sdk-middleware`,
  `@chio/next`) and template directory skeleton.
- M07.P0.T4: TTFRH bench harness scaffold under `bench/ttfrh/` with
  empty per-template runners; the lane is advisory until P5.

### P1: Vercel AI SDK middleware + `@chio/next`

- M07.P1.T1: Scaffold `sdks/typescript/packages/chio-ai-sdk-middleware/`
  with `package.json`, `tsconfig.json`, `src/index.ts` skeleton.
- M07.P1.T2: Implement `wrapWithChio(model, options)` middleware
  consuming `@chio-protocol/edge` for Edge runtime and the Node binding
  for Server runtime; verdict at tool-use boundary, not per delta.
- M07.P1.T3: Scaffold `sdks/typescript/packages/chio-next/` with App
  Router Route Handler wrapper `withChio()` and Server Action wrapper.
- M07.P1.T4: Streaming-friendly response shape: pass through AI SDK
  stream on Allow; emit a denial response (typed `BindingError` shape)
  on Deny. Document Edge vs Node selection.
- M07.P1.T5: TS-side conformance subset wiring: the new packages
  register against the trajectory-2 M02 cross-SDK verdict-matrix as a
  driver pair (one for the middleware, one for the Route Handler).
- M07.P1.T6: First template `next-ai-sdk-receipts/` skeleton (the full
  template lands in P5).

### P2: `arc mcp wrap` CLI

- M07.P2.T1: Add `crates/chio-cli/src/cli/mcp.rs` plus a `mcp/` subdir
  for subcommand machinery; register the subcommand in
  `crates/chio-cli/src/cli/dispatch.rs`.
- M07.P2.T2: `arc mcp wrap <stdio-cmd>` runs an MCP server as a child
  process and mediates `tools/list` and `tools/call` through
  `chio-mcp-adapter`'s existing native trait; verdict gating per call.
- M07.P2.T3: Per-tool capability scope inference from `tools/list`:
  default-deny manifest scaffold written to `~/.config/chio/mcp/<server-id>.toml`
  with one capability per tool; user reviews before promoting.
- M07.P2.T4: Config generators for Cursor (`~/.cursor/mcp.json`),
  Claude Desktop (`claude_desktop_config.json`), Continue, Zed. One
  emit per `arc mcp wrap --emit-config <ide>` flag; output is paste-
  ready JSON / TOML matching the IDE's documented schema.
- M07.P2.T5: `chio-attest-verify` "Chio-verified" attestation header
  embedded in tool responses; rendered in the IDE's tool-call panel
  where the IDE supports custom annotations.
- M07.P2.T6: End-to-end test wrapping a real MCP server (the existing
  `chio-mcp-adapter` test fixture server) and asserting verdict gating
  + attestation header round-trip.

### P3: Provider adapter pack II - first three (Gemini / Mistral / Groq)

Each provider gets a five-ticket cluster mirroring trajectory-1 M07
P2 (scaffold + lift/lower + streaming + fixtures + bench) collapsed
where the provider's surface is small enough.

- M07.P3.T1: Scaffold `crates/chio-gemini-tools-adapter/`; pin
  `googleapis/genai` API version in `Cargo.toml` metadata and `README.md`;
  implement `lift`/`lower` for batch and streaming `generateContent` with
  `tools` and `functionCall`/`functionResponse` parts.
- M07.P3.T2: Gemini SSE state machine + 12 conformance fixtures under
  `crates/chio-provider-conformance/fixtures/gemini/` + verdict latency
  bench; error-taxonomy doctest consuming M01 error registry.
- M07.P3.T3: Scaffold `crates/chio-mistral-tools-adapter/`; pin Mistral
  API version; implement `lift`/`lower` for `chat/completions` with
  `tools` and `tool_calls`/`tool_results`; SSE streaming.
- M07.P3.T4: Mistral 12 conformance fixtures + verdict latency bench
  + error-taxonomy doctest.
- M07.P3.T5: Scaffold `crates/chio-groq-tools-adapter/`; pin Groq API
  version; implement `lift`/`lower` (Groq mirrors the OpenAI `tool_calls`
  shape closely; reuse the lift logic where wire-compatible). 12
  conformance fixtures + verdict latency bench + error-taxonomy doctest.
- M07.P3.T6: Cross-provider verdict-equality oracle update (advisory):
  add Gemini / Mistral / Groq to the matrix; assert 6-provider equality
  under the existing oracle. Required-CI flip waits for P4.

### P4: Provider adapter pack II - last two + matrix flip

- M07.P4.T1: Scaffold `crates/chio-ollama-tools-adapter/`; pin Ollama
  API version (`/api/chat` with `tools` and `tool_calls`); implement
  `lift`/`lower` for batch and streaming.
- M07.P4.T2: Ollama localhost integration test under
  `crates/chio-ollama-tools-adapter/tests/localhost_replay.rs`; CI
  service-container lane that boots the daemon and asserts offline
  replay. 12 conformance fixtures + verdict latency bench + error-
  taxonomy doctest.
- M07.P4.T3: Scaffold `crates/chio-cohere-tools-adapter/`; pin Cohere
  API version; implement `lift`/`lower` for `/v2/chat` with `tools` and
  `tool_plan`/`tool_call`/`tool_result` blocks.
- M07.P4.T4: Cohere SSE state machine + 12 conformance fixtures +
  verdict latency bench + error-taxonomy doctest.
- M07.P4.T5: 8-provider cross-provider verdict-equality oracle:
  required-CI flip; the matrix asserts identical verdicts across
  OpenAI, Anthropic, Bedrock, Gemini, Mistral, Groq, Ollama, Cohere
  for equivalent canonical inputs under the same policy.
- M07.P4.T6: Update trajectory-1 M07 audit doc with the 8-provider
  cardinality (cross-doc forward pointer); refresh the
  `examples/cross-provider-policy/` demo to print 8 receipts.

### P5: Templates and TTFRH gate

- M07.P5.T1: Complete the `next-ai-sdk-receipts/` template: Next.js
  app + AI SDK chat route + receipts viewer route + zero-config local
  receipt sink + README single-command bootstrap.
- M07.P5.T2: Complete the `fastapi-langchain/` template: Python
  FastAPI app wrapping a LangChain agent through the trajectory-1
  Python SDK; receipts viewer is a static page served by FastAPI.
- M07.P5.T3: Complete the `cloudflare-worker/` template: Worker
  consuming `@chio-protocol/workers` and `@chio/ai-sdk-middleware`;
  receipt sink writes to a local KV namespace by default.
- M07.P5.T4: `create-chio-app` CLI tool under
  `sdks/typescript/packages/create-chio-app/`; one-line `npx create-chio-app
  <template>` invocation that clones the template, installs deps, and
  prints the next command.
- M07.P5.T5: TTFRH bench gate: required CI on changes under
  `sdks/typescript/templates/**` or `bench/ttfrh/**`. Per-template
  runner asserts < 60 s end-to-end on the reference 4-core Linux
  runner; regression > 10% blocks the PR.
- M07.P5.T6: Telemetry-free first-run audit doc entry: every template
  is asserted to perform zero outbound network calls during the bench
  run except to the upstream provider the user explicitly configured.
  Captured by an iptables-style network sentinel inside the bench
  container; failure logs the offending hostname and fails the gate.

### P6: Deployment-shape SDK drivers (closes D07 deferral)

D07 deferred the JVM / dotnet / Lambda / k8s SDK matrix to M07. The
five-primary-kernel matrix (M02 P5.T1-T5) covers Rust, Python, TS
node-http, WASM browser, and Go; the four remaining SDK trees re-host
one of those kernels but expose distinct wire surfaces (JVM via
JNI/HTTP, dotnet via the existing ChioMiddleware HTTP client, Lambda
via a local invoke shim, k8s via the controller's admission-webhook
test harness). P6 lands one driver per tree and flips the extended
manifest to required-CI so the cross-language verdict-tuple equality
claim covers all eight SDK surfaces, not just five.

- M07.P6.T1: JVM SDK verdict-matrix driver under
  `crates/chio-conformance/verdict_matrix/drivers/jvm/`; consumes
  `sdks/jvm/chio-sdk-jvm` host bindings.
- M07.P6.T2: dotnet SDK verdict-matrix driver under
  `crates/chio-conformance/verdict_matrix/drivers/dotnet/`; consumes
  `sdks/dotnet/ChioMiddleware`.
- M07.P6.T3: Lambda deployment-shape verdict-matrix driver under
  `crates/chio-conformance/verdict_matrix/drivers/lambda/`; invokes
  `sdks/lambda/chio-lambda-extension` via local invoke shim.
- M07.P6.T4: k8s admission-webhook verdict-matrix driver under
  `crates/chio-conformance/verdict_matrix/drivers/k8s/`; invokes
  `sdks/k8s/webhooks` through the controller test harness.
- M07.P6.T5: Register the four drivers in
  `crates/chio-conformance/verdict_matrix/manifest.toml` and flip the
  extended `verdict-matrix.yml` workflow to required-CI.
- M07.P6.T6: Cross-deployment integration smoke test asserting
  identical (verdict, reason_code, scope_set) tuples across all four
  drivers vs the Rust kernel reference; audit doc entry records the
  D07 deferral closure.

## Cross-milestone interactions

Hard deps (other trajectory-2 milestones):

- M01 (`urn:chio:error:*` registry at `spec/errors/registry.yaml`).
  Every new provider adapter's error-taxonomy doctest consumes the
  registry. Encoded as `soft_deps` string sentence on each P3/P4
  adapter ticket; the orchestrator gates the doctest job on
  `M01.P1.T1` merged_sha via the wave sync rule, not via a
  trajectory-2 `depends_on` edge.
- M02 (cross-SDK verdict-matrix harness). Every new framework adapter
  in P1 (`@chio/ai-sdk-middleware`, `@chio/next`) MUST register a
  driver in `crates/chio-conformance/verdict_matrix/drivers/`.
  Encoded as `soft_deps` string sentence on M07.P1.T5; the
  orchestrator gates the lane on `M02.P5.T2` (TS driver) merged_sha.
  M07 P6 also extends the matrix with four deployment-shape SDK
  drivers (JVM, dotnet, Lambda, k8s); P6 tickets carry a `soft_deps`
  string sentence gating on `M02.P5.T5` (cross-language diff oracle
  activation) merged_sha so the new drivers register only after the
  oracle is required-CI.

Soft deps (trajectory-1 artifacts referenced as string sentences):

- "trajectory-1 M07.P1.T4 (`verdict_for_provider_invocation` kernel
  shim) is the kernel-side entry point all P1 framework wrappers and
  P3/P4 provider adapters call."
- "trajectory-1 M07.P4.T6 (cross-provider verdict equality) is the
  oracle the M07.P4.T5 matrix flip extends from 3 providers to 8.
  Note: this 8-provider matrix is the M07 axis; it is disjoint from
  the 5-kernel matrix that M02 covers (Rust, Python, TS node-http,
  WASM, Go) per D07."
- "trajectory-1 M08 (`@chio-protocol/edge`, `@chio-protocol/workers`,
  `@chio-protocol/browser`) supplies the wasm artifact the new TS
  packages consume; package bundles must stay under the trajectory-1
  per-runtime size budgets."
- "trajectory-1 M07 fixture format at
  `crates/chio-provider-conformance/fixtures/{anthropic,bedrock,openai}/`
  is the precedent for the five new fixture directories."
- "trajectory-1 `crates/chio-mcp-adapter/{lib.rs,native.rs,transport.rs}`
  is the existing native MCP trait surface `arc mcp wrap` orchestrates."
- "trajectory-1 `crates/chio-attest-verify/` is the verifier surface
  embedded in the IDE attestation header (M07.P2.T5)."

Downstream consumers in trajectory-2:

- M08 (chio-arena): the arena replays M07 provider fixtures as
  scenario inputs; new provider fixtures must satisfy the M08 corpus
  contract (NDJSON shape + canonical-JSON byte equality).
- M09 (economic layer): the guard marketplace's "priced install" path
  is the natural place for `arc mcp wrap` MCP servers to register;
  M07 keeps the registration shape minimal so M09 can extend without
  rework.

## Risks and mitigations

- **Vercel AI SDK API drift**: the `wrapLanguageModel` surface has been
  GA in `ai@4.x` but mid-major bumps are common. Mitigation: pin a peer-
  dep minor band, not a single patch; the middleware refuses to install
  against an unsupported version via `peerDependencies`; CI runs the
  smoke test against the highest patched minor in the supported band on
  every PR.
- **Next.js App Router runtime split**: Edge runtime and Server runtime
  consume the wasm artifact through different code paths. Mitigation:
  the `@chio/next` package picks the right path via `runtime` export
  conditions in its `package.json`; documented in the README; smoke
  test runs both runtimes in CI.
- **MCP IDE config schema drift**: Cursor / Claude Desktop / Continue /
  Zed each evolve their config schemas. Mitigation: each `--emit-config
  <ide>` path pins the schema version it targets in the audit doc
  (M07.P2.T4 enumerates the four versions verbatim in its README and
  audit-doc snapshot); a nightly canary against published schema docs
  (script lives at `bench/ide-schema-canary/check.sh`, scheduled by
  `.github/workflows/ide-schema-canary.yml`) opens an issue if drift
  is detected, but does not break PR CI.
- **Per-tool capability inference brittleness**: `tools/list` schemas
  vary in fidelity; default-deny is the right floor but may produce
  unusable manifests for some servers. Mitigation: the inferred manifest
  is written as a scaffold with a TODO line per tool; the user is
  required to review before promotion; the CLI prints a one-line summary
  of unscoped tools.
- **Ollama daemon availability in CI**: not every runner can boot a GPU
  daemon; CPU-only Ollama is acceptable for the offline-replay test but
  takes minutes to warm. Mitigation: use a CI service container with a
  pre-pulled small model (e.g. `llama3.2:1b`); the lane is `optional`
  on PR, `required` on nightly; OLLAMA_HOST gates local-dev runs.
- **Cross-provider verdict equality cardinality**: 8 providers means
  8! / (2! * 6!) = 28 pairwise comparisons; a single divergence in any
  pair fails the lane. Mitigation: the oracle reports the minimal
  divergence set, not a flat boolean; the gate fails on any divergence
  but the audit log surfaces which two providers disagreed and on which
  scenario. Per-provider pinning of the API version is the floor for
  reproducibility.
- **`create-chio-app` template rot**: the templates depend on upstream
  npm / PyPI versions that move. Mitigation: every template lockfile is
  pinned at the moment the template lands; the TTFRH bench refuses to
  use a `--latest` flag on any package install; a quarterly maintenance
  ticket bumps the locks deliberately, not silently.
- **TTFRH bench environmental flake**: a 60-second budget is tight on
  shared CI runners. Mitigation: the bench reports p50 and p99 across
  a 5-run sample; the gate is on p99 with a 10% buffer (66 s effective);
  flake retries are forbidden (a flake means the budget is wrong, not
  that the test is wrong).

## Success criteria

- 5 new provider crates published locally (`chio-gemini-tools-adapter`,
  `chio-mistral-tools-adapter`, `chio-groq-tools-adapter`,
  `chio-ollama-tools-adapter`, `chio-cohere-tools-adapter`). Each
  builds on `cargo build --workspace`, tests pass on `cargo test
  --workspace`, clippy passes with `unwrap_used = "deny"` and
  `expect_used = "deny"`.
- 2 new TS packages published locally (`@chio/ai-sdk-middleware`,
  `@chio/next`). Each builds, tests pass, the size-budget gate stays
  green per trajectory-1 M08 budgets.
- `arc mcp wrap` subcommand present in `crates/chio-cli`; the
  end-to-end test in M07.P2.T6 wraps a real MCP server and asserts
  verdict gating + attestation header round-trip.
- 60 new conformance fixtures committed under
  `crates/chio-provider-conformance/fixtures/{gemini,mistral,groq,ollama,cohere}/`
  (12 per provider). Cross-provider verdict-equality oracle asserts
  8-provider equality on a hash-pinned scenario corpus.
- 3 templates committed under `sdks/typescript/templates/`
  (`next-ai-sdk-receipts/`, `fastapi-langchain/`, `cloudflare-worker/`).
  `create-chio-app` CLI ships under
  `sdks/typescript/packages/create-chio-app/`.
- TTFRH bench reports < 60 s p99 per template on the reference 4-core
  Linux runner; the gate is required CI.
- Telemetry-free first-run sentinel green per template.
- Four deployment-shape SDK drivers registered in
  `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/`
  and listed in the M02 hash-pinned manifest. The extended
  `verdict-matrix.yml` workflow runs required-CI against all nine
  drivers (Rust, Python, TS, WASM, Go, JVM, dotnet, Lambda, k8s); the
  cross-deployment smoke test reports zero divergence on the canonical
  scenario subset. Audit doc carries an explicit "D07 deferral closed"
  marker.
- Audit doc at `.planning/audits/M07-adoption-beachhead.md` records
  the before/after provider count (3 -> 8), fixture count, TTFRH
  numbers per template, the IDE config schema versions targeted, and
  the SDK-matrix expansion (5 -> 9 drivers).
  Linked from this narrative on milestone close.
