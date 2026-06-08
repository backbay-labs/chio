# Chio `crates/` Taxonomy and Proposed Subfolder Grouping

Research scope: redesign the file/folder architecture of the `crates/` directory for a
professional, open-source, production-ready project. This document inventories the crates,
maps the internal dependency layering, proposes a concrete subfolder grouping that assigns
every crate to exactly one group, and quantifies the migration cost and risk. No source,
scripts, workflows, or configs were modified.

## Headline numbers

- 107 top-level crate directories under `crates/` (`ls -d crates/*/ | wc -l` = 107).
- 111 `Cargo.toml` files under `crates/` total: 107 top-level + 4 nested sub-crate manifests.
- 451 intra-`crates/` relative path-dependency lines (`path = "../chio-..."`), the edges that
  break when a crate moves into a subfolder.
- 77 path references that reach into `crates/` from OUTSIDE `crates/` (fuzz, examples, tests,
  sdks, integrations, formal, xtask, and one in the root `Cargo.toml`).
- 111 explicit `"crates/..."` member entries in the root `Cargo.toml` (would all be rewritten).
- Only 1 chio crate (`chio-metrics-spec`) is wired through `[workspace.dependencies]`; every
  other internal edge is a hard-coded relative path.

## 1. Inventory and descriptions

### 1.1 Nested sub-crates (4 manifests inside 4 parent crate dirs)

These are crates living under another crate's directory rather than directly under `crates/`:

| Path | Package name | Workspace member? |
| --- | --- | --- |
| `crates/chio-data-guards/redactors/default` | `chio-data-guards-redactors-default` | Yes (listed) |
| `crates/chio-conformance/verdict_matrix` | `chio-conformance-verdict-matrix` | No (NOT listed as a member; only its lambda driver is) |
| `crates/chio-conformance/verdict_matrix/drivers/lambda` | `chio-verdict-matrix-driver-lambda` | Yes (listed) |
| `crates/chio-eval-receipt/py` | `chio-eval-receipt-py` | No (not in members list) |

These nested manifests use deeper relative paths (`../../chio-core-types`,
`../../chio-kernel`, `../../chio-kernel-browser`) and must be handled separately during any
move. The package-name mismatch (`chio-openai` dir publishes `chio-openai-adapter`) is another
naming inconsistency surfaced by the inventory.

### 1.2 Full crate inventory with descriptions

The root `Cargo.toml` already organizes members under comment-group headers. Those headers are
the project's own intended taxonomy and the seed for the proposal below. The 14 existing header
groups are: Core & types, Kernel variants, Guards & policy, Protocol adapters & edges,
Economics & settlement, Supply-chain attestation, Identity/credentials/federation,
Observability & ops, Control plane & storage, HTTP & session, Products, SDK support, Examples,
Tests, Tooling, Editor extensions.

(Descriptions are the `package.description` field from each crate's `Cargo.toml`. Trimmed for
readability.)

- chio-core: Core types for the Chio protocol
- chio-core-types: Shared substrate types for capability, receipt, manifest, session boundaries
- chio-errors: Typed Chio error codes and diagnostics
- chio-adversarial-suite: Curated adversarial trust-boundary corpus and case schema
- chio-arena: Deterministic arena scenario runner and replay bundle writer
- chio-kernel: Runtime kernel - capability validation, guard evaluation, receipt signing
- chio-kernel-browser: Browser (wasm-bindgen) bindings over chio-kernel-core
- chio-kernel-core: Portable (no_std + alloc) kernel core - verdict, capability verify, signing
- chio-kernel-mobile: Mobile FFI bindings (iOS/Android) over kernel core via UniFFI
- chio-lsp: Language server (chio.yaml, manifest, guard DSL diagnostics/completion/hover)
- chio-data-guards: Data layer guards (SQL, vector DB, warehouse cost)
- chio-data-guards-redactors-default: Default redactor (secrets, PII, bearer-token stripping)
- chio-external-guards: HTTP-backed external guard adapters
- chio-guard-registry: Guard OCI registry client with Sigstore bundle verification
- chio-guard-sdk: Guest-side SDK for writing WASM guards
- chio-guard-sdk-macros: Proc macro for the WASM guard SDK
- chio-guards: Security guards for the runtime kernel
- chio-policy: HushSpec policy format - parse, validate, merge, evaluate, compile to guards
- chio-wasm-guards: WASM guard runtime - load/execute .wasm guard modules with fuel metering
- chio-a2a-adapter: A2A-to-Chio adapter for agent-card discovery and SendMessage mediation
- chio-a2a-edge: A2A edge - exposes Chio tools as blocking A2A skills
- chio-acp-edge: ACP edge - exposes Chio tools as ACP capabilities
- chio-acp-proxy: ACP security proxy enforcing capability-based access control
- chio-ag-ui-proxy: AG-UI proxy - capability-validated interception of agent-to-UI streams
- chio-anthropic-tools-adapter: Anthropic Messages tool-use adapter
- chio-bedrock-converse-adapter: Amazon Bedrock Converse adapter (SigV4)
- chio-cohere-tools-adapter: Cohere /v2/chat tool-use adapter
- chio-cross-protocol: Shared cross-protocol bridge contracts and orchestrator runtime
- chio-edge-metrics: Shared receipt-write metrics sink for protocol edge crates
- chio-egress-contract: Typed HTTP egress contract for substrate adapters
- chio-envoy-ext-authz: Envoy ext_authz gRPC adapter bridging to the kernel
- chio-gemini-tools-adapter: Google Gemini generateContent tool-use adapter
- chio-groq-tools-adapter: Groq OpenAI-compatible tool-use adapter
- chio-mcp-adapter: Wraps MCP servers as Chio tool servers
- chio-mcp-edge: MCP edge runtime and shared transport contracts
- chio-mcp-remote: Remote hosted MCP runtime surface
- chio-mistral-tools-adapter: Mistral chat/completions tool-use adapter
- chio-ollama-tools-adapter: Ollama /api/chat tool-use adapter
- chio-openai (pkg chio-openai-adapter): OpenAI tool-call adapter (Chat Completions + Responses)
- chio-openapi: OpenAPI 3.x spec parser and ToolManifest generator
- chio-openapi-mcp-bridge: Exposes Chio-governed HTTP APIs as MCP tool surfaces via OpenAPI
- chio-provider-adapter-core: Shared provider-adapter primitives for native tool adapters
- chio-provider-conformance: Provider replay harness for native adapter conformance fixtures
- chio-tool-call-fabric: Provider-agnostic tool-call fabric for LLM adapter integrations
- chio-tower: Tower middleware for capability validation and receipt signing
- chio-anchor: Anchoring runtime and proof normalization for checkpoints
- chio-appraisal: Runtime attestation appraisal artifacts and evaluation
- chio-autonomy: Bounded autonomy pricing, execution, and rollback contracts
- chio-credit: Credit, capital, and bonded execution contracts
- chio-link: Oracle runtime for cross-currency budget enforcement
- chio-listing: Generic listing and trust-activation contracts
- chio-market: Liability-market provider, quote, and claims contracts
- chio-open-market: Open-market economics and penalty contracts
- chio-settle: Settlement runtime for web3 escrow and bond execution
- chio-underwriting: Underwriting decision, simulation, and appeal artifacts
- chio-web3: Web3 settlement, anchoring, and contract-surface artifacts
- chio-web3-bindings: Alloy bindings and packaged artifacts for the web3 contract family
- chio-replay-corpus: Replay corpus helpers for TEE captures (dedupe + re-redaction)
- chio-attest-buyer: Buyer attestation verification boundary
- chio-attest-buyer-core: Offline proof package verifier
- chio-attest-verify: Shared Sigstore verification surface (supply-chain attestation)
- chio-attest-loopback: Deterministic loopback proof package and runtime harness library
- chio-custody-hw: Hardware custody surface (HybridBackend-signed capabilities, nonce store)
- chio-weights: Model-card surface (signed weights cards, cosign bundle helper)
- chio-tee: TEE shadow runner - captures kernel decisions, emits signed redacted frames
- chio-tee-frame: Wire format for TEE replay frames (kernel decision capture)
- chio-credentials: Portable reputation credentials and Agent Passport verification
- chio-did: Self-certifying did:chio documents and resolution
- chio-federation: Federation quorum, admission, and reputation-clearing contracts
- chio-federation-authority: Runtime authority artifact issuer
- chio-governance: Generic governance charters and case evaluation
- chio-pheromone: Local pheromone substrate and transit evidence types
- chio-pheromone-relay: Live pheromone relay service and durable relay store
- chio-pheromone-runtime: Local pheromone receiver runtime and durable store
- chio-revocation-oracle: Signed sparse-Merkle epoch roots, freshness windows, revocation lookups
- chio-reputation: Deterministic local reputation scoring for agents
- chio-selective-disclosure: BBS selective disclosure projections and proof packages
- chio-runtime: Runtime admission and orchestration boundary
- chio-runtime-core: Live runtime admission for kernel-mediated cross-vendor workflows
- chio-runtime-harness: Live runtime loopback harness library
- chio-lineage: Provenance and lineage DAG indexer
- chio-log-redact: Tracing log redaction layer and macro for operator surfaces
- chio-metering: Receipt metering and economics (cost attribution, budget, billing export)
- chio-metrics-spec: Authoritative metric-name registry for SRE surfaces
- chio-otel-receipt-exporter: OpenTelemetry trace ingress and receipt-store sink
- chio-siem: SIEM exporter pipeline for receipt audit logs
- chio-config: Unified chio.yaml configuration loader
- chio-control-plane: Trust-control service, client, and shared runtime support
- chio-manifest: Tool server manifest format - definitions, signing, verification
- chio-store-sqlite: SQLite-backed persistence, query, report implementations
- chio-workflow: Skill and workflow authority - composition, manifests, workflow receipts
- chio-hosted-mcp: Hosted MCP runtime surface
- chio-http-core: Protocol-agnostic HTTP security types for the kernel
- chio-http-session: Per-session journal (request history, data flow, tool sequence)
- chio-api-protect: Zero-code reverse proxy protecting HTTP APIs with receipts
- chio-cli: CLI binary for the runtime kernel
- chio-mercury: MERCURY product app CLI
- chio-mercury-core: Typed MERCURY evidence contracts layered on receipt truth
- chio-wall: Chio-Wall companion-product CLI
- chio-wall-core: Typed Chio-Wall control-path contracts
- chio-binding-helpers: Bindings-friendly invariant helpers for SDKs
- chio-bindings-ffi: C ABI bindings for deterministic SDK invariant helpers
- chio-cpp-kernel-ffi: C ABI bindings for the C++ offline kernel SDK
- chio-conformance: Scenario loading and report generation for cross-language conformance
- chio-eval-receipt: Reference verifier surface for eval-report receipt bundles
- chio-spec-codegen: Schema-to-Rust codegen pipeline for chio-wire (typify backend)
- chio-spec-validate: JSON Schema validator for protocol scenarios and wire artifacts
- chio-test-support: Shared test-only assertion helpers (unwrap/expect shims for tests)

## 2. Dependency layers

Edges measured by counting `path = "../chio-..."` declarations in each crate manifest.

### 2.1 Most-depended-on crates (in-degree, the load-bearing foundation)

| Crate | In-degree (consumers) |
| --- | --- |
| chio-core-types | 72 |
| chio-kernel | 36 |
| chio-test-support | 23 (dev-only) |
| chio-core | 22 |
| chio-tool-call-fabric | 12 |
| chio-store-sqlite | 12 |
| chio-manifest | 12 |
| chio-federation | 12 |
| chio-egress-contract | 12 |
| chio-kernel-core | 9 |
| chio-provider-adapter-core, chio-guards, chio-appraisal | 8 |
| chio-credit, chio-attest-buyer-core | 7 |

### 2.2 Highest-coupling crates (out-degree, the top of the stack)

| Crate | Out-degree (chio deps) |
| --- | --- |
| chio-cli | 48 |
| chio-conformance | 29 |
| chio-kernel | 19 |
| chio-control-plane | 18 |
| chio-provider-conformance, chio-core | 11 |
| chio-settle | 9 |
| chio-runtime-harness, chio-wall, chio-mcp-remote, chio-attest-loopback, chio-acp-edge, chio-a2a-edge | 7 |

### 2.3 Foundation crates with NO intra-workspace chio path deps

`chio-adversarial-suite`, `chio-config`, `chio-egress-contract`, `chio-envoy-ext-authz`,
`chio-errors`, `chio-guard-sdk`, `chio-guard-sdk-macros`, `chio-http-session`,
`chio-metrics-spec`, `chio-spec-codegen`, `chio-spec-validate`, `chio-test-support`,
`chio-wall-core`. (`chio-envoy-ext-authz` is a standalone gRPC adapter; it talks to the kernel
over the wire, not via a Cargo edge.)

### 2.4 Natural layering and one important caveat

The clean layering the task hypothesized (core/types -> runtime/kernel -> guards/policy ->
protocol -> trust/attest -> market/economy -> sdk/ffi -> tooling/cli) holds at the extremes
(types at the bottom, CLI/conformance at the top) but does NOT hold cleanly in the middle.

Key structural finding: the economics/settlement crates are NOT a high layer. `chio-core`
depends directly on `chio-appraisal`, `chio-autonomy`, `chio-credit`, `chio-federation`,
`chio-governance`, `chio-listing`, `chio-market`, `chio-open-market`, `chio-underwriting`,
`chio-web3`, and `chio-kernel` pulls in the same set plus `chio-settle`. So the economic
contracts sit BELOW core/kernel in the build graph, not above. This means a strict
acyclic "economy depends on everything else" assumption is wrong; instead "economy contracts"
are foundational data-contract crates that core and kernel build on. Any subfolder grouping is
a documentation/navigation aid, not a build-layer enforcement, because Cargo does not enforce
layering by directory.

## 3. Proposed grouping table (all 107 top-level crates + 4 nested)

Proposed subfolders under `crates/`. Every crate assigned to exactly one group. The grouping
follows the project's own comment headers, with a few consolidations: "Economics & settlement"
keeps its own folder (it is large and cohesive), identity/federation/trust merge into one
`trust/` group with attestation, and observability/control-plane/storage/http split into
`observability/` and `platform/`.

Proposed top-level folders: `core`, `kernel`, `guards`, `protocol`, `economy`, `trust`,
`observability`, `platform`, `products`, `sdk`, `tooling`.

| Crate | Proposed group |
| --- | --- |
| chio-core | core |
| chio-core-types | core |
| chio-errors | core |
| chio-adversarial-suite | core |
| chio-arena | core |
| chio-kernel | kernel |
| chio-kernel-core | kernel |
| chio-kernel-browser | kernel |
| chio-kernel-mobile | kernel |
| chio-runtime | kernel |
| chio-runtime-core | kernel |
| chio-runtime-harness | kernel |
| chio-data-guards | guards |
| chio-data-guards-redactors-default (nested) | guards |
| chio-external-guards | guards |
| chio-guard-registry | guards |
| chio-guards | guards |
| chio-policy | guards |
| chio-wasm-guards | guards |
| chio-a2a-adapter | protocol |
| chio-a2a-edge | protocol |
| chio-acp-edge | protocol |
| chio-acp-proxy | protocol |
| chio-ag-ui-proxy | protocol |
| chio-anthropic-tools-adapter | protocol |
| chio-bedrock-converse-adapter | protocol |
| chio-cohere-tools-adapter | protocol |
| chio-cross-protocol | protocol |
| chio-edge-metrics | protocol |
| chio-egress-contract | protocol |
| chio-envoy-ext-authz | protocol |
| chio-gemini-tools-adapter | protocol |
| chio-groq-tools-adapter | protocol |
| chio-mcp-adapter | protocol |
| chio-mcp-edge | protocol |
| chio-mcp-remote | protocol |
| chio-mistral-tools-adapter | protocol |
| chio-ollama-tools-adapter | protocol |
| chio-openai | protocol |
| chio-openapi | protocol |
| chio-openapi-mcp-bridge | protocol |
| chio-provider-adapter-core | protocol |
| chio-provider-conformance | protocol |
| chio-tool-call-fabric | protocol |
| chio-tower | protocol |
| chio-hosted-mcp | protocol |
| chio-anchor | economy |
| chio-appraisal | economy |
| chio-autonomy | economy |
| chio-credit | economy |
| chio-link | economy |
| chio-listing | economy |
| chio-market | economy |
| chio-open-market | economy |
| chio-settle | economy |
| chio-underwriting | economy |
| chio-web3 | economy |
| chio-web3-bindings | economy |
| chio-metering | economy |
| chio-replay-corpus | trust |
| chio-attest-buyer | trust |
| chio-attest-buyer-core | trust |
| chio-attest-verify | trust |
| chio-attest-loopback | trust |
| chio-custody-hw | trust |
| chio-weights | trust |
| chio-tee | trust |
| chio-tee-frame | trust |
| chio-credentials | trust |
| chio-did | trust |
| chio-federation | trust |
| chio-federation-authority | trust |
| chio-governance | trust |
| chio-pheromone | trust |
| chio-pheromone-relay | trust |
| chio-pheromone-runtime | trust |
| chio-revocation-oracle | trust |
| chio-reputation | trust |
| chio-selective-disclosure | trust |
| chio-appraisal (note) | (kept in economy; appraisal is attestation-adjacent) |
| chio-lineage | observability |
| chio-log-redact | observability |
| chio-metrics-spec | observability |
| chio-otel-receipt-exporter | observability |
| chio-siem | observability |
| chio-config | platform |
| chio-control-plane | platform |
| chio-manifest | platform |
| chio-store-sqlite | platform |
| chio-workflow | platform |
| chio-http-core | platform |
| chio-http-session | platform |
| chio-api-protect | products |
| chio-cli | products |
| chio-mercury | products |
| chio-mercury-core | products |
| chio-wall | products |
| chio-wall-core | products |
| chio-binding-helpers | sdk |
| chio-bindings-ffi | sdk |
| chio-cpp-kernel-ffi | sdk |
| chio-eval-receipt | sdk |
| chio-eval-receipt-py (nested) | sdk |
| chio-guard-sdk | sdk |
| chio-guard-sdk-macros | sdk |
| chio-lsp | tooling |
| chio-conformance | tooling |
| chio-conformance-verdict-matrix (nested) | tooling |
| chio-verdict-matrix-driver-lambda (nested) | tooling |
| chio-spec-codegen | tooling |
| chio-spec-validate | tooling |
| chio-test-support | tooling |

Group sizes (top-level only, 107): core 5, kernel 6, guards 6, protocol 26, economy 13,
trust 20, observability 5, platform 7, products 6, sdk 6, tooling 6. (Plus 4 nested sub-crates
distributed into guards/sdk/tooling.)

Notes on judgment calls:
- `chio-metering` is economics-flavored but could equally sit in observability (it touches
  receipt cost attribution and billing export). Placed in economy for cohesion with credit/settle.
- `chio-appraisal` straddles economy and trust (attestation appraisal). Kept in economy because
  `chio-core` and `chio-kernel` consume it as a contract type, and it pulls economic semantics.
- `chio-guard-sdk` / `chio-guard-sdk-macros` are the guard-author SDK; placed in `sdk` rather
  than `guards` to keep `guards/` as the runtime guard surface. Alternatively keep them in
  `guards/` to match the existing comment header. Either is defensible.
- `chio-hosted-mcp` is protocol-adjacent (MCP hosting) and grouped under protocol; it could
  also be a product. Placed in protocol with the other MCP crates.

## 4. Migration cost and risk

### 4.1 What breaks on a move

1. Root `Cargo.toml` member list: all 111 `"crates/..."` entries must change to
   `"crates/<group>/<crate>"`. The comment headers can be preserved or replaced by folder names.
2. Intra-`crates/` path edges: 451 lines of `path = "../chio-..."`. Moving a crate into a
   subfolder changes its relative position, so consumers and the crate itself both need path
   rewrites. The exact number of edits depends on whether consumer and target end up in the same
   subfolder. Worst case all 451 lines change (`../chio-x` becomes `../../<group>/chio-x`).
3. Nested sub-crate paths: 3 deeper edges (`../../chio-core-types`, `../../chio-kernel`,
   `../../chio-kernel-browser`) plus the 4 nested manifests change depth again.
4. External references into `crates/`: 77 path lines outside `crates/` already use multi-level
   `../../crates/...` or `../crates/...`. These gain one more path segment
   (`../../crates/<group>/...`). Distribution: fuzz 23, examples/chio-3vendor 10, tests/e2e 4,
   sdks/lambda 4, examples/hello-* 16 total, xtask 3, formal/diff-tests 3, examples/otel-genai 3,
   examples/guards 4, examples/bilateral-invocation 2, tests/replay 1, sdks/rust compat 1,
   integrations/mcp-adapter 1, examples/cross-provider-policy 1, root Cargo.toml 1.

### 4.2 Does Cargo support glob members?

Yes. Cargo supports glob patterns in `workspace.members`, e.g. `"crates/*"` (current shape) or
`"crates/*/*"` for one level of nesting. A subfolder layout could use `"crates/*/*"` to capture
all `crates/<group>/<crate>` members in a single line, dramatically shrinking the member list.
Caveat: glob `"crates/*/*"` would NOT match the deeper nested sub-crates
(`crates/<group>/chio-conformance/verdict_matrix/...` and
`crates/<group>/chio-data-guards/redactors/default`); those still need explicit entries, or a
broader/recursive pattern plus `exclude` entries. Mixing a glob with explicit entries is
supported. Globbing also means a stray `Cargo.toml` (e.g. the unlisted
`chio-conformance/verdict_matrix` and `chio-eval-receipt/py`) would suddenly become a member,
which could change build behavior - this needs an audit before switching to globs.

### 4.3 The real cost driver: hard-coded path deps, not the member list

The expensive part is the 451 relative path edges, because Chio does NOT centralize internal
crate versions through `[workspace.dependencies]` (only `chio-metrics-spec` is centralized).
Every other internal dependency is a per-crate `path = "../chio-x"`.

The highest-leverage de-risking move is to FIRST migrate all internal chio deps to
`[workspace.dependencies]` (declare each chio crate once in the root, then each member writes
`chio-x = { workspace = true }`). After that one-time refactor:
- Relocating crates only requires editing the single path declaration per crate in the root
  workspace table, not 451 scattered relative paths.
- The 77 external references collapse the same way (they would use `{ workspace = true }` too,
  where the consumer is itself a workspace member; fuzz/examples that are members already can).

### 4.4 Risk register (fail-closed framing)

- High blast radius: `chio-core-types` (72 consumers) and `chio-kernel` (36). A wrong path on
  either fails the whole workspace build, but it fails LOUDLY at `cargo build` (compile-time),
  not silently - acceptable under fail-closed.
- Silent-inclusion risk if switching to globs: the two unlisted manifests
  (`chio-conformance-verdict-matrix`, `chio-eval-receipt-py`) would be pulled into the build.
  Audit and either list explicitly or exclude.
- CI / tooling that hard-codes crate paths: scripts under `scripts/`, `supply-chain/` (cargo-vet
  exemptions reference crate paths), `cargo-deny`/`cargo-vet` configs, and CI workflows may
  embed `crates/chio-x` paths. These are out of scope to edit here but MUST be swept; a path
  move that misses a vet exemption would fail the supply-chain gate (which is the desired
  fail-closed behavior, but it is a real cost). Per project memory, the cargo-deny job and
  duplicate-baseline check are path/coverage sensitive.
- `package.publish` ordering: if these are ever published to crates.io, the directory has no
  bearing, but `Cargo.lock` and any `include`/`exclude` globs in individual manifests should be
  checked for path assumptions.

### 4.5 Recommended migration sequence (lowest risk)

1. Land the `[workspace.dependencies]` refactor for all chio crates with zero directory moves
   (pure dependency-declaration change; verifiable by `cargo build --workspace` diffing nothing
   semantically). This is the big one.
2. Sweep every non-`crates/` consumer (fuzz, examples, tests, sdks, integrations, formal,
   xtask) to `{ workspace = true }` as well.
3. Audit and explicitly handle the 2 unlisted nested manifests and the redactor/lambda sub-crates.
4. Only then physically move directories into the 11 subfolders, updating the root member list
   (or switching to `crates/*/*` glob + explicit nested entries).
5. Sweep `scripts/`, `supply-chain/`, CI workflows, and docs for hard-coded `crates/chio-x` paths.
6. Run the full gate: `cargo build --workspace && cargo test --workspace && cargo clippy
   --workspace -- -D warnings && cargo fmt --all -- --check`, plus cargo-deny and cargo-vet.

## 5. Recommendation

- Adopt the 11-folder grouping in section 3 (`core`, `kernel`, `guards`, `protocol`, `economy`,
  `trust`, `observability`, `platform`, `products`, `sdk`, `tooling`). It mirrors the project's
  own comment headers, keeps the large cohesive clusters (protocol 26, trust 20, economy 13)
  intact, and gives a newcomer an immediate mental model of the system.
- Treat the grouping as navigation/documentation only. Cargo does not enforce layering by
  folder, and the actual build graph has economy contracts sitting below core/kernel, so do NOT
  document the folders as a strict dependency hierarchy - document them as functional domains.
- Do the `[workspace.dependencies]` centralization BEFORE any directory move. It converts a
  451-edge fragile rewrite into a single-table edit and is independently valuable for a
  production open-source project (single source of truth for internal versions).
- Prefer `crates/*/*` glob members plus explicit entries for the deeper nested crates, after
  auditing the two currently-unlisted manifests.
- Fix the naming inconsistency where `crates/chio-openai/` publishes `chio-openai-adapter`;
  align directory name and package name during the move (low cost while paths are already churning).
