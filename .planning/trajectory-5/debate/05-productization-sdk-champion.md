# Position 05 - Productization, SDK, and Dogfood Champion

**Author role:** Productization, SDK, and Dogfood Champion
**Date:** 2026-05-07
**Thesis:** Chio has accreted 94 production crates, 290+ planning phases, three flagship "internet-of-agents" example networks, and a v3.18 bounded-ship qualification  -  and zero external users on record. Trj5 should be the productization trajectory: finish the v4.0 WASM Guard Runtime, ship the v4.1 Rust guest SDK in source, polish the three supported paths (MCP migration, web backend, native tool server) to "ten minutes from `brew install` to first signed receipt", make `chio receipt explain` a real debugging story, and dogfood Chio against the local Chio knowledge-base MCP stack that already lives at `ops/knowledge-base/`. Hardening without users is theater. The trj4 erratum is itself the strongest evidence: the bug we keep finding ("structural framing landed, runtime wiring did not") is the bug a single real integrator would surface in a week.

---

## 1. Inventory of the actual user-facing surface

### 1.1 What the README promises vs what the user finds

`README.md` "Start Here" (lines 39-48) sends a new user through three doors: `docs/install/README.md`, `docs/start-here/PROGRESSIVE_TUTORIAL.md`, and one of three supported paths. `README.md` "Supported Paths" (lines 50-87) names exactly three:

1. MCP migration (`chio mcp serve --policy`)
2. Web backends (`hello-openapi-sidecar` -> `hello-fastapi`)
3. Native Chio tool servers (`chio mcp serve` + `NativeChioServiceBuilder`)

### 1.2 What actually works end-to-end

`examples/EXAMPLE_SURFACE_MATRIX.md` enumerates 26 examples. Each row names a primary run path (most are `smoke.sh`). Spot-checks against the migration guide and progressive tutorial show the spine is real:

- `docs/guides/MIGRATING-FROM-MCP.md` (steps 1-5) walks `chio init`, `cp examples/policies/canonical-hushspec.yaml`, `chio mcp serve`, `chio check --policy`. The verdict-table (lines 152-162) is concrete: `read_file(".env")` deny, `write_file("src/main.py")` allow, `run_command("rm -rf /")` deny.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md` (steps 2-7) drives the `examples/docker/compose.yaml` stack, surfaces `sessionId`/`capabilityId`/`receiptId`, and resolves a receipt from `http://127.0.0.1:8940/v1/receipts/query`.
- `docs/start-here/NATIVE_ADOPTION_GUIDE.md` (lines 36-65) wires `NativeChioServiceBuilder` to `examples/hello-tool/`, which is a real crate that signs a manifest with a generated keypair.
- `examples/agent-commerce-network/` and the two `internet-of-agents-*` examples are flagship narratives.

### 1.3 SDKs published vs SDKs in source

`packages/sdk/` ships three runtime client SDKs with READMEs and quickstarts: `chio-py`, `chio-ts`, `chio-go`. `sdks/` adds 20+ framework integrations: `chio-fastapi`, `chio-langchain`, `chio-langgraph`, `chio-crewai`, `chio-autogen`, `chio-temporal`, `chio-airflow`, `@chio-protocol/express`, `@chio-protocol/fastify`, `@chio-protocol/elysia`, `chio-spring-boot`, `chio-go-http`, `chio-drogon`. The guard guest SDKs exist in three languages: `crates/chio-guard-sdk` (Rust + `#[chio_guard]` proc macro), `sdks/python/chio_guard_sdk/`, `sdks/typescript/chio-guard-sdk/`, all targeting the `chio:guard@0.2.0` WIT world.

### 1.4 What the CLI actually does

`crates/chio-cli/src/cli/types.rs` defines real subcommands behind clap: `Init` (line 273, scaffolds from `templates/init/`), `mcp serve`, `mcp serve-http`, `trust serve`, `check`, `guard {new,build,inspect,test,bench,pack,install}` (Phases 384/385), `receipt {list,verify,query,explain}` (line 2660). `explain_receipt_value` is implemented at `trust_commands.rs:2629`.

### 1.5 The one place we already dogfood

The most under-celebrated artifact in the repo is `ops/knowledge-base/`. Commits `f35189be7`, `6de68c9d6`, `1ea076a94` shipped a Postgres + pgvector + Neo4j + Graphiti + Chio-KB-MCP gateway on `:8111/mcp/`, with `make kb-eval` enforcing an A-grade dogfood report (`DOGFOOD-REVIEW.md`: 22/22 fixtures, p@5 0.99, recall@10 1.00, p95 1295 ms). We have a real MCP server we run for ourselves. We do not put Chio in front of it. That is the release work layup.

---

## 2. The 5-7 highest-leverage productization gaps

### Gap 1: `chio mcp serve --policy` in front of the local KB MCP

`ops/knowledge-base/README.md` documents an MCP gateway on `:8111/mcp/`. There is no example, no smoke, no receipt log binding it to `chio mcp serve-http`. This is the single highest-conviction dogfood: every Chio agent in this repo (every Claude Code session indexing the codebase) starts producing real receipts against a real MCP server. We get bug reports for free. Migration friction we hit becomes an issue against `docs/guides/MIGRATING-FROM-MCP.md`.

### Gap 2: `chio receipt explain` is a query, not a debugging story

The subcommand exists. It is not narratively integrated. `MIGRATING-FROM-MCP.md` step 5 lists `chio receipt list` and `chio receipt verify` but never `chio receipt explain`. When a user hits "DENY: forbidden_path" and wants to know which guard, which rule, which lineage hop fired, the docs send them to `http://127.0.0.1:8940/?token=demo-token` (a JSON viewer). A real debugging story is "verdict shows you the policy rule and the receipt id; `chio receipt explain <id>` prints the parent chain, the guard pipeline, the matched grant index, and the suggested policy edit." T1.6 (`audits/T1.6-chio-explain.md`) is reopened in trj4. This is a productization audit, not a hardening audit.

### Gap 3: WASM guard guest SDK ergonomics  -  promote v4.0 + v4.1 to primary

Phase 347 shipped the WASM guard scaffold. Phases 373-376 (v4.0) harden the host, manifest, request enrichment, startup wiring. Phases 382-385 (v4.1) ship the Rust guest SDK and the `chio guard {new,build,test,bench,pack,install}` lifecycle. `crates/chio-guard-sdk/src/lib.rs:26-37` already shows a five-line guard. `examples/guards/tool-gate/src/lib.rs` is a 12-line working WASM guard. This is the asset that turns Chio from a wrapped MCP gateway into a "policy-as-code in any language" platform. v4.0 is named "parallel" in `PROJECT.md` line 29; release work should promote it to primary.

### Gap 4: The "first ten minutes" loop is not measured

There is no `make first-receipt`, no `chio doctor`, no scripted "from cold install to first signed allow + first signed deny + first explained receipt in N seconds." `examples/run-hello-smokes.sh` exists but it is not the user's first surface. We should pick one canonical path (`hello-openapi-sidecar` is the documented first stop per `WEB_BACKEND_QUICKSTART.md`) and make it the measured first-ten-minutes loop, with a CI job that fails when the loop regresses.

### Gap 5: Native tool authoring still drops you off the cliff

`docs/start-here/NATIVE_ADOPTION_GUIDE.md` is honest: lines 73-78 list "what this does not solve yet"  -  resource-template authoring, completion helpers, and transport bootstrapping are still lower-level. `examples/hello-tool/README.md` confirms this: "If you need resource templates, advanced completion, or transport bootstrapping, drop down to the lower-level traits." That cliff is the migration off-ramp. v4.x phases 386-389 introduce WIT and multi-language guest SDKs but they bypass the resource/prompt ergonomics gap. Trj5 should commit to closing it.

### Gap 6: HushSpec policy authoring has one example file and no editor support

`examples/policies/canonical-hushspec.yaml` is "the canonical starting point." There is `crates/chio-lsp/` in the tree but no documented LSP install path, no schema reference under `docs/guards/`, no `chio policy lint` walkthrough. Policy authoring is the daily user experience.

### Gap 7: Receipts are emitted but not navigated

The `:8940` dashboard, `chio receipt query`, and `explain` exist. SIEM export (`crates/chio-siem/`) and OTel exporter (`crates/chio-otel-receipt-exporter/`) exist. Neither has a documented "operator runbook on how to investigate a denial."

---

## 3. Why this matters more than another hardening trajectory

The trj4 erratum says it cleanly: "structural framing landed but runtime wiring did not." That is the canonical failure mode of a project with no users. It is also what the next hardening trajectory will produce again. A user  -  any user  -  running `chio mcp serve` against a real MCP server in anger surfaces three classes of bugs that no formal lane catches:

- **Hot-path wiring bugs.** The trj4 hot-path-wire commits (`05fd0c56e`, `708c7bb33`) are exactly the bugs an integrator would have surfaced; they were instead found by a 10-agent post-merge audit.
- **Ergonomic dead-ends.** Whether `chio receipt explain` is a real debugging tool or just a JSON dumper.
- **Documentation drift.** Quote from `MIGRATING-FROM-MCP.md` line 33: `curl -fsSL -o /tmp/chio.rb https://github.com/bb-connor/chio/releases/latest/download/chio.rb`. There is no published GitHub release; the repo is private. A user gets a 404. Hardening trajectories never find this.

The hardening trajectories produce evidence that the assurance is *internally* consistent. Productization produces evidence that it is *externally* useful. Without the second category, the first is unverifiable: we are auditing claims about a product nobody runs.

---

## 4. Counters

### 4a. "Trj4 erratum proves we're not honest enough to ship to users yet"

The erratum is a call to honesty, not silence. v3.18 already shipped the bounded-claim discipline: README banner says "Mutation kill: 31%"; release docs say "bounded Chio is comptroller-capable software, not yet a proved market position." We can ship the productization trajectory under the same bounded-claim model: "Chio v0.1.0-bounded: governed wrapped-MCP, signed receipts, file-backed policy, single-node trust service." We don't ship "agent economy"; we ship "a fail-closed wrapper for your filesystem MCP server." That product is honest *because* of the erratum, not in spite of it.

### 4b. "WASM guard v4.0 is already a parallel track"

Parallel is the problem. `PROJECT.md` line 29 names v4.0 a "parallel milestone" while v3.x ship-readiness consumes the primary lane. The result is the v4.0 phases 373-376 are landed locally, the v4.1 SDK crates exist, the example guards compile, and zero external authors have shipped a `.chioguard` archive. Promoting v4.0 + v4.1 to the primary release work lane (with v4.2 WIT migration as the follow-on) gives the WASM guard story the productization push it has been quietly waiting for. The "policy-as-code in any language" pitch is the asymmetric product surface  -  every other gateway is yaml-only.

### 4c. "Decomposition first"

Real users force decomposition cuts naturally. `crates/chio-kernel/src/kernel/mod.rs` is 6,757 LOC because there is no second consumer of the kernel forcing the API to be smaller. A second consumer  -  `chio-kb-mcp-egress` putting Chio in front of the local KB MCP, or a real customer integration  -  is the smallest possible second consumer that exposes the seams. Decomposition without a second consumer is refactoring-as-rearranging-deck-chairs; with one, it has a forcing function.

---

## 5. Conceded hardening floor (non-negotiable before shipping)

Productization does not mean ignoring trj4. The hardening floor we will *not* ship without:

- README mutation banner reaches the audit-doc threshold: `>= 65%` per trust-boundary crate, `>= 80%` on `chio-attest-verify` (`audits/T0.B-substrate-hardening.md`). Currently 31%.
- `scripts/check-threat-coverage.sh` is green AND `docs/security/threat-coverage.md` reports zero "weak or meta-only" rows (currently 9/20).
- `cargo vet` exemption count is on a documented burn-down path with a no-net-new gate (currently 819).
- `chio mcp serve` and `chio mcp serve-http` survive a 24-hour soak against the local KB MCP without a panic, leak, or unverifiable receipt.

That floor is a Wave 0-4 subset of the trj4 wave plan, not a parallel programme. Trj5 *consumes* trj4 Wave 0-4 as its hardening prerequisite, then turns the rest of the wave plan into productization-driven hardening: each new user-surfaced bug becomes a wave row.

---

## 6. The release work productization slate (concrete deliverables)

1. `chio mcp serve-http --policy` wrapping the local KB MCP gateway at `:8111/mcp/`, with a daily receipt log committed to `ops/knowledge-base/receipts/`.
2. v4.0 + v4.1 promoted to primary: WASM guard runtime hardening completion, `chio guard new/build/test/bench/pack/install` lifecycle, three published example guards in `examples/guards/`.
3. `chio receipt explain` as a documented debugging story with a guided walkthrough in `docs/guides/EXPLAIN_A_DENIAL.md`.
4. A measured "first ten minutes" smoke (`scripts/first-receipt.sh`) gated in CI.
5. One published binary release (`v0.1.0-bounded`) with verified Homebrew formula, so the `MIGRATING-FROM-MCP.md` install commands actually work.
6. One real external integrator picked up via the bounded-claim release, with their bug reports as the release work closing audit evidence.

Hardening without users is theater. The 94 crates exist. Let one person actually use them.
