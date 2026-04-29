# Next-10 Trajectory

This directory holds the planning documents for the next ten code-focused
milestones in the Chio (formerly ARC) project. Each milestone is a self-
contained planning artifact with goal, scope, success criteria, phase break-
down, dependencies, risks, and code touchpoints.

## Genesis

The trajectory was produced from a parallel seven-agent debate (2026-04-25)
that ranked candidate milestones across seven distinct lenses: protocol/spec
purist, SDK/DX champion, performance/scalability, security/adversarial,
integrations/adapter pragmatist, testing/reliability, and WASM/plugin
ecosystem. The recommended composite top ten captured the cross-lens
consensus picks plus single-lens picks backed by hard code evidence
(measured async coverage, hand-typed wire structures across SDKs, missing
fuzz targets, undocumented mega-files, stub adapters, etc.). Each doc was
then reviewed against the live codebase by a parallel reviewer pass that
pinned crate versions, sharpened success criteria, and corrected drift
between the doc and `main`.

Scope of this trajectory: pure engineering output. Releases, design partner
work, certifications, and other external workstreams are intentionally
excluded.

## The Ten Milestones

| # | Title | One-liner |
|---|-------|-----------|
| 01 | [Spec-Driven Codegen + Canonical-JSON Vectors + Conformance](01-spec-codegen-conformance.md) | Make `spec/schemas/` the source of truth (19 wire + 6 http schemas today; net add >= 20: +16 wire, +4 http), grow vectors from 35 to >= 120 cases, and package the conformance suite for cross-implementation use. |
| 02 | [Post-PR-13 Fuzzing Trajectory](02-fuzzing-post-pr13.md) | After PR #13 lands the seven-target baseline, expand to eleven additional decode boundaries, OSS-Fuzz, mutation testing, and crash-triage automation. |
| 03 | [Capability Algebra Properties + Bounded-Model Suite](03-capability-algebra-properties.md) | Eighteen named proptest invariants across `chio-core-types`, `chio-kernel-core`, `chio-credentials`, and `chio-policy`; Kani harness count grown from five to ten; TLA+/Apalache model of concurrent revocation. |
| 04 | [Deterministic Replay + Receipt Byte-Equivalence Gate](04-deterministic-replay.md) | Fifty canonical scenarios, golden receipt corpus, cross-version replay matrix (today: v0.1.0, v2.0; ratchet starts at v3.0), `chio replay` CLI for auditors. |
| 05 | [Real Async Kernel Migration](05-async-kernel-real.md) | Convert the `evaluate_tool_call` body from sync delegation to a real async flow, add a tower-based middleware stack in the existing `chio-tower` crate, criterion benches with regression gates, p99 SLOs in CI. |
| 06 | [WASM Guard Platform](06-wasm-guard-platform.md) | WIT bumped to `chio:guard@0.2.0`, OCI distribution via `oci-distribution` + cosign keyless, hot-reload via `arc_swap::ArcSwap` with N=32 canary and rollback at M>=5 errors / 60s, per-guard tracing/metrics. |
| 07 | [Provider-Native Tool Adapters](07-provider-native-adapters.md) | OpenAI Responses (snapshot 2026-04-25), Anthropic Tools (`anthropic-version: 2023-06-01` + computer-use beta header), Bedrock Converse (single AWS SDK pin, us-east-1 first), plus a shared `chio-tool-call-fabric`. |
| 08 | [Browser/Edge WASM SDK](08-browser-edge-sdk.md) | Package `@chio-protocol/browser` from the existing `chio-kernel-browser`, ship Cloudflare Workers / Vercel Edge / Deno targets via wasm-pack `--target {web,bundler}`; sign Phase 3 deferred behind a documented trust-boundary review. |
| 09 | [Supply-Chain Attestation](09-supply-chain-attestation.md) | cargo-vet baseline, deny.toml hardening, CycloneDX SBOMs, cosign keyless signing, SLSA L2 (L3 deferred), reproducible build CI on `x86_64-unknown-linux-gnu`, shared `crates/chio-attest-verify/`. |
| 10 | [Live-Traffic Tee + Replay Harness](10-tee-replay-harness.md) | `chio-tee` shadow-mode capture with three modes and SIGUSR1 hot-toggle, `chio-tee-frame.v1` NDJSON, `chio replay` runner using the M04 canonical exit-code registry (0/10/20/30/40/50), OpenTelemetry GenAI semantic conventions. |

## Dependency Graph

```
                           PR #13 (in flight)
                                  |
                                  v
                                M02
                                 (post-merge fuzzing expansion)

  M09 supply-chain         M03 capability algebra        M01 spec/codegen
  (independent)            (independent)                 (independent)
        |                         |                              |
        v                         v                              v
        +----+                    +-----------------+            +-----+
             |                                      |                  |
             v                                      v                  v
            M06 WASM guard platform                M05 async kernel    M04 replay
            (uses chio-attest-verify from M09;     (blocked by M03;    (uses M01 vectors;
             reserves chio:guards/redact for M10;  uses chio-tower;    consumes M07/M10
             provides redactor host harness)       safety net is M04)  for corpus growth)
                  |                                                          |
                  v                                                          v
                  +------------------+                         +------------+
                                     |                         |
                                     v                         v
                                    M07 provider adapters      M08 browser/edge
                                    (uses M01 + M03;           (uses M01 + M04;
                                     fabric ToolInvocation)     verify-only surface)
                                            |
                                            v
                                           M10 tee/replay
                                           (uses M01, M04, M06 redactor host,
                                            M07 traffic sources;
                                            owns chio-tee-frame.v1)
```

## Recommended Execution Waves

### Wave 1: Foundation (parallel)
- **M01** Spec-driven codegen + canonical-JSON vectors + conformance
- **M02** Post-PR-13 fuzzing expansion (gated on PR #13 merge)
- **M03** Capability algebra properties + bounded-model suite
- **M09** Supply-chain attestation

These four are independent of each other and unblock everything downstream.
M09 specifically should land early so M06's Sigstore choices reuse
`chio-attest-verify`. PR #13 must merge before M02 phase 1 starts.

### Wave 2: Trust-boundary regression nets and runtime
- **M04** Deterministic replay (after M01 stabilizes canonical JSON)
- **M05** Real async kernel (uses M03 properties + M04 replay as safety net)
- **M06** WASM guard platform (after M09 lands `chio-attest-verify`)

### Wave 3: Adapter and runtime breadth
- **M07** Provider-native tool adapters (after M01 + M03)
- **M08** Browser/edge WASM SDK (after M01 + M04)

### Wave 4: Operability
- **M10** Live-traffic tee + replay (after M01, M04, M06 redactor host
  surface, M07 traffic sources)

## Cross-doc invariants

The trajectory has several artifacts that span more than one milestone. Each
is owned by exactly one milestone; consumers reference but never duplicate.

| Artifact | Owner | Consumers | Notes |
|----------|-------|-----------|-------|
| Canonical-JSON vector corpus (`tests/bindings/vectors/{canonical,manifest,receipt,capability,hashing,signing}/v1.json`) | M01 | M02 (libFuzzer seed), M04 (golden basis), M07 (fabric round-trip), M08 (browser-runtime differential) | Grow from 35 to >= 120 cases; sha256-frozen via `MANIFEST.sha256`. |
| Receipt fixture corpus (`tests/replay/fixtures/`) | M04 | M07 (each adapter family adds scenarios), M08 (demo + Phase 3 stream parser), M10 (graduates captures via `chio replay --bless`) | NDJSON receipts + checkpoint.json + root.hex per scenario. Frozen format. |
| `chio-attest-verify` crate | M09 (Phase 3) | M06 (guard signing), M02 (fuzz target reuses it) | Single source of truth for the OIDC identity-and-issuer regex; M06 must NOT fork. |
| `chio-tee-frame.v1` NDJSON schema | M10 | M07 (`chio-provider-conformance` reuses verbatim) | Two NDJSON schemas across M07 and M10 is a defect; M10 owns the canonical definition. |
| `chio-tower` crate | M05 (extends) | M06 (host-call middleware shape), M07 (downstream adapter middleware) | Already exists at `crates/chio-tower/`; M05 lands `KernelService` + middleware stack here, not a new crate. |
| WIT `chio:guard@0.2.0` world | M06 (Phase 1) | M01 (conformance fixtures), M10 (`chio:guards/redact@0.1.0` namespace reserved here) | Four guest SDKs migrate atomically. M06 reserves the `redact` namespace; M10 ships the concrete redactor world. |
| Capability algebra in `chio-core-types` and `chio-kernel-core` | M03 (proves) | M05 (refactor must stay green), M07 (provenance derives), Lean theorems in `formal/lean4/` | Eighteen named proptest invariants distributed 5/5/4/4 across the four crates above. |
| Apalache lane (`formal/tla/RevocationPropagation.tla`) | M03 (Phase 3) | none directly; CI lane lives in `.github/workflows/ci.yml` and a nightly liveness lane in `nightly.yml` | Pinned at `0.50.x`; PROCS=4, CAPS=8 on PR. |

## Wave 1 decisions (resolved 2026-04-25)

All twelve open questions are now locked. The npm namespace was confirmed by
the user; the remaining eleven defaulted to the recommended path with brief
rationale captured below. Re-open any of these by editing this section and
the corresponding milestone doc together.

1. **Codegen toolchain primary per language (M01).** `typify` (Rust),
   `datamodel-code-generator` (Python, pydantic v2 mode),
   `json-schema-to-typescript` (TypeScript), `oapi-codegen` (Go),
   `kotlinx-serialization` codegen (Kotlin), `Microsoft.Json.Schema.ToDotNet`
   (C#). Picked for spec-coverage breadth and active maintenance.
2. **Continuous-fuzzing path (M02).** OSS-Fuzz primary, ClusterFuzzLite
   bridge running on GitHub Actions until OSS-Fuzz acceptance lands.
   ClusterFuzzLite stays as the permanent fallback. Budget cap: 2,000
   GitHub Actions runner-minutes per month for ClusterFuzzLite.
3. **npm namespace (M08).** `@chio-protocol/*` is the org scope. Do not
   attempt to provision `@chio`. All TS packages publish under the existing
   scope (`@chio-protocol/browser`, `@chio-protocol/workers`,
   `@chio-protocol/edge`, `@chio-protocol/deno`).
4. **Conformance crate publish target (M01).** Publish to crates.io as
   `chio-conformance` at `0.1.0`, ratcheting through `0.x` until the wire
   protocol stabilizes at v1.
5. **C++ peer scenario coverage (M01).** P0: `mcp_core` and `auth`. Defer
   `chio-extensions`, `tasks`, `nested_callbacks`, `notifications` to a
   follow-on milestone once the P0 surface is green.
6. **Apalache vs TLC (M03).** Apalache `0.50.x` primary. TLC available as a
   manual debug target only (no CI lane). Single CI runner image.
7. **`formal/` ownership (M03).** Placeholder file `formal/OWNERS.md` lands
   in M03 Phase 1 with `TBD-primary` / `TBD-backup` slots; assignment is the
   only Wave 1 decision deferred to the user, due before M03 closes (not
   blocking Wave 1 start).
8. **WASM guard registry (M06).** `oci-distribution` crate, already in the
   `sigstore-rs` dependency tree. No new top-level dep.
9. **Provider adapter order (M07).** OpenAI Responses first, Anthropic
   second, Bedrock last. Reflects largest deployment surface descending and
   API-stability ascending.
10. **Replay corpus storage (M10).** In-tree NDJSON under
    `tests/replay/fixtures/` with a 5 MB per-fixture cap. Oversize captures
    land in a separate `chio-tee-corpus` GitHub release artifact that CI
    pulls on demand via sha256 pin.
11. **Demo deployment surface (M08).** GitHub Pages on the same repo, served
    from `docs/demo/`. Framed in copy as engineering output, not a release
    artifact. Cloudflare Pages and Vercel rejected to avoid an external
    service-of-record dependency.
12. **Mutation-testing gate posture (M02).** Advisory for one release cycle,
    blocking thereafter. Cycle counted in releases tagged after the M02
    Phase 3 merge, not in calendar time.

The single remaining unresolved item is decision 7 (`formal/` owner names),
which can be filled in when the user is ready and does not block Wave 1.

## Confidence per milestone

Scores are subjective readiness signals derived from the post-review docs:
how much repo evidence is cited, how concrete the success criteria are, how
large the unknown surface still is, and how many cross-doc dependencies
remain unresolved. Higher is more ready to start.

| # | Title | Confidence (1-10) | Rationale |
|---|-------|--------------------|-----------|
| 01 | Spec/Codegen/Conformance | 9 | Concrete schema and vector counts (19+6 today, target +20 schemas: +16 wire, +4 http; 35 today, target >= 120 vectors). Toolchain primaries named per language. Conformance harness already exists. Open questions are pinning decisions, not unknowns. |
| 02 | Fuzzing Post-PR-13 | 8 | Eleven new targets named with verified entry points and line numbers. PR #13 status is live and the gating dependency. Only the OSS-Fuzz/ClusterFuzzLite pick and CPU budget block phase 1. |
| 03 | Capability Algebra Properties | 8 | Eighteen invariants named, redistributed to where the algebra lives (chio-core-types + chio-kernel-core, not chio-credentials/chio-policy as originally claimed). Apalache version pinned. TLA+ author availability is the remaining risk. |
| 04 | Deterministic Replay | 9 | Family-by-family scenario counts (target ~50). `KernelCheckpoint` and `ReceiptInclusionProof` named. Cross-version matrix scoped to existing tags v0.1.0 and v2.0 with the ratchet starting at v3.0 going forward. |
| 05 | Async Kernel Real | 7 | Hard counts measured (1133 fns, 3 awaits, 27 `&mut self` on Session). Twelve bench paths enumerated. v2.80 prior-art reckoning is honest about what shipped (decomposition + interior-mutability + async signature) vs what did not (the body still delegates to sync). Loom + criterion phases are concrete. The merge-conflict risk on `kernel/mod.rs` is the largest practical blocker; demands a freeze. |
| 06 | WASM Guard Platform | 7 | WIT bump to `chio:guard@0.2.0` plus four-SDK migration train named. `oci-distribution` + `arc_swap::ArcSwap` + canary N=32 + rollback M>=5 are concrete. The `chio:guards/redact@0.1.0` namespace reservation for M10 is now explicit. Sigstore-rs pre-1.0 churn is the main risk. |
| 07 | Provider-Native Adapters | 8 | Three provider crates plus fabric named. API versions pinned (OpenAI 2026-04-25 snapshot, Anthropic 2023-06-01 + computer-use beta, single AWS SDK pin). 36 fixture sessions and 250 ms p99 verdict budget are measurable. NDJSON schema alignment with M10 is now explicit. |
| 08 | Browser/Edge SDK | 8 | Per-runtime wasm-pack tooling decisions made. Per-runtime size budgets recorded. `BROWSER_SUBSET_V1` selector lives in M08 (`sdks/typescript/packages/conformance/src/browser-subset.ts`); M01 owns the corpus and emits `verify_only` tags on receipt/capability cases that the selector reads. Phase 3 (delegated signing) hard-deferred behind a written trust-boundary review with normative guards against root signing in any user-reachable runtime. |
| 09 | Supply-Chain Attestation | 9 | Each phase has a concrete tooling pick (cargo-vet baseline imports four upstream feeds, syft for CycloneDX 1.6, slsa-github-generator pinned tag, cosign keyless). SLSA L2 chosen with L3 explicitly deferred. Reproducible build scoped to one target (`x86_64-unknown-linux-gnu`). |
| 10 | Tee/Replay Harness | 7 | Three modes documented with mode-precedence rules. NDJSON frame schema spelled out with `schema_version`. Exit-code registry (six codes) is owned by M04 and consumed verbatim by M10. Reliance on M06 redactor host call is the largest cross-doc dependency; both sides now agree the namespace is reserved by M06 and the world is shipped by M10. |

### Round-2 readiness

Final cold-reader pass on 2026-04-25 after the parallel Round-2 edit train.
Per-milestone confidence is on the same 1-10 scale as the table above; the
verdict is what a senior engineer who just joined this week would conclude
from reading the doc cold.

| # | Post-R2 confidence | What improved in R2 | Cold-reader verdict |
|---|---|---|---|
| 01 | 9 | Receipt/inclusion-proof schema files (P1.T3) and vector envelope are now cross-doc anchored to M04 and M07. Vector cases gain an optional `verify_only` tag that the M08 selector reads. Header-stamp gate in CI is concrete. | Ready to start. |
| 02 | 8 | `receipt_log_replay` target (P1.T8) and structure-aware mutator (P2.T6) added; budget cap (2,000 GHA min/month) recorded; mutation-testing gate-flip mechanic via `releases.toml` documented. | Ready to start once PR #13 merges. |
| 03 | 8 | Open question #2 (formal/ ownership) and #4 (TLC fallback) reconciled with locked Wave 1 decisions. `formal/OWNERS.md` placeholder is on the Phase 3 task list. Apalache `0.50.x` pin propagated. | Ready to start; user needs to fill `formal/OWNERS.md` slots before M03 closes. |
| 04 | 9 | Cross-version matrix entries (`v0.1.0`, `v2.0`) explicit; ratchet floor `v3.0` documented; `--bless` gate logic spelled out fail-closed; the determinism canary, fuzzer-seed link, and 5MB goldens budget added as P0-blocking exit criteria. | Ready to start. |
| 05 | 7 | Phase task IDs (P0-P4) and per-bench SLOs locked. Freeze-window enforcement triple-witnessed (branch protection + CODEOWNERS + Slack template). Loom interleaving list (8 tests) and rollback storyboard committed. The bench-baseline strategy uses merge-base, not last release. | Ready to start; depends on M03 properties being green and a coordinated freeze on `kernel/mod.rs`. |
| 06 | 7 | WIT 0.2.0 verbatim skeleton committed. `bindgen!` reconciled with M05 (async = true from day one). Hot-reload race fix (per-guard mutex + 5s debounce + monotonic seq) and rollback storyboard with PagerDuty alert routes locked. M10 redactor namespace reservation aligned with M10's `redact-class` flags type. | Ready to start once M09 lands `chio-attest-verify` and M05 has shipped P1.T3. |
| 07 | 8 | `ProviderAdapter` trait surface (M07-owned) verbatim. Phase order locked OpenAI -> Anthropic -> Bedrock. Bedrock IAM principal disambiguation has a concrete TOML schema and STS caching rule. NDJSON capture format aligned with M10. Provenance-stamp signing helper (NEW) tracked. | Ready to start once M01 ships the `ProvenanceStamp` schema; safe to start in parallel with M01 if signatures are frozen day one. |
| 08 | 8 | `web-sdk.yml` workflow locked verbatim with size-budget + cold-start matrix steps. Trust-boundary review template (Phase 3 hard-gated) committed. Demo path on GitHub Pages from `docs/demo/` is the locked target. `BROWSER_SUBSET_V1` ownership clarified: M08 selector, M01 corpus + `verify_only` tag. | Ready to start once M01 Phase 2 vectors freeze and M04 emits at least one stable public-key-only fixture. |
| 09 | 9 | `chio-attest-verify` trait surface verbatim; `verify_blob` / `verify_bytes` / `verify_bundle` are the canonical names consumed by M02 and M06. cargo-vet baseline imports four upstream feeds. SLSA L2 confirmed; L3 deferred. Reproducible build pinned to `x86_64-unknown-linux-gnu`. Quarterly TUF re-bake job (NEW) added. | Ready to start. |
| 10 | 7 | `chio-tee-frame.v1` JSON Schema locked verbatim. Mode-precedence test named (`env_overrides_toml_overrides_manifest`). Bless graduation runbook spelled out with audit-log shape. Three NEW sub-tasks (FIPS smoke, spool backpressure, redaction determinism) sized in. M07-vs-M10 NDJSON shape resolved: M10 owns the canonical schema. | Needs M06 namespace reservation merged before any persistence work begins; otherwise ready. |

### Round-2 reconciliation log

Cross-doc inconsistencies the parallel Round-2 pass introduced (or that
survived from earlier rounds), now resolved on `main`:

1. **`InvocationProvenance` vs `ProvenanceStamp` (M01, M07).** Two names
   for one type. M07's verbatim trait surface defines `ProvenanceStamp`;
   the `InvocationProvenance` reference in M07 line 32 and M01 line 232
   was a leftover from an earlier draft. Both reconciled to
   `ProvenanceStamp` with the M01 row spelling out which fields are
   covered by the wire schema.
2. **Redactor host-call signature (M06, M10).** M06 line 72 had
   `classes: list<string>`; M10 has `classes: redact-class` (a WIT `flags`
   type). M06's cross-doc references section already used the correct
   shape, but the Phase 1 description disagreed. M06 line 72 reconciled
   to `classes: redact-class`.
3. **`bindgen!` async setting (M05, M06).** M05 P1.T3 mandates
   `async fn` host trait from day one; M06 had `async = false` in the
   verbatim Rust skeleton with a "flips later" note. M06 reconciled to
   `async = true` from day one with `#[async_trait::async_trait]` impl;
   the bodies may `await` only `ready()` futures until M05 P1.T3 lands.
4. **`verify_only` vector tag (M01, M08).** M08's "Conformance subset
   definition" expected receipt and capability cases tagged
   `verify_only: true`, but M01's vector field list did not include it.
   M01 success criteria reconciled to define `verify_only: bool`
   (default `false`) on receipt and capability cases.
5. **`BROWSER_SUBSET_V1` ownership claim (README, M01, M08).** README
   claimed "M01 names BROWSER_SUBSET_V1"; in fact M08 owns the selector
   constant in `sdks/typescript/packages/conformance/src/browser-subset.ts`
   and M01 owns the corpus plus the `verify_only` tag. README confidence
   row reconciled.
6. **M03 open questions vs locked Wave 1 decisions.** M03 listed
   "Who owns formal/" and "TLC fallback" as open. README locks both
   (decision 6 and decision 7). M03 reconciled to mark both as locked
   with cross-references.
7. **`ProviderAdapter::lift` parameter naming (M07).** M07 in-scope text
   said `lift(provider_request) -> ToolInvocation`; the verbatim trait
   uses `ProviderRequest` (a typed newtype). Reconciled to the typed
   form so the in-scope description matches the trait surface.

## Strongest Convergence Signals

Four of seven debate lenses (protocol, SDK, security, testing) independently
nominated some form of conformance + canonical-JSON vector work. That made
M01 the unambiguous foundation. Three lenses (protocol, security, testing)
converged on capability algebra properties (M03). Two lenses (security,
testing) converged on fuzzing (M02). Two lenses (protocol, testing)
converged on deterministic replay (M04).

## Single-Lens Picks Retained on Code Evidence

Three milestones come from a single lens but were retained because the lens
backed them with concrete repo-level findings:

- **M05 (async kernel)**: 0 async fns, 0 awaits in `crates/chio-kernel/src/lib.rs`; 3 async fns out of 1133 in `crates/chio-kernel/src/`; 27 `&mut self` methods on the session state machine; 10 `std::sync` primitives on `ChioKernel`. v2.80's decomposition (303-04), interior-mutability wrappers (305-01), and async signature flip (305-02) shipped; the body of `evaluate_tool_call` still delegates to `evaluate_tool_call_sync_with_session_roots`. The concurrency half is what M05 closes.
- **M06 (WASM guard platform)**: `wit/chio-guard/world.wit` still pins `chio:guard@0.1.0` with only `evaluate` exported; host imports remain raw `Linker::func_wrap` calls in `host.rs` at lines 110/159/221; no registry, no hot-reload, no per-guard observability.
- **M09 (supply-chain)**: `deny.toml` is a stub; binary releases ship only sha256 manifests; no cargo-vet, cargo-auditable, syft, grype, cosign, or SLSA. SLSA L2 chosen; L3 deferred to a v5+ dedicated builder.

## Picks Deliberately Cut

The debate surfaced more than ten candidates. The following were considered
and excluded with reason:

- **IETF draft maturation, LTS schema compatibility matrix** (protocol lens, self-rated cuttable): high cost, low near-term leverage; defer until v5 spec stabilizes.
- **HW-accelerated crypto, memory budget audit** (perf lens, self-rated cuttable): premature given current bottleneck analysis.
- **HSM and post-quantum signing** (security lens): trait-level agility folds into M01 wire-versioning work; backends slip.
- **M365 / Salesforce / Slack / Discord bridges** (integrations lens, self-rated cuttable): no named pilot.
- **Standalone OpenTelemetry GenAI adapter** (integrations lens): folded into M10.
- **External guards over WASI HTTP, tool servers as WASM** (WASM lens, self-rated cuttable): defer until M06 platform matures.
- **JVM Spring Boot starter, dedicated docs site** (SDK lens, self-rated cuttable): high value, defer.
- **SQLite store sharding** (perf lens): defer until M05 changes the picture.

## Relationship to GSD Planning

This trajectory directory is intentionally separate from
`.planning/milestones/` and `.planning/phases/`. Each entry here is a
candidate milestone, not a committed one. To promote a candidate into the
roadmap, run the standard GSD flow:

1. `gsd:new-milestone` to declare and seed PROJECT.md / STATE.md
2. `gsd:plan-phase` per phase listed in the candidate's phase breakdown
3. `gsd:execute-phase` to ship

The phase breakdowns in each milestone doc are sized to map roughly one-to-
one onto GSD phases. Success criteria are written to be Nyquist-checkable
post-execution.

## Source Material

- Seven-agent debate transcripts in this conversation; see synthesis in the
  triggering session.
- Recon evidence cited inline in each milestone doc (file paths, line counts,
  function counts, existing artifacts), validated by a parallel reviewer
  pass on 2026-04-25.
- Existing planning state: `.planning/PROJECT.md`, `.planning/STATE.md`,
  `.planning/MILESTONES.md`, `.planning/ROADMAP.md`,
  `.planning/codebase/CONCERNS.md`.
- House rules: project `CLAUDE.md` and `AGENTS.md` (no em dashes,
  fail-closed, conventional commits, clippy `unwrap_used = "deny"`).
