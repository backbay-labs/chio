# RESEARCH-M08: Corpus and Framework Integration Pre-Flight

Milestone: M08, chio-arena replay coliseum
Role: Layer-1 researcher coordinator
Date: 2026-04-30
Mode: planning research only. No implementation commits, no protected-path edits.

## Executive Summary

M08 should start as a generator and replay consumer, not as a new verifier. The lowest-risk path is to make `crates/chio-arena/` emit existing M04-shaped receipt bundles through `chio_replay_corpus::write_m04_fixture`, drive real `Arc<ChioKernel>` instances through the async `evaluate_tool_call` surface, and use the M02 verdict matrix as the semantic oracle once M02 finishes the corpus and diff-oracle tickets.

Current readiness is mixed:

- The replay writer exists at `crates/chio-replay-corpus/src/m04_writer.rs` with `M04Scenario`, `write_m04_fixture`, and fixed filenames `receipts.ndjson`, `checkpoint.json`, and `root.hex`.
- The replay corpus has 50 source fixtures under `tests/replay/fixtures/` across 10 families. There is no `tests/replay/fixtures/arena/` namespace yet.
- `tests/replay/goldens/` has 50 golden scenario leaf directories matching the 50 replay fixtures. Arena promotion must not bypass the existing golden byte-equivalence flow.
- `crates/chio-conformance/verdict_matrix/` exists, but it is only the M02.P4.T1 scaffold. Its `manifest.toml` reports `scenario_count = 0`, and the M02 tickets still have corpus genesis, Rust driver, diff oracle, CI, cross-language drivers, and hash pinning pending.
- `crates/chio-adversarial-suite/` does not exist yet. M08.P5.T2 should not assume M05.P0 creates it. The actual scaffold ticket is M05.P1.T1.
- `fuzz/artifacts/` exists but currently has zero files. The existing seed material is under `fuzz/corpus/`, so M08.P4.T4 needs a deliberate decision: either honor the narrative literally and tolerate an empty `fuzz/artifacts/`, or extend the loader to read `fuzz/corpus/` as the live seed corpus with hashes recorded in `arena.json`.
- `toml = "0.8"` already exists as a direct dependency in `tests/replay/Cargo.toml` and `crates/chio-conformance/Cargo.toml`, but not in root `[workspace.dependencies]`. Root already pins `tokio`, `proptest`, and `arc-swap`; root does not currently pin `rand` or `rand_chacha`.

## Canonical Inputs Read

- `.planning/trajectory-2/EXECUTION-STATE.json`: M08 status is `ticket files authored`, phase `ready_for_p0`, Wave 3.
- `.planning/trajectory-2/EXECUTION-BOARD.md`: M08 is Wave 3 breadth work, parallel with M07; cross-milestone ownership names scenario DSL and arena bundles as M08-owned and M02/M05/M09 as consumers.
- `.planning/trajectory-2/AUTONOMOUS-PROMPT.md`: execution rules require reading canonical refs, preserving trajectory-2 planning as load-bearing, and using the one-liner gate before declaring changes ready.
- `.planning/trajectory-2/tickets/manifest.yml` and `.planning/trajectory-2/tickets/M08/*.yml`: M08 has 34 pending tickets from P0 through P5.
- `.planning/trajectory-2/08-chio-arena-replay-coliseum.md`: source-of-truth narrative for arena scope, risks, and success criteria.
- `CHANGELOG.md`: current user-facing change note is the `chio-kernel` `legacy-sync` default removal, relevant because M08 should use async `evaluate_tool_call`.
- `CLAUDE.md` and `AGENTS.md`: Chio house rules, no em dashes, fail-closed, canonical JSON, clippy denies unwrap/expect.

## Current Repo Evidence

Replay corpus and writer:

- `crates/chio-replay-corpus/src/m04_writer.rs` validates a `<family>/<name>` suffix, enforces exact M04 shape, dedupes with last-wins canonical invocation semantics, writes canonical receipts, writes `checkpoint.json`, and computes `root.hex`.
- `crates/chio-replay-corpus/tests/e2e_bless_to_replay_gate.rs` covers the bless-to-gate shape.
- `tests/replay/goldens/` contains 50 golden scenario directories that pair with the replay fixture corpus.
- Existing replay-gate tests relevant to M08 are `tests/replay/tests/corpus_smoke.rs`, `tests/replay/tests/golden_byte_equivalence.rs`, `tests/replay/tests/cross_version_replay.rs`, and `tests/replay/tests/rebless_corpus.rs`.
- Existing CLI replay tests relevant to M08 are `crates/chio-cli/tests/replay.rs` and `crates/chio-cli/tests/replay_traffic.rs`.
- `tests/replay/fixtures/` contains 50 JSON fixtures:
  - `allow_simple`: 8
  - `allow_metered`: 5
  - `allow_with_delegation`: 6
  - `deny_expired`: 5
  - `deny_revoked`: 4
  - `deny_scope_mismatch`: 6
  - `guard_rewrite`: 6
  - `replay_attack`: 4
  - `tampered_canonical_json`: 3
  - `tampered_signature`: 3
- `tests/replay/fixtures/arena/` is absent. D20 reserves it for M08 auto-promotions.

Replay bless and drift gates:

- `tests/replay/src/bless.rs` implements the CHIO_BLESS gate. It denies in CI, requires `CHIO_BLESS=1`, requires non-empty `BLESS_REASON`, requires a TTY, rejects forbidden branches, and enforces audit-log/goldens lockstep.
- `.github/workflows/chio-replay-gate.yml` pins `LC_ALL=C`, `LANG=C`, `CHIO_BLESS=0`, and `CARGO_INCREMENTAL=0`, and includes a seed-immutability job for `tests/replay/test-key.seed`.
- `docs/replay-cli.md` documents the `capture -> redact -> dedupe -> review -> bless` path and the M04 fixture layout.
- `crates/chio-cli/src/cli/dispatch.rs` already routes `Commands::Replay(args)` to `cmd_replay(&args)`, and `crates/chio-cli/src/cli/replay.rs` delegates bless mode to `cmd_replay_bless`.

Kernel and runtime surfaces:

- `crates/chio-kernel/src/kernel/mod.rs` exposes `pub async fn evaluate_tool_call(&self, ...)`. The public blocking API is gated behind `legacy-sync`, while a crate-private shim remains for internal sync paths.
- `crates/chio-kernel/src/kernel/tests/all.rs` includes an async shared-kernel test using `Arc<ChioKernel>` and two spawned `evaluate_tool_call` calls.
- `crates/chio-kernel/tests/receipt_signing_async.rs` signs many receipts through one `Arc<ChioKernel>` via the async channel path.
- `crates/chio-tower/src/kernel_service.rs` is a concrete example of a shared `Arc<ChioKernel>` wrapper that calls `evaluate_tool_call().await`.
- `crates/chio-tower/tests/axum_integration.rs` is the current Rust framework integration proof for HTTP-style request wrapping.

Verdict and conformance surfaces:

- `crates/chio-provider-conformance/tests/cross_provider_equality.rs` normalizes three provider fixtures and asserts canonical JSON byte equality over normalized receipts and verdicts.
- `crates/chio-provider-conformance/src/assertions.rs` exposes `assert_canonical_bytes_eq`, `assert_canonical_json_eq`, and `assert_verdict_eq`.
- `crates/chio-conformance/verdict_matrix/SCENARIOS.md` defines the cross-SDK scenario schema as `chio.verdict-matrix.scenario.v1`.
- `crates/chio-conformance/verdict_matrix/manifest.toml` currently has `status = "scaffold"` and `scenario_count = 0`.
- `crates/chio-conformance/verdict_matrix/src/lib.rs` currently only has schema constants plus `Verdict`, `ScenarioCategory`, and `VerdictTuple`.

Framework and SDK integration surfaces:

- M07 is the framework owner, not M08. M07 owns `sdks/typescript/packages/chio-ai-sdk-middleware/**`, `sdks/typescript/packages/chio-next/**`, TS templates, provider adapters, and new verdict-matrix deployment drivers.
- Existing framework or deployment surfaces include:
  - `sdks/typescript/packages/express/`
  - `sdks/typescript/packages/fastify/`
  - `sdks/typescript/packages/node-http/`
  - `sdks/typescript/packages/browser/`
  - `sdks/typescript/packages/edge/`
  - `sdks/typescript/packages/workers/`
  - `sdks/typescript/packages/ai-sdk/`
  - `sdks/jvm/chio-sdk-jvm/`
  - `sdks/jvm/chio-spring-boot/`
  - `sdks/jvm/chio-streaming-flink/`
  - `sdks/dotnet/ChioMiddleware/`
  - `sdks/lambda/chio-lambda-extension/`
  - `sdks/k8s/controller/`
  - `packages/sdk/chio-drogon/`
- M07.P1 plans AI SDK and Next drivers into the M02 verdict matrix. M07.P6 plans JVM, dotnet, Lambda, and k8s deployment-shape drivers. M08 should consume those through M02's manifest rather than creating its own framework registry.

## Corpus Design Recommendation

Use three corpus layers with explicit ownership and promotion edges:

1. Arena scenario corpus, owned by M08:
   - Path: `arena/scenarios/`
   - Format: TOML DSL with schema name `chio.arena.scenario/v1`
   - Purpose: simulation inputs, deterministic witness, agent population, adversary blocks, virtual clock, RNG seed, and references to recorded prompts or fixture material.
   - Gate: parser rejects unknown major schema versions, missing required witness fields, wall-clock dependencies, provider SDK names, and inline secrets.

2. Arena emitted receipt bundles, owned by M08 but M04-shaped:
   - Output path during runs: `target/arena/<scenario-id>/`
   - Promotion path: `tests/replay/fixtures/arena/<class>/<hash>/`
   - Files: `receipts.ndjson`, `checkpoint.json`, `root.hex`, plus sibling `arena.json`
   - Writer: delegate receipt shape to `chio_replay_corpus::write_m04_fixture`; do not reimplement receipt signing, canonical JSON, redaction, or root recompute.
   - Manifest: `arena.json` records `scenario_id`, schema version, scenario file hash, RNG seed, virtual clock start, adversary class, source corpus hashes, verdict tuple, and M02 verdict-matrix driver set used.

3. Curated adversarial suite, owned by M05:
   - Path: `crates/chio-adversarial-suite/cases/<class>/<sha>.json`
   - Format from D13: `{ class, expected_verdict, expected_reason }` envelope, with M05 narrative also requiring threat IDs and pending triage state.
   - M08 role: producer only. Write promotion candidates after M05.P1.T1 creates the schema, and treat M05's schema as authoritative.

This split keeps generated arena data out of the curated 50-fixture M04 families, gives M08 a deterministic local output path, and leaves curation authority with M05.

## Framework Integration Recommendation

M08 should not add framework-specific adapters. Its integration contract should be "any driver registered in the M02 verdict matrix can evaluate an arena scenario projection and return the canonical verdict tuple." That keeps M08 provider-agnostic and avoids racing M07.

Recommended pre-flight contract:

- M08 scenario DSL references framework or SDK surfaces by stable driver IDs from `crates/chio-conformance/verdict_matrix/manifest.toml`, not by package path or concrete SDK import.
- `crates/chio-arena/src/leaderboard.rs` and `coevolve.rs` call the M02 diff oracle once it lands, comparing `(verdict, reason_code, scope_set)` only.
- M08 does not import provider crates or M07 framework packages. The P0.T3 grep against provider crates should expand to also reject direct imports of M07 package internals unless M02 exposes them as drivers.
- M07 owns drift against Vercel AI SDK, Next, JVM, dotnet, Lambda, and k8s. M08 only consumes the hash-pinned manifest and fails closed if a configured driver is missing or marked unsupported.

Likely driver IDs to leave room for, based on M02 and M07 tickets:

- `rust-kernel`
- `python`
- `typescript-node-http`
- `wasm-browser`
- `go`
- `typescript-ai-sdk-middleware`
- `typescript-chio-next`
- `jvm`
- `dotnet`
- `lambda`
- `k8s`

## Fixture Ownership

Primary owners:

- M08 owns:
  - `crates/chio-arena/**`
  - `arena/scenarios/**`
  - `tests/replay/fixtures/arena/**`
  - `crates/chio-cli/src/cli/arena.rs`
- M02 owns:
  - `crates/chio-conformance/verdict_matrix/**`
  - hash-pinned scenario manifest and diff-oracle semantics
- M05 owns:
  - `crates/chio-adversarial-suite/**`
  - adversarial case schema, case curation, and threat-model coverage
- M04 replay tooling owns:
  - M04-shaped receipt bundle semantics
  - CHIO_BLESS rules and replay-gate semantics
- M07 owns:
  - framework and provider adapters that register into the verdict matrix
- M09 consumes:
  - `target/arena/leaderboard.json` through reputation, but should not own M08 output schema.

Do not let M08 write into the top-level curated M04 families such as `replay_attack` or `tampered_signature`. D20 reserves `tests/replay/fixtures/arena/` as the arena namespace.

## Drift Gates to Add or Tighten

P0/P1 gates:

- Add a pre-flight audit row that records the live counts above: 50 replay fixtures, 50 replay goldens, no arena fixture namespace, M02 verdict matrix scaffold with zero scenarios, missing M05 adversarial suite, empty `fuzz/artifacts/`, and live `fuzz/corpus/` count.
- In `crates/chio-arena/Cargo.toml`, reject provider crates and direct M07 framework packages. M08 should depend on core/kernel/replay/conformance surfaces, not app frameworks.
- Add schema-name tests for `arena/scenarios/SCHEMA.md` and `arena/scenarios/schema.json`.
- In parser tests, fail closed on unknown top-level fields except `[ext]`, unknown major schema versions, missing `rng_seed`, missing `virtual_clock_start`, and inline secret-shaped values.

Determinism gates:

- Use BTreeMap or sorted Vec for any map that can affect emitted bytes.
- Ban `SystemTime::now` and direct `Instant::now()` in arena runtime modules except in bounded-budget telemetry that is excluded from receipt bytes.
- Pin `LC_ALL=C`, `LANG=C`, `CARGO_INCREMENTAL=0`, and Linux-only execution in `chio-arena-determinism.yml`.
- Assert two runs of the same scenario produce byte-identical `receipts.ndjson`, `checkpoint.json`, `root.hex`, and `arena.json` except for fields explicitly declared non-deterministic. Prefer declaring no non-deterministic fields.

Corpus drift gates:

- Hash every seed input in `arena.json`, including `fuzz/corpus/**`, `fuzz/artifacts/**`, and replay fixture files consumed by P4.T4.
- Fail closed when a referenced fixture path is absent, unless the scenario explicitly marks that source optional with a reason.
- Keep `tests/replay/fixtures/arena/**` under a separate size budget from the curated M04 set, as D20 requires.
- Use CHIO_BLESS only from local operator flows. CI must never promote fixtures.

Framework drift gates:

- Treat `crates/chio-conformance/verdict_matrix/manifest.toml` as the only driver registry.
- Require each arena run that asks for framework parity to record the manifest hash and required driver IDs.
- If a driver reports `unsupported`, the arena run should record `unsupported` and exclude it from survival-rate scoring unless the scenario declares it required. Required unsupported drivers fail the run.
- M08 should not bypass M02 by calling `crates/chio-provider-conformance` directly once the M02 diff oracle exists. Until then, P1/P2 should stay Rust-kernel-only.

Promotion gates:

- `BLESS_REASON` should be `arena:<scenario-id>` for M04 promotion.
- Promotion to M05 should wait for `crates/chio-adversarial-suite/schema/case.schema.json`, not merely M05.P0.
- Promotion should cap files per PR and require an audit entry with source scenario hash, root hash, and reason tuple.

## Likely P0 Ignition Points

1. M08.P0.T1 audit doc should be more than a placeholder.
   - Include live counts and blockers from this research.
   - Explicitly record that `crates/chio-adversarial-suite/` and `tests/replay/fixtures/arena/` are absent.
   - Explicitly record that the M02 verdict matrix exists but has zero scenarios.

2. M08.P0.T2 lock bump is low risk but should serialize with any W1/W2 lock churn.
   - `Cargo.lock` is a shared path.
   - The M08 dependencies should remain `toml`, `rand`, and `rand_chacha`; avoid pulling provider SDKs through convenience features.
   - `toml = "0.8"` exists in non-root crates today, so the root workspace pin may be a manifest-only normalization plus lock reconciliation. `rand` and `rand_chacha` are new root pins.

3. M08.P0.T3 should harden the anti-pattern grep.
   - Current ticket rejects selected provider crates.
   - Add a stronger local check for no direct dependencies on `sdks/typescript/**`, `packages/sdk/**`, or concrete provider adapters.
   - Ensure `.github/CODEOWNERS` or generated ownership includes `crates/chio-arena/Cargo.toml`.

4. Planning inconsistency to fix before P5 work:
   - M08 P5 text says "M05.P0 chio-adversarial-suite scaffold".
   - Actual M05 scaffold is M05.P1.T1. M05.P0 only pins dependencies.
   - M08.P5.T2 should gate on M05.P1.T1 for schema availability, and likely M05.P2.T4 if it needs `manifest.json`.

## Likely P1 Ignition Points

1. Scenario DSL must not drift from verdict-matrix schema.
   - M08 scenario DSL is richer than M02's scenario schema. Keep it as a generator schema, then project into M02's `(verdict, reason_code, scope_set)` comparison input.
   - Do not make M02 parse M08 TOML directly in P1.

2. The receipt-bundle writer should be a thin adapter.
   - P1.T5 should accept arena frames and call `write_m04_fixture`.
   - If arena frames do not naturally fit `chio_tee_frame::Frame`, make the adapter explicit and test it. Do not clone M04 writer logic.

3. The async kernel surface is usable but not fully async internally.
   - `evaluate_tool_call` currently delegates through `BlockingToolEvaluator`.
   - M08 can still drive `Arc<ChioKernel>` concurrently, but P1/P2 tests should catch deadlock and byte drift rather than assuming full non-blocking internals.

4. The single-agent walking skeleton should start Rust-only.
   - Framework parity is M07/M02 dependent.
   - First end-to-end proof should be scenario load -> one kernel -> M04-shaped bundle -> `chio replay` compatibility.
   - Best nearby replay contracts are `tests/replay/tests/golden_byte_equivalence.rs` and `crates/chio-cli/tests/replay.rs`; use them as shape references rather than adding a second replay verifier.

5. Link naming must follow D19.
   - Use `crates/chio-arena/src/link/`.
   - Do not touch top-level `crates/chio-link/`, which is price-oracle integration.

## Open Questions for Root or Sequencer

1. Should M08.P4.T4 read `fuzz/corpus/` in addition to `fuzz/artifacts/`? Live repo state has an empty `fuzz/artifacts/` but 136 files under `fuzz/corpus/`.
2. Should M08.P5.T2 be amended now to depend on M05.P1.T1 or M05.P2.T4 instead of the narrative's M05.P0 wording?
3. Should the M08.P0.T3 dependency-deny grep include direct framework packages as well as provider crates?

## Suggested Pre-Flight Commands

Run these before opening M08 P0:

```bash
git status --short
git log -1 --format='%H %cr %s'
test -f crates/chio-replay-corpus/src/m04_writer.rs
find tests/replay/fixtures -mindepth 2 -maxdepth 2 -name '*.json' | wc -l
find tests/replay/goldens -mindepth 2 -maxdepth 2 -type d | wc -l
test ! -e tests/replay/fixtures/arena
test -f crates/chio-conformance/verdict_matrix/manifest.toml
grep -q 'scenario_count = 0' crates/chio-conformance/verdict_matrix/manifest.toml
test ! -e crates/chio-adversarial-suite
find fuzz/artifacts -type f | wc -l
find fuzz/corpus -type f | wc -l
```

Focused tests to keep near the P0/P1 plan:

```bash
cargo test -p chio-replay-corpus --test e2e_bless_to_replay_gate
cargo test -p chio-replay-gate --test corpus_smoke
cargo test -p chio-replay-gate --test golden_byte_equivalence
cargo test -p chio-replay-gate --test cross_version_replay
cargo test -p chio-cli --test replay
cargo test -p chio-cli --test replay_traffic
cargo test -p chio-provider-conformance --test cross_provider_equality --features fixtures-openai,fixtures-anthropic,fixtures-bedrock
cargo test -p chio-kernel --test receipt_signing_async
cargo test -p chio-tower --test axum_integration
```

The provider-conformance test is feature-gated and may need recorded fixture features only. It should be treated as an oracle reference, not as a required P1 gate for M08.
