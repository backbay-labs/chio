# Milestone 08: chio-arena - Adversarial Replay Coliseum

## Lens

Single lens: simulation and adversarial corpus generation. The arena is a
deterministic multi-agent simulator that exercises real `chio-kernel`
instances against co-evolving adversaries and emits receipt bundles
indistinguishable from a real run. Every other axis (perf, DX, reputation
weighting, marketplace pricing) is downstream of this asset; the milestone
holds itself to the narrow question "does the same scenario produce the same
verdict, the same receipt bytes, and the same anchored root every time, on
every machine that runs it?". If a debate about the lens widens (for example,
"should the arena double as a perf rig?"), the milestone is too big.

## Why this is on the trajectory

Three trajectory-1 deliverables converge to make this milestone possible and
none earlier:

- trajectory-1 M04 (`.planning/trajectory/04-deterministic-replay.md`) shipped
  the bit-exact replay corpus, the `chio replay` CLI subcommand, the
  CHIO_BLESS gate, the determinism canary, the cross-version compatibility
  matrix, and the `chio-replay-gate` CI job. The arena emits scenario
  bundles in exactly the format M04 already gates: per-scenario directory
  with `receipts.ndjson`, `checkpoint.json`, `root.hex`. M08 is a generator
  whose output is M04-graduable.
- trajectory-1 M05 (`.planning/trajectory/05-async-kernel-real.md`) removed
  the `&mut self` lock on `ChioKernel` and migrated `evaluate_tool_call` to
  a real async body backed by `Arc<ChioKernel>`. Multi-agent simulation
  inside one process is now structurally viable: many agents share one
  kernel via `Arc` clones, or each agent gets its own kernel and they
  exchange tool calls in-process.
- trajectory-1 M07.P4.T6 (cross-provider verdict equality) codified the
  reason-code taxonomy and the diff oracle the arena uses as the referee
  for "all kernels agree on the verdict for this scenario". The arena does
  not invent a verdict comparator; it consumes the M07 oracle.

Two pieces of trajectory-2 are also pulled into the trajectory:

- trajectory-2 M02 (`02-mutation-and-cross-sdk-differential.md`) lands the
  `verdict_matrix/` harness and a hash-pinned scenario manifest. The arena
  feeds new scenarios into that manifest via the same `--bless` path M04
  defined.
- trajectory-2 M05 (`chio-adversarial-suite`) consumes auto-promoted arena
  failures as one input feed; the arena is the upstream generator and M05
  is the downstream regression net. The two milestones are explicitly
  separated so the suite is curated, not just whatever the latest arena
  run happened to find.

## Prior-art reckoning

What trajectory-1 already shipped that overlaps with this milestone:

- **M04 deterministic replay**: shipped at `crates/chio-replay-corpus/`
  (audit, dedupe, m04_writer, reredact modules) and `tests/replay/`
  (50-fixture corpus, goldens, keys, `release_compat_matrix.toml`).
  Preserved. The arena does not reimplement the goldens reader, the bless
  gate, or the determinism canary; it produces inputs that those existing
  systems already accept.
- **M05 async kernel**: shipped. Preserved. The arena's parallel kernel
  multiplexer wraps `Arc<ChioKernel>` instances directly. No new lock
  inversion. No new `*_blocking` shim. Multi-agent runtime is a thin layer
  above the M05 kernel surface, not a parallel rewrite.
- **M07.P4.T6 cross-provider verdict equality oracle**: shipped at
  `crates/chio-provider-conformance/`. Preserved as the verdict referee.
  The arena reuses the diff implementation; it does not fork.
- **`tests/replay/test-key.seed`**: the deterministic Ed25519 seed. Reused.
  The arena uses the same seed for parity with the M04 gate; production
  signers explicitly refuse it.
- **`crates/chio-replay-corpus/src/m04_writer.rs`**: `M04Scenario`,
  `write_m04_fixture`, `RECEIPTS_FILENAME`, `CHECKPOINT_FILENAME`,
  `ROOT_FILENAME` constants. Reused as the arena's receipt-bundle writer.
  The arena adds a sibling `manifest.json` describing the scenario
  population and adversary pool, but the receipt bundle layout is byte-for-
  byte M04.
- **trajectory-1 M02 fuzz crashes** (under `fuzz/artifacts/`): seed corpus
  for the arena's adversary populations. Not modified; the arena reads them
  to seed Phase 4 co-evolution.

What is *changed* (not preserved):

- The verdict oracle becomes a *cross-(SDK x kernel-instance)* surface
  inside one process, not just *cross-provider*. The M07.P4.T6 diff
  implementation works as-is; the arena calls it once per scenario step
  with N kernel verdicts in the witness set, where M07 calls it with N
  provider verdicts.
- The M04 bless flow gains one new reason for graduation: "auto-promoted
  from a failing arena scenario". The CHIO_BLESS gate is unchanged; the
  arena writes `BLESS_REASON=arena:<scenario-id>` and the audit log
  captures the arena run id. CI still cannot bless (the `CI=true` and TTY
  rules from M04 stand).

This milestone does NOT re-attack a v3.18-style bounded retreat. It is
greenfield work that compounds across earlier milestones.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses; update the date and numbers on
re-run.

- `crates/chio-arena/`: not present today. Genesis crate. (`test -d
  crates/chio-arena || echo MISSING`)
- `crates/chio-replay-corpus/src/m04_writer.rs`: present, with
  `M04Scenario`, `write_m04_fixture`, the three filename constants
  (`receipts.ndjson`, `checkpoint.json`, `root.hex`), `M04ByteSizes`
  summary type. Reused by the arena. (`grep -c 'pub fn write_m04_fixture'
  crates/chio-replay-corpus/src/m04_writer.rs`)
- `crates/chio-kernel/src/kernel/mod.rs` line count: 5800+ as of M05 close;
  the arena does not edit this file. (`wc -l
  crates/chio-kernel/src/kernel/mod.rs`)
- `crates/chio-cli/src/cli/dispatch.rs`: 2326 lines today. The arena adds
  one `Arena` variant to the `Commands` enum; it does not refactor
  `dispatch.rs`. M01 (trajectory-2) owns the larger refactor of this file.
  (`wc -l crates/chio-cli/src/cli/dispatch.rs`)
- `tests/replay/fixtures/`: 50 named scenarios across 10 families today.
  Arena auto-promoted scenarios land under `tests/replay/fixtures/arena/`
  in their own family namespace, never co-mingled with the curated 50.
  (`ls tests/replay/fixtures/`)
- `fuzz/artifacts/`: present today; trajectory-1 M02 dropped libFuzzer
  crash artifacts here. The arena's Phase 4 co-evolution loop seeds from
  this directory. (`ls fuzz/artifacts/ | wc -l`)
- `crates/chio-conformance/verdict_matrix/` (trajectory-2 M02): not
  present at the start of trajectory-2 but lands in M02 P4. The arena
  consumes this as an unblocked dependency; M08 worktrees open after M02
  P4 is green. (`test -d crates/chio-conformance/verdict_matrix || echo
  PENDING_M02`)
- `crates/chio-link/`: present, but the existing crate is the Chainlink
  / Pyth oracle integration (price feeds), NOT the in-process kernel
  multiplexer named in the M08 brief. The arena uses an in-process kernel
  multiplexer that lives at `crates/chio-arena/src/link/` (a submodule of
  the new crate), not in the existing `chio-link` crate. The brief's "real
  `chio-kernel` instances over in-process `chio-link`" is interpreted as
  "real `chio-kernel` instances over an in-process channel link" and the
  channel link lives in `chio-arena`. (`grep -l 'oracle' crates/chio-link/
  src/lib.rs`)

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` today (do not
re-pin):

- `tokio = { version = "1", features = ["full"] }` (trajectory-1 root pin)
- `serde`, `serde_json`, `thiserror`, `tracing` (workspace pins)
- `proptest = "1.10"` (trajectory-1 M03 + M04 pin)

Not pinned anywhere; this milestone adds them and pins versions on the day
work opens (re-check crates.io for then-current latest patch on Wave-3 open
day):

- `toml = "0.8"` for the scenario DSL parser. The DSL is TOML by spec
  (operator-readable, diffable, idiomatic for Cargo-adjacent projects).
- `rand = "0.8"` plus `rand_chacha = "0.3"` for the seeded RNG. Chacha20
  is the deterministic PRNG; the seed is part of the scenario manifest.
  Per-scenario PRNG state is part of the determinism witness.
- `quanta` or `tokio::time` virtual clock - prefer `tokio::time::pause()`
  plus a `MockInstant` driven by the scenario's virtual clock; no new
  third-party clock crate. (rationale: tokio's testing time machinery is
  already in the workspace's default tokio feature set.)
- `arc-swap = "1"` (already added by trajectory-1 M05) for the leaderboard
  store. Reuse; do not re-pin.

The arena does NOT pin any LLM-provider SDK at the workspace level. It is
provider-agnostic by construction. The M07 (trajectory-2) provider fabric
is the only place provider crates get pinned; the arena consumes that
surface through trait objects, never through concrete provider crates.

## Scope

In:

- New crate at `crates/chio-arena/` (~3-5 kLOC). Modules:
  - `src/lib.rs`: re-exports.
  - `src/scenario.rs`: scenario DSL parser, schema validation,
    determinism-witness extraction.
  - `src/runtime.rs`: scenario runtime, agent population, virtual clock,
    seeded RNG, deterministic scheduler.
  - `src/link/mod.rs`: in-process kernel multiplexer (channel-backed
    transport between agents). NOT the existing `crates/chio-link/`
    oracle crate; the name is overloaded but the surfaces are disjoint.
  - `src/adversary/mod.rs`: adversary population trait + per-class
    implementations.
  - `src/coevolve.rs`: genetic-algorithm-shaped co-evolution loop.
  - `src/promote.rs`: auto-promotion to M04 fixtures and trajectory-2
    M05 `chio-adversarial-suite`.
  - `src/leaderboard.rs`: guard survival-rate ranking.
- Scenario DSL TOML schema documented at `arena/scenarios/SCHEMA.md` with
  a JSON-schema export at `arena/scenarios/schema.json` for editor
  tooling. The scenario carries: agent population (roles, models, seed
  prompts via reference, never inline secrets), capability budgets and
  guard sets (capability tokens issued with deterministic seeds),
  adversary populations (one block per class), determinism witness
  (virtual time start, RNG seed, fixed clock).
- Reference scenario corpus at `arena/scenarios/` with one scenario per
  adversary class plus three multi-agent reference scenarios (single-agent
  walking skeleton, two-agent tool-call exchange, three-agent triangular
  delegation).
- `arc arena run scenarios/<name>.toml` and `arc arena replay
  <scenario-id>` CLI subcommands on `chio-cli`. Both routed through the
  existing `Commands` enum at `crates/chio-cli/src/cli/dispatch.rs`. The
  replay subcommand delegates to the M04 `chio replay` engine; it does not
  reimplement signature verification or root recomputation.
- `arena run` writes a receipt bundle byte-compatible with the M04
  `tests/replay/goldens/` layout (`receipts.ndjson`, `checkpoint.json`,
  `root.hex`) under `target/arena/<scenario-id>/` plus a sibling
  `arena.json` manifest describing the scenario population and adversary
  pool. Bit-exact replay via `chio replay target/arena/<scenario-id>/`
  using the existing M04 engine.
- Co-evolution loop with a fitness function = adversary survival rate
  against the deployed guard pool. Genetic operators: mutation (single-
  field perturbation under DSL-aware mutators) and crossover (two-parent
  scenario splice). Seed corpus pulled from `fuzz/artifacts/` plus the
  M04 `replay_attack` and `tampered_*` fixture families.
- Failing scenarios auto-promote to two destinations:
  1. trajectory-1 M04 vector corpus (`tests/replay/fixtures/arena/<class>/
     <hash>.json`) via the existing CHIO_BLESS gate.
  2. trajectory-2 M05 `chio-adversarial-suite` corpus (one JSON file per
     attack class).
- Leaderboard of guards by adversary-survival rate. Output: a Markdown
  table at `target/arena/leaderboard.md` per run plus a stable-schema JSON
  at `target/arena/leaderboard.json`. The leaderboard's verdict oracle is
  the trajectory-1 M07.P4.T6 cross-provider verdict equality check.
- Determinism gate: every arena run is bit-exact replayable. CI job
  `chio-arena-determinism` runs three reference scenarios twice on a
  clean checkout and asserts byte equality on the emitted receipt
  bundles. Gates on Linux only (per M04 platform-pinning).
- Adversary classes (one ticket per class in P3): prompt-injection,
  capability-overrequest, replay attempt, scope-superset escape.

Out:

- `chio-mesh` / consensus-over-receipts. Wildcard V07 is explicitly out
  of scope for trajectory-2 (per `README.md` decision 4). The arena does
  NOT consensus; it produces deterministic outputs that any number of
  parties can independently reproduce.
- ZK proofs (`chio-zk-verify`). Wildcard V02 is explicitly out of scope
  for trajectory-2.
- Concrete LLM-provider integration. The arena is provider-agnostic. Any
  scenario reference to a "model" is a string handle; the actual provider
  fabric is the trajectory-2 M07 adoption beachhead pack. M08 consumes
  M07's provider trait surface and never imports a provider SDK directly.
- Live-agent loops. The arena is offline by construction: every agent
  output is either a deterministic stub (test agents) or a recorded
  fixture replayed from disk (recorded-provider agents). Wall-clock
  network calls are forbidden inside a scenario.
- Cross-process kernel sharding. Single-process simulation only. M05's
  out-of-scope clause carries forward.
- Reputation weighting. Reputation lives in trajectory-2 M09. The arena
  emits leaderboard data; M09 consumes it.
- New receipt fields or schema changes. The M04 `tests/replay/goldens/`
  format is frozen by trajectory-1; arena outputs conform.
- Mutation testing of the arena crate itself. The arena is not a trust
  boundary in the M02 sense; the trust boundaries are the kernels it
  exercises. M02's mutation lane covers those.

## Phases

### P0: Wave-opener Cargo.lock bump and audit doc

Stage the workspace, open the audit doc, snapshot the inputs the arena
depends on (M04 corpus size, M05 async kernel surface, M07.P4.T6 oracle
location).

- M08.P0.T1: Open M08 audit doc and snapshot prerequisite trajectory-1
  + trajectory-2 artifact state.
- M08.P0.T2: Cargo.lock bump and pin `toml`, `rand`, `rand_chacha` for the
  arena DSL and PRNG.
- M08.P0.T3: Workspace member registration for `crates/chio-arena/` (empty
  crate skeleton; lib.rs + Cargo.toml only) so dependents can see it.

### P1: chio-arena crate genesis and walking skeleton

Land the crate skeleton, the scenario DSL parser, the deterministic-witness
plumbing, the in-process kernel link transport, and a single-agent walking
skeleton that emits an M04-shaped receipt bundle and replays bit-exact via
the existing `chio replay` engine.

- M08.P1.T1: Scenario DSL TOML schema spec (`arena/scenarios/SCHEMA.md`)
  and the JSON schema export.
- M08.P1.T2: `chio-arena::scenario` parser, validator, and determinism
  witness extractor.
- M08.P1.T3: `chio-arena::link` in-process channel transport for kernel
  instances (channel-backed `KernelLink` + `KernelEndpoint`).
- M08.P1.T4: Single-agent runtime: load scenario, drive one kernel,
  collect receipts.
- M08.P1.T5: Receipt-bundle writer (delegates to
  `chio_replay_corpus::write_m04_fixture`) plus the sibling `arena.json`
  manifest.
- M08.P1.T6: Single-agent walking-skeleton end-to-end test: scenario
  loads, runs, produces a receipt bundle, replays bit-exact via `chio
  replay`.

### P2: Multi-agent runtime and deterministic scheduler

Lift the walking skeleton to N agents, add the virtual clock, the seeded
RNG, the deterministic scheduler, and the kernel multiplexer so multiple
`Arc<ChioKernel>` instances share one runtime without losing determinism.

- M08.P2.T1: Virtual clock implementation (tokio time-pause harness with
  per-scenario start instant; no wall-clock reads inside a scenario).
- M08.P2.T2: Seeded RNG plumbing (`rand_chacha::ChaCha20Rng` keyed by the
  scenario's `rng_seed`, plus per-agent sub-streams via `SeedableRng::
  seed_from_u64`).
- M08.P2.T3: Deterministic scheduler: priority-queue ordered on
  (virtual-time, agent-id, intra-agent-step) with stable tiebreaks; no
  thread-local randomness.
- M08.P2.T4: Kernel multiplexer over `Arc<ChioKernel>`; agent-to-agent
  tool-call routing through `chio-arena::link`.
- M08.P2.T5: Two-agent and three-agent reference scenarios under
  `arena/scenarios/multi/` exercising tool-call exchange and triangular
  delegation.
- M08.P2.T6: Determinism gate: CI job `chio-arena-determinism` runs the
  three reference scenarios twice and asserts byte equality on the
  emitted receipt bundles.

### P3: Adversary populations (one class per ticket)

Each adversary class lands as a self-contained module under
`chio-arena::adversary`, with a unit test exercising the class against a
toy guard set and a reference scenario that triggers the class
deterministically.

- M08.P3.T1: Adversary trait and population scaffolding
  (`AdversaryClass`, `AdversaryPopulation`, scenario-side block in the
  DSL).
- M08.P3.T2: Prompt-injection adversary class (mutates seed prompt with
  injection patterns from the trajectory-1 M02 fuzz corpus).
- M08.P3.T3: Capability-overrequest adversary class (asks for
  capabilities outside the scenario's grant scope; expects fail-closed).
- M08.P3.T4: Replay-attempt adversary class (reuses a captured
  capability after expiry / revocation; intersects M04 `replay_attack`
  family).
- M08.P3.T5: Scope-superset escape adversary class (delegates with a
  scope larger than the issuer's; expects fail-closed by scope-monotone
  delegation rules).
- M08.P3.T6: Adversary-class reference scenarios under
  `arena/scenarios/adversary/`; one scenario per class.

### P4: Co-evolution loop and fitness function

Lift the adversary populations from fixed sets to co-evolving populations.
Fitness function: adversary survival rate against the deployed guard pool.
Genetic operators: DSL-aware mutation (single-field perturbation) and
two-parent crossover. Seed corpus pulled from `fuzz/artifacts/` and from
the M04 `replay_attack` / `tampered_*` families.

- M08.P4.T1: Fitness function: per-adversary survival rate over a
  scenario population; oracle = trajectory-1 M07.P4.T6 verdict equality.
- M08.P4.T2: DSL-aware mutation operator (per-field strategies; never
  mutates the determinism witness, only the adversary block).
- M08.P4.T3: Two-parent crossover operator (scenario splice on
  agent-population boundaries).
- M08.P4.T4: Seed-corpus loader: `fuzz/artifacts/` + M04
  `tests/replay/fixtures/replay_attack/` and
  `tests/replay/fixtures/tampered_signature/`.
- M08.P4.T5: Co-evolution driver: N generations, elitism, fitness-
  proportional selection, seed-corpus injection at every generation.
  Bounded-budget gate (default: 200 generations or 30 minutes wall, fail-
  closed on exceed).
- M08.P4.T6: Co-evolution determinism test: same seed corpus + same RNG
  seed produces byte-identical generation traces.

### P5: Output plumbing, leaderboard, and CLI surfaces

Auto-promotion to the M04 vector corpus and to the trajectory-2 M05
`chio-adversarial-suite`, the leaderboard renderer, and the `arc arena`
CLI subcommands.

- M08.P5.T1: Auto-promotion to M04 fixtures via the existing CHIO_BLESS
  gate. New BLESS_REASON value `arena:<scenario-id>` recognized; no gate
  weakening.
- M08.P5.T2: Auto-promotion to trajectory-2 M05 `chio-adversarial-suite`
  per-class JSON files. Soft-dep on M05 ticket; the arena writes to the
  expected path under `crates/chio-adversarial-suite/cases/`.
- M08.P5.T3: Leaderboard renderer (Markdown + stable-schema JSON output).
- M08.P5.T4: `arc arena run scenarios/<name>.toml` CLI subcommand.
- M08.P5.T5: `arc arena replay <scenario-id>` CLI subcommand (delegates
  to the existing `chio replay` engine).
- M08.P5.T6: `arc arena evolve scenarios/<seed>.toml --generations N`
  CLI subcommand for the co-evolution loop.
- M08.P5.T7: End-to-end smoke test: run -> failing scenario discovered
  -> auto-promote to both corpora -> replay bit-exact via `chio replay`.

## Cross-milestone interactions

Hard deps (other trajectory-2 milestones):

- **M02.P4 (`verdict_matrix/` harness scaffold)**: hard ticket-level
  dependency for `M08.P4.T1` (fitness function uses the verdict oracle).
  The arena does not start coding the fitness function until the verdict
  matrix manifest exists. Encoded as a soft_dep string sentence at the
  ticket level; the existing Wave 3 -> Wave 4 wave-gate boundary already
  enforces this (M02 closes in Wave 1, before Wave 3 opens), so no
  ticket-level sync rule is required.
- **M05.P0 (chio-adversarial-suite scaffold)**: hard ticket-level
  dependency for `M08.P5.T2` (auto-promotion target). Until the suite
  scaffold exists, M08 writes to a holding directory under
  `target/arena/promote-pending/` and the gate is soft-disabled.
- **M07.P0 (provider fabric scaffold)**: not strictly required at the
  ticket level (the arena uses provider trait objects, not concrete
  provider crates) but the arena's reference scenarios use the same
  provider trait names that M07 codifies. Soft dep on M07.P0 for
  vocabulary alignment; not blocking.

Soft deps (trajectory-1 artifacts referenced as string sentences):

- "trajectory-1 M04 deterministic replay corpus + `chio replay` engine
  is the bit-exact replay surface; the arena emits M04-shaped bundles
  and consumes the existing engine for replay."
- "trajectory-1 M05 async kernel surface (post-`Arc<ChioKernel>`) is the
  multi-kernel substrate; the arena's link transport wraps it."
- "trajectory-1 M07.P4.T6 cross-provider verdict equality is the
  fitness-function and leaderboard verdict oracle."
- "trajectory-1 M01 canonical-JSON RFC 8785 vectors lock the encoding
  for arena receipt bundles."
- "trajectory-1 M02 fuzz crash artifacts under `fuzz/artifacts/` are the
  seed corpus for the co-evolution loop."

Downstream consumers in trajectory-2:

- **M05 `chio-adversarial-suite`**: arena auto-promotion writes per-class
  JSON cases into the suite. Bidirectional: M08 produces, M05 curates.
- **M09 economic layer + lineage**: the leaderboard's guard-survival
  rank is one input to reputation weighting in `chio-reputation`. M09
  consumes the stable-schema JSON output from M08.P5.T3; the arena does
  not implement reputation logic itself.

## Risks and mitigations

- **Hidden non-determinism inside the arena runtime.** Multi-threaded
  scheduling, HashMap iteration, time reads, allocator-dependent layout.
  Mitigation: virtual clock with `tokio::time::pause`; explicit BTreeMap
  for any iteration that surfaces in receipts; LC_ALL=C in the CI job;
  determinism gate runs each reference scenario twice and asserts byte
  equality (P2.T6). The trajectory-1 M04 determinism canary is the
  upstream backstop.
- **Provider-coupling creep.** Easy to slip a provider crate into a
  scenario for "convenience" and lose provider-agnosticism. Mitigation:
  workspace `Cargo.toml` `[workspace.dependencies]` block does NOT pin
  any provider crate at the M08 wave open. The `chio-arena` crate's
  `Cargo.toml` is forbidden from depending on `chio-openai`,
  `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`, or
  any other provider crate. Enforcement is the M08.P0.T3 gate_check
  grep against `crates/chio-arena/Cargo.toml` (mechanical and runs in
  CI on every PR); CODEOWNERS routes review of the Cargo.toml to
  `@bb-connor` but does not by itself enforce the rule.
- **Co-evolution budget blowout.** Genetic algorithms can run for hours
  before producing a useful adversary. Mitigation: P4.T5's bounded-budget
  gate (200 generations or 30 minutes wall); on exceed the driver
  returns the current best population and exits with a non-zero status
  (the run is recorded as `budget_exceeded`, not as `failed`), so a CI
  lane does not block other PRs. Seed-corpus injection at every
  generation prevents wandering in fitness space; CI runs co-evolution
  with a 5-minute budget on PRs and the full 30-minute budget only on
  nightly.
- **Auto-promotion floods the M04 corpus.** A single bad arena run could
  add hundreds of fixtures and overwhelm the curated corpus. Mitigation:
  auto-promotion writes to a dedicated `tests/replay/fixtures/arena/`
  family namespace; the CHIO_BLESS gate's per-PR cap (default 5
  promotions per PR) carries forward and is enforced in P5.T1; the
  goldens-size budget from M04 NEW sub-task (5MB total) is a backstop.
- **`chio-link` name collision with the oracle crate.** The brief uses
  "chio-link" for the in-process kernel multiplexer, but
  `crates/chio-link/` is the price-oracle crate. Mitigation: the arena's
  multiplexer lives at `crates/chio-arena/src/link/` (a submodule, not a
  top-level crate). The narrative explicitly disambiguates. No new top-
  level `chio-link-*` crate is introduced.
- **Cross-version drift on the arena DSL.** The DSL is TOML; adding a
  field today should not break a scenario authored last week. Mitigation:
  scenario manifests carry an explicit `schema_version = "chio.arena.
  scenario/v1"` field; the parser fails closed on unknown major versions
  and tolerates unknown fields under `[ext]` only.
- **Adversary classes drift from the trajectory-1 M02 fuzz seed corpus.**
  If `fuzz/artifacts/` rotates while the arena pins file paths, the seed
  loader breaks silently. Mitigation: P4.T4 reads the corpus by
  globbing under the directory and hashing each artifact; the seed-
  corpus loader records `(artifact_path, sha256)` in `arena.json` so a
  rotated corpus surfaces as a manifest hash mismatch, not a silent
  no-op.
- **Determinism gate flakes on macOS.** Per M04 platform pinning, the
  determinism gate is Linux-only. Mitigation: P2.T6's gate runs only on
  Linux; macOS runs the suite read-only as a smoke check, mirroring
  M04's pattern.

## Success criteria

- `crates/chio-arena/` exists as a workspace member with the modules
  enumerated under "Scope" above; `cargo build -p chio-arena --quiet`,
  `cargo test -p chio-arena --quiet`, and `cargo clippy -p chio-arena --
  -D warnings` all pass.
- `arena/scenarios/SCHEMA.md` and `arena/scenarios/schema.json` document
  the scenario DSL; the parser refuses scenarios that fail schema
  validation.
- `arc arena run`, `arc arena replay`, and `arc arena evolve` are wired
  into `chio-cli` with passing integration tests.
- The single-agent walking skeleton (P1.T6) produces a receipt bundle
  byte-compatible with the M04 `tests/replay/goldens/` layout and
  replays bit-exact via the existing `chio replay` engine.
- The three reference scenarios (single-agent, two-agent, three-agent)
  pass the `chio-arena-determinism` gate twice on the same commit.
- All four adversary classes (P3.T2 through P3.T5) ship with reference
  scenarios and unit tests.
- The co-evolution loop (P4.T5) is bit-exact reproducible: same seed
  corpus + same RNG seed yields byte-identical generation traces.
- Auto-promotion to M04 fixtures (P5.T1) and to the M05
  `chio-adversarial-suite` (P5.T2) is wired and CI-tested with end-to-end
  smoke (P5.T7).
- `target/arena/leaderboard.md` and `target/arena/leaderboard.json`
  render after every arena run with stable schemas.
- The audit doc at `.planning/audits/M08-chio-arena.md` records the
  scenario corpus size, the seed-corpus hash inventory, the adversary
  class roster, and the bench numbers from a representative
  multi-agent run; linked from this narrative on milestone close.
