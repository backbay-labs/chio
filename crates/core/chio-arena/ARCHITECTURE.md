# chio-arena architecture

## Overview

`chio-arena` is a test and evaluation harness that sits outside the kernel's
trust boundary: it drives a real `ChioKernel` through deterministic,
TOML-defined scenarios and records the verdicts the kernel actually returns.
It never reads wall-clock
time; every value that feeds the determinism witness derives from the
scenario's `rng_seed`, `virtual_clock_start`, and step order, so a scenario
replay is byte-reproducible. `chio-cli` exposes the crate as `chio arena
run/replay/evolve`; the crate's own co-evolution loop additionally mutates
and cross-breeds adversary populations against the kernel's guard pipeline.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the ten public modules, re-exports their surface at `chio_arena::*`, and defines `ARENA_SCENARIO_SCHEMA`. |
| `src/scenario.rs` | `chio.arena.scenario/v1` TOML DSL: types and fail-closed validation (schema/scheduler/locale support, duplicate ids, dangling references, inline-secret and provider-SDK rejection). |
| `src/clock.rs` | `VirtualClock`, the arena's sole time authority. Strict RFC-3339 parsing, tick advancement. |
| `src/rng.rs` | `ArenaRng`: seeded `ChaCha20Rng` root plus FNV-1a-derived per-agent sub-streams. |
| `src/scheduler.rs` | `DeterministicScheduler`: total order over scenario steps by `(virtual_time, agent_id, intra_agent_step)`. |
| `src/runtime.rs` | `ArenaRuntime`: dispatches scheduled steps to a `ChioKernel`, checks each actual verdict against `expect_verdict`, and collects signed receipts into an `ArenaRun`. |
| `src/link/` (`mod.rs`, `transport.rs`, `multiplex.rs`) | In-process transport (`KernelLink`/`KernelEndpoint` over `tokio::mpsc`) and `KernelMultiplexer` routing for multi-agent cross-kernel calls. |
| `src/adversary/` (`mod.rs` + 4 class files) | `Adversary` trait, `AdversaryPopulation`, the four adversary classes, and the toy fail-closed guard evaluator their unit tests assert against. |
| `src/coevolve.rs` + `src/coevolve/` (`mutation.rs`, `crossover.rs`, `driver.rs`, `seed_corpus.rs`) | Fitness scoring, mutation, crossover, seed-corpus loading, and the N-generation co-evolution driver over adversary population blueprints. |
| `src/promote.rs` | `write_arena_bundle` (replay-compatible bundle + `arena.json`); `promote_to_fixtures` / `promote_to_adversarial_suite` (auto-promotion). |
| `src/leaderboard.rs` | Ranks a `FitnessReport` into the `chio.arena.leaderboard/v1` JSON and Markdown leaderboard. |

## Scenario lifecycle

1. `load_scenario` / `parse_scenario_str` parse the TOML DSL into a `Scenario`
   and validate it (schema/id/scheduler/locale checks, duplicate and
   dangling-reference checks, inline-secret and provider-SDK rejection) -
   failing closed before any kernel call is made.
2. `DeterministicScheduler::from_scenario` orders every step by
   `(virtual_time, agent_id, intra_agent_step)`.
3. `ArenaRuntime::run` (single agent) or `run_multi_agent` (routed through
   `KernelMultiplexer`/`KernelLink`) dispatches each step's `ToolCallRequest`
   to the bound `ChioKernel`, ticking `VirtualClock` once per step and
   consuming `ArenaRng` sub-streams. A verdict that disagrees with the step's
   `expect_verdict` fails the run with `ArenaRuntimeError::UnexpectedVerdict`.
4. Optionally, `adversary::population_from_block` builds adversary
   populations from the scenario's `[[adversaries]]` blocks, and
   `coevolve::run_coevolution` mutates and cross-breeds them across
   generations, scoring each with the toy guard evaluator
   (`evaluate_against_guards`) that mirrors the kernel's fail-closed decision
   tree.
5. `write_arena_bundle` converts the recorded `ArenaReceipt`s into
   `chio-tee-frame::Frame`s and writes them through
   `chio-replay-corpus::write_fixture`, plus an `arena.json` manifest.
6. `promote_to_fixtures` / `promote_to_adversarial_suite` optionally graduate
   `Deny` (and, for the adversarial suite, `Rewrite`) receipts into the
   fixture or adversarial-suite corpora.
7. `render_leaderboard` ranks a co-evolution `FitnessReport` into the
   `chio.arena.leaderboard/v1` document.

## Boundaries

Scenario `guards` and `budgets` blocks are parsed and validated (duplicate
ids, unknown-agent references, zero-invocation budgets, secret markers) but
are not consumed by the scheduler or runtime; guard and budget enforcement
are out of scope for this crate today.

## Invariants and failure modes

- No wall-clock reads anywhere in the determinism-sensitive path;
  `VirtualClock` is the sole time authority.
- Same scenario witness (`rng_seed`, `virtual_clock_start`, `scheduler`,
  `locale`, `agents`, `steps`) implies byte-identical schedule, RNG
  snapshots, clock trace, and verdict trace across runs, enforced by
  `tests/determinism_gate.rs` against the three reference scenarios.
- `validate_scenario` fails closed on unsupported schema version / scheduler
  / locale, duplicate agent/step/guard ids, steps or budgets referencing
  unknown agents, zero-invocation budgets, inline secret markers anywhere in
  agent/step/guard/adversary fields, and provider-SDK dependency markers in
  agent `model` strings.
- `ArenaRuntime::run` / `run_multi_agent` reject a mismatched step/request
  count or step-id ordering before dispatch, and stop the run on the first
  verdict that disagrees with the scenario's declared `expect_verdict`.
- `AdversaryPopulation::new` rejects empty populations and populations that
  mix adversary classes.
- The co-evolution driver checks its wall-clock budget only between
  generations, never mid-generation, and only decides `Completed` versus
  `BudgetExceeded`; wall-clock time never changes the generation trace's
  content.
- `promote_to_fixtures` requires `ArenaPromotionGate::read` to pass
  (`CHIO_BLESS == "1"`, non-empty `BLESS_REASON` prefixed `arena:`, `CI`
  unset/falsy) and additionally requires `BLESS_REASON` to equal
  `arena:<scenario-id>` exactly; only `Deny` receipts are written.
  `promote_to_adversarial_suite` has no `CHIO_BLESS` gate of its own; it
  writes `Deny` and `Rewrite` receipts and falls back to
  `target/arena/promote-pending/` when the live
  `crates/core/chio-adversarial-suite/cases` directory is absent.
- `write_arena_bundle` and both promotion functions reject a run whose
  `scenario_id` does not match the scenario, or whose receipts reference a
  step id outside the scenario.

## Dependencies

`chio-kernel` supplies the real `ChioKernel` every scenario step is
dispatched against, plus `ToolCallRequest`, `ToolCallResponse`, `Verdict`,
`ToolServerConnection`, and `KernelError`. The `chio-core` dependency is
aliased to `chio-core-types`, supplying `canonical_json_bytes`,
`crypto::sha256_hex`, `Keypair`, capability scope types, and receipt body
types. `chio-replay-corpus` supplies `write_fixture` and the bundle byte
layout `write_arena_bundle` produces. `chio-tee-frame` supplies the `Frame`
schema each receipt is wrapped into before writing. `rand`/`rand_chacha`
supply `ChaCha20Rng`, the deterministic RNG behind `ArenaRng` and the
adversary/co-evolution modules. `serde`/`serde_json`/`toml` handle scenario
DSL parsing and canonical serialization. `tokio` provides `mpsc`/`Mutex` for
the in-process `KernelLink` transport and the async runtime for
`ArenaRuntime`. Dev-only: `async-trait` (test `ToolServerConnection` impls),
`tempfile` (scratch bundle directories in tests).

## Extension points

- `Adversary` - implement to add an adversary class beyond the four built-in
  ones; `AdversaryPopulation::new` only requires that members share a class.
- `BlessEnv` - implement to source the `CHIO_BLESS`/`BLESS_REASON`/`CI` gate
  from something other than the process environment (`ProcessBlessEnv` is the
  production implementation; tests use a stub).
