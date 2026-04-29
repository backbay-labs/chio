# M08: chio-arena - Adversarial Replay Coliseum

**Wave:** W3  |  **Trust-boundary:** no  |  **Tickets:** 34  |  **Effort:** 43.50 days

## In one paragraph

M08 ships `chio-arena`, a deterministic multi-agent simulator on top of trajectory-1 M04 replay and M05 async kernel. It runs adversary populations (prompt-injection, capability-overrequest, replay-attempt, scope-superset-escape) under a virtual clock and seeded RNG, co-evolves them against the deployed guard pool, and auto-promotes failing scenarios into the M04 replay corpus and M05 adversarial suite via the existing CHIO_BLESS gate.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 3 | Audit doc + Cargo.lock bump (`toml`/`rand`/`rand_chacha`) + workspace registration |
| P1 | 6 | Crate genesis + scenario DSL parser + in-process kernel link + single-agent walking skeleton |
| P2 | 6 | Multi-agent runtime: virtual clock, seeded RNG, deterministic scheduler, kernel multiplexer |
| P3 | 6 | Adversary trait + four classes (prompt-injection, cap-overrequest, replay, scope-superset) |
| P4 | 6 | Co-evolution loop: fitness function, mutation/crossover, seed-corpus, determinism gate |
| P5 | 7 | Auto-promotion to M04/M05 corpora, leaderboard, `arc arena run/replay/evolve` subcommands |

## Load-bearing artifacts

- `crates/chio-arena/` (M08.P0.T3 scaffolds; P1 fills)
- `arena/scenarios/SCHEMA.md` + `arena/scenarios/schema.json` (M08.P1.T1)
- `crates/chio-arena/src/link/` in-process kernel multiplexer (M08.P1.T3; D19 disambiguates)
- Determinism gate `chio-arena-determinism` (M08.P2.T6)
- Co-evolution driver (M08.P4.T5)
- Auto-promotion to `tests/replay/fixtures/arena/` (M08.P5.T1; D20)
- Auto-promotion to `crates/chio-adversarial-suite/cases/` (M08.P5.T2)
- `target/arena/leaderboard.{md,json}` (M08.P5.T3)
- `arc arena {run, replay, evolve}` subcommands (M08.P5.T4-T6)

## Cross-trajectory deps

- trajectory-1 M04 replay engine + corpus shape - arena receipt bundles are M04-byte-compatible
- trajectory-1 M05 async kernel - multi-agent runtime uses `Arc<ChioKernel>` instances
- trajectory-1 M07.P4.T6 verdict-equality oracle - fitness function consumer
- trajectory-2 M02 verdict-matrix - referee oracle for arena runs
- trajectory-2 M05 adversarial suite - auto-promotion target via `--mode adversarial` (soft_dep)

## Locked decisions

- D19 In-process kernel multiplexer lives at `crates/chio-arena/src/link/`, not `chio-link` (existing `chio-link` price-oracle crate keeps its name)
- D20 Auto-promoted scenarios land at `tests/replay/fixtures/arena/`, separate from the curated M04 corpus, with a 5MB goldens budget

## Active freezes

none.

## When this milestone is done

- `crates/chio-arena/` builds, tests, and clippy-clean; modules per Scope present.
- `arena/scenarios/SCHEMA.md` and JSON schema document the DSL; parser refuses scenarios that fail validation.
- `arc arena run/replay/evolve` wired into `chio-cli` with passing integration tests.
- Single-agent walking skeleton produces an M04-byte-compatible receipt bundle and replays bit-exact via `chio replay`.
- Three reference scenarios pass `chio-arena-determinism` gate twice on the same commit.
- All four adversary classes ship with reference scenarios and unit tests.
- Co-evolution loop is bit-exact reproducible: same seed corpus + RNG seed yields byte-identical generation traces.
- Auto-promotion to M04 fixtures (P5.T1) and M05 suite (P5.T2) wired and CI-tested with end-to-end smoke (P5.T7).
- `target/arena/leaderboard.{md,json}` rendered after every run with stable schemas.
