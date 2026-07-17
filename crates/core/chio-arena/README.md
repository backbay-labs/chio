# chio-arena

`chio-arena` is a deterministic scenario runner for the Chio kernel. It parses
a TOML scenario DSL, schedules and dispatches tool calls against a real
`ChioKernel`, and records the resulting signed receipts into replay-compatible
bundles. It also mutates and co-evolves adversary populations against the
kernel's guard pipeline, and can auto-promote failing scenarios into the
fixture and adversarial-suite corpora.

## Responsibilities

- Parse and validate the `chio.arena.scenario/v1` TOML DSL, rejecting
  unsupported schema/scheduler/locale, duplicate ids, dangling agent
  references, inline secrets, and provider-SDK markers before a run starts.
- Schedule scenario steps into a deterministic total order and dispatch them
  to a `ChioKernel` (single-agent, or multi-agent via an in-process kernel
  link), asserting each step's actual verdict against its declared
  `expect_verdict`.
- Generate, mutate, and cross-breed adversary populations (prompt injection,
  capability overrequest, replay attempt, scope escape) through an
  N-generation co-evolution loop scored against a toy fail-closed guard
  evaluator.
- Write replay-compatible receipt bundles and auto-promote failing runs into
  the fixture corpus (`CHIO_BLESS`-gated) and the `chio-adversarial-suite`
  case corpus.
- Render a ranked leaderboard (`chio.arena.leaderboard/v1`) from a
  co-evolution fitness report.

## Public API

- **Scenario** - `load_scenario`, `parse_scenario_str` parse and validate the
  `chio.arena.scenario/v1` DSL into a `Scenario` (`ScenarioStep`,
  `ScenarioVerdict`, `DeterminismWitness`); `ScenarioError` reports
  fail-closed validation failures. Agent, budget, guard, and adversary block
  types live in the `scenario` module.
- **Determinism primitives** - `VirtualClock` (sole time authority), `ArenaRng`
  (seeded `ChaCha20Rng` root plus per-agent sub-streams),
  `DeterministicScheduler` (total order over scenario steps).
- **Runtime** - `ArenaRuntime::run` / `run_multi_agent` dispatch scenario
  steps to a `ChioKernel` and return an `ArenaRun` of `ArenaReceipt`s;
  `KernelStepRequest`, `AgentKernelBinding`, `shared_kernel_bindings`.
  Multi-agent cross-kernel calls route through `KernelLink` /
  `KernelMultiplexer`.
- **Adversary** - the `Adversary` trait, `AdversaryPopulation`,
  `AdversaryClass`, `population_from_block`, and the four concrete
  adversaries (`PromptInjectionAdversary`, `CapabilityOverrequestAdversary`,
  `ReplayAttemptAdversary`, `ScopeEscapeAdversary`). `evaluate_against_guards`
  is the toy fail-closed guard oracle their unit tests assert against.
- **Co-evolution** (`coevolve` module) - `run_coevolution` drives generations
  of `mutate_population`, `crossover_populations`, and `evaluate_population`
  over `PopulationBlueprint`s, seeded via `load_seed_corpus` from
  `fuzz/artifacts/` and the replay fixture families.
- **Promotion and reporting** - `write_arena_bundle` writes a
  replay-compatible bundle plus `arena.json`; `promote_to_fixtures` /
  `promote_to_adversarial_suite` auto-promote failing runs (the former gated
  by `ArenaPromotionGate` / `BlessEnv`); `render_leaderboard` ranks a
  `FitnessReport` into `chio.arena.leaderboard/v1` JSON and Markdown.

## Usage

```rust
use chio_arena::{load_scenario, write_arena_bundle, ArenaRuntime, KernelStepRequest};

let scenario = load_scenario("arena/scenarios/walking_skeleton.toml")?;
// kernel: Arc<ChioKernel>, tool servers and capability already set up by the caller.
let runtime = ArenaRuntime::new(kernel);
let run = runtime
    .run(&scenario, vec![KernelStepRequest { step_id: "step-1".into(), request }])
    .await?;
write_arena_bundle("target/arena/walking_skeleton", &scenario, &run)?;
```

## Testing

`cargo test -p chio-arena`

`tests/determinism_gate.rs` re-runs the three reference scenarios under
`arena/scenarios/` twice and asserts byte-identical schedules, RNG snapshots,
clock traces, and verdict traces. CI runs it under `LC_ALL=C` and
`CARGO_INCREMENTAL=0` via the `chio-arena-determinism.yml` workflow.

## See also

- `chio-kernel` - the kernel every scenario step is dispatched against.
- `chio-replay-corpus` - the receipt bundle format `write_arena_bundle` writes.
- `chio-tee-frame` - the frame schema wrapped around each receipt.
- `chio-adversarial-suite` - target corpus for `promote_to_adversarial_suite`.
- `chio-cli` - exposes this crate as `chio arena run/replay/evolve`.
