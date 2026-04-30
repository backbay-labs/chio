//! Deterministic arena support for Chio replay scenarios.

#![forbid(unsafe_code)]

pub mod adversary;
pub mod clock;
pub mod coevolve;
pub mod link;
pub mod promote;
pub mod rng;
pub mod runtime;
pub mod scenario;
pub mod scheduler;

/// Scenario schema name used by the arena DSL.
pub const ARENA_SCENARIO_SCHEMA: &str = "chio.arena.scenario/v1";

pub use adversary::{
    evaluate_against_guards, population_from_block, Adversary, AdversaryAction, AdversaryClass,
    AdversaryError, AdversaryPopulation, CapabilityOverrequestAdversary, IssuedScope,
    PromptInjectionAdversary, ReplayAttemptAdversary, ScopeEscapeAdversary, ToyGuardEvaluation,
};
pub use clock::{ClockError, VirtualClock, DEFAULT_TICK_NANOS};
pub use coevolve::mutation::{
    OverrequestBlueprint, PopulationBlueprint, PromptInjectionBlueprint, ReplayAttemptBlueprint,
    ReplayAttemptEntry, ScopeEscapeBlueprint,
};
pub use coevolve::{
    crossover_overrequest_population, crossover_populations, crossover_prompt_injection_population,
    crossover_replay_attempt_population, crossover_scope_escape_population, evaluate_population,
    mutate_overrequest_population, mutate_population, mutate_prompt_injection_population,
    mutate_replay_attempt_population, mutate_scope_escape_population, CrossoverError, FitnessError,
    FitnessInputs, FitnessReport, FitnessSample, MatrixVerdict, MutationConfig, MutationError,
    MutationKind, VerdictTuple,
};
pub use link::{
    KernelEndpoint, KernelLink, KernelMultiplexer, LinkEnvelope, LinkError, MultiplexError,
};
pub use promote::{
    write_arena_bundle, ArenaBundleManifest, ArenaBundleSummary, ArenaManifestBundle,
    ArenaManifestVerdict, PromoteError, ARENA_MANIFEST_FILENAME,
};
pub use rng::{ArenaRng, RngError};
pub use runtime::{
    shared_kernel_bindings, AgentKernelBinding, ArenaReceipt, ArenaRun, ArenaRuntime,
    ArenaRuntimeError, KernelStepRequest,
};
pub use scenario::{
    load_scenario, parse_scenario_str, DeterminismWitness, Scenario, ScenarioError, ScenarioStep,
    ScenarioVerdict,
};
pub use scheduler::{DeterministicScheduler, ScheduledStep, SchedulerError};
