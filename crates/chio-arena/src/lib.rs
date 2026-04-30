//! Deterministic arena support for Chio replay scenarios.

#![forbid(unsafe_code)]

pub mod clock;
pub mod link;
pub mod promote;
pub mod rng;
pub mod runtime;
pub mod scenario;
pub mod scheduler;

/// Scenario schema name used by the arena DSL.
pub const ARENA_SCENARIO_SCHEMA: &str = "chio.arena.scenario/v1";

pub use clock::{ClockError, VirtualClock, DEFAULT_TICK_NANOS};
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
