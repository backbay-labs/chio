//! Deterministic arena support for Chio replay scenarios.

#![forbid(unsafe_code)]

pub mod scenario;
pub mod link;
pub mod runtime;

/// Scenario schema name used by the arena DSL.
pub const ARENA_SCENARIO_SCHEMA: &str = "chio.arena.scenario/v1";

pub use scenario::{
    parse_scenario_str, DeterminismWitness, Scenario, ScenarioError, ScenarioStep,
    ScenarioVerdict,
};
pub use runtime::{
    ArenaReceipt, ArenaRun, ArenaRuntime, ArenaRuntimeError, KernelStepRequest,
};
