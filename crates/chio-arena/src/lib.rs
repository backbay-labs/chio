//! Deterministic arena support for Chio replay scenarios.

#![forbid(unsafe_code)]

pub mod scenario;
pub mod link;
pub mod promote;
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
pub use promote::{
    write_arena_bundle, ArenaBundleManifest, ArenaBundleSummary, ArenaManifestBundle,
    ArenaManifestVerdict, PromoteError, ARENA_MANIFEST_FILENAME,
};
