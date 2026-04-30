//! Co-evolution surface for the Chio arena (M08.P4).
//!
//! The Phase 4 work lifts the Phase 3 fixed adversary populations into a
//! genetic-algorithm-shaped loop. The submodules introduced over the phase
//! are:
//!
//!   * [`mutation`] (P4.T2): DSL-aware single-field mutation operator.
//!   * [`crossover`] (P4.T3): two-parent splice on agent-population
//!     boundaries.
//!   * [`seed_corpus`] (P4.T4): loader for `fuzz/artifacts/` plus the M04
//!     `replay_attack` and `tampered_signature` fixture families.
//!   * [`driver`] (P4.T5): N-generation loop with elitism, fitness-
//!     proportional selection, and the bounded-budget gate.
//!
//! This file provides the fitness function the loop optimises (P4.T1).
//! Survival rate is the share of an adversary's actions that the deployed
//! guard pool fails to deny: an action that the guards correctly deny
//! lowers fitness, an action that escapes (the guards return Allow when the
//! adversary expected Deny) raises it. The fitness function consumes the
//! verdict-matrix oracle shape from trajectory-2 M02.P4
//! (`crates/chio-conformance/verdict_matrix/`); the matrix crate lives in
//! its own workspace, so we mirror the `(Verdict, reason_code, scope_set)`
//! tuple here and document the soft-coupling. The diff implementation is
//! the trajectory-1 M07.P4.T6 cross-provider verdict equality oracle; the
//! arena calls it pairwise across the witness set, never invents a new
//! comparator.
//!
//! Determinism contract: every value computed in this module is a pure
//! function of the canonical scenario witness (`rng_seed`,
//! `virtual_clock_start`, scenario step layout) plus the per-adversary
//! action sequence. No wall-clock reads, no thread-local randomness. Two
//! arena runs of the same scenario produce byte-identical fitness scores.

pub mod crossover;
pub mod mutation;
pub mod seed_corpus;

pub use crossover::{
    crossover_overrequest_population, crossover_populations, crossover_prompt_injection_population,
    crossover_replay_attempt_population, crossover_scope_escape_population, CrossoverError,
};
pub use mutation::{
    mutate_overrequest_population, mutate_population, mutate_prompt_injection_population,
    mutate_replay_attempt_population, mutate_scope_escape_population, MutationConfig,
    MutationError, MutationKind,
};
pub use seed_corpus::{
    load_seed_corpus, SeedArtifact, SeedCorpus, SeedCorpusError, SeedCorpusSources,
};

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::adversary::{
    evaluate_against_guards, AdversaryAction, AdversaryClass, AdversaryPopulation, IssuedScope,
    ToyGuardEvaluation,
};
use crate::scenario::{ScenarioStep, ScenarioVerdict};

/// Verdict tuple mirroring the trajectory-2 M02.P4 verdict-matrix oracle
/// (`crates/chio-conformance/verdict_matrix/`). The matrix crate lives in
/// its own Cargo workspace, so the arena re-declares the tuple shape and
/// keeps the soft-coupling in commentary. The variants and reason-code
/// string layout match the matrix exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatrixVerdict {
    /// Guards permitted the action.
    Allow,
    /// Guards denied the action.
    Deny,
    /// Guards surfaced an internal error (treated as fail-closed).
    Error,
}

impl MatrixVerdict {
    /// Stable kebab-case identifier emitted into receipts.
    pub const fn as_str(&self) -> &'static str {
        match self {
            MatrixVerdict::Allow => "allow",
            MatrixVerdict::Deny => "deny",
            MatrixVerdict::Error => "error",
        }
    }
}

impl From<ScenarioVerdict> for MatrixVerdict {
    fn from(value: ScenarioVerdict) -> Self {
        match value {
            ScenarioVerdict::Allow => MatrixVerdict::Allow,
            // The arena treats Rewrite as an effective Allow at the
            // matrix level: the action was not blocked by the guards.
            ScenarioVerdict::Rewrite => MatrixVerdict::Allow,
            ScenarioVerdict::Deny => MatrixVerdict::Deny,
        }
    }
}

/// Verdict tuple recorded for one (guard pool, adversary action) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictTuple {
    /// Guard pool verdict.
    pub verdict: MatrixVerdict,
    /// Stable reason code returned by the guard pool. Ordered next to the
    /// verdict to mirror the matrix crate layout.
    pub reason_code: String,
    /// Capability scope set the action presented (sorted, mirroring
    /// `VerdictTuple::normalized` in the matrix crate).
    pub scope_set: Vec<String>,
}

impl VerdictTuple {
    fn from_evaluation(evaluation: &ToyGuardEvaluation, action: &AdversaryAction) -> Self {
        let mut scope_set = vec![format!(
            "{}:{}",
            action.mutated_step.server, action.mutated_step.tool
        )];
        scope_set.sort();
        Self {
            verdict: evaluation.verdict.into(),
            reason_code: evaluation.reason.clone(),
            scope_set,
        }
    }
}

/// Per-adversary fitness sample. Records the verdict tuple the guard pool
/// returned for each action plus whether the action was a survival (the
/// adversary expected Deny but the guards Allowed) or a defeat (the guards
/// returned the expected Deny).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitnessSample {
    /// Adversary class.
    pub class: AdversaryClass,
    /// Population name.
    pub population: String,
    /// Action sequence (mutated step ids).
    pub step_ids: Vec<String>,
    /// Per-action verdict tuples.
    pub tuples: Vec<VerdictTuple>,
    /// Number of actions the guards failed to deny (the adversary survived).
    pub survivals: u32,
    /// Number of actions the guards correctly denied.
    pub defeats: u32,
}

impl FitnessSample {
    /// Total number of actions evaluated.
    pub fn total(&self) -> u32 {
        self.survivals.saturating_add(self.defeats)
    }

    /// Survival rate in `[0.0, 1.0]`. Returns `0.0` when the sample is
    /// empty so a zero-action population never escapes selection.
    pub fn survival_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        f64::from(self.survivals) / f64::from(total)
    }
}

/// Aggregated fitness report across all populations in one generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitnessReport {
    /// Per-population sample, keyed by population name.
    pub samples: BTreeMap<String, FitnessSample>,
}

impl FitnessReport {
    /// Survival rate of the highest-fitness population. Returns `0.0` when
    /// the report is empty.
    pub fn best_survival_rate(&self) -> f64 {
        self.samples
            .values()
            .map(|sample| sample.survival_rate())
            .fold(0.0_f64, f64::max)
    }

    /// Names of the populations sorted descending by survival rate. Ties
    /// break on population name (ascending) for determinism.
    pub fn ranked_population_names(&self) -> Vec<String> {
        let mut entries: Vec<(&String, f64)> = self
            .samples
            .iter()
            .map(|(name, sample)| (name, sample.survival_rate()))
            .collect();
        entries.sort_by(|a, b| match b.1.partial_cmp(&a.1) {
            Some(Ordering::Equal) | None => a.0.cmp(b.0),
            Some(other) => other,
        });
        entries
            .into_iter()
            .map(|(name, _rate)| name.clone())
            .collect()
    }
}

/// Fitness function inputs.
#[derive(Debug)]
pub struct FitnessInputs<'a> {
    /// The base scenario step the adversaries mutate.
    pub base_step: &'a ScenarioStep,
    /// The issued capability scope used by the toy guard evaluator.
    pub issued_scope: &'a IssuedScope,
}

/// Compute fitness for a single population. The supplied RNG sub-stream is
/// used for [`AdversaryPopulation::next_action`]; the caller is responsible
/// for keying the sub-stream off the scenario witness so two runs observe
/// the same byte sequence.
pub fn evaluate_population(
    population: &mut AdversaryPopulation,
    rng: &mut rand_chacha::ChaCha20Rng,
    inputs: FitnessInputs<'_>,
    rounds: u32,
) -> Result<FitnessSample, FitnessError> {
    if rounds == 0 {
        return Err(FitnessError::ZeroRounds);
    }
    let mut tuples = Vec::with_capacity(rounds as usize);
    let mut step_ids = Vec::with_capacity(rounds as usize);
    let mut survivals = 0u32;
    let mut defeats = 0u32;
    for _ in 0..rounds {
        let action = population.next_action(inputs.base_step, rng);
        let evaluation = evaluate_against_guards(&action, inputs.issued_scope);
        let tuple = VerdictTuple::from_evaluation(&evaluation, &action);
        if matches!(evaluation.verdict, ScenarioVerdict::Deny) {
            defeats = defeats.saturating_add(1);
        } else {
            survivals = survivals.saturating_add(1);
        }
        step_ids.push(action.mutated_step.id);
        tuples.push(tuple);
    }
    Ok(FitnessSample {
        class: population.class(),
        population: population.name().to_string(),
        step_ids,
        tuples,
        survivals,
        defeats,
    })
}

/// Errors raised by the fitness function.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FitnessError {
    /// Caller asked for zero rounds; the survival-rate definition is
    /// undefined in that case and the fitness function refuses to silently
    /// return zero.
    #[error("fitness evaluation requires a non-zero round count")]
    ZeroRounds,
}
