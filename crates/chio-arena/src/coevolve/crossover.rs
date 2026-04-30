//! Two-parent crossover operator (M08.P4.T3).
//!
//! Crossover splices two parent blueprints on agent-population boundaries:
//! the operator picks a deterministic split index, takes the prefix of
//! parent A's variant/escalation/entry/pattern list, and concatenates the
//! suffix of parent B's list. The output preserves the population name of
//! parent A so the resulting blueprint is still a valid population-block
//! body.
//!
//! The two parents must share the same class. Mixed-class crossover is
//! rejected by [`crossover_populations`] (returns
//! [`CrossoverError::ClassMismatch`]) so the driver cannot accidentally
//! form invalid offspring across the population pool.
//!
//! Determinism contract: same RNG sub-stream and same parents produce
//! byte-identical offspring. The split index is sampled from
//! `1..=min(parent_a.len(), parent_b.len())` so the prefix taken from
//! parent A and the suffix taken from parent B are both non-empty when
//! both parents have members. Sampling the upper bound from the shorter
//! parent guarantees `parent_b[split..]` is a strictly shorter suffix
//! than `parent_b` itself, so the offspring always mixes material from
//! both parents (the prior bound `1..=parent_a.len()` could collapse the
//! suffix to empty when `parent_a` was longer than `parent_b`).

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

use crate::coevolve::mutation::{
    OverrequestBlueprint, PopulationBlueprint, PromptInjectionBlueprint, ReplayAttemptBlueprint,
    ScopeEscapeBlueprint,
};

/// Errors raised by the crossover operator.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CrossoverError {
    /// Parents are of different classes.
    #[error("crossover requires both parents to share a class")]
    ClassMismatch,
    /// One of the parents has no members.
    #[error("crossover requires non-empty parents")]
    EmptyParent,
}

/// Cross two parent blueprints. Both parents must be of the same class.
pub fn crossover_populations(
    parent_a: &PopulationBlueprint,
    parent_b: &PopulationBlueprint,
    rng: &mut ChaCha20Rng,
) -> Result<PopulationBlueprint, CrossoverError> {
    match (parent_a, parent_b) {
        (PopulationBlueprint::PromptInjection(a), PopulationBlueprint::PromptInjection(b)) => {
            crossover_prompt_injection_population(a, b, rng)
                .map(PopulationBlueprint::PromptInjection)
        }
        (PopulationBlueprint::Overrequest(a), PopulationBlueprint::Overrequest(b)) => {
            crossover_overrequest_population(a, b, rng).map(PopulationBlueprint::Overrequest)
        }
        (PopulationBlueprint::ReplayAttempt(a), PopulationBlueprint::ReplayAttempt(b)) => {
            crossover_replay_attempt_population(a, b, rng).map(PopulationBlueprint::ReplayAttempt)
        }
        (PopulationBlueprint::ScopeEscape(a), PopulationBlueprint::ScopeEscape(b)) => {
            crossover_scope_escape_population(a, b, rng).map(PopulationBlueprint::ScopeEscape)
        }
        _ => Err(CrossoverError::ClassMismatch),
    }
}

/// Splice two prompt-injection blueprints at a deterministic boundary.
pub fn crossover_prompt_injection_population(
    parent_a: &PromptInjectionBlueprint,
    parent_b: &PromptInjectionBlueprint,
    rng: &mut ChaCha20Rng,
) -> Result<PromptInjectionBlueprint, CrossoverError> {
    if parent_a.patterns.is_empty() || parent_b.patterns.is_empty() {
        return Err(CrossoverError::EmptyParent);
    }
    let upper = parent_a.patterns.len().min(parent_b.patterns.len());
    let split = rng.gen_range(1..=upper);
    let mut patterns: Vec<&'static str> = parent_a.patterns[..split].to_vec();
    patterns.extend_from_slice(&parent_b.patterns[split..]);
    Ok(PromptInjectionBlueprint {
        population: parent_a.population.clone(),
        patterns,
    })
}

/// Splice two overrequest blueprints.
pub fn crossover_overrequest_population(
    parent_a: &OverrequestBlueprint,
    parent_b: &OverrequestBlueprint,
    rng: &mut ChaCha20Rng,
) -> Result<OverrequestBlueprint, CrossoverError> {
    if parent_a.variants.is_empty() || parent_b.variants.is_empty() {
        return Err(CrossoverError::EmptyParent);
    }
    let upper = parent_a.variants.len().min(parent_b.variants.len());
    let split = rng.gen_range(1..=upper);
    let mut variants = parent_a.variants[..split].to_vec();
    variants.extend_from_slice(&parent_b.variants[split..]);
    Ok(OverrequestBlueprint {
        population: parent_a.population.clone(),
        variants,
    })
}

/// Splice two replay-attempt blueprints.
pub fn crossover_replay_attempt_population(
    parent_a: &ReplayAttemptBlueprint,
    parent_b: &ReplayAttemptBlueprint,
    rng: &mut ChaCha20Rng,
) -> Result<ReplayAttemptBlueprint, CrossoverError> {
    if parent_a.entries.is_empty() || parent_b.entries.is_empty() {
        return Err(CrossoverError::EmptyParent);
    }
    let upper = parent_a.entries.len().min(parent_b.entries.len());
    let split = rng.gen_range(1..=upper);
    let mut entries = parent_a.entries[..split].to_vec();
    entries.extend_from_slice(&parent_b.entries[split..]);
    Ok(ReplayAttemptBlueprint {
        population: parent_a.population.clone(),
        entries,
    })
}

/// Splice two scope-escape blueprints.
pub fn crossover_scope_escape_population(
    parent_a: &ScopeEscapeBlueprint,
    parent_b: &ScopeEscapeBlueprint,
    rng: &mut ChaCha20Rng,
) -> Result<ScopeEscapeBlueprint, CrossoverError> {
    if parent_a.escalations.is_empty() || parent_b.escalations.is_empty() {
        return Err(CrossoverError::EmptyParent);
    }
    let upper = parent_a.escalations.len().min(parent_b.escalations.len());
    let split = rng.gen_range(1..=upper);
    let mut escalations = parent_a.escalations[..split].to_vec();
    escalations.extend_from_slice(&parent_b.escalations[split..]);
    Ok(ScopeEscapeBlueprint {
        population: parent_a.population.clone(),
        escalations,
    })
}
