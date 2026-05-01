//! DSL-aware mutation operator.
//!
//! Mutation is a deterministic, single-field perturbation applied to an
//! adversary population blueprint. The operator never touches the
//! determinism witness (rng_seed, virtual_clock_start, scheduler, locale)
//! or any field outside the `[[adversaries]]` block: the contract is that
//! a mutated population is still a valid input to
//! [`crate::adversary::population_from_block`] without re-validation of
//! the surrounding scenario witness.
//!
//! Each adversary class supplies its own per-field strategy via a typed
//! blueprint structure ([`PromptInjectionBlueprint`],
//! [`OverrequestBlueprint`], [`ReplayAttemptBlueprint`],
//! [`ScopeEscapeBlueprint`]). The operator selects one field to perturb on
//! each call; the choice is driven by the supplied `ChaCha20Rng`
//! sub-stream so two runs of the same scenario produce byte-identical
//! mutations.
//!
//! Determinism contract: every value computed in this module is a pure
//! function of the supplied RNG sub-stream and the input blueprint. No
//! wall-clock reads, no thread-local randomness, no hash randomization.

use rand::{Rng, RngCore};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

use crate::adversary::{
    capability_overrequest::OverrequestVariant, prompt_injection::INJECTION_PATTERNS,
    replay_attempt::REPLAY_PATTERNS, scope_escape::ScopeEscalation,
};

/// Mutation operator configuration. Reserved for future per-field rate
/// tuning; today the operator selects one field uniformly at random and
/// applies a class-specific perturbation. Two configurations exist so the
/// driver can ratchet down mutation pressure across generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationConfig {
    /// Maximum number of mutations applied per call. The operator fires
    /// exactly one mutation when the value is `1` (the default) and chains
    /// up to `max_mutations` when the driver wants stronger perturbations.
    pub max_mutations: u8,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self { max_mutations: 1 }
    }
}

/// Discriminator for per-class mutation kinds. Recorded in receipt
/// manifests so failed adversaries surface the perturbation that produced
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    /// Replaced a prompt-injection pattern with a different canonical entry.
    PromptInjectionPatternSwap,
    /// Reordered the prompt-injection pattern list deterministically.
    PromptInjectionReorder,
    /// Toggled the target server of a capability-overrequest variant.
    OverrequestSwapServer,
    /// Toggled the target tool of a capability-overrequest variant.
    OverrequestSwapTool,
    /// Swapped the captured nonce string of a replay-attempt entry.
    ReplayAttemptSwapNonce,
    /// Replaced a replay-attempt pattern with another canonical entry.
    ReplayAttemptPatternSwap,
    /// Replaced the server of a scope-escape escalation.
    ScopeEscapeSwapServer,
    /// Replaced the tool of a scope-escape escalation.
    ScopeEscapeSwapTool,
    /// No-op: the population had no mutable field for the selected
    /// strategy. Returned so the driver can advance generations even when
    /// a population has degenerate input.
    NoOp,
}

/// Errors raised by the mutation operator.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MutationError {
    /// Empty input population.
    #[error("mutation input is empty")]
    EmptyPopulation,
    /// Configured mutation count is zero.
    #[error("mutation_config.max_mutations must be at least 1")]
    ZeroMutationCount,
}

/// Generic mutation driver: dispatches to the per-class operator. The
/// returned blueprint is a fresh instance; the input is left untouched
/// (mutators do not need `&mut`).
pub fn mutate_population(
    blueprint: PopulationBlueprint,
    rng: &mut ChaCha20Rng,
    config: MutationConfig,
) -> Result<(PopulationBlueprint, MutationKind), MutationError> {
    if config.max_mutations == 0 {
        return Err(MutationError::ZeroMutationCount);
    }
    match blueprint {
        PopulationBlueprint::PromptInjection(value) => {
            let (mutated, kind) = mutate_prompt_injection_population(&value, rng, config)?;
            Ok((PopulationBlueprint::PromptInjection(mutated), kind))
        }
        PopulationBlueprint::Overrequest(value) => {
            let (mutated, kind) = mutate_overrequest_population(&value, rng, config)?;
            Ok((PopulationBlueprint::Overrequest(mutated), kind))
        }
        PopulationBlueprint::ReplayAttempt(value) => {
            let (mutated, kind) = mutate_replay_attempt_population(&value, rng, config)?;
            Ok((PopulationBlueprint::ReplayAttempt(mutated), kind))
        }
        PopulationBlueprint::ScopeEscape(value) => {
            let (mutated, kind) = mutate_scope_escape_population(&value, rng, config)?;
            Ok((PopulationBlueprint::ScopeEscape(mutated), kind))
        }
    }
}

/// Typed view of a population suitable for mutation. The arena's runtime
/// builds populations through [`crate::adversary::population_from_block`];
/// the co-evolution loop instead operates on these blueprints, which are
/// the statically typed pre-images of those runtime populations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopulationBlueprint {
    /// Prompt-injection blueprint.
    PromptInjection(PromptInjectionBlueprint),
    /// Capability-overrequest blueprint.
    Overrequest(OverrequestBlueprint),
    /// Replay-attempt blueprint.
    ReplayAttempt(ReplayAttemptBlueprint),
    /// Scope-escape blueprint.
    ScopeEscape(ScopeEscapeBlueprint),
}

/// Blueprint for the prompt-injection class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptInjectionBlueprint {
    /// Population name.
    pub population: String,
    /// Ordered list of canonical patterns. Each entry must be one of
    /// [`INJECTION_PATTERNS`].
    pub patterns: Vec<&'static str>,
}

/// Blueprint for the capability-overrequest class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrequestBlueprint {
    /// Population name.
    pub population: String,
    /// Variants the population round-robins through.
    pub variants: Vec<OverrequestVariant>,
}

/// Blueprint for the replay-attempt class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAttemptBlueprint {
    /// Population name.
    pub population: String,
    /// One entry per population member: pattern name plus captured nonce.
    pub entries: Vec<ReplayAttemptEntry>,
}

/// One replay-attempt blueprint entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAttemptEntry {
    /// One of [`REPLAY_PATTERNS`].
    pub pattern: &'static str,
    /// Nonce string the adversary will replay.
    pub captured_nonce: String,
}

/// Blueprint for the scope-escape class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEscapeBlueprint {
    /// Population name.
    pub population: String,
    /// Escalation list.
    pub escalations: Vec<ScopeEscalation>,
}

/// Mutate a prompt-injection blueprint. Strategies:
///
///   1. Pattern swap: replace one pattern with a different canonical entry.
///   2. Reorder: rotate the pattern list left by one (deterministic).
pub fn mutate_prompt_injection_population(
    blueprint: &PromptInjectionBlueprint,
    rng: &mut ChaCha20Rng,
    _config: MutationConfig,
) -> Result<(PromptInjectionBlueprint, MutationKind), MutationError> {
    if blueprint.patterns.is_empty() {
        return Err(MutationError::EmptyPopulation);
    }
    let strategy = rng.gen_range(0..2u8);
    let mut mutated = blueprint.clone();
    match strategy {
        0 => {
            // Pattern swap.
            let index = rng.gen_range(0..mutated.patterns.len());
            let mut alternatives: Vec<&'static str> = INJECTION_PATTERNS
                .iter()
                .copied()
                .filter(|candidate| *candidate != mutated.patterns[index])
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.patterns[index] = alternatives.swap_remove(pick);
            Ok((mutated, MutationKind::PromptInjectionPatternSwap))
        }
        _ => {
            // Reorder.
            mutated.patterns.rotate_left(1);
            Ok((mutated, MutationKind::PromptInjectionReorder))
        }
    }
}

/// Mutate a capability-overrequest blueprint. Strategies:
///
///   1. Server swap on a randomly chosen variant.
///   2. Tool swap on a randomly chosen variant.
pub fn mutate_overrequest_population(
    blueprint: &OverrequestBlueprint,
    rng: &mut ChaCha20Rng,
    _config: MutationConfig,
) -> Result<(OverrequestBlueprint, MutationKind), MutationError> {
    if blueprint.variants.is_empty() {
        return Err(MutationError::EmptyPopulation);
    }
    let strategy = rng.gen_range(0..2u8);
    let mut mutated = blueprint.clone();
    let index = rng.gen_range(0..mutated.variants.len());
    const SERVERS: &[&str] = &["filesystem", "secrets", "network", "compute"];
    const TOOLS: &[&str] = &["read_file", "write_file", "exec_shell", "http_post"];
    match strategy {
        0 => {
            let current = mutated.variants[index].target_server.clone();
            let alternatives: Vec<&str> = SERVERS
                .iter()
                .copied()
                .filter(|candidate| *candidate != current.as_str())
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.variants[index].target_server = alternatives[pick].to_string();
            Ok((mutated, MutationKind::OverrequestSwapServer))
        }
        _ => {
            let current = mutated.variants[index].target_tool.clone();
            let alternatives: Vec<&str> = TOOLS
                .iter()
                .copied()
                .filter(|candidate| *candidate != current.as_str())
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.variants[index].target_tool = alternatives[pick].to_string();
            Ok((mutated, MutationKind::OverrequestSwapTool))
        }
    }
}

/// Mutate a replay-attempt blueprint. Strategies:
///
///   1. Swap captured nonce for a fresh deterministic value.
///   2. Pattern swap to a different canonical entry.
pub fn mutate_replay_attempt_population(
    blueprint: &ReplayAttemptBlueprint,
    rng: &mut ChaCha20Rng,
    _config: MutationConfig,
) -> Result<(ReplayAttemptBlueprint, MutationKind), MutationError> {
    if blueprint.entries.is_empty() {
        return Err(MutationError::EmptyPopulation);
    }
    let strategy = rng.gen_range(0..2u8);
    let mut mutated = blueprint.clone();
    let index = rng.gen_range(0..mutated.entries.len());
    match strategy {
        0 => {
            // Generate a fresh nonce from the RNG sub-stream so the result
            // is deterministic but distinct from the input.
            let raw = rng.next_u64();
            mutated.entries[index].captured_nonce = format!("nonce-{raw:016x}");
            Ok((mutated, MutationKind::ReplayAttemptSwapNonce))
        }
        _ => {
            let current = mutated.entries[index].pattern;
            let alternatives: Vec<&'static str> = REPLAY_PATTERNS
                .iter()
                .copied()
                .filter(|candidate| *candidate != current)
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.entries[index].pattern = alternatives[pick];
            Ok((mutated, MutationKind::ReplayAttemptPatternSwap))
        }
    }
}

/// Mutate a scope-escape blueprint. Strategies:
///
///   1. Server swap on a randomly chosen escalation.
///   2. Tool swap on a randomly chosen escalation.
pub fn mutate_scope_escape_population(
    blueprint: &ScopeEscapeBlueprint,
    rng: &mut ChaCha20Rng,
    _config: MutationConfig,
) -> Result<(ScopeEscapeBlueprint, MutationKind), MutationError> {
    if blueprint.escalations.is_empty() {
        return Err(MutationError::EmptyPopulation);
    }
    let strategy = rng.gen_range(0..2u8);
    let mut mutated = blueprint.clone();
    let index = rng.gen_range(0..mutated.escalations.len());
    const SERVERS: &[&str] = &["filesystem", "secrets", "network", "compute", "*"];
    const TOOLS: &[&str] = &["read_file", "write_file", "exec_shell", "http_post", "*"];
    match strategy {
        0 => {
            let current = mutated.escalations[index].server.clone();
            let alternatives: Vec<&str> = SERVERS
                .iter()
                .copied()
                .filter(|candidate| *candidate != current.as_str())
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.escalations[index].server = alternatives[pick].to_string();
            Ok((mutated, MutationKind::ScopeEscapeSwapServer))
        }
        _ => {
            let current = mutated.escalations[index].tool.clone();
            let alternatives: Vec<&str> = TOOLS
                .iter()
                .copied()
                .filter(|candidate| *candidate != current.as_str())
                .collect();
            if alternatives.is_empty() {
                return Ok((mutated, MutationKind::NoOp));
            }
            let pick = rng.gen_range(0..alternatives.len());
            mutated.escalations[index].tool = alternatives[pick].to_string();
            Ok((mutated, MutationKind::ScopeEscapeSwapTool))
        }
    }
}
