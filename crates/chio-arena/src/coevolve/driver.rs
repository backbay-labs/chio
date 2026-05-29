//! Co-evolution driver.
//!
//! N-generation loop with elitism, fitness-proportional selection,
//! mutation, two-parent crossover, and a seed-corpus injection hook. The
//! loop runs entirely off the supplied scenario witness:
//!
//!   * `rng_seed` keys the root [`ChaCha20Rng`].
//!   * Per-generation sub-streams are derived from the root via
//!     `seed_from_u64` over a stable hash of the generation index so two
//!     runs of the same scenario observe byte-identical generation
//!     traces.
//!
//! The driver fails closed on budget exceedance: when either the
//! generation cap or the wall-clock cap is reached before the requested
//! generations complete, the run record is marked
//! [`CoevolutionOutcome::BudgetExceeded`] and the driver returns the best
//! population observed so far. The risk-register entry "co-evolution
//! budget blowout" is the rationale; the CI lane runs with a 5-minute
//! wall budget on PRs and a 30-minute budget nightly.
//!
//! Determinism contract: every value computed in this module is a pure
//! function of (witness, seed corpus fingerprint, parent blueprints).
//! Wall-clock time is consulted only for budget enforcement; it never
//! influences the generation trace, which is therefore byte-identical
//! across runs of the same scenario witness even when wall-clock budget
//! varies.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::adversary::{
    capability_overrequest::CapabilityOverrequestAdversary,
    prompt_injection::PromptInjectionAdversary, replay_attempt::ReplayAttemptAdversary,
    scope_escape::ScopeEscapeAdversary, Adversary, AdversaryError, AdversaryPopulation,
    IssuedScope,
};
use crate::coevolve::crossover::crossover_populations;
use crate::coevolve::mutation::{mutate_population, MutationConfig, PopulationBlueprint};
use crate::coevolve::seed_corpus::SeedCorpus;
use crate::coevolve::{evaluate_population, FitnessInputs, FitnessReport, FitnessSample};
use crate::scenario::ScenarioStep;

/// Co-evolution budget. Reaching either threshold ends the run with
/// [`CoevolutionOutcome::BudgetExceeded`].
#[derive(Debug, Clone, Copy)]
pub struct CoevolutionBudget {
    /// Maximum generation count.
    pub max_generations: u32,
    /// Maximum wall-clock duration.
    pub max_wall_clock: Duration,
}

impl Default for CoevolutionBudget {
    fn default() -> Self {
        // Canonical defaults: 200 generations and 30 minutes wall clock.
        // CI overrides to 5 minutes for PR lanes via
        // `with_wall_clock_seconds`; nightly uses the default.
        Self {
            max_generations: 200,
            max_wall_clock: Duration::from_secs(30 * 60),
        }
    }
}

impl CoevolutionBudget {
    /// Override the generation cap.
    pub fn with_max_generations(mut self, value: u32) -> Self {
        self.max_generations = value;
        self
    }

    /// Override the wall-clock cap (in seconds).
    pub fn with_wall_clock_seconds(mut self, seconds: u64) -> Self {
        self.max_wall_clock = Duration::from_secs(seconds);
        self
    }
}

/// Co-evolution driver configuration.
#[derive(Debug, Clone)]
pub struct CoevolutionConfig {
    /// Generation count requested by the caller. The loop may stop
    /// earlier if [`CoevolutionBudget`] is exceeded.
    pub generations: u32,
    /// Number of fittest individuals carried over unchanged each
    /// generation (elitism cap).
    pub elite_count: u32,
    /// Rounds of `next_action` called per population per generation.
    pub fitness_rounds: u32,
    /// Mutation configuration applied to non-elite offspring.
    pub mutation_config: MutationConfig,
    /// Bounded budget gate.
    pub budget: CoevolutionBudget,
}

impl Default for CoevolutionConfig {
    fn default() -> Self {
        Self {
            generations: 4,
            elite_count: 1,
            fitness_rounds: 2,
            mutation_config: MutationConfig::default(),
            budget: CoevolutionBudget::default(),
        }
    }
}

/// One row of the generation trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenerationTraceEntry {
    /// Generation index (0-based).
    pub generation: u32,
    /// Fitness samples keyed by population name.
    pub samples: BTreeMap<String, FitnessSample>,
    /// Population name with the highest survival rate.
    pub best_population: String,
    /// Survival rate of the best population.
    pub best_survival_rate: f64,
}

/// Generation trace recorded over the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenerationTrace {
    /// One entry per completed generation.
    pub entries: Vec<GenerationTraceEntry>,
    /// Stable identifier of the seed-corpus fingerprint observed at run
    /// open, recorded in the run record so corpus rotation surfaces.
    pub seed_corpus_fingerprint: String,
}

/// Outcome of a coevolution run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoevolutionOutcome {
    /// Run completed the requested generation count.
    Completed,
    /// Run hit a budget cap; the trace contains the partial result.
    BudgetExceeded,
}

/// Run record returned by [`run_coevolution`]. The blueprints contain
/// borrowed `&'static str` pattern names that do not round-trip through
/// `serde`; the determinism gate consumes [`GenerationTrace`] directly,
/// which is fully serialisable.
#[derive(Debug, Clone, PartialEq)]
pub struct CoevolutionRun {
    /// Final outcome.
    pub outcome: CoevolutionOutcome,
    /// Generation trace.
    pub trace: GenerationTrace,
    /// Final population blueprints, sorted by population name.
    pub final_blueprints: Vec<PopulationBlueprint>,
}

/// Errors raised by the driver.
#[derive(Debug, Error)]
pub enum DriverError {
    /// Caller passed zero parents.
    #[error("co-evolution requires at least one parent population")]
    EmptyPopulationPool,
    /// Caller asked for zero fitness rounds.
    #[error("co-evolution requires fitness_rounds >= 1")]
    ZeroFitnessRounds,
    /// Caller asked for zero generations.
    #[error("co-evolution requires generations >= 1")]
    ZeroGenerations,
    /// Adversary construction failed.
    #[error("adversary construction failed: {0}")]
    Adversary(#[from] AdversaryError),
    /// Crossover failed.
    #[error("crossover failed: {0}")]
    Crossover(#[from] crate::coevolve::crossover::CrossoverError),
    /// Mutation failed.
    #[error("mutation failed: {0}")]
    Mutation(#[from] crate::coevolve::mutation::MutationError),
    /// Fitness evaluation failed.
    #[error("fitness evaluation failed: {0}")]
    Fitness(#[from] crate::coevolve::FitnessError),
}

/// Convert a blueprint into a runtime [`AdversaryPopulation`]. Used by
/// the driver and by integration tests that want to feed driver outputs
/// directly into the arena runtime.
pub fn blueprint_to_population(
    blueprint: &PopulationBlueprint,
) -> Result<AdversaryPopulation, AdversaryError> {
    match blueprint {
        PopulationBlueprint::PromptInjection(value) => {
            let mut members: Vec<Box<dyn Adversary + Send + Sync>> = Vec::new();
            for pattern in &value.patterns {
                members.push(Box::new(PromptInjectionAdversary::new(
                    value.population.clone(),
                    pattern,
                )?));
            }
            AdversaryPopulation::new(value.population.clone(), members)
        }
        PopulationBlueprint::Overrequest(value) => {
            let mut members: Vec<Box<dyn Adversary + Send + Sync>> = Vec::new();
            for variant in &value.variants {
                members.push(Box::new(CapabilityOverrequestAdversary::new(
                    value.population.clone(),
                    variant.clone(),
                )));
            }
            AdversaryPopulation::new(value.population.clone(), members)
        }
        PopulationBlueprint::ReplayAttempt(value) => {
            let mut members: Vec<Box<dyn Adversary + Send + Sync>> = Vec::new();
            for entry in &value.entries {
                members.push(Box::new(ReplayAttemptAdversary::new(
                    value.population.clone(),
                    entry.pattern,
                    entry.captured_nonce.clone(),
                )?));
            }
            AdversaryPopulation::new(value.population.clone(), members)
        }
        PopulationBlueprint::ScopeEscape(value) => {
            let mut members: Vec<Box<dyn Adversary + Send + Sync>> = Vec::new();
            for escalation in &value.escalations {
                members.push(Box::new(ScopeEscapeAdversary::new(
                    value.population.clone(),
                    escalation.clone(),
                )));
            }
            AdversaryPopulation::new(value.population.clone(), members)
        }
    }
}

/// Inputs to the driver loop.
#[derive(Debug)]
pub struct CoevolutionInputs<'a> {
    /// Scenario base step (driven through every adversary action).
    pub base_step: &'a ScenarioStep,
    /// Issued capability scope used by the toy guard pool.
    pub issued_scope: &'a IssuedScope,
    /// Initial parent blueprints.
    pub parents: Vec<PopulationBlueprint>,
    /// Seed corpus (used here only for its fingerprint; the downstream
    /// promote pipeline consumes the artifacts directly).
    pub seed_corpus: &'a SeedCorpus,
    /// Driver configuration.
    pub config: CoevolutionConfig,
    /// Witness seed (the scenario `rng_seed`).
    pub witness_seed: u64,
}

/// Run the co-evolution loop. The wall-clock budget is consulted between
/// generations so a generation in flight always completes; the trace
/// therefore contains a contiguous prefix of generation entries when the
/// budget is exceeded, never a half-evaluated row.
pub fn run_coevolution(inputs: CoevolutionInputs<'_>) -> Result<CoevolutionRun, DriverError> {
    if inputs.parents.is_empty() {
        return Err(DriverError::EmptyPopulationPool);
    }
    if inputs.config.fitness_rounds == 0 {
        return Err(DriverError::ZeroFitnessRounds);
    }
    if inputs.config.generations == 0 {
        return Err(DriverError::ZeroGenerations);
    }

    // The generation budget caps how many iterations we will run. When the
    // configured `generations` exceeds the budget's `max_generations` we
    // run up to the cap and report `BudgetExceeded`; the original
    // `generations` is preserved so the run is auditable. When the budget
    // is generous we run the full configured count and report `Completed`.
    let configured_generations = inputs.config.generations;
    let target_generations = configured_generations.min(inputs.config.budget.max_generations);
    let generation_budget_capped = configured_generations > target_generations;
    let started_at = Instant::now();
    let mut population_pool = inputs.parents.clone();

    let mut entries = Vec::with_capacity(target_generations as usize);
    let mut outcome = if generation_budget_capped {
        CoevolutionOutcome::BudgetExceeded
    } else {
        CoevolutionOutcome::Completed
    };

    for generation in 0..target_generations {
        if started_at.elapsed() >= inputs.config.budget.max_wall_clock {
            outcome = CoevolutionOutcome::BudgetExceeded;
            break;
        }
        let mut rng = generation_rng(inputs.witness_seed, generation);

        // Evaluate every blueprint in the pool.
        let mut samples: BTreeMap<String, FitnessSample> = BTreeMap::new();
        for blueprint in &population_pool {
            let mut population = blueprint_to_population(blueprint)?;
            let sample = evaluate_population(
                &mut population,
                &mut rng,
                FitnessInputs {
                    base_step: inputs.base_step,
                    issued_scope: inputs.issued_scope,
                },
                inputs.config.fitness_rounds,
            )?;
            samples.insert(sample.population.clone(), sample);
        }
        let report = FitnessReport {
            samples: samples.clone(),
        };
        let best_population = report
            .ranked_population_names()
            .into_iter()
            .next()
            .unwrap_or_default();
        let best_survival_rate = report.best_survival_rate();

        entries.push(GenerationTraceEntry {
            generation,
            samples,
            best_population,
            best_survival_rate,
        });

        // Form the next pool: elitism + crossover + mutation. Last
        // generation skips reproduction so the final pool reflects the
        // measured fitness.
        if generation + 1 == target_generations {
            continue;
        }
        population_pool = next_generation(&population_pool, &report, &mut rng, &inputs.config)?;
    }

    if entries.len() < target_generations as usize
        && matches!(outcome, CoevolutionOutcome::Completed)
    {
        outcome = CoevolutionOutcome::BudgetExceeded;
    }

    let mut final_blueprints = population_pool;
    final_blueprints.sort_by(|a, b| population_name(a).cmp(population_name(b)));

    Ok(CoevolutionRun {
        outcome,
        trace: GenerationTrace {
            entries,
            seed_corpus_fingerprint: inputs.seed_corpus.fingerprint_hex(),
        },
        final_blueprints,
    })
}

fn population_name(blueprint: &PopulationBlueprint) -> &str {
    match blueprint {
        PopulationBlueprint::PromptInjection(value) => &value.population,
        PopulationBlueprint::Overrequest(value) => &value.population,
        PopulationBlueprint::ReplayAttempt(value) => &value.population,
        PopulationBlueprint::ScopeEscape(value) => &value.population,
    }
}

fn generation_rng(witness_seed: u64, generation: u32) -> ChaCha20Rng {
    // FNV-1a 64-bit folded over the witness seed and the generation
    // index. Mirrors the per-agent derivation in `crate::rng` so the
    // arena's seeds and the driver's seeds share a derivation style.
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in witness_seed.to_be_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^= u64::from(b':');
    hash = hash.wrapping_mul(FNV_PRIME);
    for byte in generation.to_be_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    ChaCha20Rng::seed_from_u64(hash)
}

fn next_generation(
    population_pool: &[PopulationBlueprint],
    report: &FitnessReport,
    rng: &mut ChaCha20Rng,
    config: &CoevolutionConfig,
) -> Result<Vec<PopulationBlueprint>, DriverError> {
    let target_size = population_pool.len();
    if target_size == 0 {
        return Ok(Vec::new());
    }

    // Elitism: take the top-K by survival rate.
    let ranked = report.ranked_population_names();
    let elite_count = (config.elite_count as usize).min(target_size);
    let mut next_pool: Vec<PopulationBlueprint> = Vec::with_capacity(target_size);
    for name in ranked.iter().take(elite_count) {
        if let Some(blueprint) = population_pool
            .iter()
            .find(|candidate| population_name(candidate) == name.as_str())
        {
            next_pool.push(blueprint.clone());
        }
    }

    // Selection wheel: fitness-proportional with a +1 bias so a
    // zero-survival pool still produces offspring.
    let mut wheel: Vec<(usize, f64)> = Vec::with_capacity(population_pool.len());
    let mut total = 0.0_f64;
    for (idx, blueprint) in population_pool.iter().enumerate() {
        let name = population_name(blueprint);
        let weight = report
            .samples
            .get(name)
            .map(FitnessSample::survival_rate)
            .unwrap_or(0.0)
            + 1.0;
        total += weight;
        wheel.push((idx, total));
    }

    while next_pool.len() < target_size {
        let parent_a_idx = sample_wheel(&wheel, total, rng);
        let parent_b_idx = sample_wheel(&wheel, total, rng);
        let parent_a = &population_pool[parent_a_idx];
        let parent_b = &population_pool[parent_b_idx];
        let crossed = if same_class(parent_a, parent_b) {
            crossover_populations(parent_a, parent_b, rng)?
        } else {
            parent_a.clone()
        };
        let (mutated, _kind) = mutate_population(crossed, rng, config.mutation_config)?;
        next_pool.push(mutated);
    }

    Ok(next_pool)
}

fn same_class(a: &PopulationBlueprint, b: &PopulationBlueprint) -> bool {
    matches!(
        (a, b),
        (
            PopulationBlueprint::PromptInjection(_),
            PopulationBlueprint::PromptInjection(_)
        ) | (
            PopulationBlueprint::Overrequest(_),
            PopulationBlueprint::Overrequest(_)
        ) | (
            PopulationBlueprint::ReplayAttempt(_),
            PopulationBlueprint::ReplayAttempt(_)
        ) | (
            PopulationBlueprint::ScopeEscape(_),
            PopulationBlueprint::ScopeEscape(_)
        )
    )
}

fn sample_wheel(wheel: &[(usize, f64)], total: f64, rng: &mut ChaCha20Rng) -> usize {
    if total <= 0.0 || wheel.is_empty() {
        // Drain one u64 anyway so the RNG advances deterministically.
        let _ = rng.next_u64();
        return 0;
    }
    let pick = rng.gen::<f64>() * total;
    for (idx, threshold) in wheel {
        if pick <= *threshold {
            return *idx;
        }
    }
    // Fallback: last entry.
    wheel.last().map(|(idx, _)| *idx).unwrap_or(0)
}
