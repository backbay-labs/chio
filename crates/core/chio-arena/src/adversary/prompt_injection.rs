//! Prompt-injection adversary class.
//!
//! Mutates the seed prompt referenced by the base scenario step using
//! injection patterns drawn from the fuzz seed corpus (see
//! `fuzz/artifacts/`). The arena does NOT vendor the corpus into the
//! crate; the soft-dep is captured by storing the canonical injection
//! pattern names as constants here, and the runtime feeds the corpus
//! bytes through the same code path when wired up.
//!
//! The adversary writes a stable injection marker (`INJECTION_MARKER`)
//! plus the chosen pattern name into the mutated step's arguments under
//! the `prompt_injection` key. The toy guard evaluator in `mod.rs`
//! denies any action whose arguments contain the marker, which mirrors
//! the kernel's prompt-shield decision tree (the real shield is a
//! downstream concern; the unit test only asserts fail-closed by
//! construction).

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde_json::{Map, Value};

use crate::scenario::{ScenarioAdversary, ScenarioStep, ScenarioVerdict};

use super::{Adversary, AdversaryAction, AdversaryClass, AdversaryError, AdversaryPopulation};

/// Stable marker emitted into mutated step arguments. The toy guard
/// evaluator searches for this string; receipt manifests can grep for it.
pub const INJECTION_MARKER: &str = "chio:adversarial:prompt-injection";

/// Canonical injection pattern names. The names align with the fuzz
/// corpus categories so the dataflow between the fuzz corpus and the
/// arena adversary surface is greppable.
pub const INJECTION_PATTERNS: &[&str] = &[
    "ignore-previous-instructions",
    "system-prompt-leak",
    "tool-name-spoof",
    "json-payload-smuggle",
    "delimiter-confusion",
];

/// Stable reason marker recorded in [`AdversaryAction::reason_marker`].
pub const REASON: &str = "prompt-injection-detected";

/// Prompt-injection adversary. One instance per pattern so the population
/// round-robins through the canonical pattern set.
#[derive(Debug, Clone)]
pub struct PromptInjectionAdversary {
    population: String,
    pattern: &'static str,
}

impl PromptInjectionAdversary {
    /// Build an adversary for `pattern`. The pattern must be one of
    /// [`INJECTION_PATTERNS`].
    pub fn new(population: impl Into<String>, pattern: &str) -> Result<Self, AdversaryError> {
        let canonical = INJECTION_PATTERNS
            .iter()
            .copied()
            .find(|candidate| *candidate == pattern)
            .ok_or_else(|| AdversaryError::UnknownPattern {
                class: AdversaryClass::PromptInjection,
                pattern: pattern.to_string(),
            })?;
        Ok(Self {
            population: population.into(),
            pattern: canonical,
        })
    }

    /// Pattern this adversary injects.
    pub fn pattern(&self) -> &'static str {
        self.pattern
    }
}

impl Adversary for PromptInjectionAdversary {
    fn class(&self) -> AdversaryClass {
        AdversaryClass::PromptInjection
    }

    fn population(&self) -> &str {
        &self.population
    }

    fn act(&self, base_step: &ScenarioStep, rng: &mut ChaCha20Rng) -> AdversaryAction {
        // Consume one u64 from the RNG sub-stream so successive populations
        // observe distinct snapshots; the value is folded into the
        // mutated arguments so the determinism gate sees the entropy.
        let entropy = rng.next_u64();

        let mut arguments_map = match base_step.arguments.clone() {
            Value::Object(map) => map,
            other => {
                let mut map = Map::new();
                map.insert("base".to_string(), other);
                map
            }
        };
        let mut injection = Map::new();
        injection.insert("marker".to_string(), Value::String(INJECTION_MARKER.into()));
        injection.insert("pattern".to_string(), Value::String(self.pattern.into()));
        injection.insert(
            "entropy".to_string(),
            Value::String(format!("{entropy:016x}")),
        );
        arguments_map.insert("prompt_injection".to_string(), Value::Object(injection));
        let mutated_step = ScenarioStep {
            id: format!("{}::{}::{}", base_step.id, self.population, self.pattern),
            agent: base_step.agent.clone(),
            server: base_step.server.clone(),
            tool: base_step.tool.clone(),
            arguments: Value::Object(arguments_map),
            expect_verdict: ScenarioVerdict::Deny,
        };
        AdversaryAction {
            class: AdversaryClass::PromptInjection,
            population: self.population.clone(),
            mutated_step,
            expected_verdict: ScenarioVerdict::Deny,
            reason_marker: REASON.to_string(),
        }
    }
}

/// Build a population from the supplied DSL block.
///
/// Accepted parameters:
///
///   * `patterns` (array of strings, optional): subset of
///     [`INJECTION_PATTERNS`]; defaults to the full canonical set.
pub fn population_from_block(
    block: &ScenarioAdversary,
) -> Result<AdversaryPopulation, AdversaryError> {
    let patterns: Vec<&'static str> = if let Some(value) = block.params.get("patterns") {
        let array = value
            .as_array()
            .ok_or(AdversaryError::InvalidParameterType {
                population: block.population.clone(),
                parameter: "patterns",
                expected: "array of strings",
            })?;
        let mut resolved = Vec::with_capacity(array.len());
        for entry in array {
            let name = entry.as_str().ok_or(AdversaryError::InvalidParameterType {
                population: block.population.clone(),
                parameter: "patterns",
                expected: "array of strings",
            })?;
            let canonical = INJECTION_PATTERNS
                .iter()
                .copied()
                .find(|candidate| *candidate == name)
                .ok_or_else(|| AdversaryError::UnknownPattern {
                    class: AdversaryClass::PromptInjection,
                    pattern: name.to_string(),
                })?;
            resolved.push(canonical);
        }
        if resolved.is_empty() {
            return Err(AdversaryError::EmptyPopulation(block.population.clone()));
        }
        resolved
    } else {
        INJECTION_PATTERNS.to_vec()
    };

    let members: Vec<Box<dyn Adversary + Send + Sync>> = patterns
        .into_iter()
        .map(|pattern| {
            PromptInjectionAdversary::new(block.population.clone(), pattern)
                .map(|adv| Box::new(adv) as Box<dyn Adversary + Send + Sync>)
        })
        .collect::<Result<Vec<_>, AdversaryError>>()?;
    AdversaryPopulation::new(block.population.clone(), members)
}
