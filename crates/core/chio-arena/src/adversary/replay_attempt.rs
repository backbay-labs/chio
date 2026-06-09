//! Replay-attempt adversary class.
//!
//! Reuses a captured capability or nonce after expiry / revocation.
//! Intersects the `replay_attack` fixture family
//! (`tests/replay/fixtures/replay_attack/`); the arena consumes the same
//! nonce-reuse patterns the family encodes (immediate reuse, delayed
//! reuse, stale nonce, concurrent reuse) without duplicating the
//! fixtures.
//!
//! Each adversary writes a stable replayed nonce string into the mutated
//! step's arguments under [`REPLAYED_NONCE_KEY`]. The toy guard evaluator
//! denies the action when the nonce is in the kernel's seen-set or when the
//! issued capability is marked revoked. Real arena runs delegate to the
//! kernel's revocation store; the unit test asserts the fail-closed
//! contract without booting a kernel.

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde_json::{Map, Value};

use crate::scenario::{ScenarioAdversary, ScenarioStep, ScenarioVerdict};

use super::{Adversary, AdversaryAction, AdversaryClass, AdversaryError, AdversaryPopulation};

/// Argument key the adversary writes the replayed nonce into.
pub const REPLAYED_NONCE_KEY: &str = "replayed_nonce";

/// Stable reason marker.
pub const REASON: &str = "replay-attempt-denied";

/// Canonical pattern names. Aligned with the `replay_attack` fixture
/// family (`01_immediate_reuse`, `02_delayed_reuse`, `03_stale_nonce`,
/// `04_concurrent_reuse`). The arena consumes the family's pattern names
/// directly so audits that grep for "replay_attack" surface both sides.
pub const REPLAY_PATTERNS: &[&str] = &[
    "immediate-reuse",
    "delayed-reuse",
    "stale-nonce",
    "concurrent-reuse",
];

/// Replay-attempt adversary.
#[derive(Debug, Clone)]
pub struct ReplayAttemptAdversary {
    population: String,
    pattern: &'static str,
    captured_nonce: String,
}

impl ReplayAttemptAdversary {
    /// Build a new adversary. `captured_nonce` is the nonce string the
    /// adversary will replay; production arena runs source it from the
    /// kernel's seen-nonce store, unit tests pass a stable fixture value.
    pub fn new(
        population: impl Into<String>,
        pattern: &str,
        captured_nonce: impl Into<String>,
    ) -> Result<Self, AdversaryError> {
        let canonical = REPLAY_PATTERNS
            .iter()
            .copied()
            .find(|candidate| *candidate == pattern)
            .ok_or_else(|| AdversaryError::UnknownPattern {
                class: AdversaryClass::ReplayAttempt,
                pattern: pattern.to_string(),
            })?;
        Ok(Self {
            population: population.into(),
            pattern: canonical,
            captured_nonce: captured_nonce.into(),
        })
    }

    /// Pattern name.
    pub fn pattern(&self) -> &'static str {
        self.pattern
    }
}

impl Adversary for ReplayAttemptAdversary {
    fn class(&self) -> AdversaryClass {
        AdversaryClass::ReplayAttempt
    }

    fn population(&self) -> &str {
        &self.population
    }

    fn act(&self, base_step: &ScenarioStep, rng: &mut ChaCha20Rng) -> AdversaryAction {
        let entropy = rng.next_u64();
        let mut arguments_map = match base_step.arguments.clone() {
            Value::Object(map) => map,
            other => {
                let mut map = Map::new();
                map.insert("base".to_string(), other);
                map
            }
        };
        arguments_map.insert(
            REPLAYED_NONCE_KEY.to_string(),
            Value::String(self.captured_nonce.clone()),
        );
        let mut replay = Map::new();
        replay.insert("pattern".to_string(), Value::String(self.pattern.into()));
        replay.insert(
            "entropy".to_string(),
            Value::String(format!("{entropy:016x}")),
        );
        arguments_map.insert("replay_attempt".to_string(), Value::Object(replay));
        let mutated_step = ScenarioStep {
            id: format!("{}::{}::{}", base_step.id, self.population, self.pattern),
            agent: base_step.agent.clone(),
            server: base_step.server.clone(),
            tool: base_step.tool.clone(),
            arguments: Value::Object(arguments_map),
            expect_verdict: ScenarioVerdict::Deny,
        };
        AdversaryAction {
            class: AdversaryClass::ReplayAttempt,
            population: self.population.clone(),
            mutated_step,
            expected_verdict: ScenarioVerdict::Deny,
            reason_marker: REASON.to_string(),
        }
    }
}

/// Build a population from a DSL block.
///
/// Accepted parameters:
///
///   * `nonce` (string, required): captured nonce string to replay. Tests
///     usually set this to the same value the toy `IssuedScope::seen_nonces`
///     map carries.
///   * `patterns` (array of strings, optional): subset of [`REPLAY_PATTERNS`].
pub fn population_from_block(
    block: &ScenarioAdversary,
) -> Result<AdversaryPopulation, AdversaryError> {
    let nonce_value = block
        .params
        .get("nonce")
        .ok_or(AdversaryError::MissingParameter {
            population: block.population.clone(),
            parameter: "nonce",
        })?;
    let nonce = nonce_value
        .as_str()
        .ok_or(AdversaryError::InvalidParameterType {
            population: block.population.clone(),
            parameter: "nonce",
            expected: "string",
        })?;

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
            let canonical = REPLAY_PATTERNS
                .iter()
                .copied()
                .find(|candidate| *candidate == name)
                .ok_or_else(|| AdversaryError::UnknownPattern {
                    class: AdversaryClass::ReplayAttempt,
                    pattern: name.to_string(),
                })?;
            resolved.push(canonical);
        }
        if resolved.is_empty() {
            return Err(AdversaryError::EmptyPopulation(block.population.clone()));
        }
        resolved
    } else {
        REPLAY_PATTERNS.to_vec()
    };

    let members: Vec<Box<dyn Adversary + Send + Sync>> = patterns
        .into_iter()
        .map(|pattern| {
            ReplayAttemptAdversary::new(block.population.clone(), pattern, nonce.to_string())
                .map(|adv| Box::new(adv) as Box<dyn Adversary + Send + Sync>)
        })
        .collect::<Result<Vec<_>, AdversaryError>>()?;
    AdversaryPopulation::new(block.population.clone(), members)
}
