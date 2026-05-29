//! Adversary populations for the Chio arena.
//!
//! An [`Adversary`] is a deterministic transformation: given a base
//! [`ScenarioStep`] (the candidate "honest" step to attack) and a
//! per-agent RNG sub-stream, the adversary emits an [`AdversaryAction`]
//! describing the mutated request and the verdict the kernel-and-guard
//! pool is expected to return.
//!
//! Each adversary class is fail-closed by construction: the toy guard
//! set used in unit tests is the local helper
//! [`evaluate_against_guards`], which mirrors the kernel's policy-shape
//! decision tree (capability-scope check, nonce-replay check,
//! scope-monotone delegation check). The arena does not invent a new
//! verdict comparator; the cross-provider verdict oracle remains the
//! production referee. The toy evaluator exists strictly so unit tests
//! can prove every class triggers fail-closed without reaching into a
//! real kernel build.
//!
//! ## Determinism contract
//!
//! Every adversary action is a pure function of:
//!
//!   1. the canonical scenario witness (rng_seed, virtual_clock_start),
//!   2. the per-agent RNG sub-stream consumed by [`Adversary::act`],
//!   3. the adversary class plus its population parameters.
//!
//! No wall-clock reads, thread-local state, or network IO. Two arena runs of
//! the same scenario produce byte-identical adversary actions.

use std::collections::BTreeMap;
use std::fmt;

use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::scenario::{ScenarioAdversary, ScenarioStep, ScenarioVerdict};

pub mod capability_overrequest;
pub mod prompt_injection;
pub mod replay_attempt;
pub mod scope_escape;

pub use capability_overrequest::CapabilityOverrequestAdversary;
pub use prompt_injection::PromptInjectionAdversary;
pub use replay_attempt::ReplayAttemptAdversary;
pub use scope_escape::ScopeEscapeAdversary;

/// Canonical adversary class identifiers used by the DSL block schema and
/// by the [`AdversaryClass::as_str`] mapping written into receipt manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdversaryClass {
    /// Mutates seed prompts using injection patterns.
    PromptInjection,
    /// Asks for scope outside the issued capability.
    CapabilityOverrequest,
    /// Reuses a captured capability after expiry / revocation.
    ReplayAttempt,
    /// Delegates with a scope larger than the issuer's.
    ScopeEscape,
}

impl AdversaryClass {
    /// Stable kebab-case identifier used in the scenario DSL block.
    pub const fn as_str(self) -> &'static str {
        match self {
            AdversaryClass::PromptInjection => "prompt-injection",
            AdversaryClass::CapabilityOverrequest => "capability-overrequest",
            AdversaryClass::ReplayAttempt => "replay-attempt",
            AdversaryClass::ScopeEscape => "scope-escape",
        }
    }

    /// Parse a kebab-case identifier into a class.
    pub fn parse(value: &str) -> Result<Self, AdversaryError> {
        match value {
            "prompt-injection" => Ok(AdversaryClass::PromptInjection),
            "capability-overrequest" => Ok(AdversaryClass::CapabilityOverrequest),
            "replay-attempt" => Ok(AdversaryClass::ReplayAttempt),
            "scope-escape" => Ok(AdversaryClass::ScopeEscape),
            other => Err(AdversaryError::UnknownClass(other.to_string())),
        }
    }
}

impl fmt::Display for AdversaryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic adversary action: a mutated scenario step plus the verdict
/// the guard pool is expected to return when the action is executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdversaryAction {
    /// The class of attack the action represents.
    pub class: AdversaryClass,
    /// Population entry name (matches the DSL `population` field for the
    /// owning [`ScenarioAdversary`] block). Useful when multiple
    /// populations of the same class share a scenario.
    pub population: String,
    /// Mutated step. Only fields the adversary touches are changed; other
    /// fields are copied from the base step verbatim.
    pub mutated_step: ScenarioStep,
    /// Verdict the guard pool is expected to return.
    pub expected_verdict: ScenarioVerdict,
    /// Stable reason marker recorded in the manifest. Tests use this to
    /// assert that the adversary surfaces the intended fail-closed reason.
    pub reason_marker: String,
}

/// Adversary trait. Each adversary class implements this surface.
pub trait Adversary {
    /// Class of the adversary.
    fn class(&self) -> AdversaryClass;

    /// Stable population name (free-form, supplied by the DSL).
    fn population(&self) -> &str;

    /// Drive one step. The implementation is required to be pure with
    /// respect to the supplied `rng` sub-stream; no other randomness or
    /// wall-clock reads are permitted.
    fn act(&self, base_step: &ScenarioStep, rng: &mut ChaCha20Rng) -> AdversaryAction;
}

/// Population of adversaries that share a class and a deterministic seed
/// derivation. The arena schedules one [`AdversaryAction`] per call to
/// [`AdversaryPopulation::next_action`]; the scheduler advances the RNG
/// sub-stream so successive calls produce divergent actions while still
/// being byte-identical across runs of the same scenario.
pub struct AdversaryPopulation {
    class: AdversaryClass,
    name: String,
    members: Vec<Box<dyn Adversary + Send + Sync>>,
    cursor: usize,
}

impl fmt::Debug for AdversaryPopulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdversaryPopulation")
            .field("class", &self.class)
            .field("name", &self.name)
            .field("members", &self.members.len())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl AdversaryPopulation {
    /// Build a population from a list of class members. The class is
    /// captured from the first member; mixing classes is rejected.
    pub fn new(
        name: impl Into<String>,
        members: Vec<Box<dyn Adversary + Send + Sync>>,
    ) -> Result<Self, AdversaryError> {
        let name = name.into();
        if members.is_empty() {
            return Err(AdversaryError::EmptyPopulation(name));
        }
        let class = members[0].class();
        for member in &members[1..] {
            if member.class() != class {
                return Err(AdversaryError::MixedClassPopulation {
                    population: name,
                    expected: class,
                    actual: member.class(),
                });
            }
        }
        Ok(Self {
            class,
            name,
            members,
            cursor: 0,
        })
    }

    /// Class of the population.
    pub fn class(&self) -> AdversaryClass {
        self.class
    }

    /// Population name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the population is empty. Construction rejects empty
    /// populations, so this is always `false` for a successfully built
    /// population; provided for trait completeness with `len`.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Drive the next member (round-robin) against `base_step`, advancing
    /// the supplied RNG sub-stream.
    pub fn next_action(
        &mut self,
        base_step: &ScenarioStep,
        rng: &mut ChaCha20Rng,
    ) -> AdversaryAction {
        let index = self.cursor % self.members.len();
        self.cursor = self.cursor.wrapping_add(1);
        // Indexing is bounded by the modulus above; using `[index]` keeps
        // the call site unwrap-free under the workspace `unwrap_used` lint.
        self.members[index].act(base_step, rng)
    }
}

/// Toy guard pool used by adversary unit tests.
///
/// The evaluator mirrors the shape of the kernel's fail-closed decision
/// tree without depending on a full kernel build: it asserts that
/// (capability scope, nonce reuse, scope-monotone delegation) all hold, and
/// returns [`ScenarioVerdict::Deny`] otherwise. Real arena runs delegate to
/// the kernel; this evaluator exists so adversary unit tests can prove the
/// fail-closed contract without booting a kernel.
#[derive(Debug, Clone)]
pub struct ToyGuardEvaluation {
    /// Verdict the guards return for the action.
    pub verdict: ScenarioVerdict,
    /// Stable reason marker for the verdict.
    pub reason: String,
}

/// Evaluate an adversary action against the toy guard pool. Returns the
/// verdict and a stable reason string.
pub fn evaluate_against_guards(
    action: &AdversaryAction,
    issued_scope: &IssuedScope,
) -> ToyGuardEvaluation {
    match action.class {
        AdversaryClass::PromptInjection => evaluate_prompt_injection(action),
        AdversaryClass::CapabilityOverrequest => evaluate_overrequest(action, issued_scope),
        AdversaryClass::ReplayAttempt => evaluate_replay_attempt(action, issued_scope),
        AdversaryClass::ScopeEscape => evaluate_scope_escape(action, issued_scope),
    }
}

/// Toy issued scope used by guard evaluation.
#[derive(Debug, Clone)]
pub struct IssuedScope {
    /// Server id the capability authorises.
    pub server: String,
    /// Tool name the capability authorises.
    pub tool: String,
    /// Set of nonces the kernel has already observed; reuse triggers
    /// fail-closed under the replay-attack family rules.
    pub seen_nonces: BTreeMap<String, ()>,
    /// Whether the capability has been revoked or expired.
    pub revoked: bool,
}

impl IssuedScope {
    /// Build a scope authorised for one (server, tool) pair, no observed
    /// nonces, and not revoked.
    pub fn allow(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            seen_nonces: BTreeMap::new(),
            revoked: false,
        }
    }
}

fn evaluate_prompt_injection(action: &AdversaryAction) -> ToyGuardEvaluation {
    // Prompt-injection adversaries mutate the seed prompt referenced by the
    // action's arguments. The toy evaluator surfaces the mutation by
    // checking for the canonical injection marker recorded by the
    // adversary; presence triggers fail-closed Deny with a stable reason.
    let arguments_str = action.mutated_step.arguments.to_string();
    if arguments_str.contains(prompt_injection::INJECTION_MARKER) {
        ToyGuardEvaluation {
            verdict: ScenarioVerdict::Deny,
            reason: action.reason_marker.clone(),
        }
    } else {
        ToyGuardEvaluation {
            verdict: ScenarioVerdict::Allow,
            reason: "no-injection".to_string(),
        }
    }
}

fn evaluate_overrequest(action: &AdversaryAction, issued: &IssuedScope) -> ToyGuardEvaluation {
    // Capability-overrequest adversaries ask for a (server, tool) pair
    // outside the issued scope. The fail-closed verdict is Deny when the
    // mutated step's scope is not a subset of the issued scope.
    if action.mutated_step.server != issued.server || action.mutated_step.tool != issued.tool {
        ToyGuardEvaluation {
            verdict: ScenarioVerdict::Deny,
            reason: action.reason_marker.clone(),
        }
    } else {
        ToyGuardEvaluation {
            verdict: ScenarioVerdict::Allow,
            reason: "scope-subset".to_string(),
        }
    }
}

fn evaluate_replay_attempt(action: &AdversaryAction, issued: &IssuedScope) -> ToyGuardEvaluation {
    // Replay attempts present a previously-observed nonce or a revoked
    // capability. The mutated arguments carry the replayed nonce under the
    // canonical key recorded by the adversary; the toy evaluator denies on
    // either signal.
    if issued.revoked {
        return ToyGuardEvaluation {
            verdict: ScenarioVerdict::Deny,
            reason: action.reason_marker.clone(),
        };
    }
    if let Some(nonce) = action
        .mutated_step
        .arguments
        .get(replay_attempt::REPLAYED_NONCE_KEY)
        .and_then(|value| value.as_str())
    {
        if issued.seen_nonces.contains_key(nonce) {
            return ToyGuardEvaluation {
                verdict: ScenarioVerdict::Deny,
                reason: action.reason_marker.clone(),
            };
        }
    }
    ToyGuardEvaluation {
        verdict: ScenarioVerdict::Allow,
        reason: "fresh-nonce".to_string(),
    }
}

fn evaluate_scope_escape(action: &AdversaryAction, issued: &IssuedScope) -> ToyGuardEvaluation {
    // Scope-superset escape adversaries delegate with a scope larger than
    // the issuer's. The toy evaluator inspects the canonical
    // `delegated_scope` argument injected by the adversary; if any element
    // is outside the issued scope, the verdict is Deny by scope-monotone
    // delegation rules.
    let delegated = action
        .mutated_step
        .arguments
        .get(scope_escape::DELEGATED_SCOPE_KEY);
    if let Some(serde_json::Value::Array(items)) = delegated {
        for entry in items {
            let server = entry.get("server").and_then(|value| value.as_str());
            let tool = entry.get("tool").and_then(|value| value.as_str());
            if server != Some(issued.server.as_str()) || tool != Some(issued.tool.as_str()) {
                return ToyGuardEvaluation {
                    verdict: ScenarioVerdict::Deny,
                    reason: action.reason_marker.clone(),
                };
            }
        }
    }
    ToyGuardEvaluation {
        verdict: ScenarioVerdict::Allow,
        reason: "scope-monotone".to_string(),
    }
}

/// Errors raised by the adversary surface.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdversaryError {
    /// The DSL block referenced an unknown class.
    #[error("unknown adversary class {0}")]
    UnknownClass(String),
    /// The DSL block (or constructor) referenced an unknown pattern within a
    /// class (e.g. an injection pattern or replay pattern that is not in the
    /// canonical set). Distinct from [`UnknownClass`] so callers can tell
    /// class-level and parameter-level failures apart.
    #[error("unknown adversary pattern {pattern} for class {class}")]
    UnknownPattern {
        /// Class the pattern was supplied to.
        class: AdversaryClass,
        /// Pattern name supplied by the caller / DSL.
        pattern: String,
    },
    /// The DSL block named an empty population.
    #[error("adversary population {0} is empty")]
    EmptyPopulation(String),
    /// Population members must share a class.
    #[error(
        "adversary population {population} mixes classes (expected {expected}, found {actual})"
    )]
    MixedClassPopulation {
        /// Population name.
        population: String,
        /// Class declared by the first member.
        expected: AdversaryClass,
        /// Conflicting class.
        actual: AdversaryClass,
    },
    /// Required adversary parameter missing.
    #[error("adversary block {population} missing required parameter {parameter}")]
    MissingParameter {
        /// Population name.
        population: String,
        /// Parameter name.
        parameter: &'static str,
    },
    /// Adversary parameter has an invalid type.
    #[error(
        "adversary block {population} parameter {parameter} has invalid type (expected {expected})"
    )]
    InvalidParameterType {
        /// Population name.
        population: String,
        /// Parameter name.
        parameter: &'static str,
        /// Expected TOML type.
        expected: &'static str,
    },
}

/// Resolve a [`ScenarioAdversary`] DSL block into a concrete population.
///
/// The DSL block's `class` field selects the implementation; the optional
/// `params` table is forwarded to the class constructor. The constructor is
/// expected to be deterministic: identical params produce identical
/// populations.
pub fn population_from_block(
    block: &ScenarioAdversary,
) -> Result<AdversaryPopulation, AdversaryError> {
    let class = AdversaryClass::parse(&block.class)?;
    match class {
        AdversaryClass::PromptInjection => prompt_injection::population_from_block(block),
        AdversaryClass::CapabilityOverrequest => {
            capability_overrequest::population_from_block(block)
        }
        AdversaryClass::ReplayAttempt => replay_attempt::population_from_block(block),
        AdversaryClass::ScopeEscape => scope_escape::population_from_block(block),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_round_trip() -> Result<(), AdversaryError> {
        let cases = [
            AdversaryClass::PromptInjection,
            AdversaryClass::CapabilityOverrequest,
            AdversaryClass::ReplayAttempt,
            AdversaryClass::ScopeEscape,
        ];
        for class in cases {
            assert_eq!(AdversaryClass::parse(class.as_str())?, class);
        }
        Ok(())
    }

    #[test]
    fn unknown_class_rejected() {
        assert!(matches!(
            AdversaryClass::parse("not-a-class"),
            Err(AdversaryError::UnknownClass(_))
        ));
    }
}
