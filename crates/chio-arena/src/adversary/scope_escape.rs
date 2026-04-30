//! Scope-superset escape adversary class (P3.T5).
//!
//! Delegates with a scope larger than the issuer's. The kernel's
//! scope-monotone delegation rule (proven by the trajectory-1 M03
//! capability algebra proptest plus Kani harness) requires every delegated
//! scope to be a subset of the delegating capability's scope. This
//! adversary triggers the property and asserts fail-closed.
//!
//! Each adversary writes a canonical `delegated_scope` array into the
//! mutated step's arguments. The toy guard evaluator denies the action
//! when any element of the delegated scope is outside the issued scope;
//! real arena runs delegate to the kernel's authority surface.

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde_json::{Map, Value};

use crate::scenario::{ScenarioAdversary, ScenarioStep, ScenarioVerdict};

use super::{Adversary, AdversaryAction, AdversaryClass, AdversaryError, AdversaryPopulation};

/// Argument key the adversary writes the delegated-scope array into.
pub const DELEGATED_SCOPE_KEY: &str = "delegated_scope";

/// Stable reason marker.
pub const REASON: &str = "scope-superset-denied";

/// One delegated scope entry the adversary will inject. Each entry is a
/// (server, tool) pair that escalates beyond the issuer's grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEscalation {
    /// Stable variant label.
    pub label: String,
    /// Server the adversary tries to grant.
    pub server: String,
    /// Tool the adversary tries to grant.
    pub tool: String,
}

/// Default canonical escalations.
pub fn default_escalations() -> Vec<ScopeEscalation> {
    vec![
        ScopeEscalation {
            label: "broaden-tool".to_string(),
            server: "filesystem".to_string(),
            tool: "write_file".to_string(),
        },
        ScopeEscalation {
            label: "cross-server".to_string(),
            server: "secrets".to_string(),
            tool: "read_file".to_string(),
        },
        ScopeEscalation {
            label: "wildcard-server".to_string(),
            server: "*".to_string(),
            tool: "*".to_string(),
        },
    ]
}

/// Scope-superset escape adversary.
#[derive(Debug, Clone)]
pub struct ScopeEscapeAdversary {
    population: String,
    escalation: ScopeEscalation,
}

impl ScopeEscapeAdversary {
    /// Build a new adversary.
    pub fn new(population: impl Into<String>, escalation: ScopeEscalation) -> Self {
        Self {
            population: population.into(),
            escalation,
        }
    }

    /// Escalation label.
    pub fn label(&self) -> &str {
        &self.escalation.label
    }
}

impl Adversary for ScopeEscapeAdversary {
    fn class(&self) -> AdversaryClass {
        AdversaryClass::ScopeEscape
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
        let mut delegated_entry = Map::new();
        delegated_entry.insert(
            "server".to_string(),
            Value::String(self.escalation.server.clone()),
        );
        delegated_entry.insert(
            "tool".to_string(),
            Value::String(self.escalation.tool.clone()),
        );
        delegated_entry.insert(
            "label".to_string(),
            Value::String(self.escalation.label.clone()),
        );
        arguments_map.insert(
            DELEGATED_SCOPE_KEY.to_string(),
            Value::Array(vec![Value::Object(delegated_entry)]),
        );
        let mut escape = Map::new();
        escape.insert(
            "entropy".to_string(),
            Value::String(format!("{entropy:016x}")),
        );
        arguments_map.insert("scope_escape".to_string(), Value::Object(escape));
        // Derive the expected verdict from the delegated scope content
        // relative to the base step's (server, tool). An escalation entry
        // that delegates the same `(server, tool)` as the issuer is
        // monotone and the toy guard will return `Allow`; hardcoding
        // `Deny` would emit a self-contradictory action that could be
        // misclassified as a policy regression. The
        // `default_escalations` set keeps the natural invariant that
        // every entry escalates beyond the issuer's canonical scope, so
        // default-built populations still emit `Deny`.
        let escalates =
            self.escalation.server != base_step.server || self.escalation.tool != base_step.tool;
        let expected_verdict = if escalates {
            ScenarioVerdict::Deny
        } else {
            ScenarioVerdict::Allow
        };
        let mutated_step = ScenarioStep {
            id: format!(
                "{}::{}::{}",
                base_step.id, self.population, self.escalation.label
            ),
            agent: base_step.agent.clone(),
            server: base_step.server.clone(),
            tool: base_step.tool.clone(),
            arguments: Value::Object(arguments_map),
            expect_verdict: expected_verdict,
        };
        AdversaryAction {
            class: AdversaryClass::ScopeEscape,
            population: self.population.clone(),
            mutated_step,
            expected_verdict,
            reason_marker: REASON.to_string(),
        }
    }
}

/// Build a population from a DSL block.
///
/// Accepted parameters:
///
///   * `escalations` (array of inline tables, optional): each table holds
///     `label`, `server`, `tool` string fields. Defaults to
///     [`default_escalations`].
pub fn population_from_block(
    block: &ScenarioAdversary,
) -> Result<AdversaryPopulation, AdversaryError> {
    let escalations = if let Some(value) = block.params.get("escalations") {
        parse_escalations(&block.population, value)?
    } else {
        default_escalations()
    };
    if escalations.is_empty() {
        return Err(AdversaryError::EmptyPopulation(block.population.clone()));
    }
    let members: Vec<Box<dyn Adversary + Send + Sync>> = escalations
        .into_iter()
        .map(|escalation| {
            let adv = ScopeEscapeAdversary::new(block.population.clone(), escalation);
            Box::new(adv) as Box<dyn Adversary + Send + Sync>
        })
        .collect();
    AdversaryPopulation::new(block.population.clone(), members)
}

fn parse_escalations(
    population: &str,
    value: &Value,
) -> Result<Vec<ScopeEscalation>, AdversaryError> {
    let array = value
        .as_array()
        .ok_or(AdversaryError::InvalidParameterType {
            population: population.to_string(),
            parameter: "escalations",
            expected: "array of inline tables",
        })?;
    let mut resolved = Vec::with_capacity(array.len());
    for entry in array {
        let object = entry
            .as_object()
            .ok_or(AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "escalations",
                expected: "array of inline tables",
            })?;
        let label = object.get("label").and_then(|value| value.as_str()).ok_or(
            AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "escalations.label",
                expected: "string",
            },
        )?;
        let server = object
            .get("server")
            .and_then(|value| value.as_str())
            .ok_or(AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "escalations.server",
                expected: "string",
            })?;
        let tool = object.get("tool").and_then(|value| value.as_str()).ok_or(
            AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "escalations.tool",
                expected: "string",
            },
        )?;
        resolved.push(ScopeEscalation {
            label: label.to_string(),
            server: server.to_string(),
            tool: tool.to_string(),
        });
    }
    Ok(resolved)
}
