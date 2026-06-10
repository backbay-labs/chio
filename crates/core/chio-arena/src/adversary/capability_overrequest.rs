//! Capability-overrequest adversary class.
//!
//! Asks for a (server, tool) pair outside the issued capability scope. The
//! kernel's fail-closed contract is that any tool call whose target is not
//! a subset of the capability's grant set is denied; the toy guard
//! evaluator in `mod.rs` mirrors that decision tree without booting a
//! kernel.
//!
//! The capability algebra (scope monotonicity proven by proptest plus
//! Kani) is the correctness backstop. The arena does not reprove the
//! algebra here; it triggers the property and asserts the fail-closed
//! verdict.

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde_json::{Map, Value};

use crate::scenario::{ScenarioAdversary, ScenarioStep, ScenarioVerdict};

use super::{Adversary, AdversaryAction, AdversaryClass, AdversaryError, AdversaryPopulation};

/// Stable reason marker.
pub const REASON: &str = "capability-overrequest-denied";

/// Single overrequest variant: target server/tool plus a stable label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrequestVariant {
    /// Variant label written into receipt manifests.
    pub label: String,
    /// Out-of-scope server.
    pub target_server: String,
    /// Out-of-scope tool.
    pub target_tool: String,
}

/// Default canonical variants. Each variant escalates one or both of
/// (server, tool) outside the typical filesystem allowlist used by the
/// reference scenarios. A real arena run would source variants from
/// fuzz outputs; the canonical set here exists so unit tests have a
/// stable, kernel-free fixture.
pub fn default_variants() -> Vec<OverrequestVariant> {
    vec![
        OverrequestVariant {
            label: "swap-server".to_string(),
            target_server: "secrets".to_string(),
            target_tool: "read_file".to_string(),
        },
        OverrequestVariant {
            label: "swap-tool".to_string(),
            target_server: "filesystem".to_string(),
            target_tool: "exec_shell".to_string(),
        },
        OverrequestVariant {
            label: "swap-both".to_string(),
            target_server: "network".to_string(),
            target_tool: "http_post".to_string(),
        },
    ]
}

/// Capability-overrequest adversary.
#[derive(Debug, Clone)]
pub struct CapabilityOverrequestAdversary {
    population: String,
    variant: OverrequestVariant,
}

impl CapabilityOverrequestAdversary {
    /// Build a new adversary for the supplied variant.
    pub fn new(population: impl Into<String>, variant: OverrequestVariant) -> Self {
        Self {
            population: population.into(),
            variant,
        }
    }

    /// Variant label.
    pub fn label(&self) -> &str {
        &self.variant.label
    }
}

impl Adversary for CapabilityOverrequestAdversary {
    fn class(&self) -> AdversaryClass {
        AdversaryClass::CapabilityOverrequest
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
        let mut overrequest = Map::new();
        overrequest.insert(
            "issuer_server".to_string(),
            Value::String(base_step.server.clone()),
        );
        overrequest.insert(
            "issuer_tool".to_string(),
            Value::String(base_step.tool.clone()),
        );
        overrequest.insert(
            "variant".to_string(),
            Value::String(self.variant.label.clone()),
        );
        overrequest.insert(
            "entropy".to_string(),
            Value::String(format!("{entropy:016x}")),
        );
        arguments_map.insert(
            "capability_overrequest".to_string(),
            Value::Object(overrequest),
        );
        // Derive the expected verdict from the mutated target relative to
        // the base step's (server, tool) instead of hardcoding `Deny`. A
        // variant whose target equals the base step's scope is in-scope
        // and the toy guard will return `Allow`; hardcoding `Deny` in that
        // case would emit a self-contradictory action and produce false
        // fail-open signals. Constructor-level validation cannot reject
        // these variants in advance because the issued scope is bound to
        // the scenario step, not the population block. The
        // `default_variants` list and `population_from_block` keep an
        // additional invariant: variants supplied at construction time
        // must escalate beyond the canonical filesystem allowlist used by
        // the reference scenarios, so default-built populations always
        // emit `Deny`.
        let in_scope = self.variant.target_server == base_step.server
            && self.variant.target_tool == base_step.tool;
        let expected_verdict = if in_scope {
            ScenarioVerdict::Allow
        } else {
            ScenarioVerdict::Deny
        };
        let mutated_step = ScenarioStep {
            id: format!(
                "{}::{}::{}",
                base_step.id, self.population, self.variant.label
            ),
            agent: base_step.agent.clone(),
            server: self.variant.target_server.clone(),
            tool: self.variant.target_tool.clone(),
            arguments: Value::Object(arguments_map),
            expect_verdict: expected_verdict,
        };
        AdversaryAction {
            class: AdversaryClass::CapabilityOverrequest,
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
///   * `variants` (array of inline tables, optional): each table must hold
///     `label`, `target_server`, `target_tool` string fields. Defaults to
///     [`default_variants`].
pub fn population_from_block(
    block: &ScenarioAdversary,
) -> Result<AdversaryPopulation, AdversaryError> {
    let variants = if let Some(value) = block.params.get("variants") {
        parse_variants(&block.population, value)?
    } else {
        default_variants()
    };

    if variants.is_empty() {
        return Err(AdversaryError::EmptyPopulation(block.population.clone()));
    }

    let members: Vec<Box<dyn Adversary + Send + Sync>> = variants
        .into_iter()
        .map(|variant| {
            let adv = CapabilityOverrequestAdversary::new(block.population.clone(), variant);
            Box::new(adv) as Box<dyn Adversary + Send + Sync>
        })
        .collect();
    AdversaryPopulation::new(block.population.clone(), members)
}

fn parse_variants(
    population: &str,
    value: &Value,
) -> Result<Vec<OverrequestVariant>, AdversaryError> {
    let array = value
        .as_array()
        .ok_or(AdversaryError::InvalidParameterType {
            population: population.to_string(),
            parameter: "variants",
            expected: "array of inline tables",
        })?;
    let mut resolved = Vec::with_capacity(array.len());
    for entry in array {
        let object = entry
            .as_object()
            .ok_or(AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "variants",
                expected: "array of inline tables",
            })?;
        let label = object.get("label").and_then(|value| value.as_str()).ok_or(
            AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "variants.label",
                expected: "string",
            },
        )?;
        let target_server = object
            .get("target_server")
            .and_then(|value| value.as_str())
            .ok_or(AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "variants.target_server",
                expected: "string",
            })?;
        let target_tool = object
            .get("target_tool")
            .and_then(|value| value.as_str())
            .ok_or(AdversaryError::InvalidParameterType {
                population: population.to_string(),
                parameter: "variants.target_tool",
                expected: "string",
            })?;
        resolved.push(OverrequestVariant {
            label: label.to_string(),
            target_server: target_server.to_string(),
            target_tool: target_tool.to_string(),
        });
    }
    Ok(resolved)
}
