//! Skill manifests describing tool dependencies, I/O contracts, and budgets.
//!
//! A `SkillManifest` is authored by the skill developer and declares the
//! tools the skill needs, the order they run, what data flows between steps,
//! and the budget envelope required for execution.

use std::collections::BTreeSet;

use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

/// Schema identifier for skill manifests.
pub const SKILL_MANIFEST_SCHEMA: &str = "chio.skill-manifest.v1";

/// A skill manifest describing a multi-step tool composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Schema version.
    pub schema: String,

    /// Unique skill identifier.
    pub skill_id: String,

    /// Semantic version of the skill.
    pub version: String,

    /// Human-readable name.
    pub name: String,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Ordered steps in the skill.
    pub steps: Vec<SkillStep>,

    /// Budget envelope for a single execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_envelope: Option<MonetaryAmount>,

    /// Maximum wall-clock duration (seconds) for the entire skill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,

    /// Author identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

impl SkillManifest {
    /// Create a new skill manifest.
    pub fn new(skill_id: String, version: String, name: String, steps: Vec<SkillStep>) -> Self {
        Self {
            schema: SKILL_MANIFEST_SCHEMA.to_string(),
            skill_id,
            version,
            name,
            description: None,
            steps,
            budget_envelope: None,
            max_duration_secs: None,
            author: None,
        }
    }

    /// Return the total number of steps.
    #[must_use]
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Get the list of tool dependencies as "server_id:tool_name".
    #[must_use]
    pub fn tool_dependencies(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|s| format!("{}:{}", s.server_id, s.tool_name))
            .collect()
    }

    /// Validate that all step I/O contracts are consistent.
    ///
    /// Each step's required inputs (except the first) must be
    /// produced by a preceding step's outputs.
    pub fn validate_io_contracts(&self) -> Result<(), String> {
        let mut available_outputs: BTreeSet<&str> = BTreeSet::new();

        for (idx, step) in self.steps.iter().enumerate() {
            if let Some(ref input) = step.input_contract {
                for required in &input.required_fields {
                    if idx > 0 && !available_outputs.contains(required.as_str()) {
                        return Err(format!(
                            "step {} ({}) requires input field '{}' not produced by any preceding step",
                            idx, step.tool_name, required
                        ));
                    }
                }
            }

            if let Some(ref output) = step.output_contract {
                for field in &output.produced_fields {
                    available_outputs.insert(field);
                }
            }
        }

        Ok(())
    }
}

/// A single step in a skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillStep {
    /// Step index (0-based, for ordering).
    pub index: usize,

    /// Tool server hosting this step's tool.
    pub server_id: String,

    /// Tool to invoke in this step.
    pub tool_name: String,

    /// Human-readable step label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Input contract for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_contract: Option<IoContract>,

    /// Output contract for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_contract: Option<IoContract>,

    /// Per-step budget limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<MonetaryAmount>,

    /// Whether this step can be retried on failure.
    #[serde(default)]
    pub retryable: bool,

    /// Maximum number of retries (only relevant if retryable is true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
}

/// I/O contract describing what data a step consumes or produces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoContract {
    /// Field names required by the step (for inputs) or guaranteed (for outputs).
    #[serde(default)]
    pub required_fields: Vec<String>,

    /// Field names produced by this step (used for output contracts to track
    /// data flow to subsequent steps).
    #[serde(default)]
    pub produced_fields: Vec<String>,

    /// Optional field names.
    #[serde(default)]
    pub optional_fields: Vec<String>,

    /// JSON Schema for the data, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(
        index: usize,
        server: &str,
        tool: &str,
        inputs: Vec<&str>,
        outputs: Vec<&str>,
    ) -> SkillStep {
        SkillStep {
            index,
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            label: None,
            input_contract: if inputs.is_empty() {
                None
            } else {
                Some(IoContract {
                    required_fields: inputs.iter().map(|s| s.to_string()).collect(),
                    produced_fields: vec![],
                    optional_fields: vec![],
                    json_schema: None,
                })
            },
            output_contract: if outputs.is_empty() {
                None
            } else {
                Some(IoContract {
                    required_fields: vec![],
                    produced_fields: outputs.iter().map(|s| s.to_string()).collect(),
                    optional_fields: vec![],
                    json_schema: None,
                })
            },
            budget_limit: None,
            retryable: false,
            max_retries: None,
        }
    }

    #[test]
    fn manifest_roundtrip() {
        let manifest = SkillManifest::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            "Search and Summarize".to_string(),
            vec![
                make_step(0, "search-srv", "search", vec![], vec!["results"]),
                make_step(1, "llm-srv", "summarize", vec!["results"], vec!["summary"]),
            ],
        );

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: SkillManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.skill_id, "search-summarize");
        assert_eq!(deserialized.step_count(), 2);
    }

    #[test]
    fn tool_dependencies() {
        let manifest = SkillManifest::new(
            "s1".to_string(),
            "1.0".to_string(),
            "S1".to_string(),
            vec![
                make_step(0, "a", "t1", vec![], vec![]),
                make_step(1, "b", "t2", vec![], vec![]),
            ],
        );
        let deps = manifest.tool_dependencies();
        assert_eq!(deps, vec!["a:t1", "b:t2"]);
    }

    #[test]
    fn valid_io_contracts() {
        let manifest = SkillManifest::new(
            "s1".to_string(),
            "1.0".to_string(),
            "S1".to_string(),
            vec![
                make_step(0, "a", "t1", vec![], vec!["data"]),
                make_step(1, "b", "t2", vec!["data"], vec!["result"]),
            ],
        );
        assert!(manifest.validate_io_contracts().is_ok());
    }

    #[test]
    fn invalid_io_contracts() {
        let manifest = SkillManifest::new(
            "s1".to_string(),
            "1.0".to_string(),
            "S1".to_string(),
            vec![
                make_step(0, "a", "t1", vec![], vec!["data"]),
                make_step(1, "b", "t2", vec!["missing_field"], vec!["result"]),
            ],
        );
        let result = manifest.validate_io_contracts();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("missing_field"));
    }

    #[test]
    fn first_step_inputs_are_not_validated() {
        // First step inputs come from the caller, not from preceding steps
        let manifest = SkillManifest::new(
            "s1".to_string(),
            "1.0".to_string(),
            "S1".to_string(),
            vec![make_step(0, "a", "t1", vec!["query"], vec!["data"])],
        );
        assert!(manifest.validate_io_contracts().is_ok());
    }
}
