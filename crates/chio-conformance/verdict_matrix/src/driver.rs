use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{ScenarioCategory, Verdict, VerdictTuple, SCENARIO_SCHEMA};

pub const RUST_KERNEL_DRIVER: &str = "rust-kernel";
pub const REASON_NONE: &str = "urn:chio:error:none";
pub const REASON_SCOPE_EXCEEDED: &str = "urn:chio:error:capability:scope-exceeded";
pub const REASON_REVOKED: &str = "urn:chio:error:capability:revoked";
pub const REASON_REPLAY_DRIFT: &str = "urn:chio:error:replay:deterministic-mismatch";
pub const REASON_REPLAY_TRACE_MISSING: &str = "urn:chio:error:replay:trace-not-found";
pub const REASON_INPUT_REDACTED: &str = "urn:chio:error:guard:input-redacted";
pub const REASON_OUTPUT_REDACTED: &str = "urn:chio:error:guard:output-redacted";
pub const REASON_GUARD_DENIED: &str = "urn:chio:error:guard:denied";
pub const REASON_KERNEL_INTERNAL: &str = "urn:chio:error:kernel:internal-error";

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path} as scenario JSON: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid scenario {id}: {reason}")]
    InvalidScenario { id: String, reason: String },
    #[error("failed to list {path}: {source}")]
    List {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictScenario {
    pub schema: String,
    pub id: String,
    pub title: String,
    pub category: ScenarioCategory,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    pub script: ScenarioScript,
    pub expected: VerdictTuple,
}

impl VerdictScenario {
    pub fn validate(&self) -> Result<(), DriverError> {
        if self.schema != SCENARIO_SCHEMA {
            return Err(DriverError::InvalidScenario {
                id: self.id.clone(),
                reason: format!("schema must be `{SCENARIO_SCHEMA}`"),
            });
        }
        if self.id.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: self.id.clone(),
                reason: String::from("id must not be empty"),
            });
        }
        if self.title.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: self.id.clone(),
                reason: String::from("title must not be empty"),
            });
        }
        if self.description.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: self.id.clone(),
                reason: String::from("description must not be empty"),
            });
        }
        if self.expected.reason_code.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: self.id.clone(),
                reason: String::from("expected.reason_code must not be empty"),
            });
        }
        self.script.validate(&self.id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScenarioScript {
    pub operation: String,
    pub tool: String,
    pub input_json: String,
    #[serde(default)]
    pub capability_scopes: Vec<String>,
    #[serde(default)]
    pub required_scope: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub replay_nonce_status: ReplayNonceStatus,
    #[serde(default)]
    pub redaction_action: RedactionAction,
    #[serde(default)]
    pub redaction_phase: RedactionPhase,
    #[serde(default)]
    pub source_fixture: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ScenarioScript {
    fn validate(&self, id: &str) -> Result<(), DriverError> {
        if self.operation.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: id.to_string(),
                reason: String::from("script.operation must not be empty"),
            });
        }
        if self.tool.trim().is_empty() {
            return Err(DriverError::InvalidScenario {
                id: id.to_string(),
                reason: String::from("script.tool must not be empty"),
            });
        }
        if let Some(required_scope) = &self.required_scope {
            if required_scope.trim().is_empty() {
                return Err(DriverError::InvalidScenario {
                    id: id.to_string(),
                    reason: String::from("script.required_scope must not be empty"),
                });
            }
        }
        if let Err(source) = serde_json::from_str::<Value>(&self.input_json) {
            return Err(DriverError::InvalidScenario {
                id: id.to_string(),
                reason: format!("script.input_json is not valid JSON: {source}"),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayNonceStatus {
    #[default]
    Fresh,
    Duplicate,
    Stale,
    TraceMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionAction {
    #[default]
    None,
    Mask,
    Drop,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPhase {
    #[default]
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    Pass,
    Fail,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverOutcome {
    pub scenario_id: String,
    pub status: DriverStatus,
    pub actual: Option<VerdictTuple>,
    pub expected: VerdictTuple,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Default)]
pub struct RustKernelDriver;

impl RustKernelDriver {
    pub fn run(&self, scenario: &VerdictScenario) -> DriverOutcome {
        if let Some(unsupported) = scenario
            .requires
            .iter()
            .find(|requirement| requirement.as_str() != RUST_KERNEL_DRIVER)
        {
            return DriverOutcome {
                scenario_id: scenario.id.clone(),
                status: DriverStatus::Unsupported,
                actual: None,
                expected: scenario.expected.clone().normalized(),
                diagnostic: Some(format!("unsupported requirement `{unsupported}`")),
            };
        }

        let actual = evaluate_scenario(scenario).normalized();
        let expected = scenario.expected.clone().normalized();
        let status = if actual == expected {
            DriverStatus::Pass
        } else {
            DriverStatus::Fail
        };
        DriverOutcome {
            scenario_id: scenario.id.clone(),
            status,
            actual: Some(actual),
            expected,
            diagnostic: None,
        }
    }

    pub fn run_all(&self, scenarios: &[VerdictScenario]) -> Vec<DriverOutcome> {
        scenarios
            .iter()
            .map(|scenario| self.run(scenario))
            .collect()
    }
}

pub fn load_scenario_file(path: &Path) -> Result<VerdictScenario, DriverError> {
    let bytes = fs::read(path).map_err(|source| DriverError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let scenario =
        serde_json::from_slice::<VerdictScenario>(&bytes).map_err(|source| DriverError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    scenario.validate()?;
    Ok(scenario)
}

pub fn load_scenarios(root: &Path) -> Result<Vec<VerdictScenario>, DriverError> {
    let mut files = Vec::new();
    collect_json_files(root, &mut files)?;
    files.sort();

    let mut scenarios = Vec::with_capacity(files.len());
    for file in files {
        scenarios.push(load_scenario_file(&file)?);
    }
    Ok(scenarios)
}

fn collect_json_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), DriverError> {
    let entries = fs::read_dir(path).map_err(|source| DriverError::List {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| DriverError::List {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_json_files(&entry_path, files)?;
        } else if entry_path
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("json")
        {
            files.push(entry_path);
        }
    }
    Ok(())
}

fn evaluate_scenario(scenario: &VerdictScenario) -> VerdictTuple {
    let scopes = scenario.script.capability_scopes.clone();
    if scenario.script.operation.as_str() != "tool.call" {
        return tuple(Verdict::Error, REASON_KERNEL_INTERNAL, scopes);
    }
    if scenario.script.revoked {
        return tuple(Verdict::Deny, REASON_REVOKED, scopes);
    }
    match scenario.script.replay_nonce_status {
        ReplayNonceStatus::Duplicate | ReplayNonceStatus::Stale => {
            return tuple(Verdict::Deny, REASON_REPLAY_DRIFT, scopes);
        }
        ReplayNonceStatus::TraceMissing => {
            return tuple(Verdict::Error, REASON_REPLAY_TRACE_MISSING, scopes);
        }
        ReplayNonceStatus::Fresh => {}
    }
    if let Some(required_scope) = &scenario.script.required_scope {
        if !scenario
            .script
            .capability_scopes
            .iter()
            .any(|scope| scope == required_scope)
        {
            return tuple(Verdict::Deny, REASON_SCOPE_EXCEEDED, scopes);
        }
    }
    match scenario.script.redaction_action {
        RedactionAction::Deny => tuple(Verdict::Deny, REASON_GUARD_DENIED, scopes),
        RedactionAction::Mask | RedactionAction::Drop => {
            let reason = match scenario.script.redaction_phase {
                RedactionPhase::Input => REASON_INPUT_REDACTED,
                RedactionPhase::Output => REASON_OUTPUT_REDACTED,
            };
            tuple(Verdict::Allow, reason, scopes)
        }
        RedactionAction::None => tuple(Verdict::Allow, REASON_NONE, scopes),
    }
}

fn tuple(verdict: Verdict, reason_code: &str, scope_set: Vec<String>) -> VerdictTuple {
    VerdictTuple {
        verdict,
        reason_code: reason_code.to_string(),
        scope_set,
    }
}

pub fn category_counts(scenarios: &[VerdictScenario]) -> BTreeMap<ScenarioCategory, usize> {
    let mut counts = BTreeMap::new();
    for scenario in scenarios {
        *counts.entry(scenario.category).or_insert(0) += 1;
    }
    counts
}
