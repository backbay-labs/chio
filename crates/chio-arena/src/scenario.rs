use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::ARENA_SCENARIO_SCHEMA;

const SCHEMA_PREFIX: &str = "chio.arena.scenario/v";
const SUPPORTED_SCHEDULERS: &[&str] = &["single-agent-v1", "deterministic-multi-v1"];
const REQUIRED_LOCALE: &str = "C";
const SECRET_MARKERS: &[&str] = &[
    "BEGIN PRIVATE KEY",
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
    "password",
    "secret",
    "sk-",
    "token",
];
const PROVIDER_DEPENDENCY_MARKERS: &[&str] = &[
    "chio-openai",
    "chio-anthropic-tools-adapter",
    "chio-bedrock-converse-adapter",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub schema_version: String,
    pub id: String,
    pub title: String,
    pub rng_seed: u64,
    pub virtual_clock_start: String,
    pub determinism: DeterminismBlock,
    pub agents: Vec<ScenarioAgent>,
    #[serde(default)]
    pub budgets: Vec<ScenarioBudget>,
    #[serde(default)]
    pub guards: Vec<ScenarioGuard>,
    pub steps: Vec<ScenarioStep>,
    #[serde(default)]
    pub adversaries: Vec<ScenarioAdversary>,
    #[serde(default)]
    pub ext: BTreeMap<String, Value>,
}

impl Scenario {
    pub fn determinism_witness(&self) -> DeterminismWitness {
        DeterminismWitness {
            scenario_id: self.id.clone(),
            schema_version: self.schema_version.clone(),
            rng_seed: self.rng_seed,
            virtual_clock_start: self.virtual_clock_start.clone(),
            scheduler: self.determinism.scheduler.clone(),
            locale: self.determinism.locale.clone(),
            agents: self.agents.iter().map(|agent| agent.id.clone()).collect(),
            steps: self.steps.iter().map(|step| step.id.clone()).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterminismBlock {
    pub rng_seed: u64,
    pub virtual_clock_start: String,
    pub scheduler: String,
    pub locale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioAgent {
    pub id: String,
    pub role: String,
    pub model: String,
    pub seed_prompt_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioBudget {
    pub agent: String,
    pub server: String,
    pub tool: String,
    pub max_invocations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioGuard {
    pub id: String,
    pub mode: GuardMode,
    pub config_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardMode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioStep {
    pub id: String,
    pub agent: String,
    pub server: String,
    pub tool: String,
    pub arguments: Value,
    pub expect_verdict: ScenarioVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScenarioVerdict {
    Allow,
    Deny,
    Rewrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioAdversary {
    pub class: String,
    pub population: String,
    pub seed_ref: String,
    /// Optional kebab-case parameter map used by adversary classes to
    /// configure their populations. Unknown keys are forwarded as-is to the
    /// adversary constructor; constructors are responsible for rejecting
    /// missing or ill-typed parameters.
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismWitness {
    pub scenario_id: String,
    pub schema_version: String,
    pub rng_seed: u64,
    pub virtual_clock_start: String,
    pub scheduler: String,
    pub locale: String,
    pub agents: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ScenarioError {
    #[error("failed to read scenario {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse scenario TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported scenario schema version {0}")]
    UnsupportedSchemaVersion(String),
    #[error("invalid scenario id {0}")]
    InvalidId(String),
    #[error("determinism witness {field} does not match top-level value")]
    WitnessMismatch { field: &'static str },
    #[error("unsupported scheduler {0}")]
    UnsupportedScheduler(String),
    #[error("unsupported locale {0}")]
    UnsupportedLocale(String),
    #[error("duplicate agent id {0}")]
    DuplicateAgent(String),
    #[error("duplicate step id {0}")]
    DuplicateStep(String),
    #[error("duplicate guard id {0}")]
    DuplicateGuard(String),
    #[error("step {step_id} references unknown agent {agent_id}")]
    UnknownStepAgent { step_id: String, agent_id: String },
    #[error("budget references unknown agent {agent_id}")]
    UnknownBudgetAgent { agent_id: String },
    #[error("budget for agent {agent_id} has zero max_invocations")]
    EmptyBudget { agent_id: String },
    #[error("scenario contains inline secret marker at {path}")]
    InlineSecret { path: String },
    #[error("scenario references provider SDK dependency marker {marker}")]
    ProviderDependency { marker: &'static str },
    #[error("scenario must define at least one agent")]
    MissingAgents,
    #[error("scenario must define at least one step")]
    MissingSteps,
}

pub fn load_scenario(path: impl AsRef<Path>) -> Result<Scenario, ScenarioError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|source| ScenarioError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_scenario_str(&contents)
}

pub fn parse_scenario_str(contents: &str) -> Result<Scenario, ScenarioError> {
    let scenario: Scenario = toml::from_str(contents)?;
    validate_scenario(&scenario)?;
    Ok(scenario)
}

pub fn validate_scenario(scenario: &Scenario) -> Result<(), ScenarioError> {
    validate_schema_version(&scenario.schema_version)?;
    validate_id(&scenario.id)?;
    if scenario.agents.is_empty() {
        return Err(ScenarioError::MissingAgents);
    }
    if scenario.steps.is_empty() {
        return Err(ScenarioError::MissingSteps);
    }
    if scenario.rng_seed != scenario.determinism.rng_seed {
        return Err(ScenarioError::WitnessMismatch { field: "rng_seed" });
    }
    if scenario.virtual_clock_start != scenario.determinism.virtual_clock_start {
        return Err(ScenarioError::WitnessMismatch {
            field: "virtual_clock_start",
        });
    }
    if !SUPPORTED_SCHEDULERS.contains(&scenario.determinism.scheduler.as_str()) {
        return Err(ScenarioError::UnsupportedScheduler(
            scenario.determinism.scheduler.clone(),
        ));
    }
    if scenario.determinism.locale != REQUIRED_LOCALE {
        return Err(ScenarioError::UnsupportedLocale(
            scenario.determinism.locale.clone(),
        ));
    }

    let mut agents = BTreeSet::new();
    for agent in &scenario.agents {
        validate_id(&agent.id)?;
        if !agents.insert(agent.id.clone()) {
            return Err(ScenarioError::DuplicateAgent(agent.id.clone()));
        }
        reject_provider_dependency(&agent.model)?;
        reject_inline_secret(&format!("agents.{}.model", agent.id), &agent.model)?;
        reject_inline_secret(
            &format!("agents.{}.seed_prompt_ref", agent.id),
            &agent.seed_prompt_ref,
        )?;
    }

    for budget in &scenario.budgets {
        if !agents.contains(&budget.agent) {
            return Err(ScenarioError::UnknownBudgetAgent {
                agent_id: budget.agent.clone(),
            });
        }
        if budget.max_invocations == 0 {
            return Err(ScenarioError::EmptyBudget {
                agent_id: budget.agent.clone(),
            });
        }
    }

    let mut steps = BTreeSet::new();
    for step in &scenario.steps {
        validate_id(&step.id)?;
        if !steps.insert(step.id.clone()) {
            return Err(ScenarioError::DuplicateStep(step.id.clone()));
        }
        if !agents.contains(&step.agent) {
            return Err(ScenarioError::UnknownStepAgent {
                step_id: step.id.clone(),
                agent_id: step.agent.clone(),
            });
        }
        reject_inline_secret(&format!("steps.{}.arguments", step.id), &step.arguments)?;
    }

    let mut guards = BTreeSet::new();
    for guard in &scenario.guards {
        validate_id(&guard.id)?;
        if !guards.insert(guard.id.clone()) {
            return Err(ScenarioError::DuplicateGuard(guard.id.clone()));
        }
        reject_inline_secret(
            &format!("guards.{}.config_ref", guard.id),
            &guard.config_ref,
        )?;
    }

    for adversary in &scenario.adversaries {
        reject_inline_secret(
            &format!("adversaries.{}.seed_ref", adversary.class),
            &adversary.seed_ref,
        )?;
        for (key, value) in &adversary.params {
            let lower_key = key.to_ascii_lowercase();
            if SECRET_MARKERS
                .iter()
                .any(|marker| lower_key.contains(marker))
            {
                return Err(ScenarioError::InlineSecret {
                    path: format!("adversaries.{}.params.{}", adversary.class, key),
                });
            }
            reject_inline_secret(
                &format!("adversaries.{}.params.{}", adversary.class, key),
                value,
            )?;
        }
    }

    Ok(())
}

fn validate_schema_version(version: &str) -> Result<(), ScenarioError> {
    if version == ARENA_SCENARIO_SCHEMA {
        return Ok(());
    }
    if version.starts_with(SCHEMA_PREFIX) {
        return Err(ScenarioError::UnsupportedSchemaVersion(version.to_string()));
    }
    Err(ScenarioError::UnsupportedSchemaVersion(version.to_string()))
}

fn validate_id(value: &str) -> Result<(), ScenarioError> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Ok(());
    }
    Err(ScenarioError::InvalidId(value.to_string()))
}

fn reject_provider_dependency(value: &str) -> Result<(), ScenarioError> {
    for marker in PROVIDER_DEPENDENCY_MARKERS {
        if value.contains(marker) {
            return Err(ScenarioError::ProviderDependency { marker });
        }
    }
    Ok(())
}

fn reject_inline_secret(path: &str, value: impl SecretScan) -> Result<(), ScenarioError> {
    value.scan(path)
}

trait SecretScan {
    fn scan(&self, path: &str) -> Result<(), ScenarioError>;
}

impl SecretScan for &str {
    fn scan(&self, path: &str) -> Result<(), ScenarioError> {
        let lower = self.to_ascii_lowercase();
        for marker in SECRET_MARKERS {
            if lower.contains(&marker.to_ascii_lowercase()) {
                return Err(ScenarioError::InlineSecret {
                    path: path.to_string(),
                });
            }
        }
        Ok(())
    }
}

impl SecretScan for &String {
    fn scan(&self, path: &str) -> Result<(), ScenarioError> {
        self.as_str().scan(path)
    }
}

impl SecretScan for &Value {
    fn scan(&self, path: &str) -> Result<(), ScenarioError> {
        match self {
            Value::String(value) => value.as_str().scan(path),
            Value::Array(values) => {
                for (idx, value) in values.iter().enumerate() {
                    value.scan(&format!("{path}[{idx}]"))?;
                }
                Ok(())
            }
            Value::Object(values) => {
                for (key, value) in values {
                    let lower_key = key.to_ascii_lowercase();
                    if SECRET_MARKERS
                        .iter()
                        .any(|marker| lower_key.contains(marker))
                    {
                        return Err(ScenarioError::InlineSecret {
                            path: format!("{path}.{key}"),
                        });
                    }
                    value.scan(&format!("{path}.{key}"))?;
                }
                Ok(())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        }
    }
}
