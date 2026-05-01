//! Lambda deployment-shape verdict-matrix driver.
//!
//! The driver loads the canonical scenario corpus from
//! `crates/chio-conformance/verdict_matrix/scenarios/` and emits a
//! `(verdict, reason_code, scope_set)` tuple per scenario by invoking the
//! `sdks/lambda/chio-lambda-extension` runtime through a local invoke shim.
//! The Lambda extension itself does not embed kernel evaluation; it forwards
//! admission requests to a Chio sidecar. The deployment-shape driver mirrors
//! the TypeScript node-http driver contract: an operator-supplied sidecar
//! URL is read from `CHIO_VERDICT_MATRIX_SIDECAR_URL` (with
//! `CHIO_SIDECAR_URL` fallback). Without that variable, every scenario is
//! reported as `unsupported` with a diagnostic that names the missing
//! variable.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const DRIVER_NAME: &str = "lambda-deployment-shape";
pub const MATRIX_ROLE: &str = "deployment-shape";
pub const UNDERLYING_DRIVER: &str = "rust-kernel";
pub const SIDECAR_ENV: &str = "CHIO_VERDICT_MATRIX_SIDECAR_URL";
pub const SIDECAR_FALLBACK_ENV: &str = "CHIO_SIDECAR_URL";
pub const SCENARIO_SCHEMA: &str = "chio.verdict-matrix.scenario.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerdictTuple {
    pub verdict: String,
    pub reason_code: String,
    pub scope_set: Vec<String>,
}

impl VerdictTuple {
    pub fn normalized(mut self) -> Self {
        self.scope_set.sort();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub schema: String,
    pub id: String,
    pub category: String,
    #[serde(default)]
    pub requires: Vec<String>,
    pub expected: VerdictTuple,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioOutcome {
    pub scenario_id: String,
    pub status: String,
    pub expected: VerdictTuple,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<VerdictTuple>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriverReport {
    pub driver: String,
    pub matrix_role: String,
    pub underlying_driver: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub unsupported: usize,
    pub outcomes: Vec<ScenarioOutcome>,
}

/// Locate the scenario root by walking upward from the current working
/// directory until a `Cargo.toml` and a `crates/chio-conformance/verdict_matrix`
/// directory are both present.
pub fn resolve_scenario_root() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|err| format!("cannot read cwd: {err}"))?;
    let mut candidate: Option<&Path> = Some(cwd.as_path());
    while let Some(dir) = candidate {
        let cargo = dir.join("Cargo.toml");
        let matrix = dir.join("crates/chio-conformance/verdict_matrix");
        if cargo.exists() && matrix.exists() {
            return Ok(matrix.join("scenarios"));
        }
        candidate = dir.parent();
    }
    Err(format!(
        "could not find verdict-matrix scenario root from `{}`",
        cwd.display()
    ))
}

pub fn load_scenarios(root: &Path) -> Result<Vec<Scenario>, String> {
    if !root.is_dir() {
        return Err(format!(
            "scenario root `{}` does not exist or is not a directory",
            root.display()
        ));
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    walk(root, &mut paths)?;
    paths.sort();
    let mut scenarios = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let scenario: Scenario = serde_json::from_str(&raw)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
        if scenario.schema != SCENARIO_SCHEMA {
            return Err(format!(
                "{} has unsupported scenario schema `{}`",
                path.display(),
                scenario.schema
            ));
        }
        scenarios.push(scenario);
    }
    Ok(scenarios)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let read =
        fs::read_dir(dir).map_err(|err| format!("read_dir {} failed: {err}", dir.display()))?;
    for entry in read {
        let entry = entry.map_err(|err| format!("read_dir entry failed: {err}"))?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

pub fn run_driver(scenario_root: &Path, sidecar_url: Option<&str>) -> Result<DriverReport, String> {
    let scenarios = load_scenarios(scenario_root)?;
    let sidecar_present = sidecar_url.is_some_and(|url| !url.trim().is_empty());
    let mut outcomes = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let diagnostic = if sidecar_present {
            "Lambda deployment-shape driver local-invoke shim is operator-tactical; \
             the scaffold registers the driver shape only"
                .to_string()
        } else {
            format!(
                "set {SIDECAR_ENV} (or {SIDECAR_FALLBACK_ENV}) to a live Chio sidecar; \
                 the Lambda extension does not embed kernel evaluation"
            )
        };
        outcomes.push(ScenarioOutcome {
            scenario_id: scenario.id,
            status: "unsupported".to_string(),
            expected: scenario.expected.normalized(),
            actual: None,
            diagnostic: Some(diagnostic),
        });
    }
    let unsupported = outcomes
        .iter()
        .filter(|o| o.status == "unsupported")
        .count();
    let passed = outcomes.iter().filter(|o| o.status == "pass").count();
    let failed = outcomes.iter().filter(|o| o.status == "fail").count();
    Ok(DriverReport {
        driver: DRIVER_NAME.to_string(),
        matrix_role: MATRIX_ROLE.to_string(),
        underlying_driver: UNDERLYING_DRIVER.to_string(),
        total: outcomes.len(),
        passed,
        failed,
        unsupported,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_constants_are_stable() {
        assert_eq!(DRIVER_NAME, "lambda-deployment-shape");
        assert_eq!(MATRIX_ROLE, "deployment-shape");
        assert_eq!(UNDERLYING_DRIVER, "rust-kernel");
    }

    #[test]
    fn run_driver_marks_all_scenarios_unsupported_without_sidecar() {
        let root = match resolve_scenario_root() {
            Ok(root) => root,
            Err(err) => panic!("could not resolve scenario root: {err}"),
        };
        let report = match run_driver(&root, None) {
            Ok(report) => report,
            Err(err) => panic!("run_driver failed: {err}"),
        };
        assert_eq!(report.driver, DRIVER_NAME);
        assert!(report.total > 0, "expected scenarios to load");
        assert_eq!(report.unsupported, report.total);
        assert_eq!(report.passed, 0);
        assert_eq!(report.failed, 0);
        let first = match report.outcomes.first() {
            Some(outcome) => outcome,
            None => panic!("expected at least one outcome"),
        };
        assert_eq!(first.status, "unsupported");
        let diagnostic = match &first.diagnostic {
            Some(text) => text,
            None => panic!("expected diagnostic on unsupported outcome"),
        };
        assert!(
            diagnostic.contains(SIDECAR_ENV),
            "diagnostic should name the sidecar env var, got `{diagnostic}`"
        );
    }

    #[test]
    fn verdict_tuple_normalizes_scope_set() {
        let tuple = VerdictTuple {
            verdict: "allow".into(),
            reason_code: "urn:chio:error:none".into(),
            scope_set: vec!["tool:write".into(), "tool:read".into()],
        };
        let normalized = tuple.normalized();
        assert_eq!(
            normalized.scope_set,
            vec!["tool:read".to_string(), "tool:write".to_string()]
        );
    }
}
