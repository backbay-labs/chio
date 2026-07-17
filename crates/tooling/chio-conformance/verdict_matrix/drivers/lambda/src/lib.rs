//! Lambda deployment-shape verdict-matrix driver.
//!
//! The driver loads the canonical scenario corpus from
//! `crates/tooling/chio-conformance/verdict_matrix/scenarios/` and emits a
//! `(verdict, reason_code, scope_set)` tuple per scenario by forwarding each
//! scenario to a Chio sidecar over an HTTP `POST /chio/evaluate` wire surface.
//! This driver holds no in-process kernel; it models a deployment shape that
//! relies on a remote Chio evaluator for every verdict.
//!
//! ## Runtime-availability gate
//!
//! The driver gates on an operator-supplied sidecar URL read from
//! `CHIO_VERDICT_MATRIX_SIDECAR_URL` (with `CHIO_SIDECAR_URL` fallback):
//!
//! - When a sidecar URL is set, the driver issues a real blocking HTTP POST to
//!   `<url>/chio/evaluate` for every scenario, parses the returned verdict and
//!   the `verdict_matrix` receipt metadata, and emits a pass/fail tuple by
//!   comparing against the scenario's expected tuple. A transport error against
//!   a sidecar that is set-but-unreachable surfaces as a `fail` outcome (never
//!   a silent skip), so a misconfigured sidecar cannot masquerade as a pass.
//! - When no sidecar URL is set, the driver reports every scenario as
//!   `unsupported` with a diagnostic naming the missing variable. This is a
//!   real availability gate, not a placeholder: this driver has no in-process
//!   kernel, so there is no verdict it can honestly emit without a sidecar.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::form_urlencoded::byte_serialize;

pub const DRIVER_NAME: &str = "lambda-deployment-shape";
pub const MATRIX_ROLE: &str = "deployment-shape";
pub const UNDERLYING_DRIVER: &str = "rust-kernel";
pub const SIDECAR_ENV: &str = "CHIO_VERDICT_MATRIX_SIDECAR_URL";
pub const SIDECAR_FALLBACK_ENV: &str = "CHIO_SIDECAR_URL";
pub const SCENARIO_SCHEMA: &str = "chio.verdict-matrix.scenario.v1";

const MATRIX_SERVER_ID: &str = "verdict-matrix";
const REASON_NONE: &str = "urn:chio:error:none";
const REASON_KERNEL_INTERNAL: &str = "urn:chio:error:kernel:internal-error";
const EVALUATE_PATH: &str = "/chio/evaluate";
const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// Synthetic request timestamp (unix seconds). The verdict-matrix corpus
/// is time-invariant, so a fixed value keeps relayed requests deterministic.
const REQUEST_TIMESTAMP_SECS: u64 = 1_700_000_000;

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
pub struct ScenarioScript {
    pub operation: String,
    pub tool: String,
    pub input_json: String,
    #[serde(default)]
    pub capability_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub schema: String,
    pub id: String,
    pub category: String,
    #[serde(default)]
    pub requires: Vec<String>,
    pub script: ScenarioScript,
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
/// directory until a `Cargo.toml` and a `crates/tooling/chio-conformance/verdict_matrix`
/// directory are both present.
pub fn resolve_scenario_root() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|err| format!("cannot read cwd: {err}"))?;
    let mut candidate: Option<&Path> = Some(cwd.as_path());
    while let Some(dir) = candidate {
        let cargo = dir.join("Cargo.toml");
        let matrix = dir.join("crates/tooling/chio-conformance/verdict_matrix");
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
    let root_metadata = fs::symlink_metadata(root).map_err(|err| {
        format!(
            "failed to inspect scenario root `{}`: {err}",
            root.display()
        )
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symlinked verdict-matrix scenario root `{}`",
            root.display()
        ));
    }
    if !root_metadata.is_dir() {
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
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "refusing symlink in verdict-matrix scenario tree `{}`",
                path.display()
            ));
        }
        if file_type.is_dir() {
            walk(&path, out)?;
        } else if file_type.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("json")
        {
            out.push(path);
        }
    }
    Ok(())
}

pub fn run_driver(scenario_root: &Path, sidecar_url: Option<&str>) -> Result<DriverReport, String> {
    let scenarios = load_scenarios(scenario_root)?;
    let sidecar = sidecar_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(|url| url.trim_end_matches('/').to_string());

    let mut outcomes = Vec::with_capacity(scenarios.len());
    match sidecar {
        None => {
            for scenario in scenarios {
                outcomes.push(ScenarioOutcome {
                    scenario_id: scenario.id,
                    status: "unsupported".to_string(),
                    expected: scenario.expected.normalized(),
                    actual: None,
                    diagnostic: Some(format!(
                        "set {SIDECAR_ENV} (or {SIDECAR_FALLBACK_ENV}) to a live Chio sidecar; \
                         the Lambda extension does not embed kernel evaluation"
                    )),
                });
            }
        }
        Some(base_url) => {
            let client = build_client()?;
            for scenario in scenarios {
                if let Some(reason) = sidecar_unsupported_reason(&scenario) {
                    outcomes.push(ScenarioOutcome {
                        scenario_id: scenario.id,
                        status: "unsupported".to_string(),
                        expected: scenario.expected.normalized(),
                        actual: None,
                        diagnostic: Some(reason),
                    });
                    continue;
                }
                outcomes.push(evaluate_scenario(&client, &base_url, &scenario));
            }
        }
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

fn build_client() -> Result<reqwest::blocking::Client, String> {
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: verdict-matrix conformance
    // driver targets an operator-supplied sidecar URL via env var, outside
    // production substrate egress policy.
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .map_err(|err| format!("failed to build HTTP client: {err}"))
}

fn evaluate_scenario(
    client: &reqwest::blocking::Client,
    base_url: &str,
    scenario: &Scenario,
) -> ScenarioOutcome {
    let expected = scenario.expected.clone().normalized();
    let request_body = scenario_to_http_request(scenario);
    let url = format!("{base_url}{EVALUATE_PATH}");
    let response = match client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-chio-capability", capability_token_for(scenario))
        .json(&request_body)
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: paired with builder above.
        .send()
    {
        Ok(response) => response,
        Err(err) => {
            return fail(
                scenario.id.clone(),
                expected,
                format!("sidecar POST failed: {err}"),
            );
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return fail(
            scenario.id.clone(),
            expected,
            format!("sidecar returned {status}: {body}"),
        );
    }
    let value = match response.json::<Value>() {
        Ok(value) => value,
        Err(err) => {
            return fail(
                scenario.id.clone(),
                expected,
                format!("failed to parse sidecar response: {err}"),
            );
        }
    };
    let actual = tuple_from_evaluate_response(&value).normalized();
    let pass = actual == expected;
    ScenarioOutcome {
        scenario_id: scenario.id.clone(),
        status: if pass { "pass" } else { "fail" }.to_string(),
        actual: Some(actual),
        expected,
        diagnostic: if pass {
            None
        } else {
            Some("tuple mismatch against sidecar verdict".to_string())
        },
    }
}

fn fail(scenario_id: String, expected: VerdictTuple, diagnostic: String) -> ScenarioOutcome {
    ScenarioOutcome {
        scenario_id,
        status: "fail".to_string(),
        actual: None,
        expected,
        diagnostic: Some(diagnostic),
    }
}

/// Build the `ChioHttpRequest` body for a scenario, populating the tool-call
/// fields the sidecar's capability-scope evaluator reads. Mirrors the
/// node-http transport-client driver so the deployment shapes share one wire
/// contract.
pub fn scenario_to_http_request(scenario: &Scenario) -> Value {
    let tool = scenario.script.tool.as_str();
    let method = method_for_tool(tool);
    let path = format!(
        "/chio/tools/{}/{}",
        encode_path_segment(MATRIX_SERVER_ID),
        encode_path_segment(tool)
    );
    let arguments: Value = serde_json::from_str(&scenario.script.input_json).unwrap_or(Value::Null);
    let mut body_length = 0u64;
    let mut body_hash: Option<String> = None;
    if method != "GET" && method != "HEAD" {
        body_length = scenario.script.input_json.len() as u64;
        if body_length > 0 {
            body_hash = Some("0".repeat(64));
        }
    }
    let mut request = serde_json::json!({
        "request_id": format!("req-{}", scenario.id),
        "method": method,
        "path": path,
        "query": {},
        "headers": { "content-type": "application/json" },
        "caller": {
            "subject": format!("agent:{}", scenario.id),
            "auth_method": { "method": "anonymous" },
            "verified": true,
            "agent_id": format!("agent:{}", scenario.id),
        },
        "body_length": body_length,
        "route_pattern": path,
        "capability_id": format!("cap-{}", scenario.id),
        "tool_server": MATRIX_SERVER_ID,
        "tool_name": tool,
        "arguments": arguments,
        "timestamp": REQUEST_TIMESTAMP_SECS,
    });
    if let (Some(object), Some(hash)) = (request.as_object_mut(), body_hash) {
        object.insert("body_hash".to_string(), Value::String(hash));
    }
    request
}

fn encode_path_segment(segment: &str) -> String {
    byte_serialize(segment.as_bytes()).collect()
}

fn capability_token_for(scenario: &Scenario) -> String {
    serde_json::json!({
        "id": format!("cap-{}", scenario.id),
        "scopes": scenario.script.capability_scopes,
    })
    .to_string()
}

/// Scenario classes this sidecar relay cannot faithfully evaluate over
/// plain HTTP, mirroring the TypeScript node-http driver's
/// `unsupportedSignedCapability` gate. The `capability` and `revocation`
/// tuples turn on signed `CapabilityToken` validation (issuer, signature,
/// and time-validity per `chio-http-core::authority::validate_capability_token`);
/// this relay has no signed-token builder, so an unsigned token would force
/// a deny on validation rather than surface the intended verdict. Report
/// `unsupported` instead of a misleading pass/fail.
fn sidecar_unsupported_reason(scenario: &Scenario) -> Option<String> {
    match scenario.category.as_str() {
        "capability" | "revocation" => Some(format!(
            "lambda deployment-shape relay has no signed CapabilityToken builder; \
             sidecar evaluation of `{}` scenarios requires issuer + signature + \
             time-valid fields per chio-http-core::authority::validate_capability_token",
            scenario.category
        )),
        _ => None,
    }
}

fn method_for_tool(tool: &str) -> &'static str {
    if tool.ends_with(".read") || tool.ends_with(".get") || tool == "metrics.query" {
        "GET"
    } else {
        "POST"
    }
}

/// Derive the matrix verdict tuple from a `/chio/evaluate` response. The
/// authoritative `reason_code` and `scope_set` are read from
/// `receipt.metadata.verdict_matrix`; the verdict tag falls back to the deny
/// reason when the matrix metadata is absent.
pub fn tuple_from_evaluate_response(response: &Value) -> VerdictTuple {
    let verdict_obj = response.get("verdict");
    let verdict_tag = verdict_obj
        .and_then(|verdict| verdict.get("verdict"))
        .and_then(Value::as_str)
        .unwrap_or("error");
    let verdict = match verdict_tag {
        "allow" => "allow",
        "deny" => "deny",
        _ => "error",
    };

    let matrix = response
        .get("receipt")
        .and_then(|receipt| receipt.get("metadata"))
        .and_then(|metadata| metadata.get("verdict_matrix"));
    let reason_code = matrix
        .and_then(|matrix| matrix.get("reason_code"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| reason_from_verdict(verdict_tag, verdict_obj));
    let scope_set = matrix
        .and_then(|matrix| matrix.get("scope_set"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    VerdictTuple {
        verdict: verdict.to_string(),
        reason_code,
        scope_set,
    }
}

fn reason_from_verdict(verdict_tag: &str, verdict_obj: Option<&Value>) -> String {
    match verdict_tag {
        "allow" => REASON_NONE.to_string(),
        "deny" => verdict_obj
            .and_then(|verdict| verdict.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or(REASON_KERNEL_INTERNAL)
            .to_string(),
        _ => REASON_KERNEL_INTERNAL.to_string(),
    }
}

/// Build the expected-tuple map keyed by scenario id, used by the cross-driver
/// diff oracle once a sidecar is in play.
pub fn expected_tuple_map(scenarios: &[Scenario]) -> BTreeMap<String, VerdictTuple> {
    scenarios
        .iter()
        .map(|scenario| (scenario.id.clone(), scenario.expected.clone().normalized()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn scenario(id: &str) -> Scenario {
        Scenario {
            schema: SCENARIO_SCHEMA.to_string(),
            id: id.to_string(),
            category: "capability".to_string(),
            requires: vec![],
            script: ScenarioScript {
                operation: "tool.call".to_string(),
                tool: "files.read".to_string(),
                input_json: "{}".to_string(),
                capability_scopes: vec!["tool:read".to_string()],
            },
            expected: VerdictTuple {
                verdict: "allow".to_string(),
                reason_code: REASON_NONE.to_string(),
                scope_set: vec!["tool:read".to_string()],
            },
        }
    }

    fn unique_dir(prefix: &str) -> Result<PathBuf, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system clock before unix epoch: {err}"))?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("{prefix}-{nonce}")))
    }

    #[cfg(unix)]
    #[test]
    fn load_scenarios_rejects_symlinked_scenario_file() -> Result<(), String> {
        let root = unique_dir("chio-lambda-driver-scenarios")?;
        let outside = unique_dir("chio-lambda-driver-outside")?;
        fs::create_dir_all(&root)
            .map_err(|err| format!("failed to create {}: {err}", root.display()))?;
        fs::create_dir_all(&outside)
            .map_err(|err| format!("failed to create {}: {err}", outside.display()))?;
        fs::write(
            outside.join("escape.json"),
            r#"{
              "schema": "chio.verdict-matrix.scenario.v1",
              "id": "escaped-scenario",
              "category": "capability",
              "script": {
                "operation": "tool.call",
                "tool": "files.read",
                "input_json": "{}",
                "capability_scopes": ["tool:read"]
              },
              "expected": {
                "verdict": "allow",
                "reason_code": "urn:chio:error:none",
                "scope_set": ["tool:read"]
              }
            }"#,
        )
        .map_err(|err| format!("failed to write outside scenario: {err}"))?;
        std::os::unix::fs::symlink(outside.join("escape.json"), root.join("escape.json"))
            .map_err(|err| format!("failed to create symlink: {err}"))?;

        match load_scenarios(&root) {
            Ok(scenarios) => panic!("symlinked scenario should fail closed: {scenarios:?}"),
            Err(error) => assert!(error.contains("symlink")),
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
        Ok(())
    }

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
    fn run_driver_records_fail_when_sidecar_is_set_but_unreachable() {
        // capability/revocation scenarios self-gate to `unsupported` before
        // any sidecar call (the relay has no signed-token builder). The
        // remaining scenarios are attempted, and a set-but-unreachable
        // sidecar must surface them as `fail`, never a silent pass.
        let root = match resolve_scenario_root() {
            Ok(root) => root,
            Err(err) => panic!("could not resolve scenario root: {err}"),
        };
        // 127.0.0.1:1 is reserved and refuses connections fast.
        let report = match run_driver(&root, Some("http://127.0.0.1:1")) {
            Ok(report) => report,
            Err(err) => panic!("run_driver failed: {err}"),
        };
        assert!(report.total > 0, "expected scenarios to load");
        assert_eq!(report.passed, 0);
        assert!(
            report.unsupported > 0,
            "capability/revocation classes should gate to unsupported"
        );
        assert!(
            report.failed > 0,
            "attempted scenarios must fail against an unreachable sidecar, not skip"
        );
        assert_eq!(report.unsupported + report.failed, report.total);
    }

    #[test]
    fn scenario_to_http_request_matches_chio_http_request_contract() {
        let request = scenario_to_http_request(&scenario("shape-check"));
        let object = match request.as_object() {
            Some(object) => object,
            None => panic!("request must serialize to a JSON object"),
        };
        // request_id and timestamp are required (non-defaulted) fields on
        // ChioHttpRequest; tool inputs go under `arguments`, not `tool_arguments`.
        assert!(object.contains_key("request_id"), "request_id is required");
        assert!(object.contains_key("timestamp"), "timestamp is required");
        assert!(
            object.contains_key("arguments"),
            "tool inputs go under `arguments`"
        );
        assert!(
            !object.contains_key("tool_arguments"),
            "`tool_arguments` is not a ChioHttpRequest field"
        );
    }

    #[test]
    fn capability_and_revocation_scenarios_gate_to_unsupported() {
        let mut capability = scenario("cap-1");
        capability.category = "capability".to_string();
        assert!(sidecar_unsupported_reason(&capability).is_some());

        let mut revocation = scenario("revoke-1");
        revocation.category = "revocation".to_string();
        assert!(sidecar_unsupported_reason(&revocation).is_some());

        let mut replay = scenario("replay-1");
        replay.category = "replay".to_string();
        assert!(
            sidecar_unsupported_reason(&replay).is_none(),
            "replay scenarios are attempted, not gated"
        );
    }

    #[test]
    fn verdict_tuple_normalizes_scope_set() {
        let tuple = VerdictTuple {
            verdict: "allow".into(),
            reason_code: REASON_NONE.into(),
            scope_set: vec!["tool:write".into(), "tool:read".into()],
        };
        let normalized = tuple.normalized();
        assert_eq!(
            normalized.scope_set,
            vec!["tool:read".to_string(), "tool:write".to_string()]
        );
    }

    #[test]
    fn allow_response_with_matrix_metadata_yields_allow_tuple() {
        let response = serde_json::json!({
            "verdict": { "verdict": "allow" },
            "receipt": {
                "metadata": {
                    "verdict_matrix": {
                        "reason_code": "urn:chio:error:none",
                        "scope_set": ["tool:write", "tool:read"]
                    }
                }
            }
        });
        let tuple = tuple_from_evaluate_response(&response).normalized();
        assert_eq!(tuple.verdict, "allow");
        assert_eq!(tuple.reason_code, "urn:chio:error:none");
        assert_eq!(
            tuple.scope_set,
            vec!["tool:read".to_string(), "tool:write".to_string()]
        );
    }

    #[test]
    fn deny_response_without_matrix_metadata_falls_back_to_reason() {
        let response = serde_json::json!({
            "verdict": {
                "verdict": "deny",
                "reason": "urn:chio:error:capability:revoked",
                "guard": "capability"
            },
            "receipt": { "metadata": {} }
        });
        let tuple = tuple_from_evaluate_response(&response).normalized();
        assert_eq!(tuple.verdict, "deny");
        assert_eq!(tuple.reason_code, "urn:chio:error:capability:revoked");
        assert!(tuple.scope_set.is_empty());
    }

    #[test]
    fn http_request_sets_tool_call_fields_and_get_for_read() {
        let request = scenario_to_http_request(&scenario("capability-subset-001-read-exact"));
        assert_eq!(request.get("method").and_then(Value::as_str), Some("GET"));
        assert_eq!(
            request.get("tool_server").and_then(Value::as_str),
            Some(MATRIX_SERVER_ID)
        );
        assert_eq!(
            request.get("tool_name").and_then(Value::as_str),
            Some("files.read")
        );
        assert_eq!(
            request.get("path").and_then(Value::as_str),
            Some("/chio/tools/verdict-matrix/files.read")
        );
        assert_eq!(request.get("route_pattern"), request.get("path"));
        // GET requests carry no body hash.
        assert!(request.get("body_hash").is_none());
    }

    #[test]
    fn encode_path_segment_percent_encodes_slashes_in_tool_names() {
        let mut scenario = scenario("encoded-tool-path");
        scenario.script.tool = "terminal/create".to_string();
        let request = scenario_to_http_request(&scenario);
        assert_eq!(
            request.get("path").and_then(Value::as_str),
            Some("/chio/tools/verdict-matrix/terminal%2Fcreate")
        );
        assert_eq!(
            request.get("tool_name").and_then(Value::as_str),
            Some("terminal/create")
        );
    }
}
