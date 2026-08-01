use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    attenuation::{
        scope_hash, validate_attenuation, validate_delegation_chain, Attenuation, DelegationLink,
        DelegationLinkBody,
    },
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    governance::GovernedTransactionReceiptMetadata, kinds::BoundaryClass, kinds::ReceiptKind,
    kinds::RedactionMode, kinds::ToolOrigin, metadata::GuardEvidence,
};
use chio_kernel::dpop::{verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof, DpopProofBody};
use chio_kernel::transport::{read_frame, write_frame, TransportError};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDriver {
    Artifact,
    Stdio,
    Http,
}

impl NativeDriver {
    pub fn label(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Stdio => "stdio",
            Self::Http => "http",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeScenarioCategory {
    CapabilityValidation,
    DelegationAttenuation,
    ReceiptIntegrity,
    RevocationPropagation,
    DpopVerification,
    GovernedTransactionEnforcement,
}

impl NativeScenarioCategory {
    pub fn heading(self) -> &'static str {
        match self {
            Self::CapabilityValidation => "Capability Validation",
            Self::DelegationAttenuation => "Delegation Attenuation",
            Self::ReceiptIntegrity => "Receipt Integrity",
            Self::RevocationPropagation => "Revocation Propagation",
            Self::DpopVerification => "DPoP Verification",
            Self::GovernedTransactionEnforcement => "Governed Transaction Enforcement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAssertionKind {
    CapabilitySignatureValid,
    DelegationChainValid,
    DelegationAttenuatesParent,
    ReceiptSignatureValid,
    ReceiptTamperRejected,
    DpopProofValid,
    TerminalStatus,
    ToolErrorCode,
    ResponseReceiptSignatureValid,
    GovernedReceiptPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeAssertionSpec {
    pub name: String,
    pub kind: NativeAssertionKind,
    #[serde(default)]
    pub expected_bool: Option<bool>,
    #[serde(default)]
    pub expected_string: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeScenarioDescriptor {
    pub id: String,
    pub title: String,
    pub category: NativeScenarioCategory,
    pub driver: NativeDriver,
    pub fixture: String,
    pub spec_version: String,
    pub assertions: Vec<NativeAssertionSpec>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub http_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeStatus {
    Pass,
    Fail,
}

impl NativeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeAssertionResult {
    pub name: String,
    pub status: NativeStatus,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeScenarioResult {
    pub scenario_id: String,
    pub title: String,
    pub category: NativeScenarioCategory,
    pub driver: NativeDriver,
    pub spec_version: String,
    pub status: NativeStatus,
    pub duration_ms: u64,
    pub assertions: Vec<NativeAssertionResult>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NativeConformanceRunOptions {
    pub repo_root: PathBuf,
    pub scenarios_dir: PathBuf,
    pub results_output: PathBuf,
    pub report_output: PathBuf,
    pub peer_label: String,
    pub stdio_command: Option<PathBuf>,
    pub http_base_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NativeConformanceRunSummary {
    pub scenario_count: usize,
    pub results_output: PathBuf,
    pub report_output: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFixtureRequest {
    pub scenario_id: String,
    pub request: AgentMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFixtureResponse {
    pub messages: Vec<KernelMessage>,
}

#[derive(Debug, thiserror::Error)]
pub enum NativeSuiteError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("http driver error: {0}")]
    Http(String),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("fixture `{0}` is not known")]
    UnknownFixture(String),

    #[error("scenario `{scenario}` requires a stdio command")]
    MissingStdioCommand { scenario: String },

    #[error("scenario `{scenario}` requires an http base url")]
    MissingHttpBaseUrl { scenario: String },

    #[error("scenario `{scenario}` produced no terminal response")]
    MissingTerminalResponse { scenario: String },
}

pub fn default_native_run_options() -> NativeConformanceRunOptions {
    let repo_root = super::default_repo_root();
    NativeConformanceRunOptions {
        scenarios_dir: repo_root.join("tests/conformance/native/scenarios"),
        results_output: repo_root.join("tests/conformance/native/results/generated/chio-self.json"),
        report_output: repo_root.join("tests/conformance/native/reports/generated/chio-self.md"),
        peer_label: "chio-self".to_string(),
        stdio_command: None,
        http_base_url: None,
        repo_root,
    }
}

pub fn run_native_conformance_suite(
    options: &NativeConformanceRunOptions,
) -> Result<NativeConformanceRunSummary, NativeSuiteError> {
    let scenarios = load_native_scenarios_from_dir(&options.scenarios_dir)?;
    if let Some(parent) = options.results_output.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = options.report_output.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut results = Vec::new();
    for scenario in &scenarios {
        results.push(execute_native_scenario(scenario, options)?);
    }

    fs::write(
        &options.results_output,
        serde_json::to_string_pretty(&results).map_err(|source| NativeSuiteError::Json {
            path: options.results_output.display().to_string(),
            source,
        })?,
    )?;
    fs::write(
        &options.report_output,
        generate_native_markdown_report(&results),
    )?;

    Ok(NativeConformanceRunSummary {
        scenario_count: results.len(),
        results_output: options.results_output.clone(),
        report_output: options.report_output.clone(),
    })
}

pub fn load_native_scenarios_from_dir(
    path: impl AsRef<Path>,
) -> Result<Vec<NativeScenarioDescriptor>, NativeSuiteError> {
    let mut scenarios = Vec::new();
    let path = path.as_ref();
    require_native_scenario_directory(path)?;
    collect_native_scenarios(path, &mut scenarios)?;
    if scenarios.is_empty() {
        return Err(empty_native_scenario_directory_error(path));
    }
    scenarios.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(scenarios)
}

#[allow(clippy::expect_used)]
pub fn fixture_messages_for_request(request: &AgentMessage) -> Vec<KernelMessage> {
    match request {
        AgentMessage::Heartbeat => vec![KernelMessage::Heartbeat],
        AgentMessage::ListCapabilities => vec![KernelMessage::CapabilityList {
            capabilities: vec![build_valid_capability()],
        }],
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            tool,
            params,
            ..
        } if capability_token.id == "cap-revoked-001" => {
            vec![KernelMessage::ToolCallResponse {
                id: id.clone(),
                result: ToolCallResult::Err {
                    error: ToolCallError::CapabilityRevoked,
                },
                receipt: Box::new(build_receipt(
                    "rcpt-revoked-001",
                    &capability_token.id,
                    tool,
                    params.as_ref().clone(),
                    Decision::Deny {
                        reason: "capability revoked".to_string(),
                        guard: "revocation_store".to_string(),
                    },
                    None,
                )),
                execution_nonce: None,
            }]
        }
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            tool,
            params,
            ..
        } if tool == "governed_transfer" => {
            let metadata = serde_json::to_value(GovernedTransactionReceiptMetadata {
                intent_id: "intent-governed-001".to_string(),
                intent_hash: build_governed_intent()
                    .binding_hash()
                    .expect("hash deterministic governed intent"),
                purpose: "settle supplier invoice".to_string(),
                server_id: "conformance".to_string(),
                tool_name: "governed_transfer".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                approval: None,
                runtime_assurance: None,
                call_chain: None,
                autonomy: None,
                economic_authorization: None,
            })
            .ok()
            .map(|value| serde_json::json!({ "governed_transaction": value }));

            vec![KernelMessage::ToolCallResponse {
                id: id.clone(),
                result: ToolCallResult::Ok {
                    value: serde_json::json!({
                        "ok": true,
                        "tool": tool,
                        "governed": true
                    }),
                },
                receipt: Box::new(build_receipt(
                    "rcpt-governed-001",
                    &capability_token.id,
                    tool,
                    params.as_ref().clone(),
                    Decision::Allow,
                    metadata,
                )),
                execution_nonce: None,
            }]
        }
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            tool,
            params,
            ..
        } => {
            vec![KernelMessage::ToolCallResponse {
                id: id.clone(),
                result: ToolCallResult::Ok {
                    value: serde_json::json!({
                        "ok": true,
                        "tool": tool,
                        "fixture": "native"
                    }),
                },
                receipt: Box::new(build_receipt(
                    "rcpt-ok-001",
                    &capability_token.id,
                    tool,
                    params.as_ref().clone(),
                    Decision::Allow,
                    None,
                )),
                execution_nonce: None,
            }]
        }
    }
}

fn collect_native_scenarios(
    path: &Path,
    scenarios: &mut Vec<NativeScenarioDescriptor>,
) -> Result<(), NativeSuiteError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(NativeSuiteError::Io(std::io::Error::other(format!(
                "refusing symlink in native conformance scenario tree: {}",
                entry_path.display()
            ))));
        }
        if file_type.is_dir() {
            collect_native_scenarios(&entry_path, scenarios)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            let content = fs::read_to_string(&entry_path)?;
            let scenario =
                serde_json::from_str(&content).map_err(|source| NativeSuiteError::Json {
                    path: entry_path.display().to_string(),
                    source,
                })?;
            scenarios.push(scenario);
        }
    }
    Ok(())
}

fn require_native_scenario_directory(path: &Path) -> Result<(), NativeSuiteError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        NativeSuiteError::Io(std::io::Error::new(
            source.kind(),
            format!(
                "native conformance scenario directory {} is not readable: {source}",
                path.display()
            ),
        ))
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(NativeSuiteError::Io(std::io::Error::other(format!(
            "refusing symlinked native conformance scenario directory: {}",
            path.display()
        ))));
    }
    if !file_type.is_dir() {
        return Err(NativeSuiteError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "native conformance scenario directory {} is not a directory",
                path.display()
            ),
        )));
    }
    Ok(())
}

fn empty_native_scenario_directory_error(path: &Path) -> NativeSuiteError {
    NativeSuiteError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "native conformance scenario directory {} is empty: expected at least one JSON scenario",
            path.display()
        ),
    ))
}

fn execute_native_scenario(
    scenario: &NativeScenarioDescriptor,
    options: &NativeConformanceRunOptions,
) -> Result<NativeScenarioResult, NativeSuiteError> {
    let start = Instant::now();
    let outcome = match scenario.driver {
        NativeDriver::Artifact => execute_artifact_scenario(scenario),
        NativeDriver::Stdio => execute_stdio_scenario(scenario, options),
        NativeDriver::Http => execute_http_scenario(scenario, options),
    }?;

    let duration_ms = start.elapsed().as_millis() as u64;
    let status = if outcome
        .assertions
        .iter()
        .all(|assertion| assertion.status == NativeStatus::Pass)
    {
        NativeStatus::Pass
    } else {
        NativeStatus::Fail
    };
    let failure_message = if status == NativeStatus::Fail {
        outcome
            .assertions
            .iter()
            .find(|assertion| assertion.status == NativeStatus::Fail)
            .and_then(|assertion| assertion.message.clone())
    } else {
        None
    };

    Ok(NativeScenarioResult {
        scenario_id: scenario.id.clone(),
        title: scenario.title.clone(),
        category: scenario.category,
        driver: scenario.driver,
        spec_version: scenario.spec_version.clone(),
        status,
        duration_ms,
        assertions: outcome.assertions,
        notes: scenario.notes.clone(),
        failure_message,
    })
}

struct ScenarioOutcome {
    assertions: Vec<NativeAssertionResult>,
}

fn execute_artifact_scenario(
    scenario: &NativeScenarioDescriptor,
) -> Result<ScenarioOutcome, NativeSuiteError> {
    let fixture = build_fixture(&scenario.fixture)?;
    let assertions = scenario
        .assertions
        .iter()
        .map(|assertion| evaluate_artifact_assertion(assertion, &fixture))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScenarioOutcome { assertions })
}

fn execute_stdio_scenario(
    scenario: &NativeScenarioDescriptor,
    options: &NativeConformanceRunOptions,
) -> Result<ScenarioOutcome, NativeSuiteError> {
    let fixture = build_fixture(&scenario.fixture)?;
    let request = fixture
        .request()
        .ok_or_else(|| NativeSuiteError::UnknownFixture(scenario.fixture.clone()))?;
    let command =
        options
            .stdio_command
            .as_ref()
            .ok_or_else(|| NativeSuiteError::MissingStdioCommand {
                scenario: scenario.id.clone(),
            })?;

    let mut child = Command::new(command)
        .current_dir(&options.repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| NativeSuiteError::Io(std::io::Error::other("failed to open child stdin")))?;
    let mut child_stdout = child.stdout.take().ok_or_else(|| {
        NativeSuiteError::Io(std::io::Error::other("failed to open child stdout"))
    })?;

    let request_bytes = canonical_json_bytes(&request)
        .map_err(|error| NativeSuiteError::Http(error.to_string()))?;
    write_frame(&mut child_stdin, &request_bytes)?;
    child_stdin.flush()?;
    drop(child_stdin);

    let messages = read_kernel_messages(&mut child_stdout)?;
    let _ = child.wait();
    let assertions = scenario
        .assertions
        .iter()
        .map(|assertion| evaluate_message_assertion(assertion, &messages))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScenarioOutcome { assertions })
}

fn execute_http_scenario(
    scenario: &NativeScenarioDescriptor,
    options: &NativeConformanceRunOptions,
) -> Result<ScenarioOutcome, NativeSuiteError> {
    let fixture = build_fixture(&scenario.fixture)?;
    let request = fixture
        .request()
        .ok_or_else(|| NativeSuiteError::UnknownFixture(scenario.fixture.clone()))?;
    let base_url =
        options
            .http_base_url
            .as_ref()
            .ok_or_else(|| NativeSuiteError::MissingHttpBaseUrl {
                scenario: scenario.id.clone(),
            })?;
    let path = scenario
        .http_path
        .clone()
        .unwrap_or_else(|| "/chio-conformance/v1/invoke".to_string());
    let url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        }
    );
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: the native conformance HTTP
    // driver targets a caller-supplied harness endpoint, not production
    // substrate tool egress.
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| NativeSuiteError::Http(error.to_string()))?;
    let response = client
        .post(&url)
        .json(&NativeFixtureRequest {
            scenario_id: scenario.id.clone(),
            request,
        })
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: native conformance harness
        // dispatch, outside substrate tool egress.
        .send()
        .map_err(|error| NativeSuiteError::Http(error.to_string()))?;
    if !response.status().is_success() {
        return Err(NativeSuiteError::Http(format!(
            "unexpected status {} from {url}",
            response.status()
        )));
    }
    let response: NativeFixtureResponse = response
        .json()
        .map_err(|error| NativeSuiteError::Http(error.to_string()))?;
    let assertions = scenario
        .assertions
        .iter()
        .map(|assertion| evaluate_message_assertion(assertion, &response.messages))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScenarioOutcome { assertions })
}

fn read_kernel_messages(reader: &mut impl Read) -> Result<Vec<KernelMessage>, NativeSuiteError> {
    let mut messages = Vec::new();
    loop {
        match read_frame(reader) {
            Ok(frame) => {
                let message: KernelMessage =
                    serde_json::from_slice(&frame).map_err(|source| NativeSuiteError::Json {
                        path: "<stdio>".to_string(),
                        source,
                    })?;
                let terminal = matches!(message, KernelMessage::ToolCallResponse { .. });
                messages.push(message);
                if terminal {
                    break;
                }
            }
            Err(TransportError::ConnectionClosed) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(messages)
}

fn evaluate_artifact_assertion(
    assertion: &NativeAssertionSpec,
    fixture: &NativeFixture,
) -> Result<NativeAssertionResult, NativeSuiteError> {
    match assertion.kind {
        NativeAssertionKind::CapabilitySignatureValid => {
            let actual = fixture
                .valid_capability()?
                .verify_signature()
                .unwrap_or(false);
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::DelegationChainValid => {
            let (_, child) = fixture.delegation_pair()?;
            let actual = validate_delegation_chain(&child.delegation_chain, Some(4)).is_ok();
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::DelegationAttenuatesParent => {
            let (parent, child) = fixture.delegation_pair()?;
            let actual = validate_attenuation(&parent.scope, &child.scope).is_ok();
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::ReceiptSignatureValid => {
            let actual = fixture.valid_receipt()?.verify_signature().unwrap_or(false);
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::ReceiptTamperRejected => {
            let actual = !fixture
                .tampered_receipt()?
                .verify_signature()
                .unwrap_or(false);
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::DpopProofValid => {
            let dpop = fixture.dpop_case()?;
            let nonce_store = DpopNonceStore::new(32, Duration::from_secs(60));
            let actual = verify_dpop_proof(
                dpop.proof,
                dpop.capability,
                dpop.expected_tool_server,
                dpop.expected_tool_name,
                dpop.expected_action_hash,
                &nonce_store,
                &DpopConfig::default(),
            )
            .is_ok();
            compare_bool_assertion(assertion, actual)
        }
        _ => Ok(NativeAssertionResult {
            name: assertion.name.clone(),
            status: NativeStatus::Fail,
            message: Some("assertion kind requires message-driven execution".to_string()),
        }),
    }
}

fn evaluate_message_assertion(
    assertion: &NativeAssertionSpec,
    messages: &[KernelMessage],
) -> Result<NativeAssertionResult, NativeSuiteError> {
    match assertion.kind {
        NativeAssertionKind::TerminalStatus => {
            let (result, _) = terminal_response(messages).ok_or_else(|| {
                NativeSuiteError::MissingTerminalResponse {
                    scenario: assertion.name.clone(),
                }
            })?;
            let actual = tool_result_status(result).to_string();
            compare_string_assertion(assertion, actual)
        }
        NativeAssertionKind::ToolErrorCode => {
            let (result, _) = terminal_response(messages).ok_or_else(|| {
                NativeSuiteError::MissingTerminalResponse {
                    scenario: assertion.name.clone(),
                }
            })?;
            let actual = match result {
                ToolCallResult::Err { error } => tool_error_code(error).to_string(),
                _ => "not_an_error".to_string(),
            };
            compare_string_assertion(assertion, actual)
        }
        NativeAssertionKind::ResponseReceiptSignatureValid => {
            let (_, receipt) = terminal_response(messages).ok_or_else(|| {
                NativeSuiteError::MissingTerminalResponse {
                    scenario: assertion.name.clone(),
                }
            })?;
            let actual = receipt.verify_signature().unwrap_or(false);
            compare_bool_assertion(assertion, actual)
        }
        NativeAssertionKind::GovernedReceiptPresent => {
            let (_, receipt) = terminal_response(messages).ok_or_else(|| {
                NativeSuiteError::MissingTerminalResponse {
                    scenario: assertion.name.clone(),
                }
            })?;
            let actual = receipt
                .metadata
                .as_ref()
                .and_then(|value| value.get("governed_transaction"))
                .is_some();
            compare_bool_assertion(assertion, actual)
        }
        _ => Ok(NativeAssertionResult {
            name: assertion.name.clone(),
            status: NativeStatus::Fail,
            message: Some("assertion kind requires artifact execution".to_string()),
        }),
    }
}

fn compare_bool_assertion(
    assertion: &NativeAssertionSpec,
    actual: bool,
) -> Result<NativeAssertionResult, NativeSuiteError> {
    let expected = assertion.expected_bool.ok_or_else(|| {
        NativeSuiteError::Http(format!(
            "assertion {} is missing expectedBool",
            assertion.name
        ))
    })?;
    Ok(NativeAssertionResult {
        name: assertion.name.clone(),
        status: if actual == expected {
            NativeStatus::Pass
        } else {
            NativeStatus::Fail
        },
        message: if actual == expected {
            None
        } else {
            Some(format!("expected {expected}, got {actual}"))
        },
    })
}

fn compare_string_assertion(
    assertion: &NativeAssertionSpec,
    actual: String,
) -> Result<NativeAssertionResult, NativeSuiteError> {
    let expected = assertion.expected_string.clone().ok_or_else(|| {
        NativeSuiteError::Http(format!(
            "assertion {} is missing expectedString",
            assertion.name
        ))
    })?;
    Ok(NativeAssertionResult {
        name: assertion.name.clone(),
        status: if actual == expected {
            NativeStatus::Pass
        } else {
            NativeStatus::Fail
        },
        message: if actual == expected {
            None
        } else {
            Some(format!("expected `{expected}`, got `{actual}`"))
        },
    })
}

fn terminal_response(messages: &[KernelMessage]) -> Option<(&ToolCallResult, &ChioReceipt)> {
    messages.iter().find_map(|message| match message {
        KernelMessage::ToolCallResponse {
            result, receipt, ..
        } => Some((result, receipt.as_ref())),
        _ => None,
    })
}

fn tool_result_status(result: &ToolCallResult) -> &'static str {
    match result {
        ToolCallResult::Ok { .. } => "ok",
        ToolCallResult::StreamComplete { .. } => "stream_complete",
        ToolCallResult::Cancelled { .. } => "cancelled",
        ToolCallResult::Incomplete { .. } => "incomplete",
        ToolCallResult::Err { .. } => "err",
    }
}

fn tool_error_code(error: &ToolCallError) -> &'static str {
    match error {
        ToolCallError::CapabilityDenied(_) => "capability_denied",
        ToolCallError::CapabilityExpired => "capability_expired",
        ToolCallError::CapabilityRevoked => "capability_revoked",
        ToolCallError::PolicyDenied { .. } => "policy_denied",
        ToolCallError::ToolServerError(_) => "tool_server_error",
        ToolCallError::InternalError(_) => "internal_error",
    }
}

fn generate_native_markdown_report(results: &[NativeScenarioResult]) -> String {
    let mut output = String::new();
    output.push_str("# Chio Native Conformance Report\n\n");
    output.push_str("Generated from native conformance result artifacts.\n\n");

    if results.is_empty() {
        output.push_str("No native conformance results were generated.\n");
        return output;
    }

    output.push_str("## Summary\n\n");
    for category in [
        NativeScenarioCategory::CapabilityValidation,
        NativeScenarioCategory::DelegationAttenuation,
        NativeScenarioCategory::ReceiptIntegrity,
        NativeScenarioCategory::RevocationPropagation,
        NativeScenarioCategory::DpopVerification,
        NativeScenarioCategory::GovernedTransactionEnforcement,
    ] {
        let category_results = results
            .iter()
            .filter(|result| result.category == category)
            .collect::<Vec<_>>();
        if category_results.is_empty() {
            continue;
        }
        let passed = category_results
            .iter()
            .filter(|result| result.status == NativeStatus::Pass)
            .count();
        output.push_str(&format!(
            "- {}: {passed}/{} pass\n",
            category.heading(),
            category_results.len()
        ));
    }
    output.push('\n');

    for category in [
        NativeScenarioCategory::CapabilityValidation,
        NativeScenarioCategory::DelegationAttenuation,
        NativeScenarioCategory::ReceiptIntegrity,
        NativeScenarioCategory::RevocationPropagation,
        NativeScenarioCategory::DpopVerification,
        NativeScenarioCategory::GovernedTransactionEnforcement,
    ] {
        let category_results = results
            .iter()
            .filter(|result| result.category == category)
            .collect::<Vec<_>>();
        if category_results.is_empty() {
            continue;
        }
        output.push_str(&format!("## {}\n\n", category.heading()));
        output.push_str("| Scenario | Driver | Status | Duration |\n");
        output.push_str("| --- | --- | --- | --- |\n");
        for result in category_results {
            output.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} ms |\n",
                result.scenario_id,
                result.driver.label(),
                result.status.label(),
                result.duration_ms
            ));
        }
        output.push('\n');
    }

    let failures = results
        .iter()
        .filter(|result| result.status == NativeStatus::Fail)
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        output.push_str("## Failures\n\n");
        for failure in failures {
            output.push_str(&format!(
                "- `{}`: {}\n",
                failure.scenario_id,
                failure
                    .failure_message
                    .as_deref()
                    .unwrap_or("scenario failed without a recorded failure message")
            ));
        }
    }

    output
}

enum NativeFixture {
    Capability(Box<CapabilityToken>),
    Delegation {
        parent: Box<CapabilityToken>,
        child: Box<CapabilityToken>,
    },
    Receipt {
        valid: Box<ChioReceipt>,
        tampered: Box<ChioReceipt>,
    },
    Dpop {
        proof: Box<DpopProof>,
        capability: Box<CapabilityToken>,
        expected_tool_server: String,
        expected_tool_name: String,
        expected_action_hash: String,
    },
    Request(AgentMessage),
}

impl NativeFixture {
    fn valid_capability(&self) -> Result<&CapabilityToken, NativeSuiteError> {
        match self {
            Self::Capability(token) => Ok(token),
            _ => Err(NativeSuiteError::Http(
                "fixture is not a capability".to_string(),
            )),
        }
    }

    fn delegation_pair(&self) -> Result<(&CapabilityToken, &CapabilityToken), NativeSuiteError> {
        match self {
            Self::Delegation { parent, child } => Ok((parent.as_ref(), child.as_ref())),
            _ => Err(NativeSuiteError::Http(
                "fixture is not a delegation pair".to_string(),
            )),
        }
    }

    fn valid_receipt(&self) -> Result<&ChioReceipt, NativeSuiteError> {
        match self {
            Self::Receipt { valid, .. } => Ok(valid.as_ref()),
            _ => Err(NativeSuiteError::Http(
                "fixture is not a receipt".to_string(),
            )),
        }
    }

    fn tampered_receipt(&self) -> Result<&ChioReceipt, NativeSuiteError> {
        match self {
            Self::Receipt { tampered, .. } => Ok(tampered.as_ref()),
            _ => Err(NativeSuiteError::Http(
                "fixture is not a receipt".to_string(),
            )),
        }
    }

    fn dpop_case(&self) -> Result<DpopCase<'_>, NativeSuiteError> {
        match self {
            Self::Dpop {
                proof,
                capability,
                expected_tool_server,
                expected_tool_name,
                expected_action_hash,
            } => Ok(DpopCase {
                proof: proof.as_ref(),
                capability,
                expected_tool_server,
                expected_tool_name,
                expected_action_hash,
            }),
            _ => Err(NativeSuiteError::Http(
                "fixture is not a dpop case".to_string(),
            )),
        }
    }

    fn request(&self) -> Option<AgentMessage> {
        match self {
            Self::Request(request) => Some(request.clone()),
            _ => None,
        }
    }
}

struct DpopCase<'a> {
    proof: &'a DpopProof,
    capability: &'a CapabilityToken,
    expected_tool_server: &'a str,
    expected_tool_name: &'a str,
    expected_action_hash: &'a str,
}

fn build_fixture(id: &str) -> Result<NativeFixture, NativeSuiteError> {
    match id {
        "valid_capability" => Ok(NativeFixture::Capability(
            Box::new(build_valid_capability()),
        )),
        "delegation_pair" => {
            let (parent, child) = build_delegation_pair();
            Ok(NativeFixture::Delegation {
                parent: Box::new(parent),
                child: Box::new(child),
            })
        }
        "signed_receipt" => {
            let valid = build_receipt(
                "rcpt-integrity-001",
                "cap-valid-001",
                "echo",
                serde_json::json!({"text": "hello"}),
                Decision::Allow,
                None,
            );
            let mut tampered = valid.clone();
            tampered.tool_name = "tampered".to_string();
            Ok(NativeFixture::Receipt {
                valid: Box::new(valid),
                tampered: Box::new(tampered),
            })
        }
        "valid_dpop" => {
            let capability = build_dpop_capability();
            let params = serde_json::json!({"amount": 25, "currency": "USD"});
            let action_hash = chio_core::sha256_hex(
                &canonical_json_bytes(&params)
                    .map_err(|error| NativeSuiteError::Http(error.to_string()))?,
            );
            let proof = DpopProof::sign(
                DpopProofBody {
                    schema: chio_kernel::dpop::DPOP_SCHEMA.to_string(),
                    capability_id: capability.id.clone(),
                    tool_server: "conformance".to_string(),
                    tool_name: "transfer".to_string(),
                    action_hash: action_hash.clone(),
                    nonce: "nonce-001".to_string(),
                    issued_at: current_unix_timestamp(),
                    agent_key: dpop_subject_keypair().public_key(),
                },
                &dpop_subject_keypair(),
            )
            .map_err(|error| NativeSuiteError::Http(error.to_string()))?;
            Ok(NativeFixture::Dpop {
                proof: Box::new(proof),
                capability: Box::new(capability),
                expected_tool_server: "conformance".to_string(),
                expected_tool_name: "transfer".to_string(),
                expected_action_hash: action_hash,
            })
        }
        "revoked_capability_request" => Ok(NativeFixture::Request(build_revoked_request())),
        "governed_request" => Ok(NativeFixture::Request(build_governed_request())),
        other => Err(NativeSuiteError::UnknownFixture(other.to_string())),
    }
}

fn authority_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn capability_subject_keypair() -> Keypair {
    Keypair::from_seed(&[11u8; 32])
}

fn delegated_subject_keypair() -> Keypair {
    Keypair::from_seed(&[13u8; 32])
}

fn dpop_subject_keypair() -> Keypair {
    Keypair::from_seed(&[17u8; 32])
}

fn kernel_keypair() -> Keypair {
    Keypair::from_seed(&[23u8; 32])
}

fn build_scope(
    tool_name: &str,
    dpop_required: Option<bool>,
    constraints: Vec<Constraint>,
) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "conformance".to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: Some(5),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required,
        }],
        ..ChioScope::default()
    }
}

#[allow(clippy::expect_used)]
fn build_capability(
    id: &str,
    subject: &Keypair,
    scope: ChioScope,
    delegation_chain: Vec<DelegationLink>,
) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: authority_keypair().public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            delegation_chain,
            aggregate_invocation_budget: None,
        },
        &authority_keypair(),
    )
    .expect("sign deterministic capability")
}

fn build_valid_capability() -> CapabilityToken {
    build_capability(
        "cap-valid-001",
        &capability_subject_keypair(),
        build_scope("echo", None, vec![]),
        vec![],
    )
}

fn build_dpop_capability() -> CapabilityToken {
    build_capability(
        "cap-dpop-001",
        &dpop_subject_keypair(),
        build_scope("transfer", Some(true), vec![]),
        vec![],
    )
}

#[allow(clippy::expect_used)]
fn build_delegation_pair() -> (CapabilityToken, CapabilityToken) {
    let parent_subject = capability_subject_keypair();
    let child_subject = delegated_subject_keypair();
    let parent = build_capability(
        "cap-parent-001",
        &parent_subject,
        build_scope("echo", None, vec![]),
        vec![],
    );
    let child_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "conformance".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::MaxLength(32)],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let child_scope_hash = scope_hash(&child_scope).expect("hash child delegation scope");
    let delegation = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent.id.clone(),
            delegator: parent_subject.public_key(),
            delegatee: child_subject.public_key(),
            attenuations: vec![
                Attenuation::ReduceBudget {
                    server_id: "conformance".to_string(),
                    tool_name: "echo".to_string(),
                    max_invocations: 1,
                },
                Attenuation::AddConstraint {
                    server_id: "conformance".to_string(),
                    tool_name: "echo".to_string(),
                    constraint: Constraint::MaxLength(32),
                },
            ],
            timestamp: 1_700_000_100,
            scope_hash: Some(child_scope_hash),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &parent_subject,
    )
    .expect("sign deterministic delegation");

    let child = build_capability(
        "cap-child-001",
        &child_subject,
        child_scope,
        vec![delegation],
    );
    (parent, child)
}

fn build_governed_intent() -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: "intent-governed-001".to_string(),
        server_id: "conformance".to_string(),
        tool_name: "governed_transfer".to_string(),
        purpose: "settle supplier invoice".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "amount": 1250,
            "currency": "USD",
            "seller": "supplier-001"
        })),
        body: Default::default(),
    }
}

fn build_governed_request() -> AgentMessage {
    AgentMessage::ToolCallRequest {
        id: "req-governed-001".to_string(),
        capability_token: Box::new(build_capability(
            "cap-governed-001",
            &capability_subject_keypair(),
            build_scope(
                "governed_transfer",
                None,
                vec![Constraint::GovernedIntentRequired],
            ),
            vec![],
        )),
        server_id: "conformance".to_string(),
        tool: "governed_transfer".to_string(),
        params: Box::new(serde_json::json!({
            "amount": 1250,
            "currency": "USD",
            "seller": "supplier-001"
        })),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
    }
}

fn build_revoked_request() -> AgentMessage {
    AgentMessage::ToolCallRequest {
        id: "req-revoked-001".to_string(),
        capability_token: Box::new(build_capability(
            "cap-revoked-001",
            &capability_subject_keypair(),
            build_scope("echo", None, vec![]),
            vec![],
        )),
        server_id: "conformance".to_string(),
        tool: "echo".to_string(),
        params: Box::new(serde_json::json!({"text": "hello"})),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
    }
}

#[allow(clippy::expect_used)]
fn build_receipt(
    receipt_id: &str,
    capability_id: &str,
    tool_name: &str,
    params: serde_json::Value,
    decision: Decision,
    metadata: Option<serde_json::Value>,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_700_000_200,
            capability_id: capability_id.to_string(),
            tool_server: "conformance".to_string(),
            tool_name: tool_name.to_string(),
            action: ToolCallAction::from_parameters(params).expect("build action"),
            decision: Some(decision),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core::sha256_hex(b"{\"ok\":true}"),
            policy_hash: "policy-hash-001".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ConformanceGuard".to_string(),
                verdict: true,
                details: None,
            }],
            metadata,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_keypair().public_key(),
            bbs_projection_version: None,
        },
        &kernel_keypair(),
    )
    .expect("sign deterministic receipt")
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn load_native_scenarios_reads_checked_in_suite() {
        let repo_root = crate::default_repo_root();
        let scenarios =
            load_native_scenarios_from_dir(repo_root.join("tests/conformance/native/scenarios"))
                .expect("load native scenarios");
        assert_eq!(scenarios.len(), 6);
        assert!(scenarios
            .iter()
            .any(|scenario| { scenario.category == NativeScenarioCategory::CapabilityValidation }));
        assert!(scenarios.iter().any(|scenario| {
            scenario.category == NativeScenarioCategory::GovernedTransactionEnforcement
        }));
    }

    #[test]
    fn load_native_scenarios_rejects_missing_directory() {
        let missing = std::env::temp_dir().join(format!(
            "chio-conformance-native-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&missing);

        match load_native_scenarios_from_dir(&missing) {
            Ok(scenarios) => panic!("missing native scenario directory should fail: {scenarios:?}"),
            Err(error) => assert!(error.to_string().contains("directory")),
        }
    }

    #[test]
    fn load_native_scenarios_rejects_empty_directory() {
        let dir = std::env::temp_dir().join(format!(
            "chio-conformance-native-empty-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create empty native scenario dir");

        match load_native_scenarios_from_dir(&dir) {
            Ok(scenarios) => panic!("empty native scenario directory should fail: {scenarios:?}"),
            Err(error) => assert!(error.to_string().contains("empty")),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn load_native_scenarios_rejects_symlinked_json_file() {
        let dir = std::env::temp_dir().join(format!(
            "chio-conformance-native-symlink-{}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "chio-conformance-native-symlink-outside-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&dir).expect("create native scenario dir");
        fs::create_dir_all(&outside).expect("create outside dir");
        fs::write(
            outside.join("escape.json"),
            r#"{
              "id": "escape",
              "title": "Escape",
              "category": "capability_validation",
              "driver": "artifact",
              "fixture": "valid-capability",
              "specVersion": "1.0",
              "assertions": []
            }"#,
        )
        .expect("write outside scenario");
        std::os::unix::fs::symlink(outside.join("escape.json"), dir.join("escape.json"))
            .expect("create scenario symlink");

        match load_native_scenarios_from_dir(&dir) {
            Ok(scenarios) => panic!("symlinked native scenario should fail: {scenarios:?}"),
            Err(error) => assert!(error.to_string().contains("symlink")),
        }

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn native_fixture_responses_include_governed_receipt_metadata() {
        let request = build_governed_request();
        let messages = fixture_messages_for_request(&request);
        let (_, receipt) = terminal_response(&messages).expect("terminal response");
        assert!(receipt.verify_signature().expect("verify signature"));
        assert!(receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get("governed_transaction"))
            .is_some());
    }
}
