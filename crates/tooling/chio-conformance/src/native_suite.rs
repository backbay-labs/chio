use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, validate_attenuation, validate_delegation_chain,
        Attenuation, AttenuationProof, DelegationLink, DelegationLinkBody,
    },
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
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
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RevocationStore, RevocationStoreError,
    RuntimeTraceEvent, RuntimeTraceObserver, ToolCallRequest, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use chio_trace_validate::{RuntimeTraceMutation, RuntimeTraceRecorder};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const NATIVE_TRACE_OBSERVER_KEY: &str =
    include_str!("../../../../formal/tla/trace/fixtures/native-conformance-observer-key.txt");

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
    pub trace_output: Option<PathBuf>,
    pub trace_negative_output: Option<PathBuf>,
    pub trace_monotone_negative_output: Option<PathBuf>,
    pub trace_attenuation_negative_output: Option<PathBuf>,
    pub trace_freshness_negative_output: Option<PathBuf>,
    pub trace_observer_key_output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct NativeConformanceRunSummary {
    pub scenario_count: usize,
    pub results_output: PathBuf,
    pub report_output: PathBuf,
    pub trace_output: Option<PathBuf>,
    pub trace_negative_output: Option<PathBuf>,
    pub trace_monotone_negative_output: Option<PathBuf>,
    pub trace_attenuation_negative_output: Option<PathBuf>,
    pub trace_freshness_negative_output: Option<PathBuf>,
    pub trace_observer_key_output: Option<PathBuf>,
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

    #[error("trace output requires both a log path and an observer-key artifact path")]
    IncompleteTraceOutput,

    #[error("the passing revocation scenario did not produce a receipt")]
    MissingRevocationTraceReceipt,

    #[error("native trace observer key does not match its checked pin")]
    TraceObserverKeyPinMismatch,

    #[error("trace construction error: {0}")]
    Trace(#[from] chio_trace_validate::TraceError),

    #[error("kernel trace execution error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),

    #[error("trace receipt store error: {0}")]
    ReceiptStore(#[from] chio_kernel::ReceiptStoreError),

    #[error("trace capability construction error: {0}")]
    Core(#[from] chio_core::Error),
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
        trace_output: None,
        trace_negative_output: None,
        trace_monotone_negative_output: None,
        trace_attenuation_negative_output: None,
        trace_freshness_negative_output: None,
        trace_observer_key_output: None,
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

    let trace_outputs = [
        options.trace_observer_key_output.is_some(),
        options.trace_negative_output.is_some(),
        options.trace_monotone_negative_output.is_some(),
        options.trace_attenuation_negative_output.is_some(),
        options.trace_freshness_negative_output.is_some(),
    ];
    if trace_outputs
        .into_iter()
        .any(|present| present != options.trace_output.is_some())
    {
        return Err(NativeSuiteError::IncompleteTraceOutput);
    }

    let mut results = Vec::new();
    for scenario in &scenarios {
        let (result, terminal_receipt) = execute_native_scenario(scenario, options)?;
        let _terminal_receipt = terminal_receipt;
        results.push(result);
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

    if let (Some(trace_output), Some(observer_key_output)) =
        (&options.trace_output, &options.trace_observer_key_output)
    {
        let (trace, trusted_key) = capture_native_revocation_trace()?;
        chio_trace_validate::write_trace_artifact(trace_output, &trace)?;
        chio_trace_validate::write_trace_artifact(
            observer_key_output,
            format!("{}\n", trusted_key.to_hex()).as_bytes(),
        )?;
        if let Some(negative_output) = &options.trace_negative_output {
            let (negative_trace, negative_key) = capture_runtime_revocation_trace_with_store(
                "native-revocation-visibility-bypass",
                true,
                false,
                TraceRevocationTarget::PresentedCapability,
                RuntimeTraceMutation::None,
            )?;
            if negative_key != trusted_key {
                return Err(NativeSuiteError::TraceObserverKeyPinMismatch);
            }
            chio_trace_validate::write_trace_artifact(negative_output, &negative_trace)?;
        }
        for (output, context, mutation) in [
            (
                options.trace_monotone_negative_output.as_ref(),
                "native-duplicate-receipt-time",
                RuntimeTraceMutation::DuplicateReceiptTime,
            ),
            (
                options.trace_attenuation_negative_output.as_ref(),
                "native-delegation-depth-above-limit",
                RuntimeTraceMutation::DepthAboveLimit,
            ),
            (
                options.trace_freshness_negative_output.as_ref(),
                "native-future-revocation-epoch",
                RuntimeTraceMutation::FutureRevocationEpoch,
            ),
        ] {
            let output = output.ok_or(NativeSuiteError::IncompleteTraceOutput)?;
            let (negative_trace, negative_key) = capture_runtime_revocation_trace_with_store(
                context,
                false,
                false,
                TraceRevocationTarget::DelegationAncestor,
                mutation,
            )?;
            if negative_key != trusted_key {
                return Err(NativeSuiteError::TraceObserverKeyPinMismatch);
            }
            chio_trace_validate::write_trace_artifact(output, &negative_trace)?;
        }
    }

    Ok(NativeConformanceRunSummary {
        scenario_count: results.len(),
        results_output: options.results_output.clone(),
        report_output: options.report_output.clone(),
        trace_output: options.trace_output.clone(),
        trace_negative_output: options.trace_negative_output.clone(),
        trace_monotone_negative_output: options.trace_monotone_negative_output.clone(),
        trace_attenuation_negative_output: options.trace_attenuation_negative_output.clone(),
        trace_freshness_negative_output: options.trace_freshness_negative_output.clone(),
        trace_observer_key_output: options.trace_observer_key_output.clone(),
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
                    params.clone(),
                    Decision::Deny {
                        reason: "capability revoked".to_string(),
                        guard: "revocation_store".to_string(),
                    },
                    None,
                )),
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
                    params.clone(),
                    Decision::Allow,
                    metadata,
                )),
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
                    params.clone(),
                    Decision::Allow,
                    None,
                )),
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
) -> Result<(NativeScenarioResult, Option<ChioReceipt>), NativeSuiteError> {
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

    Ok((
        NativeScenarioResult {
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
        },
        outcome.terminal_receipt,
    ))
}

struct ScenarioOutcome {
    assertions: Vec<NativeAssertionResult>,
    terminal_receipt: Option<ChioReceipt>,
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
    Ok(ScenarioOutcome {
        assertions,
        terminal_receipt: None,
    })
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
    let terminal_receipt = terminal_response(&messages).map(|(_, receipt)| receipt.clone());
    let assertions = scenario
        .assertions
        .iter()
        .map(|assertion| evaluate_message_assertion(assertion, &messages))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScenarioOutcome {
        assertions,
        terminal_receipt,
    })
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
    let terminal_receipt =
        terminal_response(&response.messages).map(|(_, receipt)| receipt.clone());
    let assertions = scenario
        .assertions
        .iter()
        .map(|assertion| evaluate_message_assertion(assertion, &response.messages))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScenarioOutcome {
        assertions,
        terminal_receipt,
    })
}

fn capture_native_revocation_trace(
) -> Result<(Vec<u8>, chio_core::crypto::PublicKey), NativeSuiteError> {
    capture_runtime_revocation_trace("native-revocation-conformance")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceRevocationTarget {
    PresentedCapability,
    DelegationAncestor,
}

pub fn capture_runtime_revocation_trace(
    context: &str,
) -> Result<(Vec<u8>, chio_core::crypto::PublicKey), NativeSuiteError> {
    capture_runtime_revocation_trace_with_store(
        context,
        false,
        false,
        TraceRevocationTarget::DelegationAncestor,
        RuntimeTraceMutation::None,
    )
}

fn capture_runtime_revocation_trace_with_store(
    context: &str,
    blind_revocation_store: bool,
    drop_admission_callbacks: bool,
    revocation_target: TraceRevocationTarget,
    mutation: RuntimeTraceMutation,
) -> Result<(Vec<u8>, chio_core::crypto::PublicKey), NativeSuiteError> {
    let observer = Keypair::from_seed(&[167; 32]);
    let observer_key = observer.public_key();
    if observer_key.to_hex() != NATIVE_TRACE_OBSERVER_KEY.trim() {
        return Err(NativeSuiteError::TraceObserverKeyPinMismatch);
    }
    let kernel_key = kernel_keypair();
    let parent_scope = trace_scope(true, 5);
    let child_scope = trace_scope(false, 4);
    let child_id = "cap-runtime-trace-child";
    let subject = delegated_subject_keypair();
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let receipt_store_dir = tempfile::tempdir()?;
    let receipt_store_path = receipt_store_dir.path().join("receipt-trace.sqlite");
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: kernel_key.clone(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 4,
        policy_hash: chio_core::sha256_hex(b"trace-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    })
    .with_capability_trust_roots(vec![(kernel_key.public_key(), parent_scope_hash.clone())]);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(receipt_store_path)?))?;
    let parent = kernel.issue_capability(&kernel_key.public_key(), parent_scope.clone(), 300)?;
    let now = current_unix_timestamp().max(parent.issued_at);
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent.id.clone(),
            delegator: kernel_key.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![Attenuation::ReduceBudget {
                server_id: "conformance".to_string(),
                tool_name: "echo".to_string(),
                max_invocations: 4,
            }],
            timestamp: now,
            scope_hash: Some(parent_scope_hash.clone()),
        },
        &kernel_key,
    )?;
    let proof = AttenuationProof {
        parent_scope_hash: parent_scope_hash.clone(),
        child_scope_hash,
        normalized_subset_proof: compute_attenuation_witness(&parent_scope, &child_scope)?,
    };
    let capability = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: child_id.to_string(),
                issuer: kernel_key.public_key(),
                subject: subject.public_key(),
                scope: child_scope,
                issued_at: now,
                expires_at: now.saturating_add(120).min(parent.expires_at),
                delegation_chain: vec![link],
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: Some(10_000),
        },
        &kernel_key,
    )?;
    let recorder = Arc::new(RuntimeTraceRecorder::new_with_mutation(
        kernel_key.public_key(),
        observer,
        context,
        mutation,
    )?);
    let runtime_observer: Arc<dyn RuntimeTraceObserver> = if drop_admission_callbacks {
        Arc::new(AdmissionDroppingObserver {
            inner: recorder.clone(),
        })
    } else {
        recorder.clone()
    };
    kernel.set_runtime_trace_observer(runtime_observer);
    if blind_revocation_store {
        kernel.set_revocation_store(Box::new(BlindRevocationStore));
    }
    kernel.register_tool_server(Box::new(NativeTraceEchoServer));
    kernel
        .register_budget_parent(parent.id.clone(), 10_000)
        .map_err(|error| NativeSuiteError::Http(error.to_string()))?;

    let allow = kernel.evaluate_tool_call_blocking(&trace_request(
        "runtime-trace-allow",
        &capability,
        &subject,
        1,
    ))?;
    if allow.verdict != Verdict::Allow {
        return Err(NativeSuiteError::Http(format!(
            "runtime trace pre-revocation call did not allow: {}",
            allow
                .reason
                .as_deref()
                .unwrap_or("kernel supplied no reason")
        )));
    }
    let revoked_capability_id = match revocation_target {
        TraceRevocationTarget::PresentedCapability => &capability.id,
        TraceRevocationTarget::DelegationAncestor => &parent.id,
    };
    kernel.revoke_capability(revoked_capability_id)?;
    let deny = kernel.evaluate_tool_call_blocking(&trace_request(
        "runtime-trace-deny",
        &capability,
        &subject,
        2,
    ))?;
    let expected_post_revoke = if blind_revocation_store {
        Verdict::Allow
    } else {
        Verdict::Deny
    };
    if deny.verdict != expected_post_revoke {
        return Err(NativeSuiteError::Http(
            "runtime trace post-revocation verdict did not match its calibrated store".to_string(),
        ));
    }
    Ok((recorder.finish()?, observer_key))
}

struct AdmissionDroppingObserver {
    inner: Arc<RuntimeTraceRecorder>,
}

impl RuntimeTraceObserver for AdmissionDroppingObserver {
    fn observe(&self, event: RuntimeTraceEvent) {
        if !matches!(&event, RuntimeTraceEvent::RevocationAdmission { .. }) {
            self.inner.observe(event);
        }
    }
}

struct BlindRevocationStore;

impl RevocationStore for BlindRevocationStore {
    fn is_revoked(&self, _capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(false)
    }

    fn revoke(&self, _capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(true)
    }
}

fn trace_scope(delegable: bool, max_invocations: u32) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "conformance".to_string(),
            tool_name: "echo".to_string(),
            operations,
            constraints: Vec::new(),
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn trace_request(
    request_id: &str,
    capability: &CapabilityToken,
    subject: &Keypair,
    nonce: u64,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "echo".to_string(),
        server_id: "conformance".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({"nonce": nonce}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

struct NativeTraceEchoServer;

#[async_trait::async_trait]
impl ToolServerConnection for NativeTraceEchoServer {
    fn server_id(&self) -> &str {
        "conformance"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(arguments)
    }
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
        params: serde_json::json!({
            "amount": 1250,
            "currency": "USD",
            "seller": "supplier-001"
        }),
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
        params: serde_json::json!({"text": "hello"}),
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
    fn native_trace_observations_are_signed_and_non_vacuous() {
        let (encoded, trusted_key) = capture_native_revocation_trace().expect("trace");
        assert_eq!(trusted_key.to_hex(), NATIVE_TRACE_OBSERVER_KEY.trim());
        let observations =
            chio_trace_validate::decode_observations(&encoded, std::slice::from_ref(&trusted_key))
                .expect("decode trace");
        assert!(observations.observations()[0]
            .body
            .trace_id
            .starts_with("runtime:"));
        let chio_trace_validate::ObservationEvent::Revoke {
            capability_id: revoked_ancestor,
            ..
        } = &observations.observations()[1].body.event
        else {
            panic!("second observation is not a revocation");
        };
        let chio_trace_validate::ObservationEvent::Evaluate {
            receipt,
            revocation_subject_ids,
            revocation_source_id,
            ..
        } = &observations.observations()[2].body.event
        else {
            panic!("third observation is not an evaluation");
        };
        assert_ne!(&receipt.capability_id, revoked_ancestor);
        assert_eq!(
            revocation_subject_ids,
            &[receipt.capability_id.clone(), revoked_ancestor.clone()]
        );
        assert_eq!(revocation_source_id.as_ref(), Some(revoked_ancestor));
        let projection =
            chio_trace_validate::project_revocation_trace(&observations).expect("project trace");

        assert_eq!(projection.action_coverage().revoke, 1);
        assert_eq!(projection.action_coverage().evaluate, 2);
        assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);
        assert_eq!(projection.invariant_witnesses().attenuated_admission, 2);
    }

    #[test]
    fn runtime_trace_refuses_a_dropped_admission_callback() {
        let error = capture_runtime_revocation_trace_with_store(
            "native-dropped-admission-calibration",
            false,
            true,
            TraceRevocationTarget::DelegationAncestor,
            RuntimeTraceMutation::None,
        )
        .expect_err("dropped admission callback must reject finalization");
        assert!(
            error.to_string().contains("no matching admission callback"),
            "unexpected recorder error: {error}"
        );
    }

    #[test]
    fn blind_store_capture_retains_the_prior_direct_revocation() {
        let (encoded, trusted_key) = capture_runtime_revocation_trace_with_store(
            "native-blind-store-calibration-test",
            true,
            false,
            TraceRevocationTarget::PresentedCapability,
            RuntimeTraceMutation::None,
        )
        .expect("capture blind-store trace");
        let decoded = chio_trace_validate::decode_observations(&encoded, &[trusted_key])
            .expect("decode blind-store trace");
        let projection = chio_trace_validate::project_revocation_trace(&decoded)
            .expect("project blind-store trace");
        assert!(projection.events().iter().any(|event| matches!(
            &event.action,
            chio_trace_validate::ProjectedAction::Evaluate {
                verdict,
                seen_epoch,
                ..
            } if verdict == "allow" && *seen_epoch > 0
        )));
    }

    #[test]
    fn runtime_trace_mutations_reach_the_formal_projection() {
        for (context, mutation) in [
            (
                "native-monotone-calibration-test",
                RuntimeTraceMutation::DuplicateReceiptTime,
            ),
            (
                "native-attenuation-calibration-test",
                RuntimeTraceMutation::DepthAboveLimit,
            ),
            (
                "native-freshness-calibration-test",
                RuntimeTraceMutation::FutureRevocationEpoch,
            ),
        ] {
            let (encoded, trusted_key) = capture_runtime_revocation_trace_with_store(
                context,
                false,
                false,
                TraceRevocationTarget::DelegationAncestor,
                mutation,
            )
            .expect("capture calibrated runtime trace");
            let decoded = chio_trace_validate::decode_observations(&encoded, &[trusted_key])
                .expect("decode calibrated runtime trace");
            let projection = chio_trace_validate::project_revocation_trace(&decoded)
                .expect("project calibrated runtime trace");
            assert_eq!(projection.events().len(), 3);

            match mutation {
                RuntimeTraceMutation::DuplicateReceiptTime => {
                    let times = projection
                        .events()
                        .iter()
                        .filter_map(|event| match &event.action {
                            chio_trace_validate::ProjectedAction::Evaluate {
                                receipt_time, ..
                            } => Some(*receipt_time),
                            chio_trace_validate::ProjectedAction::Revoke { .. } => None,
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(times, [1, 1]);
                }
                RuntimeTraceMutation::DepthAboveLimit => {
                    assert_eq!(projection.depth_max(), 4);
                    assert!(projection.events().iter().any(|event| matches!(
                        &event.action,
                        chio_trace_validate::ProjectedAction::Evaluate {
                            delegation_depth: 5,
                            ..
                        }
                    )));
                }
                RuntimeTraceMutation::FutureRevocationEpoch => {
                    assert!(projection.events().iter().any(|event| matches!(
                        &event.action,
                        chio_trace_validate::ProjectedAction::Revoke { epoch: 4 }
                    )));
                }
                RuntimeTraceMutation::None => unreachable!(),
            }
        }
    }

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
