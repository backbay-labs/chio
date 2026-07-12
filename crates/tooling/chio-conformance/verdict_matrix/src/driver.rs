use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, ExecutionNonceError, InMemoryExecutionNonceStore, NonceBinding,
};
use chio_kernel::post_invocation::{
    PostInvocationContext, PostInvocationHook, PostInvocationVerdict,
};
use chio_kernel::{
    ChioKernel, Guard, GuardContext, GuardDecision, KernelConfig, KernelError, NestedFlowBridge,
    ToolCallRequest, ToolServerConnection, Verdict as KernelVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{ScenarioCategory, Verdict, VerdictTuple, SCENARIO_SCHEMA};

pub const RUST_KERNEL_DRIVER: &str = "rust-kernel";
const MATRIX_SERVER_ID: &str = "verdict-matrix";
const MATRIX_INPUT_METADATA: &str = "verdict_matrix";
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
        validate_identity_field(&self.id, "id", &self.id)?;
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
        validate_identity_values(&self.id, "tags entry", &self.tags)?;
        validate_identity_values(&self.id, "requires entry", &self.requires)?;
        validate_identity_field(&self.id, "expected.reason_code", &self.expected.reason_code)?;
        validate_identity_values(
            &self.id,
            "expected.scope_set entry",
            &self.expected.scope_set,
        )?;
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
        validate_identity_field(id, "script.operation", &self.operation)?;
        validate_identity_field(id, "script.tool", &self.tool)?;
        validate_identity_values(
            id,
            "script.capability_scopes entry",
            &self.capability_scopes,
        )?;
        if let Some(required_scope) = &self.required_scope {
            validate_identity_field(id, "script.required_scope", required_scope)?;
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

fn validate_identity_values(id: &str, label: &str, values: &[String]) -> Result<(), DriverError> {
    for value in values {
        validate_identity_field(id, label, value)?;
    }
    Ok(())
}

fn validate_identity_field(id: &str, label: &str, value: &str) -> Result<(), DriverError> {
    if value.trim().is_empty() {
        return Err(DriverError::InvalidScenario {
            id: id.to_string(),
            reason: format!("{label} must not be empty"),
        });
    }
    if value.trim() != value {
        return Err(DriverError::InvalidScenario {
            id: id.to_string(),
            reason: format!("{label} must not contain surrounding whitespace"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DriverError::InvalidScenario {
            id: id.to_string(),
            reason: format!("{label} must not contain control characters"),
        });
    }
    Ok(())
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
            .find(|requirement| !rust_kernel_supports_requirement(requirement))
        {
            return DriverOutcome {
                scenario_id: scenario.id.clone(),
                status: DriverStatus::Unsupported,
                actual: None,
                expected: scenario.expected.clone().normalized(),
                diagnostic: Some(format!("unsupported requirement `{unsupported}`")),
            };
        }

        let expected = scenario.expected.clone().normalized();
        let actual = match evaluate_scenario(scenario) {
            Ok(actual) => actual.normalized(),
            Err(error) => {
                return DriverOutcome {
                    scenario_id: scenario.id.clone(),
                    status: DriverStatus::Fail,
                    actual: None,
                    expected,
                    diagnostic: Some(error),
                };
            }
        };
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

fn rust_kernel_supports_requirement(requirement: &str) -> bool {
    matches!(
        requirement,
        RUST_KERNEL_DRIVER
            | "kernel-semantics"
            | "capability-authority"
            | "revocation-store"
            | "replay-nonce"
            | "execution-nonce-store"
            | "guard-pipeline"
            | "receipt-log"
    )
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

fn evaluate_scenario(scenario: &VerdictScenario) -> Result<VerdictTuple, String> {
    if scenario.script.operation.as_str() != "tool.call" {
        return Ok(tuple(
            Verdict::Error,
            REASON_KERNEL_INTERNAL,
            scenario.script.capability_scopes.clone(),
        ));
    }

    let mut kernel = ChioKernel::new(kernel_config());
    configure_replay_store(&mut kernel, scenario);
    configure_redaction_hooks(&mut kernel, scenario);
    kernel.register_tool_server(Box::new(MatrixToolServer::new()));

    let subject = Keypair::generate();
    let scope = scope_from_labels(&scenario.script.capability_scopes)?;
    let capability = kernel
        .issue_capability(&subject.public_key(), scope, 300)
        .map_err(|error| format!("capability issuance failed: {error}"))?;
    if scenario.script.revoked {
        kernel
            .revoke_capability(&capability.id)
            .map_err(|error| format!("capability revocation failed: {error}"))?;
    }

    let arguments = serde_json::from_str::<Value>(&scenario.script.input_json)
        .map_err(|error| format!("script.input_json parse failed: {error}"))?;
    let request = ToolCallRequest {
        request_id: scenario.id.clone(),
        capability: capability.clone(),
        tool_name: scenario.script.tool.clone(),
        server_id: MATRIX_SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    if scenario.category == ScenarioCategory::Replay {
        return evaluate_replay_scenario(&kernel, &request, &capability, scenario);
    }

    let metadata = input_redaction_metadata(&scenario.script);
    let response = kernel
        .evaluate_tool_call_blocking_with_metadata(&request, metadata)
        .map_err(|error| format!("kernel evaluation failed: {error}"))?;
    Ok(tuple_from_response(
        &response,
        &scenario.script.capability_scopes,
    ))
}

fn tuple(verdict: Verdict, reason_code: &str, scope_set: Vec<String>) -> VerdictTuple {
    VerdictTuple {
        verdict,
        reason_code: reason_code.to_string(),
        scope_set,
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "verdict-matrix-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn configure_replay_store(kernel: &mut ChioKernel, scenario: &VerdictScenario) {
    if scenario.category != ScenarioCategory::Replay {
        return;
    }

    let mut config = ExecutionNonceConfig::default();
    if scenario.script.replay_nonce_status == ReplayNonceStatus::Stale {
        config.nonce_ttl_secs = 0;
    }
    if scenario.script.replay_nonce_status == ReplayNonceStatus::TraceMissing {
        config.require_nonce = true;
    }
    let store = InMemoryExecutionNonceStore::from_config(&config);
    kernel.set_execution_nonce_store(config, Box::new(store));
}

fn configure_redaction_hooks(kernel: &mut ChioKernel, scenario: &VerdictScenario) {
    match (
        scenario.script.redaction_phase,
        scenario.script.redaction_action,
    ) {
        (RedactionPhase::Input, RedactionAction::Deny) => {
            kernel.add_guard(Box::new(MatrixInputGuard));
        }
        (RedactionPhase::Output, RedactionAction::Mask | RedactionAction::Drop) => {
            kernel.add_post_invocation_hook(Box::new(MatrixOutputHook::new(
                scenario.script.redaction_action,
            )));
        }
        (RedactionPhase::Output, RedactionAction::Deny) => {
            kernel.add_post_invocation_hook(Box::new(MatrixOutputHook::new(RedactionAction::Deny)));
        }
        _ => {}
    }
}

fn scope_from_labels(labels: &[String]) -> Result<ChioScope, String> {
    let grants = labels
        .iter()
        .map(|label| grant_from_label(label))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ChioScope {
        grants,
        ..ChioScope::default()
    })
}

fn grant_from_label(label: &str) -> Result<ToolGrant, String> {
    let tool_name = match label {
        "tool:read" => "files.read",
        "tool:write" => "files.write",
        "tool:admin" => "system.rotate",
        "telemetry:read" => "metrics.query",
        "prompt:read" => "prompts.get",
        "prompt:write" => "prompts.update",
        "resource:read" => "resources.read",
        "tool:call" => "tools.invoke",
        other => return Err(format!("unsupported capability scope label `{other}`")),
    };
    Ok(ToolGrant {
        server_id: MATRIX_SERVER_ID.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    })
}

fn input_redaction_metadata(script: &ScenarioScript) -> Option<Value> {
    if script.redaction_phase != RedactionPhase::Input {
        return None;
    }
    let action = match script.redaction_action {
        RedactionAction::Mask => "mask",
        RedactionAction::Drop => "drop",
        _ => return None,
    };
    Some(serde_json::json!({
        MATRIX_INPUT_METADATA: {
            "input_redaction": {
                "action": action,
                "applied": true
            }
        }
    }))
}

fn evaluate_replay_scenario(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    scenario: &VerdictScenario,
) -> Result<VerdictTuple, String> {
    let response = kernel
        .evaluate_tool_call_blocking_with_metadata(request, None)
        .map_err(|error| format!("kernel evaluation failed: {error}"))?;
    if response.verdict != KernelVerdict::Allow {
        return Ok(tuple_from_response(
            &response,
            &scenario.script.capability_scopes,
        ));
    }

    match scenario.script.replay_nonce_status {
        ReplayNonceStatus::Fresh => verify_fresh_nonce(
            kernel,
            request,
            capability,
            &response,
            &scenario.script.capability_scopes,
        ),
        ReplayNonceStatus::Duplicate => verify_duplicate_nonce(
            kernel,
            request,
            capability,
            &response,
            &scenario.script.capability_scopes,
        ),
        ReplayNonceStatus::Stale => verify_stale_nonce(
            kernel,
            request,
            capability,
            &response,
            &scenario.script.capability_scopes,
        ),
        ReplayNonceStatus::TraceMissing => {
            match kernel.require_presented_execution_nonce(request, capability) {
                Ok(()) => Err("missing execution nonce was accepted".to_string()),
                Err(_) => Ok(tuple(
                    Verdict::Error,
                    REASON_REPLAY_TRACE_MISSING,
                    scenario.script.capability_scopes.clone(),
                )),
            }
        }
    }
}

fn verify_fresh_nonce(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    response: &chio_kernel::ToolCallResponse,
    scope_set: &[String],
) -> Result<VerdictTuple, String> {
    let nonce = response
        .execution_nonce
        .as_deref()
        .ok_or_else(|| "kernel allow response did not include an execution nonce".to_string())?;
    let binding = nonce_binding(request, capability, response);
    match kernel.verify_presented_execution_nonce(nonce, &binding) {
        Ok(()) => Ok(tuple(Verdict::Allow, REASON_NONE, scope_set.to_vec())),
        Err(error) => Ok(tuple(
            Verdict::Deny,
            replay_reason_code(&error),
            scope_set.to_vec(),
        )),
    }
}

fn verify_duplicate_nonce(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    response: &chio_kernel::ToolCallResponse,
    scope_set: &[String],
) -> Result<VerdictTuple, String> {
    let nonce = response
        .execution_nonce
        .as_deref()
        .ok_or_else(|| "kernel allow response did not include an execution nonce".to_string())?;
    let binding = nonce_binding(request, capability, response);
    if let Err(error) = kernel.verify_presented_execution_nonce(nonce, &binding) {
        return Ok(tuple(
            Verdict::Deny,
            replay_reason_code(&error),
            scope_set.to_vec(),
        ));
    }
    match kernel.verify_presented_execution_nonce(nonce, &binding) {
        Ok(()) => Err("duplicate execution nonce was accepted".to_string()),
        Err(error) => Ok(tuple(
            Verdict::Deny,
            replay_reason_code(&error),
            scope_set.to_vec(),
        )),
    }
}

fn verify_stale_nonce(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    response: &chio_kernel::ToolCallResponse,
    scope_set: &[String],
) -> Result<VerdictTuple, String> {
    let nonce = response
        .execution_nonce
        .as_deref()
        .ok_or_else(|| "kernel allow response did not include an execution nonce".to_string())?;
    let binding = nonce_binding(request, capability, response);
    match kernel.verify_presented_execution_nonce(nonce, &binding) {
        Ok(()) => Err("stale execution nonce was accepted".to_string()),
        Err(error) => Ok(tuple(
            Verdict::Deny,
            replay_reason_code(&error),
            scope_set.to_vec(),
        )),
    }
}

fn nonce_binding(
    request: &ToolCallRequest,
    capability: &CapabilityToken,
    response: &chio_kernel::ToolCallResponse,
) -> NonceBinding {
    NonceBinding {
        subject_id: capability.subject.to_hex(),
        capability_id: capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    }
}

fn replay_reason_code(error: &ExecutionNonceError) -> &'static str {
    match error {
        ExecutionNonceError::Expired { .. }
        | ExecutionNonceError::Replayed
        | ExecutionNonceError::BindingMismatch { .. }
        | ExecutionNonceError::InvalidSignature
        | ExecutionNonceError::BadSchema { .. }
        | ExecutionNonceError::Encoding(_)
        | ExecutionNonceError::Store(_) => REASON_REPLAY_DRIFT,
    }
}

fn tuple_from_response(
    response: &chio_kernel::ToolCallResponse,
    scope_set: &[String],
) -> VerdictTuple {
    match response.verdict {
        KernelVerdict::Allow => {
            let reason = if has_input_redaction_metadata(response) {
                REASON_INPUT_REDACTED
            } else if has_output_redaction_metadata(response) {
                REASON_OUTPUT_REDACTED
            } else {
                REASON_NONE
            };
            tuple(Verdict::Allow, reason, scope_set.to_vec())
        }
        KernelVerdict::Deny => tuple(
            Verdict::Deny,
            deny_reason_code(response.reason.as_deref()),
            scope_set.to_vec(),
        ),
        KernelVerdict::PendingApproval => {
            tuple(Verdict::Deny, REASON_GUARD_DENIED, scope_set.to_vec())
        }
    }
}

fn has_input_redaction_metadata(response: &chio_kernel::ToolCallResponse) -> bool {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(MATRIX_INPUT_METADATA))
        .and_then(|metadata| metadata.get("input_redaction"))
        .and_then(|metadata| metadata.get("applied"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn has_output_redaction_metadata(response: &chio_kernel::ToolCallResponse) -> bool {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("post_invocation"))
        .and_then(|metadata| metadata.get("sanitized"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn deny_reason_code(reason: Option<&str>) -> &'static str {
    let Some(reason) = reason else {
        return REASON_KERNEL_INTERNAL;
    };
    let lower = reason.to_ascii_lowercase();
    if lower.contains("revoked") {
        REASON_REVOKED
    } else if lower.contains("not in capability scope") || lower.contains("out of scope") {
        REASON_SCOPE_EXCEEDED
    } else if lower.contains("guard") || lower.contains("redaction") {
        REASON_GUARD_DENIED
    } else {
        REASON_KERNEL_INTERNAL
    }
}

struct MatrixToolServer {
    id: String,
}

impl MatrixToolServer {
    fn new() -> Self {
        Self {
            id: MATRIX_SERVER_ID.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MatrixToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        matrix_tools()
            .iter()
            .map(|tool| (*tool).to_string())
            .collect()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        if !matrix_tools().contains(&tool_name) {
            return Err(KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                self.id, tool_name
            )));
        }
        Ok(serde_json::json!({
            "server": self.id,
            "tool": tool_name,
            "arguments": arguments
        }))
    }
}

fn matrix_tools() -> &'static [&'static str] {
    &[
        "files.read",
        "files.write",
        "system.rotate",
        "metrics.query",
        "prompts.get",
        "prompts.update",
        "resources.read",
        "tools.invoke",
    ]
}

struct MatrixInputGuard;

impl Guard for MatrixInputGuard {
    fn name(&self) -> &str {
        "verdict-matrix-input"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::deny(Vec::new()))
    }
}

struct MatrixOutputHook {
    action: RedactionAction,
    evidence: Mutex<Option<GuardEvidence>>,
}

impl MatrixOutputHook {
    fn new(action: RedactionAction) -> Self {
        Self {
            action,
            evidence: Mutex::new(None),
        }
    }

    fn set_evidence(&self, verdict: bool, details: &str) {
        if let Ok(mut evidence) = self.evidence.lock() {
            *evidence = Some(GuardEvidence {
                guard_name: self.name().to_string(),
                verdict,
                details: Some(details.to_string()),
            });
        }
    }
}

impl PostInvocationHook for MatrixOutputHook {
    fn name(&self) -> &str {
        "verdict-matrix-output"
    }

    fn inspect(&self, _ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        match self.action {
            RedactionAction::None => PostInvocationVerdict::Allow,
            RedactionAction::Deny => {
                self.set_evidence(false, "output redaction denied the response");
                PostInvocationVerdict::Block(
                    "guard \"verdict-matrix-output\" denied the request".to_string(),
                )
            }
            RedactionAction::Mask | RedactionAction::Drop => {
                self.set_evidence(true, "output redaction sanitized the response");
                PostInvocationVerdict::Redact(redacted_output_envelope(response))
            }
        }
    }

    fn take_evidence(&self) -> Option<GuardEvidence> {
        match self.evidence.lock() {
            Ok(mut evidence) => evidence.take(),
            Err(_) => None,
        }
    }
}

fn redacted_output_envelope(response: &Value) -> Value {
    match response.get("kind").and_then(Value::as_str) {
        Some("stream") => {
            let complete = response
                .get("stream")
                .and_then(|stream| stream.get("complete"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if complete {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": true,
                        "chunks": [{"redacted": true}]
                    }
                })
            } else {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": false,
                        "reason": "redacted incomplete stream",
                        "chunks": [{"redacted": true}]
                    }
                })
            }
        }
        _ => serde_json::json!({
            "kind": "value",
            "value": {"redacted": true}
        }),
    }
}

pub fn category_counts(scenarios: &[VerdictScenario]) -> BTreeMap<ScenarioCategory, usize> {
    let mut counts = BTreeMap::new();
    for scenario in scenarios {
        *counts.entry(scenario.category).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_scenario() -> VerdictScenario {
        VerdictScenario {
            schema: SCENARIO_SCHEMA.to_string(),
            id: "scenario-a".to_string(),
            title: "Scenario A".to_string(),
            category: ScenarioCategory::Capability,
            description: "A valid capability scenario.".to_string(),
            tags: vec!["capability_subset".to_string()],
            requires: vec![RUST_KERNEL_DRIVER.to_string()],
            artifacts: vec!["fixtures/scenario-a.json".to_string()],
            timeout_ms: Some(1_000),
            script: ScenarioScript {
                operation: "tool.call".to_string(),
                tool: "files.read".to_string(),
                input_json: r#"{"path":"README.md"}"#.to_string(),
                capability_scopes: vec!["tool:read".to_string()],
                required_scope: Some("tool:read".to_string()),
                revoked: false,
                replay_nonce_status: ReplayNonceStatus::Fresh,
                redaction_action: RedactionAction::None,
                redaction_phase: RedactionPhase::Input,
                source_fixture: Some("fixtures/scenario-a.ndjson".to_string()),
                extra: BTreeMap::new(),
            },
            expected: VerdictTuple {
                verdict: Verdict::Allow,
                reason_code: REASON_NONE.to_string(),
                scope_set: vec!["tool:read".to_string()],
            },
        }
    }

    fn assert_invalid(scenario: VerdictScenario, expected_reason: &str) {
        let Err(error) = scenario.validate() else {
            panic!("scenario validation accepted an invalid identity field");
        };
        assert!(
            error.to_string().contains(expected_reason),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn scenario_validation_rejects_padded_identity_fields() {
        let mut scenario = valid_scenario();
        scenario.id = " scenario-a".to_string();
        assert_invalid(scenario, "id must not contain surrounding whitespace");

        let mut scenario = valid_scenario();
        scenario.expected.reason_code = format!(" {REASON_NONE}");
        assert_invalid(
            scenario,
            "expected.reason_code must not contain surrounding whitespace",
        );

        let mut scenario = valid_scenario();
        scenario.script.operation = "tool.call ".to_string();
        assert_invalid(
            scenario,
            "script.operation must not contain surrounding whitespace",
        );

        let mut scenario = valid_scenario();
        scenario.script.tool = " files.read".to_string();
        assert_invalid(
            scenario,
            "script.tool must not contain surrounding whitespace",
        );

        let mut scenario = valid_scenario();
        scenario.script.required_scope = Some(" tool:read".to_string());
        assert_invalid(
            scenario,
            "script.required_scope must not contain surrounding whitespace",
        );
    }
}
