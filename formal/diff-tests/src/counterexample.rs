use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

#[cfg(not(target_arch = "wasm32"))]
use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::sha256_hex;
#[cfg(not(target_arch = "wasm32"))]
use chio_core::crypto::{canonical_json_bytes, Keypair};
#[cfg(not(target_arch = "wasm32"))]
use chio_core::receipt::decision::Decision;
#[cfg(not(target_arch = "wasm32"))]
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::Deserialize;
use serde_json::{Map, Value};

#[cfg(not(target_arch = "wasm32"))]
use crate::receipt_before_allow_trace::decode_receipt_before_allow;

#[derive(Clone, Copy, Debug)]
pub struct ExpectedStep<'a> {
    pub index: usize,
    pub action_hint: &'a str,
    pub expected: &'a [(&'a str, &'a str)],
}

#[derive(Debug)]
pub enum CounterexampleError {
    Json(serde_json::Error),
    Invalid(String),
    #[cfg(not(target_arch = "wasm32"))]
    Kernel(KernelError),
}

impl fmt::Display for CounterexampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid trace JSON: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Kernel(error) => write!(formatter, "kernel replay failed: {error}"),
        }
    }
}

impl Error for CounterexampleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Kernel(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<serde_json::Error> for CounterexampleError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<KernelError> for CounterexampleError {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}

#[derive(Debug, Deserialize)]
struct Trace {
    vars: Vec<String>,
    states: Vec<Map<String, Value>>,
    #[serde(default, rename = "loop")]
    loop_start: Option<usize>,
}

pub fn assert_trace_shape(
    source_path: &str,
    trace_json: &str,
    expected_sha256: &str,
    expected_variables: &[&str],
    expected_steps: &[ExpectedStep<'_>],
    expected_loop_start: Option<usize>,
) -> Result<(), CounterexampleError> {
    let digest = sha256_hex(trace_json.as_bytes());
    if digest != expected_sha256 {
        return Err(invalid("embedded trace digest changed"));
    }
    let expected_suffix = format!("_{}.rs", &digest[..12]);
    if !source_path.ends_with(&expected_suffix) {
        return Err(invalid(
            "generated test filename does not match trace digest",
        ));
    }
    let trace: Trace = serde_json::from_str(trace_json)?;
    let variables: Vec<&str> = trace.vars.iter().map(String::as_str).collect();
    if variables != expected_variables {
        return Err(invalid("embedded trace variables changed"));
    }
    if trace.states.len() != expected_steps.len() {
        return Err(invalid("embedded trace state count changed"));
    }
    if trace.loop_start != expected_loop_start {
        return Err(invalid("embedded trace loop marker changed"));
    }

    let expected_variable_set: BTreeSet<&str> = expected_variables.iter().copied().collect();
    for (index, (state, step)) in trace.states.iter().zip(expected_steps).enumerate() {
        if step.index != index {
            return Err(invalid(format!("step table index {index} changed")));
        }
        if step.action_hint.is_empty() {
            return Err(invalid(format!("step {index} has no action hint")));
        }
        if step.action_hint != trace_action_hint(&trace, index) {
            return Err(invalid(format!("step {index} action hint changed")));
        }
        let recorded_index = state
            .get("#meta")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("index"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        if recorded_index != Some(index) {
            return Err(invalid(format!("state {index} metadata index changed")));
        }

        let mut names = BTreeSet::new();
        for (name, expected_json) in step.expected {
            if !names.insert(*name) {
                return Err(invalid(format!("step {index} repeats variable {name}")));
            }
            let expected: Value = serde_json::from_str(expected_json)?;
            if state.get(*name) != Some(&expected) {
                return Err(invalid(format!("state {index} value for {name} changed")));
            }
        }
        if names != expected_variable_set {
            return Err(invalid(format!("step {index} variable set changed")));
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn replay_receipt_before_allow(
    trace_json: &str,
    expected_authority: &str,
    expected_capability: &str,
) -> Result<(), CounterexampleError> {
    let trace: Trace = serde_json::from_str(trace_json)?;
    let witness = decode_receipt_before_allow(&trace.vars, &trace.states)
        .map_err(|error| invalid(error.to_string()))?;
    if witness.authority != expected_authority || witness.capability != expected_capability {
        return Err(invalid("generated replay witness changed"));
    }

    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "0".repeat(64),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.register_tool_server(Box::new(ReplayServer));

    let subject = Keypair::generate();
    let capability = kernel.issue_capability(
        &subject.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "trace-server".to_string(),
                tool_name: "trace-tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let request = ToolCallRequest {
        request_id: format!(
            "authority-{}-capability-{}",
            witness.authority, witness.capability
        ),
        capability: capability.clone(),
        tool_name: "trace-tool".to_string(),
        server_id: "trace-server".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({
            "authority": witness.authority,
            "model_capability": witness.capability,
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    if !kernel.receipt_log().is_empty() {
        return Err(invalid("kernel receipt log was not empty before replay"));
    }
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    if response.verdict != Verdict::Allow {
        return Err(invalid(
            "production replay did not produce an allow response",
        ));
    }
    let response_signature_valid = response
        .receipt
        .verify_signature()
        .map_err(|error| invalid(format!("response receipt signature failed: {error}")))?;
    if !response_signature_valid {
        return Err(invalid("response receipt signature is invalid"));
    }
    let receipt_log = kernel.receipt_log();
    let receipts = receipt_log.receipts();
    let persisted = receipts
        .iter()
        .find(|receipt| receipt.id == response.receipt.id)
        .ok_or_else(|| invalid("allow response was published before its receipt was recorded"))?;
    if persisted.capability_id != capability.id {
        return Err(invalid("persisted receipt names a different capability"));
    }
    if persisted.decision != Some(Decision::Allow) {
        return Err(invalid(
            "persisted receipt does not carry an allow decision",
        ));
    }
    let signature_valid = persisted
        .verify_signature()
        .map_err(|error| invalid(format!("persisted receipt signature failed: {error}")))?;
    if !signature_valid {
        return Err(invalid("persisted receipt signature is invalid"));
    }
    let response_bytes = canonical_json_bytes(&response.receipt)
        .map_err(|error| invalid(format!("response receipt encoding failed: {error}")))?;
    let persisted_bytes = canonical_json_bytes(persisted)
        .map_err(|error| invalid(format!("persisted receipt encoding failed: {error}")))?;
    if response_bytes != persisted_bytes {
        return Err(invalid(
            "returned allow receipt differs from the persisted receipt",
        ));
    }
    Ok(())
}

fn trace_action_hint(trace: &Trace, index: usize) -> String {
    let state = &trace.states[index];
    if let Some(action) = state
        .get("#meta")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("action"))
        .and_then(Value::as_str)
        .filter(|action| !action.is_empty())
    {
        return action.to_string();
    }
    if index == 0 {
        return "initial".to_string();
    }
    let previous = &trace.states[index - 1];
    let changed: Vec<&str> = trace
        .vars
        .iter()
        .filter(|name| previous.get(*name) != state.get(*name))
        .map(String::as_str)
        .collect();
    if changed.is_empty() {
        "stutter".to_string()
    } else {
        format!("changed: {}", changed.join(", "))
    }
}

fn invalid(message: impl Into<String>) -> CounterexampleError {
    CounterexampleError::Invalid(message.into())
}

#[cfg(not(target_arch = "wasm32"))]
struct ReplayServer;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl ToolServerConnection for ReplayServer {
    fn server_id(&self) -> &str {
        "trace-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["trace-tool".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(arguments)
    }
}
