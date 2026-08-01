// Kernel-backed CapabilityChecker implementation.
//
// Routes ACP live-path checks through the shared cross-protocol orchestrator and
// kernel guard pipeline. A no-op authority server satisfies the kernel's
// registered-target contract without duplicating the real ACP side effect.

use std::sync::Arc;

use chio_core::capability::token::CapabilityToken;
use chio_cross_protocol::capability_bridge::{CapabilityBridge, CrossProtocolCapabilityRef};
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::CrossProtocolExecutionRequest;
use chio_cross_protocol::orchestrator::CrossProtocolOrchestrator;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection, Verdict as KernelVerdict,
};
use serde_json::json;

const ACP_GUARD_READ_TOOL: &str = "fs/read_text_file";
const ACP_GUARD_WRITE_TOOL: &str = "fs/write_text_file";
const ACP_GUARD_TERMINAL_TOOL: &str = "terminal/create";
const ACP_GUARD_TERMINAL_KILL_TOOL: &str = "terminal/kill";
const ACP_GUARD_TERMINAL_RELEASE_TOOL: &str = "terminal/release";

struct AcpGuardCapabilityBridge;

impl CapabilityBridge for AcpGuardCapabilityBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Acp
    }

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError> {
        request
            .pointer("/metadata/chio/capabilityRef")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let Some(object) = envelope.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "request envelope must be a JSON object".to_string(),
            ));
        };
        let metadata = object
            .entry("metadata".to_string())
            .or_insert_with(|| json!({}));
        let Some(metadata_obj) = metadata.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata must be a JSON object".to_string(),
            ));
        };
        let chio = metadata_obj
            .entry("chio".to_string())
            .or_insert_with(|| json!({}));
        let Some(chio_obj) = chio.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata.chio must be a JSON object".to_string(),
            ));
        };
        chio_obj.insert(
            "capabilityRef".to_string(),
            serde_json::to_value(cap_ref)
                .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
        );
        Ok(())
    }

    fn protocol_context(&self, request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(Some(json!({
            "sessionId": request.get("sessionId").cloned().unwrap_or(Value::Null),
            "operation": request.get("operation").cloned().unwrap_or(Value::Null),
            "resource": request.get("resource").cloned().unwrap_or(Value::Null),
        })))
    }
}

struct AcpAuthorityToolServer {
    server_id: String,
}

impl AcpAuthorityToolServer {
    fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for AcpAuthorityToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            ACP_GUARD_READ_TOOL.to_string(),
            ACP_GUARD_WRITE_TOOL.to_string(),
            ACP_GUARD_TERMINAL_TOOL.to_string(),
            ACP_GUARD_TERMINAL_KILL_TOOL.to_string(),
            ACP_GUARD_TERMINAL_RELEASE_TOOL.to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "authorityOnly": true,
            "toolName": tool_name,
            "arguments": arguments,
        }))
    }
}

/// Kernel-backed capability checker.
///
/// Uses the shared cross-protocol orchestrator plus a guard-only kernel server
/// to make the authoritative allow/deny decision for ACP file and terminal
/// operations. Every successful check emits a signed Chio receipt.
pub struct KernelCapabilityChecker {
    kernel: Arc<ChioKernel>,
    server_id: String,
}

impl KernelCapabilityChecker {
    /// Create a new kernel-backed checker.
    pub fn new(mut kernel: ChioKernel, server_id: impl Into<String>) -> Self {
        let server_id = server_id.into();
        kernel.register_tool_server(Box::new(AcpAuthorityToolServer::new(server_id.clone())));
        Self {
            kernel: Arc::new(kernel),
            server_id,
        }
    }

    fn parse_token(&self, token_json: &str) -> Result<CapabilityToken, CapabilityCheckError> {
        serde_json::from_str(token_json)
            .map_err(|error| CapabilityCheckError::InvalidToken(format!("failed to parse token: {error}")))
    }

    fn map_request(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<(&'static str, Value), CapabilityCheckError> {
        match request.operation.as_str() {
            "fs_read" => Ok((
                ACP_GUARD_READ_TOOL,
                json!({
                    "path": request.resource,
                    "authorization_parameter_hash": request.authorization_parameter_hash,
                    "operation_payload": request.operation_payload,
                }),
            )),
            "fs_write" => Ok((
                ACP_GUARD_WRITE_TOOL,
                json!({
                    "path": request.resource,
                    "authorization_parameter_hash": request.authorization_parameter_hash,
                    "operation_payload": request.operation_payload,
                }),
            )),
            "terminal" => Ok((
                ACP_GUARD_TERMINAL_TOOL,
                json!({
                    "command": request.resource,
                    "authorization_parameter_hash": request.authorization_parameter_hash,
                    "operation_payload": request.operation_payload,
                }),
            )),
            "terminal_kill" => Ok((
                ACP_GUARD_TERMINAL_KILL_TOOL,
                json!({
                    "terminalId": request.resource,
                    "authorization_parameter_hash": request.authorization_parameter_hash,
                    "operation_payload": request.operation_payload,
                }),
            )),
            "terminal_release" => Ok((
                ACP_GUARD_TERMINAL_RELEASE_TOOL,
                json!({
                    "terminalId": request.resource,
                    "authorization_parameter_hash": request.authorization_parameter_hash,
                    "operation_payload": request.operation_payload,
                }),
            )),
            other => Err(CapabilityCheckError::Internal(format!(
                "unsupported ACP operation for authoritative enforcement: {other}"
            ))),
        }
    }

    fn build_source_envelope(
        &self,
        request: &AcpCapabilityRequest,
        arguments: &Value,
        tool_call_id: &str,
        kernel_request_id: &str,
    ) -> Value {
        json!({
            "sessionId": request.session_id,
            "toolCallId": tool_call_id,
            "operation": request.operation,
            "resource": request.resource,
            "arguments": arguments,
            "operationPayload": request.operation_payload,
            "receipt_context": {
                "request_id": kernel_request_id,
                "authorization_correlation_id": request.authorization_correlation_id,
                "session_id": request.session_id,
                "tool_call_id": tool_call_id,
                "operation": request.operation,
                "resource": request.resource,
                "authorization_parameter_hash": request.authorization_parameter_hash,
            },
        })
    }
}

impl CapabilityChecker for KernelCapabilityChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        let token_json = match &request.token {
            Some(token) if !token.trim().is_empty() => token,
            _ => {
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: None,
                    receipt_id: None,
                    receipt_request_id: None,
                    execution_nonce: None,
                    reason: "no capability token presented".to_string(),
                });
            }
        };

        let capability = match self.parse_token(token_json) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: None,
                    receipt_id: None,
                    receipt_request_id: None,
                    execution_nonce: None,
                    reason: error.to_string(),
                });
            }
        };
        // ACP fs/read_text_file, fs/write_text_file, and terminal/create
        // request parameters do not carry a toolCallId. Only the operations
        // that mutate an existing tool call (terminal_kill, terminal_release)
        // require the binding at the live authorization step; for the file
        // and terminal-create operations the matching toolCallId arrives on
        // the later session/update notification.
        let tool_call_id_required =
            matches!(request.operation.as_str(), "terminal_kill" | "terminal_release");
        let tool_call_id = match request
            .tool_call_id
            .as_deref()
            .filter(|tool_call_id| !tool_call_id.trim().is_empty())
        {
            Some(tool_call_id) => tool_call_id,
            None if tool_call_id_required => {
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: Some(capability.id.clone()),
                    receipt_id: None,
                    receipt_request_id: None,
                    execution_nonce: None,
                    reason: "ACP authorization requires a tool_call_id binding".to_string(),
                });
            }
            None => "",
        };
        let (tool_name, arguments) = match self.map_request(request) {
            Ok(mapped) => mapped,
            Err(error) => {
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: Some(capability.id.clone()),
                    receipt_id: None,
                    receipt_request_id: None,
                    execution_nonce: None,
                    reason: error.to_string(),
                });
            }
        };
        let request_hash = chio_core::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(&json!({
                "sessionId": request.session_id,
                "toolCallId": tool_call_id,
                "operation": request.operation,
                "resource": request.resource,
                "authorization_parameter_hash": request.authorization_parameter_hash,
                "operation_payload": request.operation_payload,
            }))
            .map_err(|error| CapabilityCheckError::Internal(error.to_string()))?,
        );
        let kernel_request_id = format!("acp-live-guard-{request_hash}");
        let orchestrated = CrossProtocolOrchestrator::new(self.kernel.as_ref())
            .execute(
                &AcpGuardCapabilityBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: format!("acp-guard-{}-{request_hash}", request.session_id),
                    kernel_request_id: kernel_request_id.clone(),
                    target_protocol: DiscoveryProtocol::Native,
                    target_server_id: self.server_id.clone(),
                    target_tool_name: tool_name.to_string(),
                    agent_id: capability.subject.to_hex(),
                    arguments: arguments.clone(),
                    capability: capability.clone(),
                    source_envelope: self.build_source_envelope(
                        request,
                        &arguments,
                        tool_call_id,
                        &kernel_request_id,
                    ),
                    dpop_proof: None,
                    execution_nonce: request.execution_nonce.clone(),
                    governed_intent: None,
                    approval_token: None,
                    approval_tokens: Vec::new(),
                    threshold_approval_proposal: None,
                    supplemental_authorization: None,
                    model_metadata: None,
                },
            )
            .map_err(|error| CapabilityCheckError::Internal(error.to_string()))?;

        let response = orchestrated.response;
        let capability_id = Some(response.receipt.capability_id.clone());
        let receipt_id = Some(response.receipt.id.clone());
        let receipt_request_id = Some(response.request_id.clone());
        let execution_nonce = response.execution_nonce.as_deref().cloned();

        let is_nonce_preflight = matches!(response.verdict, KernelVerdict::Allow)
            && response.output.is_none()
            && response.execution_nonce.is_some();

        match response.verdict {
            KernelVerdict::Allow if is_nonce_preflight => Ok(AcpVerdict {
                allowed: false,
                capability_id,
                receipt_id,
                receipt_request_id,
                execution_nonce,
                reason: "execution nonce required for ACP operation".to_string(),
            }),
            KernelVerdict::Allow => Ok(AcpVerdict {
                allowed: true,
                capability_id,
                receipt_id,
                receipt_request_id,
                execution_nonce: None,
                reason: "authorized through kernel-backed ACP guard pipeline".to_string(),
            }),
            KernelVerdict::Deny => Ok(AcpVerdict {
                allowed: false,
                capability_id,
                receipt_id,
                receipt_request_id,
                execution_nonce: None,
                reason: response
                    .reason
                    .unwrap_or_else(|| "kernel denied ACP operation".to_string()),
            }),
            KernelVerdict::PendingApproval => Ok(AcpVerdict {
                allowed: false,
                capability_id,
                receipt_id,
                receipt_request_id,
                execution_nonce: None,
                reason: response
                    .reason
                    .unwrap_or_else(|| "ACP operation requires approval".to_string()),
            }),
        }
    }
}
