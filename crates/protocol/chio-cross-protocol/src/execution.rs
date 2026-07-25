use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    supplemental_authorization::OpaqueSupplementalAuthorization,
    token::CapabilityToken,
};
use chio_kernel::dpop;
use chio_kernel::{ChioKernel, SignedExecutionNonce, ToolCallRequest, ToolCallResponse};
use serde_json::{json, Value};

use crate::capability_bridge::{CrossProtocolCapabilityEnvelope, CrossProtocolCapabilityRef};
use crate::discovery::DiscoveryProtocol;
use crate::error::BridgeError;
use crate::routing::{route_selection_metadata, RouteSelectionEvidence};

/// Kernel-bound execution request for a bridged hop.
#[derive(Debug, Clone)]
pub struct CrossProtocolExecutionRequest {
    pub origin_request_id: String,
    pub kernel_request_id: String,
    pub target_protocol: DiscoveryProtocol,
    pub target_server_id: String,
    pub target_tool_name: String,
    pub agent_id: String,
    pub arguments: Value,
    pub capability: CapabilityToken,
    pub source_envelope: Value,
    pub dpop_proof: Option<dpop::DpopProof>,
    pub execution_nonce: Option<SignedExecutionNonce>,
    pub governed_intent: Option<GovernedTransactionIntent>,
    pub approval_token: Option<GovernedApprovalToken>,
    pub approval_tokens: Vec<GovernedApprovalToken>,
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    pub supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    pub model_metadata: Option<ModelMetadata>,
}

/// Build the exact kernel request for a bridged execution.
///
/// Keeping this projection in one place prevents protocol executors from
/// selecting one approval, dropping the rest, or reconstructing signed
/// capability fields.
pub fn kernel_tool_call_request(request: &CrossProtocolExecutionRequest) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request.kernel_request_id.clone(),
        capability: request.capability.clone(),
        tool_name: request.target_tool_name.clone(),
        server_id: request.target_server_id.clone(),
        agent_id: request.agent_id.clone(),
        arguments: request.arguments.clone(),
        dpop_proof: request.dpop_proof.clone(),
        execution_nonce: request.execution_nonce.clone(),
        governed_intent: request.governed_intent.clone(),
        approval_token: request.approval_token.clone(),
        approval_tokens: request.approval_tokens.clone(),
        threshold_approval_proposal: request.threshold_approval_proposal.clone(),
        supplemental_authorization: request.supplemental_authorization.clone(),
        model_metadata: request.model_metadata.clone(),
        federated_origin_kernel_id: None,
    }
}

/// Fully prepared target-protocol request handed to a protocol-specific executor.
pub struct CrossProtocolTargetRequest<'a> {
    pub kernel: &'a ChioKernel,
    pub execution: &'a CrossProtocolExecutionRequest,
    pub source_protocol: DiscoveryProtocol,
    pub bridge_id: &'a str,
    pub capability_ref: &'a CrossProtocolCapabilityRef,
    pub capability_envelope: &'a CrossProtocolCapabilityEnvelope,
    pub route_selection: &'a RouteSelectionEvidence,
    pub projected_request: &'a Value,
}

/// One target-side hop emitted by a target protocol executor.
#[derive(Debug, Clone)]
pub struct TargetExecutionHop {
    pub protocol: DiscoveryProtocol,
    pub request_id: String,
    pub receipt_id: Option<String>,
}

/// Result returned by a target-protocol executor.
pub struct CrossProtocolTargetExecution {
    pub response: ToolCallResponse,
    pub protocol_result: Option<Value>,
    pub protocol_notifications: Vec<Value>,
    pub route_hops: Vec<TargetExecutionHop>,
}

/// Pluggable executor for a non-native target protocol.
pub trait TargetProtocolExecutor: Send + Sync {
    fn target_protocol(&self) -> DiscoveryProtocol;

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError>;
}

/// Default non-native protocol executor for OpenAI-shaped function-call
/// projections.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiTargetExecutor;

impl TargetProtocolExecutor for OpenAiTargetExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::OpenAi
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let route_metadata = metadata_with_source_receipt_context(
            route_selection_metadata(request.route_selection)?,
            &request.execution.source_envelope,
        )?;
        let response = request
            .kernel
            .evaluate_tool_call_blocking_with_metadata(
                &kernel_tool_call_request(request.execution),
                Some(route_metadata),
            )
            .map_err(BridgeError::Kernel)?;

        let receipt_ref = response.receipt.id.clone();
        let output = render_protocol_output(&response.output, response.reason.as_deref());

        Ok(CrossProtocolTargetExecution {
            response,
            protocol_result: Some(json!({
                "type": "function_call_output",
                "call_id": request.execution.origin_request_id,
                "output": output,
                "receipt_ref": receipt_ref,
            })),
            protocol_notifications: Vec::new(),
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::OpenAi,
                    request_id: format!("{}:openai", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_ref),
                },
            ],
        })
    }
}

pub fn metadata_with_source_receipt_context(
    mut metadata: Value,
    source_envelope: &Value,
) -> Result<Value, BridgeError> {
    let Some(receipt_context) = source_envelope.get("receipt_context").cloned() else {
        return Ok(metadata);
    };
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "receipt metadata must be a JSON object".to_string(),
        ));
    };
    metadata_obj.insert("receipt_context".to_string(), receipt_context);
    Ok(metadata)
}

fn render_protocol_output(
    output: &Option<chio_kernel::ToolCallOutput>,
    reason: Option<&str>,
) -> String {
    match output {
        Some(chio_kernel::ToolCallOutput::Value(value)) => value
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())),
        Some(chio_kernel::ToolCallOutput::Stream(stream)) => serde_json::to_string(
            &stream
                .chunks
                .iter()
                .map(|chunk| chunk.data.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_string()),
        None => reason.unwrap_or("{}").to_string(),
    }
}
