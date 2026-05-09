//! Shared cross-protocol bridge contracts and runtime orchestration substrate.
//!
//! This crate centralizes the reusable types needed by outward protocol edges
//! so A2A, ACP, and later MCP/OpenAI/HTTP bridge paths do not each redefine
//! provenance, attenuation, and receipt-lineage behavior independently.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical_json_bytes;
use chio_core::capability::{
    CapabilityToken, ChioScope, GovernedApprovalToken, GovernedTransactionIntent, ModelMetadata,
};
use chio_core::sha256_hex;
use chio_kernel::dpop;
use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse, Verdict as KernelVerdict};
use chio_manifest::{LatencyHint, ToolDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const CROSS_PROTOCOL_AUTHORITY_PATH: &str = "cross_protocol_orchestrator";
pub const CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA: &str = "chio.cross-protocol-cap.v1";

/// Shared target-protocol registry and default binding policy for
/// claim-eligible routes.
pub struct TargetProtocolRegistry<'a> {
    default_target_protocol: DiscoveryProtocol,
    executors: BTreeMap<DiscoveryProtocol, &'a dyn TargetProtocolExecutor>,
}

/// Protocol families Chio can bridge across.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProtocol {
    Native,
    Http,
    Mcp,
    A2a,
    Acp,
    OpenAi,
}

impl DiscoveryProtocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Http => "http",
            Self::Mcp => "mcp",
            Self::A2a => "a2a",
            Self::Acp => "acp",
            Self::OpenAi => "open_ai",
        }
    }
}

impl fmt::Display for DiscoveryProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'a> TargetProtocolRegistry<'a> {
    #[must_use]
    pub fn new(default_target_protocol: DiscoveryProtocol) -> Self {
        Self {
            default_target_protocol,
            executors: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_executor(mut self, executor: &'a dyn TargetProtocolExecutor) -> Self {
        self.executors.insert(executor.target_protocol(), executor);
        self
    }

    #[must_use]
    pub fn default_target_protocol(&self) -> DiscoveryProtocol {
        self.default_target_protocol
    }

    pub fn resolve_target_protocol(
        &self,
        tool: &ToolDefinition,
    ) -> Result<DiscoveryProtocol, String> {
        let target =
            schema_string_extension(&tool.input_schema, "x-chio-target-protocol").or_else(|| {
                tool.output_schema
                    .as_ref()
                    .and_then(|schema| schema_string_extension(schema, "x-chio-target-protocol"))
            });

        match target {
            Some(value) => parse_discovery_protocol(&value),
            None => Ok(self.default_target_protocol),
        }
    }

    #[must_use]
    pub fn supports_target_protocol(&self, protocol: DiscoveryProtocol) -> bool {
        protocol == DiscoveryProtocol::Native || self.executors.contains_key(&protocol)
    }

    fn executor_for_target(
        &self,
        protocol: DiscoveryProtocol,
    ) -> Option<&'a dyn TargetProtocolExecutor> {
        self.executors.get(&protocol).copied()
    }
}

/// Shared lifecycle surfaces for claim-eligible and compatibility routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLifecycleSurface {
    A2aAuthoritative,
    A2aCompatibility,
    AcpAuthoritative,
    AcpCompatibility,
}

/// Canonical runtime lifecycle contract surfaced by claim-eligible bridges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLifecycleContract {
    pub surface: String,
    pub blocking_entrypoint: String,
    pub stream_entrypoint: String,
    pub follow_up_entrypoint: String,
    pub cancel_entrypoint: String,
    pub stream_delivery: String,
    pub partial_output_delivery: String,
    pub claim_eligible: bool,
    pub compatibility_only: bool,
}

#[must_use]
pub fn runtime_lifecycle_contract(surface: RuntimeLifecycleSurface) -> RuntimeLifecycleContract {
    match surface {
        RuntimeLifecycleSurface::A2aAuthoritative => RuntimeLifecycleContract {
            surface: "a2a_authoritative".to_string(),
            blocking_entrypoint: "message/send".to_string(),
            stream_entrypoint: "message/stream".to_string(),
            follow_up_entrypoint: "task/get".to_string(),
            cancel_entrypoint: "task/cancel".to_string(),
            stream_delivery: "collated_terminal_payload".to_string(),
            partial_output_delivery: "collated_terminal_payload".to_string(),
            claim_eligible: true,
            compatibility_only: false,
        },
        RuntimeLifecycleSurface::A2aCompatibility => RuntimeLifecycleContract {
            surface: "a2a_compatibility".to_string(),
            blocking_entrypoint: "message/send".to_string(),
            stream_entrypoint: "unsupported".to_string(),
            follow_up_entrypoint: "unsupported".to_string(),
            cancel_entrypoint: "unsupported".to_string(),
            stream_delivery: "collected_final_payload_only".to_string(),
            partial_output_delivery: "collected_final_payload_only".to_string(),
            claim_eligible: false,
            compatibility_only: true,
        },
        RuntimeLifecycleSurface::AcpAuthoritative => RuntimeLifecycleContract {
            surface: "acp_authoritative".to_string(),
            blocking_entrypoint: "tool/invoke".to_string(),
            stream_entrypoint: "tool/stream".to_string(),
            follow_up_entrypoint: "tool/resume".to_string(),
            cancel_entrypoint: "tool/cancel".to_string(),
            stream_delivery: "resumed_terminal_payload".to_string(),
            partial_output_delivery: "resumed_terminal_payload".to_string(),
            claim_eligible: true,
            compatibility_only: false,
        },
        RuntimeLifecycleSurface::AcpCompatibility => RuntimeLifecycleContract {
            surface: "acp_compatibility".to_string(),
            blocking_entrypoint: "tool/invoke".to_string(),
            stream_entrypoint: "unsupported".to_string(),
            follow_up_entrypoint: "unsupported".to_string(),
            cancel_entrypoint: "unsupported".to_string(),
            stream_delivery: "collected_final_payload_only".to_string(),
            partial_output_delivery: "collected_final_payload_only".to_string(),
            claim_eligible: false,
            compatibility_only: true,
        },
    }
}

#[must_use]
pub fn runtime_lifecycle_metadata(surface: RuntimeLifecycleSurface) -> Value {
    match serde_json::to_value(runtime_lifecycle_contract(surface)) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

/// Truthful bridge fidelity contract for publication gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BridgeFidelity {
    Lossless,
    Adapted { caveats: Vec<String> },
    Unsupported { reason: String },
}

impl BridgeFidelity {
    #[must_use]
    pub fn published_by_default(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    #[must_use]
    pub fn caveats(&self) -> &[String] {
        match self {
            Self::Adapted { caveats } => caveats.as_slice(),
            Self::Lossless | Self::Unsupported { .. } => &[],
        }
    }

    #[must_use]
    pub fn unsupported_reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported { reason } => Some(reason.as_str()),
            Self::Lossless | Self::Adapted { .. } => None,
        }
    }
}

/// Semantic hints that influence truthful bridge publication decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSemanticHints {
    pub publish: bool,
    pub approval_required: bool,
    pub streams_output: bool,
    pub supports_cancellation: bool,
    pub partial_output: bool,
}

/// Extract bridge-semantic hints from a tool definition and optional `x-chio-*`
/// schema extensions.
#[must_use]
pub fn semantic_hints_for_tool(tool: &ToolDefinition) -> BridgeSemanticHints {
    let publish = schema_bool_extension(&tool.input_schema, "x-chio-publish")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-publish"))
        })
        .unwrap_or(true);

    let approval_required = schema_bool_extension(&tool.input_schema, "x-chio-approval-required")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-approval-required"))
        })
        .unwrap_or(false);

    let streams_output = schema_bool_extension(&tool.input_schema, "x-chio-streaming")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-streaming"))
        })
        .unwrap_or(matches!(
            tool.latency_hint,
            Some(LatencyHint::Moderate | LatencyHint::Slow)
        ));

    let supports_cancellation = schema_bool_extension(&tool.input_schema, "x-chio-cancellation")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-cancellation"))
        })
        .unwrap_or(matches!(tool.latency_hint, Some(LatencyHint::Slow)));

    let partial_output = schema_bool_extension(&tool.input_schema, "x-chio-partial-output")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-partial-output"))
        })
        .unwrap_or(streams_output);

    BridgeSemanticHints {
        publish,
        approval_required,
        streams_output,
        supports_cancellation,
        partial_output,
    }
}

/// Resolve the authoritative target protocol advertised for a tool.
///
/// `x-chio-target-protocol` follows the same schema-extension pattern as the
/// other `x-chio-*` bridge hints. When omitted, Chio defaults to `native`.
pub fn target_protocol_for_tool(tool: &ToolDefinition) -> Result<DiscoveryProtocol, String> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native).resolve_target_protocol(tool)
}

/// Resolve the authoritative target protocol using an explicit registry policy
/// rather than silent `Native` fallback.
pub fn target_protocol_for_tool_with_registry(
    tool: &ToolDefinition,
    registry: &TargetProtocolRegistry<'_>,
) -> Result<DiscoveryProtocol, String> {
    registry.resolve_target_protocol(tool)
}

/// Plan a control-plane route selection for an authoritative call.
pub fn plan_authoritative_route(
    request_id: &str,
    source_protocol: DiscoveryProtocol,
    requested_target_protocol: DiscoveryProtocol,
    governed_intent: Option<&GovernedTransactionIntent>,
    registry: &TargetProtocolRegistry<'_>,
    availability: &BTreeMap<DiscoveryProtocol, RouteAvailabilityStatus>,
) -> Result<RoutePlanningOutcome, BridgeError> {
    let hints = route_planning_hints(governed_intent)?;
    let mut targets = vec![requested_target_protocol];
    if let Some(preferred) = hints.preferred_target_protocol {
        if !targets.contains(&preferred) {
            targets.push(preferred);
        }
    }
    if hints.disallow_projected_protocols
        && requested_target_protocol != DiscoveryProtocol::Native
        && !targets.contains(&DiscoveryProtocol::Native)
    {
        targets.push(DiscoveryProtocol::Native);
    }
    if hints.allow_native_fallback && !targets.contains(&DiscoveryProtocol::Native) {
        targets.push(DiscoveryProtocol::Native);
    }

    let candidates = targets
        .into_iter()
        .map(|target_protocol| {
            build_route_candidate(source_protocol, target_protocol, registry, availability)
        })
        .collect::<Vec<_>>();

    let available_candidate = |protocol: DiscoveryProtocol| -> Option<&RouteCandidateEvidence> {
        candidates
            .iter()
            .find(|candidate| candidate.target_protocol == protocol && candidate.available)
    };

    let decision = if hints.disallow_projected_protocols
        && requested_target_protocol != DiscoveryProtocol::Native
    {
        if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Attenuate,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("governed intent disallowed projected protocols; selected native route"),
                governed_intent,
                &candidates,
            )?
        } else {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Deny,
                source_protocol,
                requested_target_protocol,
                candidates.first(),
                Some("governed intent disallowed projected protocols and no native route was available"),
                governed_intent,
                &candidates,
            )?
        }
    } else if let Some(preferred) = hints.preferred_target_protocol {
        if let Some(candidate) = available_candidate(preferred) {
            planned_outcome(
                request_id,
                if preferred == requested_target_protocol {
                    RouteSelectionDecision::Select
                } else {
                    RouteSelectionDecision::Attenuate
                },
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                if preferred == requested_target_protocol {
                    None
                } else {
                    Some("control-plane policy preferred an alternate target protocol")
                },
                governed_intent,
                &candidates,
            )?
        } else if let Some(candidate) = available_candidate(requested_target_protocol) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Select,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("preferred target protocol unavailable; retained requested route"),
                governed_intent,
                &candidates,
            )?
        } else if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Attenuate,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("preferred target protocol unavailable; attenuated to native fallback"),
                governed_intent,
                &candidates,
            )?
        } else {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Deny,
                source_protocol,
                requested_target_protocol,
                candidates.first(),
                Some("no candidate route satisfied the preferred target protocol policy"),
                governed_intent,
                &candidates,
            )?
        }
    } else if let Some(candidate) = available_candidate(requested_target_protocol) {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Select,
            source_protocol,
            requested_target_protocol,
            Some(candidate),
            None,
            governed_intent,
            &candidates,
        )?
    } else if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Attenuate,
            source_protocol,
            requested_target_protocol,
            Some(candidate),
            Some("requested target protocol unavailable; attenuated to native fallback"),
            governed_intent,
            &candidates,
        )?
    } else {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Deny,
            source_protocol,
            requested_target_protocol,
            candidates.first(),
            Some("no candidate route was available at planning time"),
            governed_intent,
            &candidates,
        )?
    };

    Ok(decision)
}

/// Build receipt metadata wrapper for signed route-selection evidence.
pub fn route_selection_metadata(evidence: &RouteSelectionEvidence) -> Result<Value, BridgeError> {
    Ok(json!({
        "route_selection": serde_json::to_value(evidence)
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
    }))
}

/// Parse a protocol-family name used in bridge metadata.
pub fn parse_discovery_protocol(value: &str) -> Result<DiscoveryProtocol, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "native" => Ok(DiscoveryProtocol::Native),
        "http" => Ok(DiscoveryProtocol::Http),
        "mcp" => Ok(DiscoveryProtocol::Mcp),
        "a2a" => Ok(DiscoveryProtocol::A2a),
        "acp" => Ok(DiscoveryProtocol::Acp),
        "open_ai" | "openai" => Ok(DiscoveryProtocol::OpenAi),
        _ => Err(format!(
            "unsupported x-chio-target-protocol value `{value}`; expected one of native, http, mcp, a2a, acp, open_ai"
        )),
    }
}

/// Stable capability reference carried across protocol boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossProtocolCapabilityRef {
    pub chio_capability_id: String,
    pub origin_protocol: DiscoveryProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_context: Option<Value>,
    pub parent_capability_hash: String,
}

impl CrossProtocolCapabilityRef {
    pub fn from_capability(
        capability: &CapabilityToken,
        origin_protocol: DiscoveryProtocol,
        protocol_context: Option<Value>,
    ) -> Result<Self, BridgeError> {
        Ok(Self {
            chio_capability_id: capability.id.clone(),
            origin_protocol,
            protocol_context,
            parent_capability_hash: parent_capability_hash(capability)?,
        })
    }
}

/// Attenuated envelope that records how a capability crossed a protocol hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossProtocolCapabilityEnvelope {
    pub schema: String,
    pub capability: CapabilityToken,
    pub target_protocol: DiscoveryProtocol,
    pub attenuated_scope: ChioScope,
    pub bridged_at: u64,
    pub bridge_id: String,
}

/// One hop in a cross-protocol request trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolHop {
    pub protocol: DiscoveryProtocol,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub bridge_id: String,
    pub timestamp: u64,
}

/// Cross-hop request lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossProtocolTraceContext {
    pub trace_id: String,
    pub hops: Vec<ProtocolHop>,
    pub session_fingerprint: String,
}

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
    pub governed_intent: Option<GovernedTransactionIntent>,
    pub approval_token: Option<GovernedApprovalToken>,
    pub model_metadata: Option<ModelMetadata>,
}

/// Result of executing a bridged call through the shared orchestrator.
#[derive(Debug)]
pub struct OrchestratedToolCall {
    pub response: ToolCallResponse,
    pub source_protocol: DiscoveryProtocol,
    pub target_protocol: DiscoveryProtocol,
    pub terminal_protocol: DiscoveryProtocol,
    pub bridge_id: String,
    pub capability_ref: CrossProtocolCapabilityRef,
    pub capability_envelope: CrossProtocolCapabilityEnvelope,
    pub trace: CrossProtocolTraceContext,
    pub route: CrossProtocolRouteEvidence,
    pub projected_request: Value,
    pub protocol_result: Option<Value>,
    pub protocol_notifications: Vec<Value>,
}

impl OrchestratedToolCall {
    #[must_use]
    pub fn metadata(&self) -> Value {
        json!({
            "chio": {
                "receiptId": self.response.receipt.id,
                "receipt": self.response.receipt,
                "receiptRef": {
                    "receiptId": self.response.receipt.id,
                    "capabilityId": self.response.receipt.capability_id,
                    "traceId": self.trace.trace_id,
                    "bridgeId": self.bridge_id,
                    "sourceProtocol": self.source_protocol,
                    "targetProtocol": self.target_protocol,
                },
                "decision": match self.response.verdict {
                    KernelVerdict::Allow => "allow",
                    KernelVerdict::Deny => "deny",
                    KernelVerdict::PendingApproval => "pending_approval",
                },
                "capabilityId": self.response.receipt.capability_id,
                "authorityPath": CROSS_PROTOCOL_AUTHORITY_PATH,
                "authoritative": true,
                "reason": self.response.reason,
                "routeSelection": self
                    .response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("route_selection").cloned()),
                "bridge": {
                    "bridgeId": self.bridge_id,
                    "sourceProtocol": self.source_protocol,
                    "targetProtocol": self.target_protocol,
                    "terminalProtocol": self.terminal_protocol,
                    "capabilityRef": self.capability_ref,
                    "capabilityEnvelope": self.capability_envelope,
                    "route": self.route,
                    "trace": self.trace,
                },
                "targetExecution": {
                    "projectedResult": self.protocol_result.is_some(),
                    "notificationCount": self.protocol_notifications.len(),
                    "routeHopCount": self.route.selected_protocols.len(),
                    "multiHop": self.route.multi_hop,
                    "terminalProtocol": self.terminal_protocol,
                }
            }
        })
    }
}

/// Route evidence emitted by the shared fabric for an authoritative bridged
/// execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossProtocolRouteEvidence {
    pub selected_protocols: Vec<DiscoveryProtocol>,
    pub terminal_protocol: DiscoveryProtocol,
    pub multi_hop: bool,
}

/// Availability state for one route family at planning time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteAvailabilityStatus {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RouteAvailabilityStatus {
    #[must_use]
    pub fn available() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
        }
    }
}

/// Candidate route considered by the shared control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCandidateEvidence {
    pub route_id: String,
    pub target_protocol: DiscoveryProtocol,
    pub selected_protocols: Vec<DiscoveryProtocol>,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_reason: Option<String>,
}

/// Planner decision for a route candidate set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteSelectionDecision {
    Select,
    Attenuate,
    Deny,
}

/// Signed route-selection evidence emitted by the shared control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSelectionEvidence {
    pub route_selection_id: String,
    pub decision: RouteSelectionDecision,
    pub source_protocol: DiscoveryProtocol,
    pub requested_target_protocol: DiscoveryProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_target_protocol: Option<DiscoveryProtocol>,
    pub selected_protocols: Vec<DiscoveryProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_id: Option<String>,
    pub candidates: Vec<RouteCandidateEvidence>,
}

/// Concrete planning result used by the shared orchestrator.
#[derive(Debug, Clone)]
pub struct RoutePlanningOutcome {
    pub selected_target_protocol: Option<DiscoveryProtocol>,
    pub evidence: RouteSelectionEvidence,
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
        let route_metadata = route_selection_metadata(request.route_selection)?;
        let response = request
            .kernel
            .evaluate_tool_call_blocking_with_metadata(
                &ToolCallRequest {
                    request_id: request.execution.kernel_request_id.clone(),
                    capability: request.execution.capability.clone(),
                    tool_name: request.execution.target_tool_name.clone(),
                    server_id: request.execution.target_server_id.clone(),
                    agent_id: request.execution.agent_id.clone(),
                    arguments: request.execution.arguments.clone(),
                    dpop_proof: request.execution.dpop_proof.clone(),
                    governed_intent: request.execution.governed_intent.clone(),
                    approval_token: request.execution.approval_token.clone(),
                    model_metadata: request.execution.model_metadata.clone(),
                    federated_origin_kernel_id: None,
                },
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

/// Protocol-specific capability extraction/injection hooks.
pub trait CapabilityBridge: Send + Sync {
    fn source_protocol(&self) -> DiscoveryProtocol;

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError>;

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError>;

    fn protocol_context(&self, _request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(None)
    }
}

/// Shared cross-protocol runtime over the existing kernel substrate.
pub struct CrossProtocolOrchestrator<'a> {
    kernel: &'a ChioKernel,
    target_registry: TargetProtocolRegistry<'a>,
    route_availability: BTreeMap<DiscoveryProtocol, RouteAvailabilityStatus>,
}

impl<'a> CrossProtocolOrchestrator<'a> {
    #[must_use]
    pub fn new(kernel: &'a ChioKernel) -> Self {
        Self {
            kernel,
            target_registry: TargetProtocolRegistry::new(DiscoveryProtocol::Native),
            route_availability: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_executor(mut self, executor: &'a dyn TargetProtocolExecutor) -> Self {
        self.target_registry = self.target_registry.with_executor(executor);
        self
    }

    #[must_use]
    pub fn with_registry(mut self, registry: TargetProtocolRegistry<'a>) -> Self {
        self.target_registry = registry;
        self
    }

    #[must_use]
    pub fn with_protocol_availability(
        mut self,
        protocol: DiscoveryProtocol,
        availability: RouteAvailabilityStatus,
    ) -> Self {
        self.route_availability.insert(protocol, availability);
        self
    }

    pub fn execute<B: CapabilityBridge>(
        &self,
        bridge: &B,
        request: CrossProtocolExecutionRequest,
    ) -> Result<OrchestratedToolCall, BridgeError> {
        let source_protocol = bridge.source_protocol();
        let provided_ref = bridge.extract_capability_ref(&request.source_envelope)?;
        let capability_ref = match provided_ref {
            Some(cap_ref) => {
                if cap_ref.chio_capability_id != request.capability.id {
                    return Err(BridgeError::CapabilityRefMismatch {
                        expected: request.capability.id.clone(),
                        actual: cap_ref.chio_capability_id,
                    });
                }
                cap_ref
            }
            None => CrossProtocolCapabilityRef::from_capability(
                &request.capability,
                source_protocol,
                bridge.protocol_context(&request.source_envelope)?,
            )?,
        };

        let mut projected_request = request.source_envelope.clone();
        bridge.inject_capability_ref(&mut projected_request, &capability_ref)?;

        let bridge_id = format!(
            "chio-bridge-{}-{}-{}",
            source_protocol, request.target_protocol, request.origin_request_id
        );
        let bridged_at = current_unix_timestamp();
        let attenuated_scope = attenuate_scope_for_tool(
            &request.capability.scope,
            &request.target_server_id,
            &request.target_tool_name,
        );
        if !attenuated_scope.is_subset_of(&request.capability.scope) {
            return Err(BridgeError::InvalidAttenuation(
                "attenuated scope must remain a strict subset of the parent capability".to_string(),
            ));
        }

        let capability_envelope = CrossProtocolCapabilityEnvelope {
            schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
            capability: request.capability.clone(),
            target_protocol: request.target_protocol,
            attenuated_scope,
            bridged_at,
            bridge_id: bridge_id.clone(),
        };

        let planning = plan_authoritative_route(
            &request.origin_request_id,
            source_protocol,
            request.target_protocol,
            request.governed_intent.as_ref(),
            &self.target_registry,
            &self.route_availability,
        )?;

        if planning.evidence.decision == RouteSelectionDecision::Deny {
            let deny_reason = planning
                .evidence
                .reason
                .clone()
                .unwrap_or_else(|| "route selection denied".to_string());
            let response = self
                .kernel
                .sign_planned_deny_response(
                    &ToolCallRequest {
                        request_id: request.kernel_request_id.clone(),
                        capability: request.capability.clone(),
                        tool_name: request.target_tool_name.clone(),
                        server_id: request.target_server_id.clone(),
                        agent_id: request.agent_id.clone(),
                        arguments: request.arguments.clone(),
                        dpop_proof: request.dpop_proof.clone(),
                        governed_intent: request.governed_intent.clone(),
                        approval_token: request.approval_token.clone(),
                        model_metadata: request.model_metadata.clone(),
                        federated_origin_kernel_id: None,
                    },
                    &deny_reason,
                    Some(route_selection_metadata(&planning.evidence)?),
                )
                .map_err(BridgeError::Kernel)?;
            let deny_route_hops = route_hops_from_planning(
                &planning.evidence,
                &request.kernel_request_id,
                &response.receipt.id,
            );
            let route = build_route_evidence(source_protocol, &deny_route_hops)?;
            let trace = build_trace_context(
                &request,
                source_protocol,
                &bridge_id,
                &deny_route_hops,
                bridged_at,
            )?;

            return Ok(OrchestratedToolCall {
                response,
                source_protocol,
                target_protocol: request.target_protocol,
                terminal_protocol: route.terminal_protocol,
                bridge_id,
                capability_ref,
                capability_envelope,
                trace,
                route,
                projected_request,
                protocol_result: None,
                protocol_notifications: Vec::new(),
            });
        }

        let selected_target_protocol = planning.selected_target_protocol.ok_or_else(|| {
            BridgeError::InvalidRequest(
                "route planner returned no selected target protocol".to_string(),
            )
        })?;
        let mut selected_request = request.clone();
        selected_request.target_protocol = selected_target_protocol;

        let target_execution = self.execute_target(
            &selected_request,
            source_protocol,
            &bridge_id,
            &capability_ref,
            &capability_envelope,
            &planning.evidence,
            &projected_request,
        )?;
        let route = build_route_evidence(source_protocol, &target_execution.route_hops)?;

        let trace = build_trace_context(
            &request,
            source_protocol,
            &bridge_id,
            &target_execution.route_hops,
            bridged_at,
        )?;

        Ok(OrchestratedToolCall {
            response: target_execution.response,
            source_protocol,
            target_protocol: selected_request.target_protocol,
            terminal_protocol: route.terminal_protocol,
            bridge_id,
            capability_ref,
            capability_envelope,
            trace,
            route,
            projected_request,
            protocol_result: target_execution.protocol_result,
            protocol_notifications: target_execution.protocol_notifications,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_target(
        &self,
        request: &CrossProtocolExecutionRequest,
        source_protocol: DiscoveryProtocol,
        bridge_id: &str,
        capability_ref: &CrossProtocolCapabilityRef,
        capability_envelope: &CrossProtocolCapabilityEnvelope,
        route_selection: &RouteSelectionEvidence,
        projected_request: &Value,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        if request.target_protocol == DiscoveryProtocol::Native {
            let route_metadata = route_selection_metadata(route_selection)?;
            let response = self
                .kernel
                .evaluate_tool_call_blocking_with_metadata(
                    &ToolCallRequest {
                        request_id: request.kernel_request_id.clone(),
                        capability: request.capability.clone(),
                        tool_name: request.target_tool_name.clone(),
                        server_id: request.target_server_id.clone(),
                        agent_id: request.agent_id.clone(),
                        arguments: request.arguments.clone(),
                        dpop_proof: request.dpop_proof.clone(),
                        governed_intent: request.governed_intent.clone(),
                        approval_token: request.approval_token.clone(),
                        model_metadata: request.model_metadata.clone(),
                        federated_origin_kernel_id: None,
                    },
                    Some(route_metadata),
                )
                .map_err(BridgeError::Kernel)?;
            let receipt_id = response.receipt.id.clone();
            return Ok(CrossProtocolTargetExecution {
                response,
                protocol_result: None,
                protocol_notifications: Vec::new(),
                route_hops: vec![TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                }],
            });
        }

        let executor = self
            .target_registry
            .executor_for_target(request.target_protocol)
            .ok_or(BridgeError::UnsupportedTargetProtocol(
                request.target_protocol,
            ))?;

        executor.execute(CrossProtocolTargetRequest {
            kernel: self.kernel,
            execution: request,
            source_protocol,
            bridge_id,
            capability_ref,
            capability_envelope,
            route_selection,
            projected_request,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("capability reference mismatch: expected {expected}, got {actual}")]
    CapabilityRefMismatch { expected: String, actual: String },

    #[error("invalid attenuation: {0}")]
    InvalidAttenuation(String),

    #[error("invalid request envelope: {0}")]
    InvalidRequest(String),

    #[error("canonical serialization failed: {0}")]
    Canonical(String),

    #[error("unsupported target protocol: {0}")]
    UnsupportedTargetProtocol(DiscoveryProtocol),

    #[error("kernel error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
}

fn build_trace_context(
    request: &CrossProtocolExecutionRequest,
    source_protocol: DiscoveryProtocol,
    bridge_id: &str,
    route_hops: &[TargetExecutionHop],
    timestamp: u64,
) -> Result<CrossProtocolTraceContext, BridgeError> {
    let route_protocols = route_hops
        .iter()
        .map(|hop| hop.protocol.as_str())
        .collect::<Vec<_>>();
    let trace_id = sha256_hex(
        &canonical_json_bytes(&json!({
            "originRequestId": request.origin_request_id,
            "kernelRequestId": request.kernel_request_id,
            "sourceProtocol": source_protocol,
            "targetProtocol": request.target_protocol,
            "routeProtocols": route_protocols,
            "capabilityId": request.capability.id,
            "bridgeId": bridge_id,
        }))
        .map_err(|error| BridgeError::Canonical(error.to_string()))?,
    );
    let session_fingerprint = sha256_hex(
        &canonical_json_bytes(&json!({
            "agentId": request.agent_id,
            "capabilityId": request.capability.id,
            "sourceProtocol": source_protocol,
            "bridgeId": bridge_id,
        }))
        .map_err(|error| BridgeError::Canonical(error.to_string()))?,
    );

    Ok(CrossProtocolTraceContext {
        trace_id,
        session_fingerprint,
        hops: std::iter::once(ProtocolHop {
            protocol: source_protocol,
            request_id: request.origin_request_id.clone(),
            receipt_id: None,
            bridge_id: bridge_id.to_string(),
            timestamp,
        })
        .chain(route_hops.iter().map(|hop| ProtocolHop {
            protocol: hop.protocol,
            request_id: hop.request_id.clone(),
            receipt_id: hop.receipt_id.clone(),
            bridge_id: bridge_id.to_string(),
            timestamp,
        }))
        .collect(),
    })
}

fn build_route_evidence(
    source_protocol: DiscoveryProtocol,
    route_hops: &[TargetExecutionHop],
) -> Result<CrossProtocolRouteEvidence, BridgeError> {
    let Some(last_hop) = route_hops.last() else {
        return Err(BridgeError::InvalidRequest(
            "target executor must return at least one target-side hop".to_string(),
        ));
    };

    Ok(CrossProtocolRouteEvidence {
        selected_protocols: std::iter::once(source_protocol)
            .chain(route_hops.iter().map(|hop| hop.protocol))
            .collect(),
        terminal_protocol: last_hop.protocol,
        multi_hop: route_hops.len() > 1,
    })
}

#[derive(Debug, Default)]
struct RoutePlanningHints {
    preferred_target_protocol: Option<DiscoveryProtocol>,
    allow_native_fallback: bool,
    disallow_projected_protocols: bool,
}

fn route_planning_hints(
    governed_intent: Option<&GovernedTransactionIntent>,
) -> Result<RoutePlanningHints, BridgeError> {
    let Some(context) = governed_intent.and_then(|intent| intent.context.as_ref()) else {
        return Ok(RoutePlanningHints::default());
    };
    let Some(control_plane) = context
        .get("chioControlPlane")
        .or_else(|| context.get("chio_control_plane"))
    else {
        return Ok(RoutePlanningHints::default());
    };
    let Some(object) = control_plane.as_object() else {
        return Err(BridgeError::InvalidRequest(
            "governed intent arcControlPlane context must be an object".to_string(),
        ));
    };

    let preferred_target_protocol = object
        .get("preferredTargetProtocol")
        .or_else(|| object.get("preferred_target_protocol"))
        .and_then(Value::as_str)
        .map(parse_discovery_protocol)
        .transpose()
        .map_err(BridgeError::InvalidRequest)?;

    Ok(RoutePlanningHints {
        preferred_target_protocol,
        allow_native_fallback: object
            .get("allowNativeFallback")
            .or_else(|| object.get("allow_native_fallback"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        disallow_projected_protocols: object
            .get("disallowProjectedProtocols")
            .or_else(|| object.get("disallow_projected_protocols"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn build_route_candidate(
    source_protocol: DiscoveryProtocol,
    target_protocol: DiscoveryProtocol,
    registry: &TargetProtocolRegistry<'_>,
    availability: &BTreeMap<DiscoveryProtocol, RouteAvailabilityStatus>,
) -> RouteCandidateEvidence {
    let registry_availability = if registry.supports_target_protocol(target_protocol) {
        RouteAvailabilityStatus::available()
    } else {
        RouteAvailabilityStatus::unavailable(format!(
            "target protocol `{target_protocol}` is not registered"
        ))
    };
    let availability = availability
        .get(&target_protocol)
        .cloned()
        .unwrap_or(registry_availability);

    RouteCandidateEvidence {
        route_id: format!("{}-route", target_protocol.as_str()),
        target_protocol,
        selected_protocols: planned_protocols_for_target(source_protocol, target_protocol),
        available: availability.available,
        availability_reason: availability.reason,
    }
}

fn planned_protocols_for_target(
    source_protocol: DiscoveryProtocol,
    target_protocol: DiscoveryProtocol,
) -> Vec<DiscoveryProtocol> {
    match target_protocol {
        DiscoveryProtocol::Native => vec![source_protocol, DiscoveryProtocol::Native],
        DiscoveryProtocol::Mcp | DiscoveryProtocol::OpenAi => {
            vec![source_protocol, target_protocol, DiscoveryProtocol::Native]
        }
        _ => vec![source_protocol, target_protocol],
    }
}

#[allow(clippy::too_many_arguments)]
fn planned_outcome(
    request_id: &str,
    decision: RouteSelectionDecision,
    source_protocol: DiscoveryProtocol,
    requested_target_protocol: DiscoveryProtocol,
    selected_candidate: Option<&RouteCandidateEvidence>,
    reason: Option<&str>,
    governed_intent: Option<&GovernedTransactionIntent>,
    candidates: &[RouteCandidateEvidence],
) -> Result<RoutePlanningOutcome, BridgeError> {
    let selected_route_id = if decision == RouteSelectionDecision::Deny {
        None
    } else {
        selected_candidate.map(|candidate| candidate.route_id.clone())
    };
    let selected_target_protocol = if decision == RouteSelectionDecision::Deny {
        None
    } else {
        selected_candidate.map(|candidate| candidate.target_protocol)
    };
    let selected_protocols = selected_candidate
        .map(|candidate| candidate.selected_protocols.clone())
        .unwrap_or_else(|| {
            candidates
                .first()
                .map(|candidate| candidate.selected_protocols.clone())
                .unwrap_or_else(|| vec![source_protocol, requested_target_protocol])
        });
    let route_selection_id = sha256_hex(
        &canonical_json_bytes(&json!({
            "requestId": request_id,
            "sourceProtocol": source_protocol,
            "requestedTargetProtocol": requested_target_protocol,
            "selectedRouteId": selected_route_id,
            "selectedTargetProtocol": selected_target_protocol,
            "selectedProtocols": selected_protocols,
            "decision": decision,
            "governedIntentId": governed_intent.map(|intent| intent.id.clone()),
        }))
        .map_err(|error| BridgeError::Canonical(error.to_string()))?,
    );

    Ok(RoutePlanningOutcome {
        selected_target_protocol,
        evidence: RouteSelectionEvidence {
            route_selection_id,
            decision,
            source_protocol,
            requested_target_protocol,
            selected_route_id,
            selected_target_protocol,
            selected_protocols,
            reason: reason.map(str::to_string),
            governed_intent_id: governed_intent.map(|intent| intent.id.clone()),
            candidates: candidates.to_vec(),
        },
    })
}

fn route_hops_from_planning(
    evidence: &RouteSelectionEvidence,
    kernel_request_id: &str,
    receipt_id: &str,
) -> Vec<TargetExecutionHop> {
    let target_protocols = evidence
        .selected_protocols
        .iter()
        .copied()
        .skip(1)
        .collect::<Vec<_>>();
    let last_index = target_protocols.len().saturating_sub(1);

    target_protocols
        .into_iter()
        .enumerate()
        .map(|(index, protocol)| TargetExecutionHop {
            protocol,
            request_id: if index == 0 && protocol != DiscoveryProtocol::Native {
                format!("{}:{}", kernel_request_id, protocol.as_str())
            } else {
                kernel_request_id.to_string()
            },
            receipt_id: (index == last_index).then(|| receipt_id.to_string()),
        })
        .collect()
}

fn parent_capability_hash(capability: &CapabilityToken) -> Result<String, BridgeError> {
    let lineage_anchor = capability
        .delegation_chain
        .last()
        .map(|link| link.capability_id.as_bytes().to_vec())
        .unwrap_or_else(|| capability.id.as_bytes().to_vec());
    Ok(sha256_hex(&canonical_json_bytes(&lineage_anchor).map_err(
        |error| BridgeError::Canonical(error.to_string()),
    )?))
}

fn attenuate_scope_for_tool(parent: &ChioScope, server_id: &str, tool_name: &str) -> ChioScope {
    let grants = parent
        .grants
        .iter()
        .filter(|grant| grant.server_id == server_id && grant.tool_name == tool_name)
        .cloned()
        .collect();

    ChioScope {
        grants,
        resource_grants: vec![],
        prompt_grants: vec![],
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn schema_bool_extension(schema: &Value, key: &str) -> Option<bool> {
    schema.as_object()?.get(key)?.as_bool()
}

fn schema_string_extension(schema: &Value, key: &str) -> Option<String> {
    schema.as_object()?.get(key)?.as_str().map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use chio_core::capability::{
        CapabilityTokenBody, Constraint, ModelMetadata, ModelSafetyTier, Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
        DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_manifest::ToolDefinition;

    struct MockBridge;

    impl CapabilityBridge for MockBridge {
        fn source_protocol(&self) -> DiscoveryProtocol {
            DiscoveryProtocol::A2a
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
            Ok(request
                .pointer("/metadata/chio/targetSkillId")
                .and_then(Value::as_str)
                .map(|skill| json!({ "targetSkillId": skill })))
        }
    }

    struct MockToolServer;

    struct MockMcpExecutor;

    impl TargetProtocolExecutor for MockMcpExecutor {
        fn target_protocol(&self) -> DiscoveryProtocol {
            DiscoveryProtocol::Mcp
        }

        fn execute(
            &self,
            request: CrossProtocolTargetRequest<'_>,
        ) -> Result<CrossProtocolTargetExecution, BridgeError> {
            let route_metadata = route_selection_metadata(request.route_selection)?;
            let response = request
                .kernel
                .evaluate_tool_call_blocking_with_metadata(
                    &ToolCallRequest {
                        request_id: request.execution.kernel_request_id.clone(),
                        capability: request.execution.capability.clone(),
                        tool_name: request.execution.target_tool_name.clone(),
                        server_id: request.execution.target_server_id.clone(),
                        agent_id: request.execution.agent_id.clone(),
                        arguments: request.execution.arguments.clone(),
                        dpop_proof: request.execution.dpop_proof.clone(),
                        governed_intent: request.execution.governed_intent.clone(),
                        approval_token: request.execution.approval_token.clone(),
                        model_metadata: request.execution.model_metadata.clone(),
                        federated_origin_kernel_id: None,
                    },
                    Some(route_metadata),
                )
                .map_err(BridgeError::Kernel)?;
            let receipt_id = response.receipt.id.clone();

            Ok(CrossProtocolTargetExecution {
                response,
                protocol_result: Some(json!({
                    "content": [{"type": "text", "text": "projected"}],
                    "structuredContent": {"mode": "mcp"},
                    "isError": false
                })),
                protocol_notifications: vec![
                    json!({"jsonrpc": "2.0", "method": "notifications/test"}),
                ],
                route_hops: vec![
                    TargetExecutionHop {
                        protocol: DiscoveryProtocol::Mcp,
                        request_id: format!("{}:mcp", request.execution.kernel_request_id),
                        receipt_id: None,
                    },
                    TargetExecutionHop {
                        protocol: DiscoveryProtocol::Native,
                        request_id: request.execution.kernel_request_id.clone(),
                        receipt_id: Some(receipt_id),
                    },
                ],
            })
        }
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            "test-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(json!({"result":"ok"}))
        }
    }

    fn unix_now() -> u64 {
        current_unix_timestamp()
    }

    fn test_kernel() -> (Keypair, ChioKernel) {
        let keypair = Keypair::generate();
        let config = KernelConfig {
            ca_public_keys: vec![keypair.public_key()],
            keypair: keypair.clone(),
            max_delegation_depth: 8,
            policy_hash: "policy-cross-protocol-test".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        };
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer));
        (keypair, kernel)
    }

    fn capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> CapabilityToken {
        capability_for_tool_with_constraints(issuer, subject, server_id, tool_name, vec![])
    }

    fn capability_for_tool_with_constraints(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
        constraints: Vec<Constraint>,
    ) -> CapabilityToken {
        let now = unix_now();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{server_id}-{tool_name}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints,
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: now.saturating_sub(30),
                expires_at: now + 300,
                delegation_chain: vec![],
            },
            issuer,
        )
        .unwrap()
    }

    fn semantic_tool(
        name: &str,
        latency_hint: Option<LatencyHint>,
        input_schema: Value,
        output_schema: Option<Value>,
    ) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("semantic tool {name}"),
            input_schema,
            output_schema,
            pricing: None,
            has_side_effects: false,
            latency_hint,
        }
    }

    #[test]
    fn target_protocol_defaults_to_native() {
        let tool = semantic_tool(
            "echo",
            Some(LatencyHint::Instant),
            json!({"type": "object"}),
            None,
        );
        assert_eq!(
            target_protocol_for_tool(&tool).unwrap(),
            DiscoveryProtocol::Native
        );
    }

    #[test]
    fn target_protocol_can_be_registry_derived() {
        let tool = semantic_tool(
            "echo",
            Some(LatencyHint::Instant),
            json!({"type": "object"}),
            None,
        );
        let registry = TargetProtocolRegistry::new(DiscoveryProtocol::OpenAi);
        assert_eq!(
            target_protocol_for_tool_with_registry(&tool, &registry).unwrap(),
            DiscoveryProtocol::OpenAi
        );
    }

    #[test]
    fn target_protocol_reads_schema_extension() {
        let tool = semantic_tool(
            "echo",
            Some(LatencyHint::Instant),
            json!({
                "type": "object",
                "x-chio-target-protocol": "mcp"
            }),
            None,
        );
        assert_eq!(
            target_protocol_for_tool(&tool).unwrap(),
            DiscoveryProtocol::Mcp
        );
    }

    #[test]
    fn target_protocol_rejects_unknown_extension_value() {
        let tool = semantic_tool(
            "echo",
            Some(LatencyHint::Instant),
            json!({
                "type": "object",
                "x-chio-target-protocol": "smtp"
            }),
            None,
        );
        assert!(target_protocol_for_tool(&tool).is_err());
    }

    #[test]
    fn orchestrator_executes_and_preserves_bridge_lineage() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let orchestrator = CrossProtocolOrchestrator::new(&kernel);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-task-1".to_string(),
                    kernel_request_id: "a2a-a2a-task-1".to_string(),
                    target_protocol: DiscoveryProtocol::Native,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();

        assert_eq!(result.source_protocol, DiscoveryProtocol::A2a);
        assert_eq!(result.target_protocol, DiscoveryProtocol::Native);
        assert_eq!(
            result.capability_ref.chio_capability_id,
            "cap-test-srv-echo"
        );
        assert_eq!(
            result.projected_request["metadata"]["chio"]["capabilityRef"]["chioCapabilityId"]
                .as_str(),
            Some("cap-test-srv-echo")
        );
        assert_eq!(result.trace.hops.len(), 2);
        assert!(result.trace.hops[1].receipt_id.is_some());

        let metadata = result.metadata();
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some(CROSS_PROTOCOL_AUTHORITY_PATH)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("a2a")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["terminalProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["routeSelection"]["decision"].as_str(),
            Some("select")
        );
        assert_eq!(
            metadata["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
            Some("native")
        );
    }

    #[test]
    fn orchestrator_fail_closes_with_empty_attenuation_on_out_of_scope_target() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let orchestrator = CrossProtocolOrchestrator::new(&kernel);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-task-2".to_string(),
                    kernel_request_id: "a2a-a2a-task-2".to_string(),
                    target_protocol: DiscoveryProtocol::Native,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "write".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"nope"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "write" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();

        assert!(result
            .capability_envelope
            .attenuated_scope
            .grants
            .is_empty());
        assert!(matches!(result.response.verdict, KernelVerdict::Deny));
        assert_eq!(result.metadata()["chio"]["decision"].as_str(), Some("deny"));
        assert_eq!(
            result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
            Some("select")
        );
    }

    #[test]
    fn pending_approval_metadata_is_not_labeled_allow() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let orchestrator = CrossProtocolOrchestrator::new(&kernel);

        let mut result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-task-pending".to_string(),
                    kernel_request_id: "a2a-a2a-task-pending".to_string(),
                    target_protocol: DiscoveryProtocol::Native,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();
        result.response.verdict = KernelVerdict::PendingApproval;
        result.response.reason = Some("approval required".to_string());

        let metadata = result.metadata();
        assert_eq!(
            metadata["chio"]["decision"].as_str(),
            Some("pending_approval")
        );
        assert_eq!(
            metadata["chio"]["reason"].as_str(),
            Some("approval required")
        );
    }

    #[test]
    fn orchestrator_dispatches_to_registered_target_executor() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let executor = MockMcpExecutor;
        let orchestrator = CrossProtocolOrchestrator::new(&kernel).with_executor(&executor);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-task-mcp".to_string(),
                    kernel_request_id: "a2a-mcp-1".to_string(),
                    target_protocol: DiscoveryProtocol::Mcp,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();

        assert_eq!(result.target_protocol, DiscoveryProtocol::Mcp);
        assert_eq!(
            result
                .protocol_result
                .as_ref()
                .and_then(|value| value["isError"].as_bool()),
            Some(false)
        );
        assert_eq!(result.protocol_notifications.len(), 1);
        assert_eq!(
            result.metadata()["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(result.trace.hops.len(), 3);
        assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::Mcp);
        assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
        assert_eq!(
            result.metadata()["chio"]["bridge"]["route"]["multiHop"],
            Value::Bool(true)
        );
        assert_eq!(
            result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
            Some("mcp")
        );
    }

    #[test]
    fn orchestrator_preserves_model_metadata_for_model_constrained_grant() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let orchestrator = CrossProtocolOrchestrator::new(&kernel);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-model-1".to_string(),
                    kernel_request_id: "a2a-model-kernel-1".to_string(),
                    target_protocol: DiscoveryProtocol::Native,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool_with_constraints(
                        &issuer,
                        &subject,
                        "test-srv",
                        "echo",
                        vec![Constraint::ModelConstraint {
                            allowed_model_ids: vec!["gpt-5".to_string()],
                            min_safety_tier: Some(ModelSafetyTier::High),
                        }],
                    ),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: Some(ModelMetadata {
                        model_id: "gpt-5".to_string(),
                        safety_tier: Some(ModelSafetyTier::High),
                        provider: Some("openai".to_string()),
                        provenance_class: chio_core::capability::ProvenanceEvidenceClass::Asserted,
                    }),
                },
            )
            .unwrap();

        assert!(matches!(result.response.verdict, KernelVerdict::Allow));
    }

    #[test]
    fn orchestrator_denies_unregistered_non_native_target_with_signed_route_selection() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let orchestrator = CrossProtocolOrchestrator::new(&kernel);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-task-mcp-missing".to_string(),
                    kernel_request_id: "a2a-mcp-missing-1".to_string(),
                    target_protocol: DiscoveryProtocol::Mcp,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();

        assert!(matches!(result.response.verdict, KernelVerdict::Deny));
        assert_eq!(
            result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
            Some("deny")
        );
        assert_eq!(
            result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
            None
        );
    }

    #[test]
    fn orchestrator_dispatches_to_registered_openai_target_executor() {
        let (issuer, kernel) = test_kernel();
        let subject = Keypair::generate();
        let executor = OpenAiTargetExecutor;
        let orchestrator = CrossProtocolOrchestrator::new(&kernel).with_executor(&executor);

        let result = orchestrator
            .execute(
                &MockBridge,
                CrossProtocolExecutionRequest {
                    origin_request_id: "a2a-openai-1".to_string(),
                    kernel_request_id: "a2a-openai-kernel-1".to_string(),
                    target_protocol: DiscoveryProtocol::OpenAi,
                    target_server_id: "test-srv".to_string(),
                    target_tool_name: "echo".to_string(),
                    agent_id: subject.public_key().to_hex(),
                    arguments: json!({"message":"hello"}),
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                    source_envelope: json!({
                        "message": {"role":"user"},
                        "metadata": { "chio": { "targetSkillId": "echo" } }
                    }),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
            )
            .unwrap();

        assert_eq!(result.target_protocol, DiscoveryProtocol::OpenAi);
        assert_eq!(result.terminal_protocol, DiscoveryProtocol::Native);
        assert_eq!(
            result
                .protocol_result
                .as_ref()
                .and_then(|value| value["type"].as_str()),
            Some("function_call_output")
        );
        assert_eq!(
            result
                .protocol_result
                .as_ref()
                .and_then(|value| value["receipt_ref"].as_str()),
            Some(result.response.receipt.id.as_str())
        );
        assert_eq!(result.trace.hops.len(), 3);
        assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::OpenAi);
        assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
        assert_eq!(
            result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
            Some("open_ai")
        );
    }

    fn governed_intent_with_control_plane(control_plane: Value) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "test-srv".to_string(),
            tool_name: "echo".to_string(),
            purpose: "test route planning".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(json!({ "chioControlPlane": control_plane })),
        }
    }

    #[test]
    fn plan_authoritative_route_prefers_registered_protocol_from_governed_intent() {
        let executor = MockMcpExecutor;
        let registry =
            TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
        let planning = plan_authoritative_route(
            "req-route-preferred",
            DiscoveryProtocol::A2a,
            DiscoveryProtocol::Native,
            Some(&governed_intent_with_control_plane(json!({
                "preferredTargetProtocol": "mcp",
                "allowNativeFallback": true
            }))),
            &registry,
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(
            planning.selected_target_protocol,
            Some(DiscoveryProtocol::Mcp)
        );
        assert_eq!(
            planning.evidence.decision,
            RouteSelectionDecision::Attenuate
        );
        assert_eq!(
            planning.evidence.selected_target_protocol,
            Some(DiscoveryProtocol::Mcp)
        );
    }

    #[test]
    fn plan_authoritative_route_attentuates_to_native_fallback_when_requested_route_is_unavailable()
    {
        let mut availability = BTreeMap::new();
        availability.insert(
            DiscoveryProtocol::Mcp,
            RouteAvailabilityStatus::unavailable("mcp route unavailable"),
        );
        let executor = MockMcpExecutor;
        let registry =
            TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
        let planning = plan_authoritative_route(
            "req-route-fallback",
            DiscoveryProtocol::A2a,
            DiscoveryProtocol::Mcp,
            Some(&governed_intent_with_control_plane(json!({
                "allowNativeFallback": true
            }))),
            &registry,
            &availability,
        )
        .unwrap();

        assert_eq!(
            planning.selected_target_protocol,
            Some(DiscoveryProtocol::Native)
        );
        assert_eq!(
            planning.evidence.decision,
            RouteSelectionDecision::Attenuate
        );
        assert_eq!(
            planning.evidence.reason.as_deref(),
            Some("requested target protocol unavailable; attenuated to native fallback")
        );
    }

    #[test]
    fn plan_authoritative_route_denies_when_projected_protocols_are_disallowed_without_native() {
        let executor = MockMcpExecutor;
        let registry =
            TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
        let mut availability = BTreeMap::new();
        availability.insert(
            DiscoveryProtocol::Native,
            RouteAvailabilityStatus::unavailable("native route unavailable"),
        );

        let planning = plan_authoritative_route(
            "req-route-deny",
            DiscoveryProtocol::A2a,
            DiscoveryProtocol::Mcp,
            Some(&governed_intent_with_control_plane(json!({
                "disallowProjectedProtocols": true
            }))),
            &registry,
            &availability,
        )
        .unwrap();

        assert_eq!(planning.selected_target_protocol, None);
        assert_eq!(planning.evidence.decision, RouteSelectionDecision::Deny);
        assert_eq!(
            planning.evidence.reason.as_deref(),
            Some(
                "governed intent disallowed projected protocols and no native route was available"
            )
        );
    }

    #[test]
    fn semantic_hints_respect_extensions_and_defaults() {
        let explicit = semantic_tool(
            "explicit",
            Some(LatencyHint::Fast),
            json!({
                "type": "object",
                "x-chio-publish": false,
                "x-chio-approval-required": true,
                "x-chio-cancellation": true
            }),
            Some(json!({
                "type": "object",
                "x-chio-streaming": true,
                "x-chio-partial-output": true
            })),
        );
        let explicit_hints = semantic_hints_for_tool(&explicit);
        assert!(!explicit_hints.publish);
        assert!(explicit_hints.approval_required);
        assert!(explicit_hints.streams_output);
        assert!(explicit_hints.supports_cancellation);
        assert!(explicit_hints.partial_output);

        let fallback = semantic_tool(
            "fallback",
            Some(LatencyHint::Slow),
            json!({"type": "object"}),
            None,
        );
        let fallback_hints = semantic_hints_for_tool(&fallback);
        assert!(fallback_hints.publish);
        assert!(!fallback_hints.approval_required);
        assert!(fallback_hints.streams_output);
        assert!(fallback_hints.supports_cancellation);
        assert!(fallback_hints.partial_output);
    }

    #[test]
    fn runtime_lifecycle_contract_serializes_shared_surface_metadata() {
        let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::A2aAuthoritative);
        let json = serde_json::to_value(lifecycle).unwrap();
        assert_eq!(json["surface"], "a2a_authoritative");
        assert_eq!(json["blockingEntrypoint"], "message/send");
        assert_eq!(json["streamEntrypoint"], "message/stream");
        assert_eq!(json["followUpEntrypoint"], "task/get");
        assert_eq!(json["cancelEntrypoint"], "task/cancel");
        assert_eq!(json["claimEligible"], true);
        assert_eq!(json["compatibilityOnly"], false);
    }

    #[test]
    fn bridge_fidelity_helpers_report_publication_state() {
        let lossless = BridgeFidelity::Lossless;
        assert!(lossless.published_by_default());
        assert!(lossless.caveats().is_empty());
        assert_eq!(lossless.unsupported_reason(), None);

        let adapted = BridgeFidelity::Adapted {
            caveats: vec!["partial output collated".to_string()],
        };
        assert!(adapted.published_by_default());
        assert_eq!(adapted.caveats(), ["partial output collated"]);
        assert_eq!(adapted.unsupported_reason(), None);

        let unsupported = BridgeFidelity::Unsupported {
            reason: "interactive permission prompt required".to_string(),
        };
        assert!(!unsupported.published_by_default());
        assert!(unsupported.caveats().is_empty());
        assert_eq!(
            unsupported.unsupported_reason(),
            Some("interactive permission prompt required")
        );
    }
}
