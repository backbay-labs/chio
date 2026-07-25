use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::{ChioKernel, ToolCallResponse, Verdict as KernelVerdict};
use serde_json::{json, Value};

use crate::capability_bridge::{
    attenuate_scope_for_tool, CapabilityBridge, CrossProtocolCapabilityEnvelope,
    CrossProtocolCapabilityRef, CrossProtocolTraceContext, ProtocolHop,
    CROSS_PROTOCOL_AUTHORITY_PATH, CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA,
};
use crate::discovery::{DiscoveryProtocol, TargetProtocolRegistry};
use crate::error::BridgeError;
use crate::execution::{
    kernel_tool_call_request, metadata_with_source_receipt_context, CrossProtocolExecutionRequest,
    CrossProtocolTargetExecution, CrossProtocolTargetRequest, TargetExecutionHop,
    TargetProtocolExecutor,
};
use crate::routing::{
    build_route_evidence, plan_authoritative_route, route_hops_from_planning,
    route_selection_metadata, CrossProtocolRouteEvidence, RouteAvailabilityStatus,
    RouteSelectionDecision, RouteSelectionEvidence,
};
use crate::validation::{validate_execution_request_boundary, validate_provided_capability_ref};

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
                "terminalState": self.response.terminal_state,
                "executionNonce": self.response.execution_nonce,
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
        validate_execution_request_boundary(&request)?;
        let source_protocol = bridge.source_protocol();
        let provided_ref = bridge.extract_capability_ref(&request.source_envelope)?;
        let capability_ref = match provided_ref {
            Some(cap_ref) => {
                validate_provided_capability_ref(&cap_ref, &request.capability, source_protocol)?;
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
                    &kernel_tool_call_request(&request),
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
            let capability_envelope = CrossProtocolCapabilityEnvelope {
                schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
                capability_ref: capability_ref.clone(),
                target_protocol: request.target_protocol,
                attenuated_scope: attenuated_scope.clone(),
                bridged_at,
                bridge_id: bridge_id.clone(),
            };

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
        let capability_envelope = CrossProtocolCapabilityEnvelope {
            schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
            capability_ref: capability_ref.clone(),
            target_protocol: selected_request.target_protocol,
            attenuated_scope,
            bridged_at,
            bridge_id: bridge_id.clone(),
        };

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
            &selected_request,
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
            let route_metadata = metadata_with_source_receipt_context(
                route_selection_metadata(route_selection)?,
                &request.source_envelope,
            )?;
            let response = self
                .kernel
                .evaluate_tool_call_blocking_with_metadata(
                    &kernel_tool_call_request(request),
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

pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
