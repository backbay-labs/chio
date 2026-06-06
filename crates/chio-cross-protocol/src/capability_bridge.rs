use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::discovery::DiscoveryProtocol;
use crate::error::BridgeError;

pub const CROSS_PROTOCOL_AUTHORITY_PATH: &str = "cross_protocol_orchestrator";
pub const CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA: &str = "chio.cross-protocol-cap.v1";

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

pub(crate) fn parent_capability_hash(capability: &CapabilityToken) -> Result<String, BridgeError> {
    let lineage_anchor = capability
        .delegation_chain
        .last()
        .map(|link| link.capability_id.as_bytes().to_vec())
        .unwrap_or_else(|| capability.id.as_bytes().to_vec());
    Ok(sha256_hex(&canonical_json_bytes(&lineage_anchor).map_err(
        |error| BridgeError::Canonical(error.to_string()),
    )?))
}

pub(crate) fn attenuate_scope_for_tool(
    parent: &ChioScope,
    server_id: &str,
    tool_name: &str,
) -> ChioScope {
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
