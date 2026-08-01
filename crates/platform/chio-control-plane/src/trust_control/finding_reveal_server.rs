//! Reference seller tool server for purchased finding reveals.
//!
//! Serves sealed payload bytes as the exact two-field reveal envelope for
//! `read_finding(finding_id)`. The server is buyer-blind: it holds only
//! finding identities and sealed bytes, never buyer identity, pricing, or
//! reservation state; the mediating kernel owns every admission and money
//! decision before this server is reached.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};

/// The tool name every purchased reveal is served under.
pub const READ_FINDING_TOOL: &str = "read_finding";

/// One sealed payload the server can reveal.
#[derive(Clone)]
pub struct SealedFindingPayload {
    /// Media type advertised by the signed finding; echoed verbatim in
    /// the reveal envelope.
    pub media_type: String,
    /// The raw payload bytes, sealed seller-side.
    pub payload: Vec<u8>,
}

/// Buyer-blind reveal server over an immutable sealed-payload map.
pub struct FindingRevealServer {
    server_id: String,
    sealed: Arc<HashMap<String, SealedFindingPayload>>,
}

impl FindingRevealServer {
    /// Build a reveal server for one seller identity over its sealed
    /// payloads, keyed by finding id.
    #[must_use]
    pub fn new(server_id: String, sealed: HashMap<String, SealedFindingPayload>) -> Self {
        Self {
            server_id,
            sealed: Arc::new(sealed),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FindingRevealServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![READ_FINDING_TOOL.to_owned()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != READ_FINDING_TOOL {
            return Err(KernelError::Internal(format!("unknown tool: {tool_name}")));
        }
        let finding_id = arguments
            .get("finding_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelError::Internal("read_finding requires a finding_id argument".to_owned())
            })?;
        let sealed = self.sealed.get(finding_id).ok_or_else(|| {
            KernelError::Internal("no sealed payload for this finding".to_owned())
        })?;
        Ok(serde_json::json!({
            "media_type": sealed.media_type,
            "payload_b64": base64::engine::general_purpose::STANDARD.encode(&sealed.payload),
        }))
    }
}
