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
use chio_store_sqlite::{SqliteFindingPayloadStore, TenantId, TenantKey};

/// The tool name every purchased reveal is served under.
pub const READ_FINDING_TOOL: &str = "read_finding";

/// One sealed payload the server can reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedFindingPayload {
    /// Media type advertised by the signed finding; echoed verbatim in
    /// the reveal envelope.
    pub media_type: String,
    /// The raw payload bytes, sealed seller-side.
    pub payload: Vec<u8>,
}

/// Fail-closed resolver used by the buyer-blind reveal server.
pub trait FindingPayloadResolver: Send + Sync {
    /// Resolve one sealed payload by its public Finding identity.
    fn resolve(&self, finding_id: &str)
        -> Result<SealedFindingPayload, FindingPayloadResolveError>;
}

/// Coarse resolution error. The reveal surface intentionally does not expose
/// storage or cryptographic details to a buyer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingPayloadResolveError;

struct InMemoryFindingPayloadResolver {
    sealed: HashMap<String, SealedFindingPayload>,
}

impl FindingPayloadResolver for InMemoryFindingPayloadResolver {
    fn resolve(
        &self,
        finding_id: &str,
    ) -> Result<SealedFindingPayload, FindingPayloadResolveError> {
        self.sealed
            .get(finding_id)
            .cloned()
            .ok_or(FindingPayloadResolveError)
    }
}

/// Production resolver backed by the encrypted durable payload store.
pub struct SqliteFindingPayloadResolver {
    store: Arc<SqliteFindingPayloadStore>,
    tenant_id: TenantId,
    key: Arc<TenantKey>,
}

impl SqliteFindingPayloadResolver {
    /// Bind a durable store to one operator tenant and its payload key.
    #[must_use]
    pub fn new(
        store: Arc<SqliteFindingPayloadStore>,
        tenant_id: TenantId,
        key: Arc<TenantKey>,
    ) -> Self {
        Self {
            store,
            tenant_id,
            key,
        }
    }
}

impl FindingPayloadResolver for SqliteFindingPayloadResolver {
    fn resolve(
        &self,
        finding_id: &str,
    ) -> Result<SealedFindingPayload, FindingPayloadResolveError> {
        let record = self
            .store
            .get(&self.tenant_id, &self.key, finding_id)
            .map_err(|_| FindingPayloadResolveError)?;
        Ok(SealedFindingPayload {
            media_type: record.media_type,
            payload: record.payload,
        })
    }
}

/// Buyer-blind reveal server over a sealed-payload resolver.
pub struct FindingRevealServer {
    server_id: String,
    resolver: Arc<dyn FindingPayloadResolver>,
}

impl FindingRevealServer {
    /// Build a reveal server for one seller identity over its sealed
    /// payloads, keyed by finding id.
    #[must_use]
    pub fn new(server_id: String, sealed: HashMap<String, SealedFindingPayload>) -> Self {
        Self {
            server_id,
            resolver: Arc::new(InMemoryFindingPayloadResolver { sealed }),
        }
    }

    /// Build a reveal server over a production or test payload resolver.
    #[must_use]
    pub fn with_resolver(server_id: String, resolver: Arc<dyn FindingPayloadResolver>) -> Self {
        Self {
            server_id,
            resolver,
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
        let sealed = self.resolver.resolve(finding_id).map_err(|_| {
            KernelError::Internal("sealed finding payload is unavailable".to_owned())
        })?;
        Ok(serde_json::json!({
            "media_type": sealed.media_type,
            "payload_b64": base64::engine::general_purpose::STANDARD.encode(&sealed.payload),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_finding::finding_payload_sha256;

    #[tokio::test]
    async fn durable_resolver_reveals_after_store_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let tenant_id = TenantId::new("operator-alpha");
        let key = TenantKey::from_bytes([9; 32]);
        let payload = b"diff --git a/a.rs b/a.rs\n";
        let digest = finding_payload_sha256("text/x-diff", payload).unwrap();
        SqliteFindingPayloadStore::open(&path)
            .unwrap()
            .put(
                &tenant_id,
                &key,
                "finding-1",
                "text/x-diff",
                &digest,
                payload,
            )
            .unwrap();

        let resolver = SqliteFindingPayloadResolver::new(
            Arc::new(SqliteFindingPayloadStore::open(&path).unwrap()),
            tenant_id,
            Arc::new(key),
        );
        let server = FindingRevealServer::with_resolver("seller-1".to_owned(), Arc::new(resolver));
        let response = server
            .invoke(
                READ_FINDING_TOOL,
                serde_json::json!({"finding_id": "finding-1"}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(response["media_type"], "text/x-diff");
        assert_eq!(
            response["payload_b64"],
            base64::engine::general_purpose::STANDARD.encode(payload)
        );
    }

    #[tokio::test]
    async fn missing_payload_fails_closed_without_storage_detail() {
        let server = FindingRevealServer::new("seller-1".to_owned(), HashMap::new());
        let error = server
            .invoke(
                READ_FINDING_TOOL,
                serde_json::json!({"finding_id": "missing"}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "internal error: sealed finding payload is unavailable"
        );
    }
}
