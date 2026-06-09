use async_trait::async_trait;

use crate::{ProviderError, ProviderId, ToolInvocation, VerdictResult};

/// Raw upstream request payload bytes.
///
/// Adapters wrap whatever the native SDK or HTTP client surfaced for an
/// outgoing request. The fabric never inspects these bytes; they exist purely
/// as opaque material that adapters lift into [`ToolInvocation`].
pub struct ProviderRequest(pub Vec<u8>);

/// Raw upstream response payload bytes.
///
/// Lower returns these so the caller can hand the bytes back to the upstream
/// transport without the fabric mediating wire-format details.
pub struct ProviderResponse(pub Vec<u8>);

/// Canonical-JSON tool output bytes (RFC 8785).
///
/// Tool execution results are passed back through [`ProviderAdapter::lower`]
/// in canonical form so downstream auditors see byte-identical material
/// regardless of which provider produced or consumed the call.
pub struct ToolResult(pub Vec<u8>);

/// Provider-agnostic adapter contract.
///
/// Each native adapter implements this trait to lift an upstream request into
/// a normalized [`ToolInvocation`] and to lower a kernel [`VerdictResult`] plus
/// tool result back into the wire format the upstream expects.
///
/// The trait is intentionally minimal so it stays dyn-compatible and so the
/// streaming state machine in `stream.rs` can wrap any implementer uniformly.
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderId;
    fn api_version(&self) -> &str;
    async fn lift(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError>;
    async fn lower(
        &self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ProviderResponse, ProviderError>;
}
