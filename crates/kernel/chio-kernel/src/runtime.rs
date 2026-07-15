use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent},
    scope::ModelMetadata,
    token::CapabilityToken,
};
use chio_core::receipt::body::ChioReceipt;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, OperationTerminalState, RequestId, RootDefinition,
};

use crate::dpop;
use crate::execution_nonce::SignedExecutionNonce;
use crate::{AgentId, KernelError, ServerId};

/// Verdict of a guard or capability evaluation.
///
/// This is the kernel's own verdict type, distinct from `chio_core::receipt::decision::Decision`.
/// The kernel uses this internally; it maps to `chio_core::receipt::decision::Decision` when
/// building receipts.
///
/// The `PendingApproval` variant is a marker: the payload (`ApprovalRequest`)
/// is returned separately via [`crate::approval::HitlVerdict`] so existing
/// call sites that pattern-match on `Verdict` and rely on its `Copy` semantics
/// keep compiling without change. The public contract is: `Allow`, `Deny`, and
/// `PendingApproval` are the three possible outcomes of guard evaluation, and
/// callers receive the full approval request via the richer HITL API surface
/// when they need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
    /// The action is suspended pending a human decision. Look up the
    /// associated `ApprovalRequest` via the HITL API.
    PendingApproval,
}

/// A tool call request as seen by the kernel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCallRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The signed capability token authorizing this call.
    pub capability: CapabilityToken,
    /// The tool to invoke.
    pub tool_name: String,
    /// The server hosting the tool.
    pub server_id: ServerId,
    /// The calling agent's identifier (hex-encoded public key).
    pub agent_id: AgentId,
    /// Tool arguments.
    pub arguments: serde_json::Value,
    /// Optional DPoP proof. Required when the matched grant has `dpop_required == Some(true)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_proof: Option<dpop::DpopProof>,
    /// Optional execution nonce presented for a strict nonce-protected
    /// dispatch. The nonce is minted by an allow evaluation and consumed
    /// exactly once before the tool server is invoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,
    /// Optional governed transaction intent bound to this invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token authorizing this governed invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<GovernedApprovalToken>,
    /// Optional metadata describing the model executing the calling
    /// agent. Consumed by `Constraint::ModelConstraint` enforcement.
    ///
    /// Absent when callers omit it; when the matched grant carries a
    /// `ModelConstraint` with any requirement, the call is denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,
    /// Identifier of the origin kernel when this request crosses a federation
    /// boundary (agent in Org A invoking a tool in Org B). When set, the
    /// local (tool-host) kernel persists the signed receipt locally before
    /// requesting bilateral co-signing from the origin kernel. Absent for
    /// intra-org calls.
    ///
    /// The field is skipped from wire serialization when `None` so the
    /// wire format stays byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_origin_kernel_id: Option<String>,
}

/// The kernel's response to a tool call request.
///
/// The `execution_nonce` field is a sibling so the `Verdict` enum can keep
/// its `Copy` semantics. The nonce is only populated for `Verdict::Allow`
/// and only when the kernel has an `ExecutionNonceConfig` installed;
/// non-allow responses and nonce-disabled deployments continue to carry
/// `None` here.
#[derive(Debug)]
pub struct ToolCallResponse {
    /// Correlation identifier (matches the request).
    pub request_id: String,
    /// The kernel's verdict.
    pub verdict: Verdict,
    /// The tool's output payload, which may be a direct value or a stream.
    pub output: Option<ToolCallOutput>,
    /// Denial reason (populated when verdict is Deny).
    pub reason: Option<String>,
    /// Explicit terminal lifecycle state for this request.
    pub terminal_state: OperationTerminalState,
    /// Signed receipt attesting to this decision.
    pub receipt: ChioReceipt,
    /// Short-lived, single-use execution nonce bound to this allow verdict.
    /// Populated only on `Verdict::Allow` when an `ExecutionNonceConfig` is
    /// installed on the kernel. Deployments without a config leave this
    /// `None` and keep working.
    ///
    /// Boxed so the deny/cancel/incomplete hot paths (which all carry
    /// `None`) don't widen the `SessionOperationResponse::ToolCall`
    /// variant and trip clippy's `large_enum_variant`.
    pub execution_nonce: Option<Box<SignedExecutionNonce>>,
}

/// Streamed tool output emitted before the final tool response frame.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallChunk {
    pub data: serde_json::Value,
}

/// Complete streamed output captured by the kernel.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallStream {
    pub chunks: Vec<ToolCallChunk>,
}

impl ToolCallStream {
    pub fn chunk_count(&self) -> u64 {
        self.chunks.len() as u64
    }
}

/// Sum the canonical byte size of a materialized stream and deny with
/// `Overloaded { StreamBytes }` if it exceeds `max_total_bytes` (0 = unlimited).
/// Uses the same per-chunk measurement as truncate_stream_to_limits, so the
/// at-arrival count and the finalize-time count agree by construction.
pub fn enforce_stream_byte_limit(
    stream: &ToolCallStream,
    max_total_bytes: u64,
) -> Result<(), KernelError> {
    if max_total_bytes == 0 {
        return Ok(());
    }
    let mut total: u64 = 0;
    for chunk in &stream.chunks {
        let bytes = crate::canonical_json_bytes(&chunk.data)
            .map_err(|e| KernelError::Internal(format!("failed to size stream chunk: {e}")))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > max_total_bytes {
            return Err(KernelError::Overloaded {
                resource: crate::OverloadResource::StreamBytes,
            });
        }
    }
    Ok(())
}

/// Fallible per-chunk push for KernelError-returning accumulators. Denies before
/// materializing past `max_total_bytes` (StreamBytes) OR past `max_chunks`
/// retained chunks (StreamChunks), and maps a failed allocation under strict
/// overcommit to a typed deny (Allocation) rather than an abort.
///
/// The chunk-count bound closes the tiny-chunk gap in the byte-only bound: a
/// connector using this as its advertised accumulation-time limit could otherwise
/// accept millions of tiny chunks that each stay under `max_total_bytes` while
/// `acc` retains millions of `ToolCallChunk` objects (and receipt signing later
/// allocates a hash per chunk). Both caps use `0 = unlimited`.
pub fn push_chunk_bounded(
    acc: &mut Vec<ToolCallChunk>,
    running_bytes: &mut u64,
    chunk: ToolCallChunk,
    max_total_bytes: u64,
    max_chunks: u64,
) -> Result<(), KernelError> {
    // Chunk-count bound: shed before retaining another chunk when the retained
    // count is already at the cap, so a flood of tiny chunks under the byte cap
    // still cannot grow `acc` (or the per-chunk signing preimage) without bound.
    if max_chunks > 0 && acc.len() as u64 >= max_chunks {
        return Err(KernelError::Overloaded {
            resource: crate::OverloadResource::StreamChunks,
        });
    }
    let chunk_bytes = crate::canonical_json_bytes(&chunk.data)
        .map_err(|e| KernelError::Internal(format!("failed to size stream chunk: {e}")))?
        .len() as u64;
    let next = running_bytes.saturating_add(chunk_bytes);
    if max_total_bytes > 0 && next > max_total_bytes {
        return Err(KernelError::Overloaded {
            resource: crate::OverloadResource::StreamBytes,
        });
    }
    acc.try_reserve(1).map_err(|_| KernelError::Overloaded {
        resource: crate::OverloadResource::Allocation,
    })?;
    acc.push(chunk);
    *running_bytes = next;
    Ok(())
}

/// Output produced by a tool invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolCallOutput {
    Value(serde_json::Value),
    Stream(ToolCallStream),
}

/// Stream-capable tool-server result.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolServerStreamResult {
    Complete(ToolCallStream),
    Incomplete {
        stream: ToolCallStream,
        reason: String,
    },
}

/// Tool-server output produced after validation and guard checks.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolServerOutput {
    Value(serde_json::Value),
    Stream(ToolServerStreamResult),
}

/// Bridge exposed to tool-server implementations while a parent request is in flight.
///
/// Wrapped servers can use this to trigger negotiated server-to-client requests such as
/// `roots/list` and `sampling/createMessage`, or to surface wrapped MCP notifications,
/// without escaping kernel mediation.
pub trait NestedFlowBridge: Send {
    fn parent_request_id(&self) -> &RequestId;

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        Ok(())
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError>;

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError>;

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError>;

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError>;

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError>;

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError>;
}

/// Raw client transport used by the kernel to service nested flows on behalf of a parent request.
///
/// The kernel owns lineage, policy, and in-flight bookkeeping. Implementors only move the nested
/// request or notification across the client transport and return the decoded response.
pub trait NestedFlowClient: Send {
    fn poll_parent_cancellation(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn list_roots(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError>;

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError>;

    fn create_elicitation(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError>;

    fn notify_elicitation_completed(
        &mut self,
        parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), KernelError>;

    fn notify_resource_updated(
        &mut self,
        parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), KernelError>;

    fn notify_resources_list_changed(
        &mut self,
        parent_context: &OperationContext,
    ) -> Result<(), KernelError>;
}

/// Cost reported by a tool server after invocation.
///
/// Tool servers that track monetary costs override `invoke_with_cost` and
/// return this struct. Servers that do not override return `None` via the
/// default implementation, and the kernel charges `max_cost_per_invocation`
/// as a worst-case debit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolInvocationCost {
    /// Cost in the currency's smallest unit (e.g. cents for USD).
    pub units: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Optional cost breakdown for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<serde_json::Value>,
}

/// Trait representing a connection to a tool server.
///
/// The kernel holds one `ToolServerConnection` per registered server. In
/// production this is an mTLS connection over UDS or TCP. For testing,
/// an in-process implementation can be used.
#[async_trait::async_trait]
pub trait ToolServerConnection: Send + Sync {
    /// The server's unique identifier.
    fn server_id(&self) -> &str;

    /// List the tool names available on this server.
    fn tool_names(&self) -> Vec<String>;

    /// Whether the named tool is annotated read-only (no external side
    /// effect). Default `false` fails safe: an unannotated or unknown tool is
    /// treated as side-effecting and gets a durable dispatch intent before it
    /// runs. Connections that know their tool annotations override this.
    fn tool_is_read_only(&self, _tool_name: &str) -> bool {
        false
    }

    /// Invoke a tool on this server. The kernel has already validated the
    /// capability and run guards before calling this.
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError>;

    /// Invoke a tool and optionally report the actual cost of the invocation.
    ///
    /// Tool servers that track monetary costs should override this method.
    /// The default implementation delegates to `invoke` and returns `None`
    /// cost, meaning the kernel will charge `max_cost_per_invocation` as
    /// the worst-case debit.
    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self
            .invoke(tool_name, arguments, nested_flow_bridge)
            .await?;
        Ok((value, None))
    }

    /// Invoke a tool that can emit multiple streamed chunks before its final terminal state.
    ///
    /// Servers that do not support streaming can ignore this and rely on `invoke`.
    async fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let _ = (tool_name, arguments, nested_flow_bridge);
        Ok(None)
    }

    /// Drain asynchronous events emitted after a tool invocation has already returned.
    ///
    /// Native tool servers can use this to surface late URL-elicitation completions and
    /// catalog/resource notifications without depending on a still-live request-local bridge.
    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolServerEvent {
    ElicitationCompleted { elicitation_id: String },
    ResourceUpdated { uri: String },
    ResourcesListChanged,
    ToolsListChanged,
    PromptsListChanged,
}
