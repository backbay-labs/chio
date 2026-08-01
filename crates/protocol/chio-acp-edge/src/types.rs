// ACP protocol wire types and the kernel execution context.

/// An ACP capability advertisement derived from a Chio tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapability {
    /// Capability identifier (matches the Chio tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the capability.
    pub description: String,
    /// The ACP category this maps to (e.g., "tool", "fs", "terminal").
    pub category: AcpCategory,
    /// Whether the capability requires explicit permission.
    pub requires_permission: bool,
    /// Fidelity assessment for this mapping.
    pub bridge_fidelity: BridgeFidelity,
}

/// ACP capability categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpCategory {
    /// General tool invocation.
    Tool,
    /// Filesystem operations.
    Filesystem,
    /// Terminal/command execution.
    Terminal,
    /// Browser-based operations.
    Browser,
}

/// An ACP permission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    /// The capability ID being requested.
    pub capability_id: String,
    /// Arguments for the invocation.
    pub arguments: Value,
}

/// An ACP permission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    /// Permission granted.
    Allow,
    /// Permission denied.
    Deny,
}

/// Result of an ACP tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpInvocationResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The result data.
    pub data: Value,
    /// Optional error message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Chio metadata such as signed receipts when the kernel path is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

impl AcpTaskStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Result of handling a JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub struct AcpJsonRpcResponse {
    value: Option<Value>,
}

impl AcpJsonRpcResponse {
    pub fn response(value: Value) -> Self {
        Self { value: Some(value) }
    }

    pub fn notification() -> Self {
        Self { value: None }
    }

    pub fn from_optional(value: Option<Value>) -> Self {
        Self { value }
    }

    pub fn as_value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.value.as_ref().and_then(|value| value.get(key))
    }

    pub fn into_value(self) -> Option<Value> {
        self.value
    }

    pub fn is_notification(&self) -> bool {
        self.value.is_none()
    }
}

impl std::ops::Index<&str> for AcpJsonRpcResponse {
    type Output = Value;

    fn index(&self, index: &str) -> &Self::Output {
        match self.value.as_ref() {
            Some(value) => &value[index],
            None => panic!("JSON-RPC notification has no response"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpInvocationTask {
    pub id: String,
    pub status: AcpTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Execution context required for kernel-mediated ACP invocations.
#[derive(Debug, Clone)]
pub struct AcpKernelExecutionContext {
    /// The signed capability token authorizing this invocation.
    pub capability: CapabilityToken,
    /// The authenticated calling agent identifier.
    pub agent_id: String,
    /// Optional DPoP proof when the matched grant requires sender binding.
    pub dpop_proof: Option<dpop::DpopProof>,
    /// Optional execution nonce for strict kernel dispatch.
    pub execution_nonce: Option<SignedExecutionNonce>,
    /// Optional governed transaction intent carried with this invocation.
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token for governed transaction execution.
    pub approval_token: Option<GovernedApprovalToken>,
    /// Optional threshold approval tokens.
    pub approval_tokens: Vec<GovernedApprovalToken>,
    /// Signed proposal binding a threshold approval set.
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// Opaque authenticated extension forwarded without interpretation.
    pub supplemental_authorization:
        Option<chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization>,
    /// Optional metadata about the model that originated this invocation.
    pub model_metadata: Option<ModelMetadata>,
}
