// A2A protocol wire types and the kernel execution context.

/// A skill entry in the A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSkillEntry {
    /// Skill identifier (matches the Chio tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what the skill does.
    pub description: String,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Example inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Input modes supported.
    pub input_modes: Vec<String>,
    /// Output modes supported.
    pub output_modes: Vec<String>,
    /// Fidelity assessment.
    pub bridge_fidelity: BridgeFidelity,
}

/// An A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent name.
    pub name: String,
    /// Agent description.
    pub description: String,
    /// Agent version.
    pub version: String,
    /// Supported interfaces.
    pub supported_interfaces: Vec<AgentInterface>,
    /// Capabilities.
    pub capabilities: AgentCapabilities,
    /// Default input modes.
    pub default_input_modes: Vec<String>,
    /// Default output modes.
    pub default_output_modes: Vec<String>,
    /// Skills (tools exposed as A2A skills).
    pub skills: Vec<A2aSkillEntry>,
}

/// An A2A interface definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// URL for the A2A endpoint.
    pub url: String,
    /// Protocol binding.
    pub protocol_binding: String,
    /// Protocol version.
    pub protocol_version: String,
}

/// A2A agent capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether streaming is supported.
    #[serde(default)]
    pub streaming: bool,
    /// Whether push notifications are supported.
    #[serde(default)]
    pub push_notifications: bool,
    /// Whether state transition history is tracked.
    #[serde(default)]
    pub state_transition_history: bool,
}

/// An A2A SendMessage request (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    /// The message to send.
    pub message: A2aMessage,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// An A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    /// Role of the message sender.
    pub role: String,
    /// Message parts.
    pub parts: Vec<A2aPart>,
    /// Optional message metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A single part of an A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum A2aPart {
    /// A text part.
    #[serde(rename = "text")]
    Text { text: String },
    /// A structured data part.
    #[serde(rename = "data")]
    Data { data: Value },
}

/// A2A task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Result of handling a JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub struct A2aJsonRpcResponse {
    value: Option<Value>,
}

impl A2aJsonRpcResponse {
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

impl std::ops::Index<&str> for A2aJsonRpcResponse {
    type Output = Value;

    fn index(&self, index: &str) -> &Self::Output {
        match self.value.as_ref() {
            Some(value) => &value[index],
            None => panic!("JSON-RPC notification has no response"),
        }
    }
}

/// An A2A task response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    /// Task identifier.
    pub id: String,
    /// Current status.
    pub status: TaskStatus,
    /// Optional status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// The result message (present when completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    /// Chio metadata such as signed receipts when the kernel path is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Execution context required for kernel-mediated A2A invocations.
#[derive(Debug, Clone)]
pub struct A2aKernelExecutionContext {
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
