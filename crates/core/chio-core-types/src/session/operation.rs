use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::AgentId;

use super::identifiers::{ProgressToken, RequestId, SessionId};

/// Terminal runtime state for a session-scoped request.
///
/// This tracks lifecycle completion independently from authorization verdicts.
/// A denied request still reaches a terminal `Completed` state, while cancelled
/// or interrupted work records a different terminal outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OperationTerminalState {
    Completed,
    Cancelled { reason: String },
    Incomplete { reason: String },
}

impl OperationTerminalState {
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

/// Normalized operation kind, independent of edge framing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ToolCall,
    CreateMessage,
    CreateElicitation,
    ListRoots,
    ListResources,
    ReadResource,
    ListResourceTemplates,
    ListPrompts,
    GetPrompt,
    Complete,
    ListCapabilities,
    Heartbeat,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::CreateMessage => "create_message",
            Self::CreateElicitation => "create_elicitation",
            Self::ListRoots => "list_roots",
            Self::ListResources => "list_resources",
            Self::ReadResource => "read_resource",
            Self::ListResourceTemplates => "list_resource_templates",
            Self::ListPrompts => "list_prompts",
            Self::GetPrompt => "get_prompt",
            Self::Complete => "complete",
            Self::ListCapabilities => "list_capabilities",
            Self::Heartbeat => "heartbeat",
        }
    }
}

/// Session-scoped metadata attached to every normalized operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationContext {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_token: Option<ProgressToken>,
}

impl OperationContext {
    pub fn new(session_id: SessionId, request_id: RequestId, agent_id: AgentId) -> Self {
        Self {
            session_id,
            request_id,
            agent_id,
            parent_request_id: None,
            progress_token: None,
        }
    }
}
