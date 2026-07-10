use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

use super::messages::{CreateElicitationOperation, CreateMessageOperation};
use super::operation::OperationKind;
use super::payloads::{CompleteOperation, GetPromptOperation, ReadResourceOperation};
use super::resources::ToolCallOperation;

/// Higher-level operations the runtime can evaluate within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum SessionOperation {
    ToolCall(Box<ToolCallOperation>),
    CreateMessage(CreateMessageOperation),
    CreateElicitation(CreateElicitationOperation),
    ListRoots,
    ListResources,
    ReadResource(ReadResourceOperation),
    ListResourceTemplates,
    ListPrompts,
    GetPrompt(GetPromptOperation),
    Complete(CompleteOperation),
    ListCapabilities,
    Heartbeat,
}

impl SessionOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::ToolCall(_) => OperationKind::ToolCall,
            Self::CreateMessage(_) => OperationKind::CreateMessage,
            Self::CreateElicitation(_) => OperationKind::CreateElicitation,
            Self::ListRoots => OperationKind::ListRoots,
            Self::ListResources => OperationKind::ListResources,
            Self::ReadResource(_) => OperationKind::ReadResource,
            Self::ListResourceTemplates => OperationKind::ListResourceTemplates,
            Self::ListPrompts => OperationKind::ListPrompts,
            Self::GetPrompt(_) => OperationKind::GetPrompt,
            Self::Complete(_) => OperationKind::Complete,
            Self::ListCapabilities => OperationKind::ListCapabilities,
            Self::Heartbeat => OperationKind::Heartbeat,
        }
    }
}
