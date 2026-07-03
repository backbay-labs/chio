use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::resources::{SamplingMessage, SamplingTool, SamplingToolChoice};

/// Normalized payload for an MCP `sampling/createMessage` child request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageOperation {
    pub messages: Vec<SamplingMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    pub max_tokens: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop_sequences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<SamplingTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<SamplingToolChoice>,
}

/// Result payload returned by a client-side sampling request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageResult {
    pub role: String,
    pub content: serde_json::Value,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

/// Action selected by the client during an elicitation flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationAction {
    Accept,
    Decline,
    Cancel,
}

/// Normalized payload for an MCP `elicitation/create` child request.
///
/// Chio ships both form-mode and URL-mode elicitation. URL-mode completion is
/// brokered by the edge via pending elicitation ownership and later
/// `notifications/elicitation/complete` forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum CreateElicitationOperation {
    Form {
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
        meta: Option<serde_json::Value>,
        message: String,
        #[serde(rename = "requestedSchema")]
        requested_schema: serde_json::Value,
    },
    Url {
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
        meta: Option<serde_json::Value>,
        message: String,
        url: String,
        #[serde(rename = "elicitationId")]
        elicitation_id: String,
    },
}

/// Result payload returned by a client-side elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateElicitationResult {
    pub action: ElicitationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
}
