use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::capability::token::CapabilityToken;

use super::normalization::ResourceUriClassification;
use super::resources::{CompletionArgument, CompletionReference};

/// Resource read payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceOperation {
    pub capability: CapabilityToken,
    pub uri: String,
}

impl ReadResourceOperation {
    pub fn classify_uri_for_runtime(&self) -> ResourceUriClassification {
        ResourceUriClassification::from_uri(&self.uri)
    }
}

/// Prompt retrieval payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptOperation {
    pub capability: CapabilityToken,
    pub prompt_name: String,
    pub arguments: serde_json::Value,
}

/// Completion payload for prompt arguments or resource templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteOperation {
    pub capability: CapabilityToken,
    pub reference: CompletionReference,
    pub argument: CompletionArgument,
    #[serde(default)]
    pub context_arguments: serde_json::Value,
}
