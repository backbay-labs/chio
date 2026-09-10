//! Import function tools without inferring execution authority or pricing.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{
    validate_manifest, ManifestError, ToolDefinition, ToolManifest, ToolPricing,
    TOOL_MANIFEST_SCHEMA,
};

/// Governance declarations supplied by the application for each imported tool.
///
/// There is deliberately no default. `pricing: None` explicitly declares that
/// this manifest does not advertise metered pricing for the tool. A manifest
/// declaration does not issue a capability or authorize execution.
#[derive(Debug, Clone)]
pub struct ToolGovernance {
    pub has_side_effects: bool,
    pub pricing: Option<ToolPricing>,
}

/// An invalid provider definition or an incomplete governance declaration.
#[derive(Debug, thiserror::Error)]
pub enum OpenAiManifestError {
    #[error("OpenAI tool {index} has an invalid or missing {field}")]
    InvalidTool { index: usize, field: &'static str },
    #[error("declare side effects and pricing for OpenAI tool {0}")]
    MissingGovernance(String),
    #[error("governance declaration has no matching OpenAI tool: {0}")]
    UnknownGovernance(String),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

impl ToolManifest {
    /// Build a validated manifest from OpenAI function-tool definitions.
    ///
    /// Accepts Chat Completions' nested `function` object and Responses' flat
    /// function definition. Provider-native tools are refused. Every tool must
    /// have an exact-name governance declaration; extra declarations are refused
    /// as likely misspellings. Missing parameters mean an empty object schema.
    ///
    /// The server name initially equals its ID. The result is unsigned: register
    /// and sign it using the normal host lifecycle. This does not authenticate the
    /// public key, grant capabilities, or infer side effects from tool names.
    pub fn from_openai_tools(
        server_id: impl Into<chio_core::ServerId>,
        public_key: impl Into<String>,
        version: impl Into<String>,
        definitions: &[Value],
        governance: &BTreeMap<String, ToolGovernance>,
    ) -> Result<Self, OpenAiManifestError> {
        let mut tools = Vec::with_capacity(definitions.len());
        for (index, entry) in definitions.iter().enumerate() {
            let invalid = |field| OpenAiManifestError::InvalidTool { index, field };
            if entry.get("type").and_then(Value::as_str) != Some("function") {
                return Err(invalid("type (expected function)"));
            }
            let function = entry.get("function").unwrap_or(entry);
            if !function.is_object() {
                return Err(invalid("function object"));
            }
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("name"))?;
            let description = match function.get("description") {
                Some(value) => value.as_str().ok_or_else(|| invalid("description"))?,
                None => "",
            };
            let declaration = governance
                .get(name)
                .ok_or_else(|| OpenAiManifestError::MissingGovernance(name.to_owned()))?;
            tools.push(ToolDefinition {
                name: name.to_owned(),
                description: description.to_owned(),
                input_schema: function
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
                output_schema: None,
                pricing: declaration.pricing.clone(),
                has_side_effects: declaration.has_side_effects,
                latency_hint: None,
            });
        }
        for name in governance.keys() {
            if !tools.iter().any(|tool| &tool.name == name) {
                return Err(OpenAiManifestError::UnknownGovernance(name.clone()));
            }
        }
        let server_id = server_id.into();
        let manifest = Self {
            schema: TOOL_MANIFEST_SCHEMA.to_owned(),
            name: server_id.to_string(),
            server_id,
            description: None,
            version: version.into(),
            tools,
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: public_key.into(),
        };
        validate_manifest(&manifest)?;
        Ok(manifest)
    }
}
