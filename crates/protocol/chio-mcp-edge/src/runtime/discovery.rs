use std::collections::BTreeMap;

use chio_manifest::{LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpExposedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outputSchema"
    )]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
}

#[derive(Debug, Clone)]
pub(super) struct ExposedToolBinding {
    pub(super) tool: McpExposedTool,
    pub(super) server_id: String,
    pub(super) tool_name: String,
}

pub(super) fn build_exposed_tool_bindings(
    manifests: Vec<ToolManifest>,
) -> Result<(Vec<ExposedToolBinding>, BTreeMap<String, usize>), AdapterError> {
    let mut tool_index = BTreeMap::new();
    let mut tools = Vec::new();

    for manifest in manifests {
        chio_manifest::validate_manifest(&manifest)?;

        for tool in manifest.tools {
            if tool_index.contains_key(&tool.name) {
                return Err(AdapterError::ManifestError(
                    chio_manifest::ManifestError::DuplicateToolName(tool.name),
                ));
            }

            let exposed_name = tool.name.clone();
            let binding = ExposedToolBinding {
                tool: manifest_tool_to_mcp_tool(tool)?,
                server_id: manifest.server_id.clone(),
                tool_name: exposed_name.clone(),
            };
            tool_index.insert(exposed_name, tools.len());
            tools.push(binding);
        }
    }

    Ok((tools, tool_index))
}

fn manifest_tool_to_mcp_tool(tool: ToolDefinition) -> Result<McpExposedTool, AdapterError> {
    validate_schema_object(&tool.name, "inputSchema", &tool.input_schema)?;
    if let Some(output_schema) = tool.output_schema.as_ref() {
        validate_schema_object(&tool.name, "outputSchema", output_schema)?;
    }

    let annotations = Some(json!({
        "readOnlyHint": !tool.has_side_effects,
        "destructiveHint": tool.has_side_effects,
    }));

    let mut execution = serde_json::Map::new();
    execution.insert("taskSupport".to_string(), json!("optional"));
    if let Some(latency_hint) = tool.latency_hint {
        execution.insert(
            "suggestedLatency".to_string(),
            json!(latency_hint_to_label(latency_hint)),
        );
    }

    Ok(McpExposedTool {
        name: tool.name,
        title: None,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        annotations,
        execution: Some(Value::Object(execution)),
    })
}

fn validate_schema_object(
    tool_name: &str,
    field_name: &str,
    schema: &Value,
) -> Result<(), AdapterError> {
    if schema.is_object() {
        return Ok(());
    }

    Err(AdapterError::ParseError(format!(
        "MCP exposed tool `{tool_name}` {field_name} must be a JSON object"
    )))
}

fn latency_hint_to_label(latency_hint: LatencyHint) -> &'static str {
    match latency_hint {
        LatencyHint::Instant => "instant",
        LatencyHint::Fast => "fast",
        LatencyHint::Moderate => "moderate",
        LatencyHint::Slow => "slow",
    }
}
