use std::sync::Arc;

use chio_anthropic_tools_adapter::{
    transport::MockTransport, AnthropicAdapter, AnthropicAdapterConfig,
};
use chio_manifest::{LatencyHint, ServerTool, ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA};
use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::json;

fn config() -> AnthropicAdapterConfig {
    AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        "deadbeef",
        "wks_test",
    )
}

fn manifest(server_tools: Vec<ServerTool>) -> ToolManifest {
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "anthropic-1".into(),
        name: "Anthropic Messages".to_string(),
        description: Some("Anthropic tool manifest".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: "regular_tool".to_string(),
            description: "Regular client-hosted tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: Some(json!({"type": "object"})),
            pricing: None,
            has_side_effects: false,
            latency_hint: Some(LatencyHint::Fast),
        }],
        server_tools,
        required_permissions: None,
        public_key: "deadbeef".to_string(),
    }
}

fn tool_use_payload(name: &str) -> Result<ProviderRequest, serde_json::Error> {
    let payload = json!({
        "type": "message",
        "id": "msg_01",
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": "toolu_01",
            "name": name,
            "input": {"command": "pwd"}
        }]
    });
    serde_json::to_vec(&payload).map(ProviderRequest)
}

#[test]
#[cfg(not(feature = "computer-use"))]
fn server_tools_fail_closed_without_computer_use_feature() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AnthropicAdapter::new_with_manifest(
        config(),
        Arc::new(MockTransport::new()),
        &manifest(vec![ServerTool::Bash]),
    )?;
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("requires the `computer-use` cargo feature")
    ));
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_fail_closed_without_manifest_allowlist() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AnthropicAdapter::new(config(), Arc::new(MockTransport::new()));
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("manifest server_tools does not allow")
    ));
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_manifest_allowlist_allows_matching_tool() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AnthropicAdapter::new_with_manifest(
        config(),
        Arc::new(MockTransport::new()),
        &manifest(vec![ServerTool::Bash]),
    )?;
    let invocations = adapter.lift_batch(tool_use_payload("bash_20241022")?)?;

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "bash_20241022");
    Ok(())
}

#[test]
#[cfg(feature = "computer-use")]
fn server_tools_manifest_allowlist_denies_unlisted_peer() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AnthropicAdapter::new_with_manifest(
        config(),
        Arc::new(MockTransport::new()),
        &manifest(vec![ServerTool::TextEditor]),
    )?;
    let result = adapter.lift_batch(tool_use_payload("bash_20241022")?);

    assert!(matches!(
        result,
        Err(ProviderError::Malformed(message))
            if message.contains("`bash_20241022`") && message.contains("`bash`")
    ));
    Ok(())
}

#[test]
fn server_tools_gate_ignores_regular_custom_tools() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AnthropicAdapter::new(config(), Arc::new(MockTransport::new()));
    let invocations = adapter.lift_batch(tool_use_payload("regular_tool")?)?;

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "regular_tool");
    Ok(())
}
