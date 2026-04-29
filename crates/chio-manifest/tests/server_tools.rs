use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, validate_manifest, verify_manifest, LatencyHint, ManifestError, ServerTool,
    ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA,
};
use serde_json::json;

fn sample_manifest(server_tools: Vec<ServerTool>) -> ToolManifest {
    let keypair = Keypair::from_seed(&[9u8; 32]);
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-anthropic".into(),
        name: "Anthropic tools".to_string(),
        description: Some("server tool gate".to_string()),
        version: "1.0.0".to_string(),
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
        public_key: keypair.public_key().to_hex(),
    }
}

#[test]
fn server_tools_default_to_empty_allowlist() -> Result<(), Box<dyn std::error::Error>> {
    let json = json!({
        "schema": TOOL_MANIFEST_SCHEMA,
        "server_id": "srv-anthropic",
        "name": "Anthropic tools",
        "description": "server tool gate",
        "version": "1.0.0",
        "tools": [{
            "name": "regular_tool",
            "description": "Regular client-hosted tool",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "pricing": null,
            "has_side_effects": false,
            "latency_hint": "fast"
        }],
        "required_permissions": null,
        "public_key": "deadbeef"
    });
    let manifest: ToolManifest = serde_json::from_value(json)?;

    assert!(manifest.server_tools.is_empty());
    assert!(!manifest.allows_server_tool(ServerTool::ComputerUse));
    assert!(!manifest.allows_server_tool(ServerTool::Bash));
    assert!(!manifest.allows_server_tool(ServerTool::TextEditor));
    Ok(())
}

#[test]
fn server_tools_allowlist_round_trips_and_signs() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[11u8; 32]);
    let mut manifest = sample_manifest(vec![ServerTool::ComputerUse, ServerTool::TextEditor]);
    manifest.public_key = keypair.public_key().to_hex();

    validate_manifest(&manifest)?;
    assert!(manifest.allows_server_tool(ServerTool::ComputerUse));
    assert!(!manifest.allows_server_tool(ServerTool::Bash));
    assert!(manifest.allows_server_tool(ServerTool::TextEditor));

    let encoded = serde_json::to_value(&manifest)?;
    assert_eq!(
        encoded.get("server_tools"),
        Some(&json!(["computer_use", "text_editor"]))
    );

    let signed = sign_manifest(&manifest, &keypair)?;
    verify_manifest(&signed, &keypair.public_key())?;
    Ok(())
}

#[test]
fn duplicate_server_tools_reject_at_validation() {
    let manifest = sample_manifest(vec![ServerTool::Bash, ServerTool::Bash]);

    assert!(matches!(
        validate_manifest(&manifest),
        Err(ManifestError::DuplicateServerTool(tool)) if tool == "bash"
    ));
}

#[test]
fn anthropic_wire_names_map_to_stable_allowlist_entries() {
    assert_eq!(
        ServerTool::from_anthropic_wire_name("computer_use_20241022"),
        Some(ServerTool::ComputerUse)
    );
    assert_eq!(
        ServerTool::from_anthropic_wire_name("bash_20241022"),
        Some(ServerTool::Bash)
    );
    assert_eq!(
        ServerTool::from_anthropic_wire_name("text_editor_20241022"),
        Some(ServerTool::TextEditor)
    );
    assert_eq!(ServerTool::from_anthropic_wire_name("custom_bash"), None);
}
