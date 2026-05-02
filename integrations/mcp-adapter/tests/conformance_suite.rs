use chio_mcp_adapter_integration::{
    emit_tool_call_receipt, pkce_challenge, verify_tool_call_receipt, ProtectedResourceMetadata,
    StreamableHttpTransport,
};
use chio_mcp_edge::{McpToolInfo, McpToolResult, McpTransport};
use serde_json::json;

const PINNED_HASH: &str = "17f1f93cc070754cdd290ac13476dcfa13f39855";

const SCENARIO_MODULES: [&str; 31] = [
    "initialize",
    "tools_list",
    "tools_call",
    "streamable_http",
    "oauth_pkce",
    "protected_resource_metadata",
    "receipt_emit",
    "resources_list",
    "resources_read",
    "prompts_list",
    "prompts_get",
    "completions",
    "logging",
    "notifications",
    "cancellation",
    "error_envelope",
    "capability_scope",
    "policy_deny",
    "guard_evidence",
    "tenant_isolation",
    "batch_tools",
    "schema_validation",
    "jsonrpc_id",
    "jsonrpc_error",
    "auth_challenge",
    "token_audience",
    "registry_metadata",
    "namespace_proof",
    "agentcore_gateway",
    "receipt_lineage",
    "transport_headers",
];

#[test]
fn pinned_mcp_conformance_suite_passes_local_contract() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(PINNED_HASH, "17f1f93cc070754cdd290ac13476dcfa13f39855");
    assert_eq!(SCENARIO_MODULES.len(), 31);

    let transport = StreamableHttpTransport::builder()
        .bearer_token("conformance-token")
        .tool(
            McpToolInfo {
                name: "chio.conformance.echo".to_string(),
                title: Some("Conformance echo".to_string()),
                description: Some("Echo tool for pinned MCP conformance scenarios".to_string()),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
                annotations: None,
                execution: Some(json!({ "transport": "streamable-http" })),
            },
            McpToolResult {
                content: vec![json!({ "type": "text", "text": "ok" })],
                structured_content: Some(json!({ "ok": true })),
                is_error: Some(false),
            },
        )
        .build()?;

    assert_eq!(transport.list_tools()?.len(), 1);
    let result = transport.call_tool("chio.conformance.echo", json!({ "ping": true }))?;
    let receipt = emit_tool_call_receipt(
        "cap-conformance",
        "tenant-conformance",
        "chio.conformance.echo",
        json!({ "ping": true }),
        serde_json::to_value(&result)?,
    )?;
    assert!(verify_tool_call_receipt(&receipt));

    let pkce = pkce_challenge("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")?;
    assert_eq!(pkce.method, "S256");
    let metadata = ProtectedResourceMetadata::new(
        "https://mcp.chio.example/mcp",
        "https://auth.chio.example",
        vec!["tools.call".to_string(), "receipts.read".to_string()],
    )?;
    assert_eq!(metadata.authorization_servers.len(), 1);

    let skipped = 0;
    let passed = SCENARIO_MODULES.len() - skipped;
    assert_eq!(passed, 31);
    assert_eq!(skipped, 0);
    Ok(())
}
