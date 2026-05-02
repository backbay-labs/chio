use chio_mcp_adapter_integration::{
    emit_tool_call_receipt, verify_tool_call_receipt, ProtectedResourceMetadata,
    StreamableHttpTransport,
};
use chio_mcp_edge::{McpToolInfo, McpToolResult, McpTransport};
use serde_json::json;

#[test]
fn agentcore_gateway_consumer_receives_chio_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let scenario: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/agentcore_gateway/scenario.json"))?;
    assert_eq!(scenario["consumer"], "aws-bedrock-agentcore-gateway");
    assert_eq!(scenario["oauth"]["grant_type"], "authorization_code_pkce");

    let metadata = ProtectedResourceMetadata::new(
        scenario["resource"].as_str().unwrap_or_default(),
        scenario["authorization_server"]
            .as_str()
            .unwrap_or_default(),
        vec!["tools.call".to_string(), "receipts.read".to_string()],
    )?;
    assert_eq!(metadata.bearer_methods_supported[0], "header");

    let transport = StreamableHttpTransport::builder()
        .bearer_token("agentcore-token")
        .tool(
            McpToolInfo {
                name: "chio.bedrock.invoke".to_string(),
                title: Some("Invoke governed Bedrock".to_string()),
                description: Some("AgentCore Gateway consumer test tool".to_string()),
                input_schema: json!({ "type": "object" }),
                output_schema: None,
                annotations: None,
                execution: Some(json!({ "consumer": "agentcore-gateway" })),
            },
            McpToolResult {
                content: vec![json!({ "type": "text", "text": "bedrock ok" })],
                structured_content: Some(json!({ "receipt_required": true })),
                is_error: Some(false),
            },
        )
        .build()?;

    let result = transport.call_tool("chio.bedrock.invoke", json!({ "model": "bedrock" }))?;
    let receipt = emit_tool_call_receipt(
        "cap-agentcore",
        "tenant-agentcore",
        "chio.bedrock.invoke",
        json!({ "model": "bedrock" }),
        serde_json::to_value(&result)?,
    )?;
    assert!(verify_tool_call_receipt(&receipt));
    assert_eq!(receipt["metadata"]["transport"], "streamable-http");
    Ok(())
}
