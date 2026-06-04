use chio_mcp_adapter_integration::{
    emit_tool_call_receipt, verify_tool_call_receipt, McpReceiptError, StreamableHttpTransport,
};
use chio_mcp_edge::{McpToolInfo, McpToolResult, McpTransport};
use serde_json::json;

fn tool_info() -> McpToolInfo {
    McpToolInfo {
        name: "chio.receipt.issue".to_string(),
        title: Some("Issue Chio receipt".to_string()),
        description: Some("Emit a Chio-format receipt for a governed tool call".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "tenant_id": { "type": "string" }
            },
            "required": ["tenant_id"]
        }),
        output_schema: None,
        annotations: None,
        execution: Some(json!({ "transport": "streamable-http" })),
    }
}

fn tool_result() -> McpToolResult {
    McpToolResult {
        content: vec![json!({ "type": "text", "text": "receipt issued" })],
        structured_content: Some(json!({ "ok": true })),
        is_error: Some(false),
    }
}

#[test]
fn streamable_http_transport_round_trip_emits_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let transport = StreamableHttpTransport::builder()
        .endpoint_path("/mcp")
        .bearer_token("test-token")
        .tool(tool_info(), tool_result())
        .build()?;

    let tools = transport.list_tools()?;
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "chio.receipt.issue");

    let result = transport.call_tool("chio.receipt.issue", json!({ "tenant_id": "tenant-a" }))?;
    assert_eq!(result.is_error, Some(false));

    let receipt = emit_tool_call_receipt(
        "cap-mcp-a",
        "tenant-a",
        "chio.receipt.issue",
        json!({ "tenant_id": "tenant-a" }),
        serde_json::to_value(&result)?,
    )?;
    assert!(verify_tool_call_receipt(&receipt));
    assert_eq!(receipt["tool_server"], "chio-mcp");

    let exchanges = transport.exchange_log()?;
    assert_eq!(exchanges.len(), 2);
    assert_eq!(exchanges[0].headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(exchanges[1].body["method"], "tools/call");
    Ok(())
}

#[test]
fn streamable_http_exchange_log_redacts_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let transport = StreamableHttpTransport::builder()
        .endpoint_path("/mcp")
        .bearer_token("sensitive-token")
        .tool(tool_info(), tool_result())
        .build()?;

    transport.list_tools()?;

    let exchanges = transport.exchange_log()?;
    assert_eq!(exchanges[0].headers["authorization"], "Bearer <redacted>");
    assert!(!format!("{:?}", exchanges).contains("sensitive-token"));
    Ok(())
}

#[test]
fn streamable_http_transport_rejects_padded_bearer_token() {
    let result = StreamableHttpTransport::builder()
        .endpoint_path("/mcp")
        .bearer_token(" sensitive-token")
        .build();

    let Err(error) = result else {
        panic!("padded bearer token should fail closed");
    };
    assert!(error.to_string().contains("bearer token"));
}

#[test]
fn receipt_emission_rejects_padded_capability_id() {
    let error = emit_tool_call_receipt(
        " cap-mcp-a",
        "tenant-a",
        "chio.receipt.issue",
        json!({}),
        json!({}),
    )
    .err();

    assert_eq!(error, Some(McpReceiptError::MissingCapabilityId));
}
