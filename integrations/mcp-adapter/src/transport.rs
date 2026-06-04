use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chio_mcp_edge::{
    AdapterError, McpServerCapabilities, McpToolInfo, McpToolResult, McpTransport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const REDACTED_AUTHORIZATION_HEADER: &str = "Bearer <redacted>";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamableHttpExchange {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: serde_json::Value,
}

#[derive(Clone)]
pub struct StreamableHttpTransport {
    endpoint_path: String,
    bearer_token: String,
    tools: Arc<BTreeMap<String, McpToolInfo>>,
    results: Arc<BTreeMap<String, McpToolResult>>,
    exchanges: Arc<Mutex<Vec<StreamableHttpExchange>>>,
}

#[derive(Default)]
pub struct StreamableHttpTransportBuilder {
    endpoint_path: Option<String>,
    bearer_token: Option<String>,
    tools: BTreeMap<String, McpToolInfo>,
    results: BTreeMap<String, McpToolResult>,
}

impl StreamableHttpTransportBuilder {
    pub fn endpoint_path(mut self, endpoint_path: impl Into<String>) -> Self {
        self.endpoint_path = Some(endpoint_path.into());
        self
    }

    pub fn bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.bearer_token = Some(bearer_token.into());
        self
    }

    pub fn tool(mut self, tool: McpToolInfo, result: McpToolResult) -> Self {
        self.results.insert(tool.name.clone(), result);
        self.tools.insert(tool.name.clone(), tool);
        self
    }

    pub fn build(self) -> Result<StreamableHttpTransport, AdapterError> {
        let endpoint_path = self.endpoint_path.unwrap_or_else(|| "/mcp".to_string());
        if !endpoint_path.starts_with('/') {
            return Err(AdapterError::ConnectionFailed(
                "streamable HTTP endpoint path must be absolute".to_string(),
            ));
        }
        let bearer_token = self.bearer_token.ok_or_else(|| {
            AdapterError::ConnectionFailed("OAuth bearer token is required".to_string())
        })?;
        if bearer_token.trim().is_empty()
            || bearer_token.trim() != bearer_token
            || bearer_token
                .chars()
                .any(|character| character.is_ascii_control() || character.is_ascii_whitespace())
        {
            return Err(AdapterError::ConnectionFailed(
                "OAuth bearer token must be non-empty and must not contain whitespace or control characters"
                    .to_string(),
            ));
        }
        Ok(StreamableHttpTransport {
            endpoint_path,
            bearer_token,
            tools: Arc::new(self.tools),
            results: Arc::new(self.results),
            exchanges: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

impl StreamableHttpTransport {
    pub fn builder() -> StreamableHttpTransportBuilder {
        StreamableHttpTransportBuilder::default()
    }

    pub fn exchange_log(&self) -> Result<Vec<StreamableHttpExchange>, AdapterError> {
        let exchanges = self.exchanges.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "streamable HTTP exchange log lock poisoned: {error}"
            ))
        })?;
        Ok(exchanges.clone())
    }

    fn wire_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert("accept".to_string(), "application/json".to_string());
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", self.bearer_token),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert(
            "mcp-protocol-version".to_string(),
            MCP_PROTOCOL_VERSION.to_string(),
        );
        headers
    }

    fn redacted_exchange_headers(&self) -> BTreeMap<String, String> {
        let mut headers = self.wire_headers();
        headers.insert(
            "authorization".to_string(),
            REDACTED_AUTHORIZATION_HEADER.to_string(),
        );
        headers
    }

    fn push_exchange(&self, body: serde_json::Value) -> Result<(), AdapterError> {
        let exchange = StreamableHttpExchange {
            method: "POST".to_string(),
            path: self.endpoint_path.clone(),
            headers: self.redacted_exchange_headers(),
            body,
        };
        let mut exchanges = self.exchanges.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "streamable HTTP exchange log lock poisoned: {error}"
            ))
        })?;
        exchanges.push(exchange);
        Ok(())
    }
}

impl McpTransport for StreamableHttpTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        McpServerCapabilities {
            tools_list_changed: false,
            resources_supported: false,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_supported: false,
            prompts_list_changed: false,
            completions_supported: false,
            logging_supported: true,
        }
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        self.push_exchange(json!({
            "jsonrpc": "2.0",
            "id": "tools-list",
            "method": "tools/list"
        }))?;
        Ok(self.tools.values().cloned().collect())
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.push_exchange(json!({
            "jsonrpc": "2.0",
            "id": format!("tools-call-{tool_name}"),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }))?;
        self.results
            .get(tool_name)
            .cloned()
            .ok_or_else(|| AdapterError::ToolNotFound(tool_name.to_string()))
    }
}
