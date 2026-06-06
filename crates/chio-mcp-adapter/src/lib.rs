//! # chio-mcp-adapter
//!
//! Compatibility adapter that wraps an existing MCP (Model Context Protocol)
//! server and exposes it as a Chio tool server. Existing MCP tools continue to
//! work while gaining Chio capability tokens, guard evaluation, and signed
//! receipts.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod edge {
    pub use chio_mcp_edge::{
        AdapterError, ChioMcpEdge, McpEdgeConfig, McpExposedTool, McpServerCapabilities,
        McpToolInfo, McpToolResult, McpTransport,
    };
}
mod errors;
mod framing;
#[cfg(feature = "fuzz")]
pub mod fuzz;
pub mod loaded_weights;
mod manifest;
pub mod native;
pub mod prompts;
pub mod resources;
mod result_mapping;
pub mod server;
pub mod transport;
mod url_elicitation;

#[cfg(test)]
mod tests;
