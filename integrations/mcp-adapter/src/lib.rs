//! Distribution integration for Chio's registry-listed MCP server.
//!
//! This crate extends the existing `chio-mcp-edge` transport contract with
//! the Streamable HTTP, OAuth 2.1 + PKCE, RFC9728 Protected
//! Resource Metadata, and receipt-emission surfaces used by the AWS Bedrock
//! and MCP listing lane.

#![forbid(unsafe_code)]

pub mod oauth;
pub mod prm;
pub mod receipt_emit;
pub mod transport;

pub use oauth::{
    authorization_url, pkce_challenge, AuthorizationRequest, OAuthError, PkceChallenge,
};
pub use prm::{PrmError, ProtectedResourceMetadata};
pub use receipt_emit::{emit_tool_call_receipt, verify_tool_call_receipt, McpReceiptError};
pub use transport::{
    StreamableHttpExchange, StreamableHttpTransport, StreamableHttpTransportBuilder,
};
