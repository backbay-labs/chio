#![allow(clippy::result_large_err)]

pub use chio_control_plane::{CliError, JwtProviderProfile};

#[path = "remote_mcp/admin.rs"]
mod remote_mcp_admin;

include!("remote_mcp/session_core.rs");
include!("remote_mcp/http_service.rs");
include!("remote_mcp/oauth.rs");
include!("remote_mcp/tests.rs");
