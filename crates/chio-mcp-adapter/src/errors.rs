use chio_kernel::KernelError;

use crate::edge::AdapterError;
use crate::url_elicitation::parse_url_elicitation_required_error;

pub(crate) fn map_tool_invocation_error(error: AdapterError) -> KernelError {
    match error {
        AdapterError::RequestCancelled { request_id, reason } => {
            KernelError::RequestCancelled { request_id, reason }
        }
        AdapterError::McpError {
            code: -32042,
            message,
            data,
        } => match parse_url_elicitation_required_error(message, data) {
            Ok(error) => error,
            Err(message) => KernelError::ToolServerError(message),
        },
        AdapterError::ConnectionFailed(message) | AdapterError::ParseError(message) => {
            KernelError::RequestIncomplete(message)
        }
        other => KernelError::ToolServerError(other.to_string()),
    }
}
