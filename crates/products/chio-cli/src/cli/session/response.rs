use super::*;

pub(crate) fn tool_response_messages(
    request_id: String,
    response: chio_kernel::ToolCallResponse,
) -> Vec<KernelMessage> {
    let execution_nonce = response.execution_nonce.clone();
    let mut messages = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(ToolCallStream { chunks })) => chunks
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk)| KernelMessage::ToolCallChunk {
                id: request_id.clone(),
                chunk_index: chunk_index as u64,
                data: chunk.data.clone(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let chunks_received = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(stream)) => stream.chunk_count(),
        _ => 0,
    };

    let result = match (
        response.verdict,
        response.terminal_state.clone(),
        response.output,
    ) {
        (chio_kernel::Verdict::Allow, _, Some(ToolCallOutput::Value(value))) => {
            ToolCallResult::Ok { value }
        }
        (chio_kernel::Verdict::Allow, _, Some(ToolCallOutput::Stream(_))) => {
            ToolCallResult::StreamComplete {
                total_chunks: chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Cancelled { reason }, _) => {
            ToolCallResult::Cancelled {
                reason,
                chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Incomplete { reason }, _) => {
            ToolCallResult::Incomplete {
                reason,
                chunks_received,
            }
        }
        (chio_kernel::Verdict::Deny, OperationTerminalState::Completed, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: "kernel".to_string(),
                reason: response
                    .reason
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        },
        (chio_kernel::Verdict::Allow, _, None) => ToolCallResult::Ok {
            value: serde_json::Value::Null,
        },
        // Map PendingApproval to a policy-denied result so
        // the existing session driver surfaces it to the caller; the
        // HTTP `/approvals` surface is the mechanism for resume.
        (chio_kernel::Verdict::PendingApproval, _, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: "approval".to_string(),
                reason: response
                    .reason
                    .unwrap_or_else(|| "tool call requires approval".to_string()),
            },
        },
    };

    messages.push(KernelMessage::ToolCallResponse {
        id: request_id,
        result,
        receipt: Box::new(response.receipt),
        execution_nonce,
    });
    messages
}
