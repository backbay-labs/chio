use super::*;

pub(crate) fn handle_agent_message(
    kernel: &mut ChioKernel,
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
    stats: &mut SessionStats,
) -> Vec<KernelMessage> {
    let is_tool_call = matches!(msg, AgentMessage::ToolCallRequest { .. });
    if is_tool_call {
        stats.requests += 1;
    }

    let (context, operation) = normalize_agent_message(msg, session_id, session_agent_id);
    if let Some(conflict) = msg.authorization_conflict() {
        return reject_conflicting_authorization(
            kernel,
            &context,
            operation,
            session_agent_id,
            conflict,
            stats,
        );
    }
    match kernel.evaluate_session_operation(&context, &operation) {
        Ok(SessionOperationResponse::ToolCall(response)) => {
            match response.verdict {
                chio_kernel::Verdict::Allow => stats.allowed += 1,
                chio_kernel::Verdict::Deny => stats.denied += 1,
                // Pending approval is a non-terminal
                // outcome; from the CLI's accounting perspective we
                // fold it into denied until the human responds.
                chio_kernel::Verdict::PendingApproval => stats.denied += 1,
            }

            tool_response_messages(context.request_id.to_string(), response)
        }
        Ok(SessionOperationResponse::CapabilityList { capabilities }) => {
            vec![KernelMessage::CapabilityList { capabilities }]
        }
        Ok(
            SessionOperationResponse::RootList { .. }
            | SessionOperationResponse::ResourceList { .. }
            | SessionOperationResponse::ResourceRead { .. }
            | SessionOperationResponse::ResourceReadDenied { .. }
            | SessionOperationResponse::ResourceTemplateList { .. }
            | SessionOperationResponse::PromptList { .. }
            | SessionOperationResponse::PromptGet { .. }
            | SessionOperationResponse::Completion { .. },
        ) => {
            error!(
                request_id = %context.request_id,
                "unexpected non-tool session response on Chio stdio transport"
            );
            vec![KernelMessage::Heartbeat]
        }
        Ok(SessionOperationResponse::Heartbeat) => vec![KernelMessage::Heartbeat],
        Err(e) => match operation {
            SessionOperation::ToolCall(tool_call) => {
                stats.denied += 1;
                error!(
                    request_id = %context.request_id,
                    error = %e,
                    "kernel session evaluation error"
                );

                let request = KernelToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability,
                    tool_name: tool_call.tool_name,
                    server_id: tool_call.server_id,
                    agent_id: session_agent_id.to_string(),
                    arguments: tool_call.arguments,
                    dpop_proof: None,
                    execution_nonce: None,
                    governed_intent: tool_call.governed_intent,
                    approval_token: tool_call.approval_token,
                    approval_tokens: tool_call.approval_tokens,
                    threshold_approval_proposal: tool_call.threshold_approval_proposal,
                    supplemental_authorization: tool_call.supplemental_authorization,
                    model_metadata: None,
                    federated_origin_kernel_id: None,
                };

                match make_error_receipt(kernel, &request) {
                    Ok(receipt) => vec![KernelMessage::ToolCallResponse {
                        id: context.request_id.to_string(),
                        result: ToolCallResult::Err {
                            error: ToolCallError::InternalError(e.to_string()),
                        },
                        receipt: Box::new(receipt),
                        execution_nonce: None,
                    }],
                    Err(sign_err) => {
                        error!(
                            error = %sign_err,
                            request_id = %context.request_id,
                            "failed to sign error receipt; dropping tool call response"
                        );
                        vec![]
                    }
                }
            }
            SessionOperation::ListCapabilities => {
                error!(error = %e, session_id = %session_id, "failed to list capabilities");
                vec![KernelMessage::CapabilityList {
                    capabilities: vec![],
                }]
            }
            SessionOperation::CreateMessage(_)
            | SessionOperation::CreateElicitation(_)
            | SessionOperation::ListRoots
            | SessionOperation::ListResources
            | SessionOperation::ReadResource(_)
            | SessionOperation::ListResourceTemplates
            | SessionOperation::ListPrompts
            | SessionOperation::GetPrompt(_)
            | SessionOperation::Complete(_) => {
                error!(
                    error = %e,
                    request_id = %context.request_id,
                    "unexpected resource/prompt session failure on Chio stdio transport"
                );
                vec![KernelMessage::Heartbeat]
            }
            SessionOperation::Heartbeat => {
                error!(error = %e, session_id = %session_id, "failed to handle heartbeat");
                vec![KernelMessage::Heartbeat]
            }
        },
    }
}

fn reject_conflicting_authorization(
    kernel: &mut ChioKernel,
    context: &OperationContext,
    operation: SessionOperation,
    session_agent_id: &str,
    conflict: &'static str,
    stats: &mut SessionStats,
) -> Vec<KernelMessage> {
    let SessionOperation::ToolCall(tool_call) = operation else {
        return vec![KernelMessage::Heartbeat];
    };
    stats.denied += 1;
    error!(
        request_id = %context.request_id,
        conflict = conflict,
        "denied tool call presenting conflicting authorization artifacts"
    );
    let request = KernelToolCallRequest {
        request_id: context.request_id.to_string(),
        capability: tool_call.capability,
        tool_name: tool_call.tool_name,
        server_id: tool_call.server_id,
        agent_id: session_agent_id.to_string(),
        arguments: tool_call.arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: tool_call.governed_intent,
        approval_token: tool_call.approval_token,
        approval_tokens: tool_call.approval_tokens,
        threshold_approval_proposal: tool_call.threshold_approval_proposal,
        supplemental_authorization: tool_call.supplemental_authorization,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    match make_error_receipt(kernel, &request) {
        Ok(receipt) => vec![KernelMessage::ToolCallResponse {
            id: context.request_id.to_string(),
            result: ToolCallResult::Err {
                error: ToolCallError::PolicyDenied {
                    guard: "session_authorization".to_string(),
                    reason: conflict.to_string(),
                },
            },
            receipt: Box::new(receipt),
            execution_nonce: None,
        }],
        Err(sign_err) => {
            error!(
                error = %sign_err,
                request_id = %context.request_id,
                "failed to sign denial receipt; dropping tool call response"
            );
            vec![]
        }
    }
}

pub(crate) fn normalize_agent_message(
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
) -> (OperationContext, SessionOperation) {
    match msg {
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            server_id,
            tool,
            params,
            governed_intent,
            approval_token,
            approval_tokens,
            threshold_approval_proposal,
            supplemental_authorization,
            execution_nonce,
        } => (
            OperationContext::new(
                session_id.clone(),
                RequestId::new(id.clone()),
                session_agent_id.to_string(),
            ),
            SessionOperation::ToolCall(Box::new(ToolCallOperation {
                capability: *capability_token.clone(),
                server_id: server_id.clone(),
                tool_name: tool.clone(),
                arguments: params.as_ref().clone(),
                governed_intent: governed_intent.as_deref().cloned(),
                approval_token: approval_token.as_deref().cloned(),
                approval_tokens: approval_tokens.clone(),
                threshold_approval_proposal: threshold_approval_proposal.as_deref().cloned(),
                supplemental_authorization: supplemental_authorization.as_deref().cloned(),
                execution_nonce: execution_nonce
                    .as_deref()
                    .and_then(|nonce| serde_json::to_value(nonce).ok()),
                model_metadata: None,
                extra_metadata: None,
            })),
        ),
        AgentMessage::ListCapabilities => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "list_capabilities"),
                session_agent_id.to_string(),
            ),
            SessionOperation::ListCapabilities,
        ),
        AgentMessage::Heartbeat => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "heartbeat"),
                session_agent_id.to_string(),
            ),
            SessionOperation::Heartbeat,
        ),
    }
}
