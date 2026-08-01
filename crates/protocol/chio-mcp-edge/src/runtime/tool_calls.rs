use super::receipts::{record_receipt_write_error, record_receipt_write_kernel_error};
use super::*;

/// Bridge-only request for projecting a Chio tool invocation through MCP session semantics.
#[derive(Debug, Clone)]
pub struct BridgeMcpToolCallRequest {
    pub request_id: String,
    pub capability: CapabilityToken,
    pub server_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub agent_id: String,
    pub execution_nonce: Option<SignedExecutionNonce>,
    pub governed_intent: Option<GovernedTransactionIntent>,
    pub approval_token: Option<GovernedApprovalToken>,
    pub approval_tokens: Vec<GovernedApprovalToken>,
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    pub supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    pub model_metadata: Option<ModelMetadata>,
    pub route_selection_metadata: Option<Value>,
    pub peer_supports_chio_tool_streaming: bool,
}

/// Bridge-only MCP tool-call execution result.
#[derive(Debug)]
pub struct BridgeMcpToolCall {
    pub response: ToolCallResponse,
    pub mcp_result: Value,
    pub notifications: Vec<Value>,
}

impl BridgeMcpToolCall {
    /// Project a kernel tool-call response through the MCP bridge result surface.
    ///
    /// This is the production projection used by bridge execution and by
    /// hosts that already hold a kernel response, including PendingApproval.
    pub fn from_kernel_response(
        response: ToolCallResponse,
        request_id: &str,
        peer_supports_chio_tool_streaming: bool,
    ) -> Result<Self, AdapterError> {
        bridge_mcp_tool_call_from_response(
            response,
            request_id,
            peer_supports_chio_tool_streaming,
            true,
        )
    }
}

/// Default non-native protocol executor for MCP target projections.
#[derive(Debug, Default, Clone, Copy)]
pub struct McpTargetExecutor {
    pub peer_supports_chio_tool_streaming: bool,
}

impl TargetProtocolExecutor for McpTargetExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let route_metadata = metadata_with_source_receipt_context(
            route_selection_metadata(request.route_selection)?,
            &request.execution.source_envelope,
        )?;
        let response = request
            .kernel
            .evaluate_tool_call_blocking_with_metadata(
                &kernel_tool_call_request(request.execution),
                Some(route_metadata),
            )
            .map_err(BridgeError::Kernel)?;
        let bridge = bridge_mcp_tool_call_from_response(
            response,
            &request.execution.kernel_request_id,
            self.peer_supports_chio_tool_streaming,
            false,
        )
        .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?;
        let receipt_id = bridge.response.receipt.id.clone();

        Ok(CrossProtocolTargetExecution {
            response: bridge.response,
            protocol_result: Some(bridge.mcp_result),
            protocol_notifications: bridge.notifications,
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Mcp,
                    request_id: format!("{}:mcp", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                },
            ],
        })
    }
}

pub async fn execute_bridge_mcp_tool_call_async(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let BridgeMcpToolCallRequest {
        request_id,
        capability,
        server_id,
        tool_name,
        arguments,
        agent_id,
        execution_nonce,
        governed_intent,
        approval_token,
        approval_tokens,
        threshold_approval_proposal,
        supplemental_authorization,
        model_metadata,
        route_selection_metadata,
        peer_supports_chio_tool_streaming,
    } = request;
    let kernel_request = ToolCallRequest {
        request_id: request_id.clone(),
        capability,
        tool_name,
        server_id,
        agent_id,
        arguments,
        dpop_proof: None,
        execution_nonce,
        governed_intent,
        approval_token,
        approval_tokens,
        threshold_approval_proposal,
        supplemental_authorization,
        model_metadata,
        federated_origin_kernel_id: None,
    };
    let response = match kernel
        .evaluate_tool_call_with_metadata(&kernel_request, route_selection_metadata)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            record_receipt_write_kernel_error(&error);
            return Err(AdapterError::KernelRuntime(error.to_string()));
        }
    };

    BridgeMcpToolCall::from_kernel_response(
        response,
        &request_id,
        peer_supports_chio_tool_streaming,
    )
}

pub fn execute_bridge_mcp_tool_call(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| {
                handle.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
            })
        }
        Ok(_) => {
            let kernel_request = ToolCallRequest {
                request_id: request.request_id.clone(),
                capability: request.capability.clone(),
                tool_name: request.tool_name.clone(),
                server_id: request.server_id.clone(),
                agent_id: request.agent_id.clone(),
                arguments: request.arguments.clone(),
                dpop_proof: None,
                execution_nonce: request.execution_nonce.clone(),
                governed_intent: request.governed_intent.clone(),
                approval_token: request.approval_token.clone(),
                approval_tokens: request.approval_tokens.clone(),
                threshold_approval_proposal: request.threshold_approval_proposal.clone(),
                supplemental_authorization: request.supplemental_authorization.clone(),
                model_metadata: request.model_metadata.clone(),
                federated_origin_kernel_id: None,
            };
            let response = match kernel.evaluate_tool_call_blocking_with_metadata(
                &kernel_request,
                request.route_selection_metadata.clone(),
            ) {
                Ok(response) => response,
                Err(error) => {
                    record_receipt_write_kernel_error(&error);
                    return Err(AdapterError::KernelRuntime(error.to_string()));
                }
            };
            BridgeMcpToolCall::from_kernel_response(
                response,
                &request.request_id,
                request.peer_supports_chio_tool_streaming,
            )
        }
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| AdapterError::KernelRuntime(error.to_string()))?;
            runtime.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
        }
    }
}

fn bridge_mcp_tool_call_from_response(
    response: ToolCallResponse,
    request_id: &str,
    peer_supports_chio_tool_streaming: bool,
    record_receipt_write: bool,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let mut notifications = Vec::new();
    let mcp_result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
        pending_notifications: &mut notifications,
        request_id: &json!(request_id),
        output: response.output.clone(),
        reason: response.reason.clone(),
        verdict: response.verdict,
        terminal_state: &response.terminal_state,
        execution_nonce: response.execution_nonce.as_deref(),
        peer_supports_chio_tool_streaming,
        related_task_id: None,
    });

    if record_receipt_write {
        // Emit `chio_receipt_write_total` at the MCP receipt-sink
        // boundary. PendingApproval is normal HITL flow, so it must not feed
        // infrastructure error burn-rate numerators.
        crate::metrics::record_receipt_write_verdict(response.verdict);
    }

    Ok(BridgeMcpToolCall {
        response,
        mcp_result,
        notifications,
    })
}

pub(super) struct ToolCallRequestContext<'a> {
    pub(super) id: &'a Value,
    pub(super) session_id: &'a SessionId,
    pub(super) context: &'a OperationContext,
    pub(super) operation: &'a ToolCallOperation,
    pub(super) related_task_id: Option<&'a str>,
}

pub(super) struct KernelToolResultArgs<'a> {
    pub(super) client_request_id: &'a Value,
    pub(super) session_id: &'a SessionId,
    pub(super) output: Option<ToolCallOutput>,
    pub(super) reason: Option<String>,
    pub(super) verdict: Verdict,
    pub(super) terminal_state: &'a OperationTerminalState,
    pub(super) execution_nonce: Option<Box<SignedExecutionNonce>>,
    pub(super) related_task_id: Option<&'a str>,
}

impl ChioMcpEdge {
    pub(super) fn prepare_tool_call_request(
        &mut self,
        id: &Value,
        params: &Value,
    ) -> Result<(SessionId, OperationContext, ToolCallOperation), Value> {
        let session_id = match &self.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_SERVER_NOT_INITIALIZED,
                    "tools/call requires initialize followed by notifications/initialized",
                ))
            }
        };

        let tool_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "tools/call requires a tool name",
                ))
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let stable_request_id = parse_request_stable_request_id(id, params)?;
        let model_metadata = parse_request_model_metadata(id, params)?;
        let execution_nonce = parse_request_execution_nonce(id, params)?;
        let governed_intent = parse_request_governed_intent(id, params)?;
        let (approval_token, approval_tokens, threshold_approval_proposal) =
            parse_request_approval_artifacts(id, params)?;
        let supplemental_authorization = parse_request_supplemental_authorization(id, params)?;
        if stable_request_id.is_none()
            && (approval_token.is_some()
                || !approval_tokens.is_empty()
                || threshold_approval_proposal.is_some()
                || supplemental_authorization.is_some())
        {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "MCP approval artifacts and supplemental authorization require \
                 _meta.chioRequestId",
            ));
        }
        let extra_metadata = parse_request_extra_metadata(id, params)?;

        let Some(&tool_index) = self.tool_index.get(tool_name) else {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "unknown tool",
            ));
        };
        let binding = self.tools[tool_index].clone();

        let capability = match select_capability_for_request(
            &self.capabilities,
            &binding.tool_name,
            &binding.server_id,
            &arguments,
            model_metadata.as_ref(),
        ) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_denied",
                        "tool": binding.tool_name,
                        "server": binding.server_id,
                    }),
                );
                return Err(jsonrpc_result(
                    id.clone(),
                    tool_error_result("tool is not authorized by the active capability set"),
                ));
            }
        };

        let nonce_bound_request_id = execution_nonce
            .as_ref()
            .map(|nonce| nonce.nonce.bound_to.request_id.as_str());
        let context = build_operation_context_for_retry(
            id,
            session_id.clone(),
            &self.agent_id,
            "tools/call",
            params,
            nonce_bound_request_id,
        )?;
        let execution_nonce = execution_nonce
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_REQUEST,
                    &format!("failed to serialize execution nonce: {error}"),
                )
            })?;

        Ok((
            session_id,
            context,
            ToolCallOperation {
                capability,
                server_id: binding.server_id,
                tool_name: binding.tool_name,
                arguments,
                governed_intent,
                approval_token,
                approval_tokens,
                threshold_approval_proposal,
                supplemental_authorization,
                execution_nonce,
                model_metadata,
                extra_metadata,
            },
        ))
    }

    pub(super) fn evaluate_tool_call_operation(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let operation = SessionOperation::ToolCall(Box::new(operation.clone()));
        match self.kernel.evaluate_session_operation(context, &operation) {
            Ok(SessionOperationResponse::ToolCall(response)) => self
                .tool_result_for_kernel_response(KernelToolResultArgs {
                    client_request_id: id,
                    session_id,
                    output: response.output,
                    reason: response.reason,
                    verdict: response.verdict,
                    terminal_state: &response.terminal_state,
                    execution_nonce: response.execution_nonce,
                    related_task_id,
                }),
            Ok(
                SessionOperationResponse::RootList { .. }
                | SessionOperationResponse::ResourceList { .. }
                | SessionOperationResponse::ResourceRead { .. }
                | SessionOperationResponse::ResourceReadDenied { .. }
                | SessionOperationResponse::ResourceTemplateList { .. }
                | SessionOperationResponse::PromptList { .. }
                | SessionOperationResponse::PromptGet { .. }
                | SessionOperationResponse::Completion { .. }
                | SessionOperationResponse::CapabilityList { .. }
                | SessionOperationResponse::Heartbeat,
            ) => ToolCallEdgeOutcome::JsonRpcError {
                code: JSONRPC_INTERNAL_ERROR,
                message: "unexpected kernel response type".to_string(),
                data: None,
            },
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        }
    }

    pub(super) fn evaluate_tool_call_operation_with_transport<
        R: BufRead + Send,
        W: Write + Send,
    >(
        &mut self,
        request: ToolCallRequestContext<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = EdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            reader,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                execution_nonce: response.execution_nonce,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    pub(super) fn evaluate_tool_call_operation_with_transport_channel<W: Write>(
        &mut self,
        request: ToolCallRequestContext<'_>,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = QueuedEdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            client_rx,
            cancel_rx,
            writer,
        };

        let outcome = match self
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                operation,
                &mut nested_flow_client,
            ) {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                execution_nonce: response.execution_nonce,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }
    pub(super) fn handle_tools_call(&mut self, id: Value, params: Value) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation(&id, &session_id, &context, &operation, None),
        )
    }

    // Reader/writer transport variant dispatched from `handle_request_with_transport`.
    pub(super) fn handle_tools_call_with_transport<R: BufRead + Send, W: Write + Send>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                false,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                reader,
                writer,
            ),
        )
    }

    pub(super) fn handle_tools_call_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                client_rx,
                cancel_rx,
                writer,
            ),
        )
    }
    pub(super) fn tool_result_for_kernel_response(
        &mut self,
        args: KernelToolResultArgs<'_>,
    ) -> ToolCallEdgeOutcome {
        let KernelToolResultArgs {
            client_request_id,
            session_id,
            output,
            reason,
            verdict,
            terminal_state,
            execution_nonce,
            related_task_id,
        } = args;
        let peer_supports_chio_tool_streaming = self.peer_supports_chio_tool_streaming(session_id);
        crate::metrics::record_receipt_write_verdict(verdict);
        let result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
            pending_notifications: &mut self.pending_notifications,
            request_id: client_request_id,
            output,
            reason,
            verdict,
            terminal_state,
            execution_nonce: execution_nonce.as_deref(),
            peer_supports_chio_tool_streaming,
            related_task_id,
        });

        if let Some(reason) = cancellation_reason_from_tool_result(&result) {
            return ToolCallEdgeOutcome::Cancelled { reason };
        }

        match terminal_state {
            OperationTerminalState::Cancelled { reason } => ToolCallEdgeOutcome::Cancelled {
                reason: reason.clone(),
            },
            _ => ToolCallEdgeOutcome::Result(result),
        }
    }

    pub(super) fn tool_call_error_outcome(
        &mut self,
        session_id: &SessionId,
        error: chio_kernel::KernelError,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        match error {
            chio_kernel::KernelError::RequestCancelled { reason, .. } => {
                ToolCallEdgeOutcome::Cancelled { reason }
            }
            chio_kernel::KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                if let Err(register_error) = self.kernel.register_session_required_url_elicitations(
                    session_id,
                    &elicitations,
                    related_task_id,
                ) {
                    self.emit_log_with_related_task(
                        LogLevel::Warning,
                        "chio.mcp.elicitation",
                        json!({
                            "event": "session_elicitation_registration_failed",
                            "error": register_error.to_string(),
                        }),
                        related_task_id,
                    );
                }
                ToolCallEdgeOutcome::JsonRpcError {
                    code: JSONRPC_URL_ELICITATION_REQUIRED,
                    message,
                    data: Some(json!({ "elicitations": elicitations })),
                }
            }
            other => {
                record_receipt_write_error();
                ToolCallEdgeOutcome::Result(tool_error_result(&other.to_string()))
            }
        }
    }

    pub(super) fn persist_accepted_url_elicitations(
        &mut self,
        session_id: &SessionId,
        accepted_url_elicitations: Vec<AcceptedUrlElicitation>,
    ) {
        for accepted in accepted_url_elicitations {
            if let Err(error) = self.kernel.register_session_pending_url_elicitation(
                session_id,
                accepted.elicitation_id,
                accepted.related_task_id,
            ) {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.elicitation",
                    json!({
                        "event": "session_elicitation_registration_failed",
                        "error": error.to_string(),
                    }),
                );
            }
        }
    }
}
