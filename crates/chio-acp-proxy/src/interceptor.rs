use std::collections::{HashMap, VecDeque};

/// Direction of a message flowing through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the editor/IDE client toward the ACP agent.
    ClientToAgent,
    /// From the ACP agent toward the editor/IDE client.
    AgentToClient,
}

/// The outcome of intercepting a single message.
#[derive(Debug, Clone)]
pub enum InterceptResult {
    /// Forward the (possibly modified) message to its destination.
    Forward(Value),
    /// Block the message and return an error response to the sender.
    Block(Value),
    /// Forward the message AND record an audit entry for it.
    ForwardWithReceipt(Value, Box<AcpToolCallAuditEntry>),
}

enum CapabilityGate {
    Skip,
    Allow(AcpCapabilityAuditContext),
    Block(Value),
}

/// Core message interception logic for the ACP proxy.
///
/// The interceptor examines every JSON-RPC message, delegates to
/// specialized guards, and decides whether to forward, block, or
/// augment the message with an audit entry.
///
/// When a `ReceiptSigner` is installed, audit entries are promoted
/// to signed Chio receipts. When a `CapabilityChecker` is installed,
/// file and terminal operations are validated against capability tokens
/// before falling back to the built-in guards.
pub struct MessageInterceptor {
    config: AcpProxyConfig,
    permission_mapper: PermissionMapper,
    fs_guard: FsGuard,
    terminal_guard: TerminalGuard,
    receipt_logger: ReceiptLogger,
    /// Optional receipt signer for producing signed Chio receipts.
    receipt_signer: Option<Box<dyn ReceiptSigner>>,
    /// Optional capability checker for token-based access control.
    capability_checker: Option<Box<dyn CapabilityChecker>>,
    /// Attestation mode controlling how signing failures are handled.
    attestation_mode: AcpAttestationMode,
    /// Capability context captured from successful live-path checks.
    ///
    /// Pending contexts are queued by `pending:<session_id>` until ACP
    /// tool-call events expose `toolCallId`; active contexts then move to
    /// `tool:<session_id>:<tool_call_id>` so interleaved calls cannot overwrite
    /// each other's authorization.
    live_capability_contexts: std::sync::Mutex<HashMap<String, VecDeque<AcpCapabilityAuditContext>>>,
}

impl MessageInterceptor {
    /// Build an interceptor from the given proxy configuration.
    pub fn new(config: AcpProxyConfig) -> Self {
        let fs_guard = FsGuard::new(config.allowed_path_prefixes().to_vec());
        let terminal_guard = TerminalGuard::new(config.allowed_commands().to_vec());
        let receipt_logger = ReceiptLogger::new(config.server_id());
        let permission_mapper = PermissionMapper::new(3600);

        Self {
            config,
            permission_mapper,
            fs_guard,
            terminal_guard,
            receipt_logger,
            receipt_signer: None,
            capability_checker: None,
            attestation_mode: AcpAttestationMode::default(),
            live_capability_contexts: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Build an interceptor with kernel-injected signer and checker.
    pub fn with_kernel(
        config: AcpProxyConfig,
        signer: Option<Box<dyn ReceiptSigner>>,
        checker: Option<Box<dyn CapabilityChecker>>,
        attestation_mode: AcpAttestationMode,
    ) -> Self {
        let fs_guard = FsGuard::new(config.allowed_path_prefixes().to_vec());
        let terminal_guard = TerminalGuard::new(config.allowed_commands().to_vec());
        let receipt_logger = ReceiptLogger::new(config.server_id());
        let permission_mapper = PermissionMapper::new(3600);

        Self {
            config,
            permission_mapper,
            fs_guard,
            terminal_guard,
            receipt_logger,
            receipt_signer: signer,
            capability_checker: checker,
            attestation_mode,
            live_capability_contexts: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Whether a receipt signer is installed.
    pub fn has_receipt_signer(&self) -> bool {
        self.receipt_signer.is_some()
    }

    /// Whether a capability checker is installed.
    pub fn has_capability_checker(&self) -> bool {
        self.capability_checker.is_some()
    }

    /// The current attestation mode.
    pub fn attestation_mode(&self) -> AcpAttestationMode {
        self.attestation_mode
    }

    /// Intercept a JSON-RPC message flowing in the given `direction`.
    ///
    /// Returns an `InterceptResult` describing whether to forward,
    /// block, or forward-with-receipt.
    pub fn intercept(
        &self,
        direction: Direction,
        message: &Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        let method = extract_method(message);

        match (direction, method) {
            // -- Agent-to-client: file system reads --
            (Direction::AgentToClient, Some(AcpMethod::FsReadTextFile)) => {
                self.intercept_fs_read(message)
            }
            // -- Agent-to-client: file system writes --
            (Direction::AgentToClient, Some(AcpMethod::FsWriteTextFile)) => {
                self.intercept_fs_write(message)
            }
            // -- Agent-to-client: terminal create --
            (Direction::AgentToClient, Some(AcpMethod::TerminalCreate)) => {
                self.intercept_terminal_create(message)
            }
            // -- Agent-to-client: permission requests --
            (Direction::AgentToClient, Some(AcpMethod::SessionRequestPermission)) => {
                self.intercept_permission_request(message)
            }
            // -- Agent-to-client: session updates (receipt generation) --
            (Direction::AgentToClient, Some(AcpMethod::SessionUpdate)) => {
                self.intercept_session_update(message)
            }
            // -- New ACP methods: forward unchanged (no guard needed) --
            (_, Some(AcpMethod::Authenticate))
            | (_, Some(AcpMethod::SessionLoad))
            | (_, Some(AcpMethod::SessionList))
            | (_, Some(AcpMethod::SessionSetConfigOption))
            | (_, Some(AcpMethod::SessionSetMode))
            | (_, Some(AcpMethod::TerminalOutput))
            | (_, Some(AcpMethod::TerminalWaitForExit)) => {
                Ok(InterceptResult::Forward(message.clone()))
            }
            // -- Everything else: forward unchanged --
            _ => Ok(InterceptResult::Forward(message.clone())),
        }
    }

    /// Return a reference to the underlying proxy configuration.
    pub fn config(&self) -> &AcpProxyConfig {
        &self.config
    }

    /// Expose the permission mapper for tests.
    #[cfg(test)]
    pub fn permission_mapper(&self) -> &PermissionMapper {
        &self.permission_mapper
    }

    // -- private handlers --

    fn intercept_fs_read(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message
            .get("params")
            .ok_or_else(|| AcpProxyError::Protocol("missing params in fs/read_text_file".into()))?;

        let read_params: ReadTextFileParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                AcpProxyError::Protocol(format!("invalid fs/read_text_file params: {e}"))
            })?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: read_params.session_id.clone(),
                operation: "fs_read".to_string(),
                resource: read_params.path.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                return Ok(InterceptResult::Block(response));
            }
        };

        match self.fs_guard.check_read(&read_params.path) {
            Ok(()) => {
                if let Some(ref context) = capability_context {
                    self.remember_capability_context(&read_params.session_id, context.clone());
                }
                Ok(InterceptResult::Forward(message.clone()))
            }
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(path = %read_params.path, "fs read blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    fn intercept_fs_write(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message.get("params").ok_or_else(|| {
            AcpProxyError::Protocol("missing params in fs/write_text_file".into())
        })?;

        let write_params: WriteTextFileParams =
            serde_json::from_value(params.clone()).map_err(|e| {
                AcpProxyError::Protocol(format!("invalid fs/write_text_file params: {e}"))
            })?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: write_params.session_id.clone(),
                operation: "fs_write".to_string(),
                resource: write_params.path.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                return Ok(InterceptResult::Block(response));
            }
        };

        match self.fs_guard.check_write(&write_params.path) {
            Ok(()) => {
                if let Some(ref context) = capability_context {
                    self.remember_capability_context(&write_params.session_id, context.clone());
                }
                Ok(InterceptResult::Forward(message.clone()))
            }
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(path = %write_params.path, "fs write blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    fn intercept_terminal_create(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message
            .get("params")
            .ok_or_else(|| AcpProxyError::Protocol("missing params in terminal/create".into()))?;

        let term_params: CreateTerminalParams = serde_json::from_value(params.clone())
            .map_err(|e| AcpProxyError::Protocol(format!("invalid terminal/create params: {e}")))?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: term_params.session_id.clone(),
                operation: "terminal".to_string(),
                resource: term_params.command.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                return Ok(InterceptResult::Block(response));
            }
        };

        match self
            .terminal_guard
            .check_command(&term_params.command, &term_params.args)
        {
            Ok(()) => {
                if let Some(ref context) = capability_context {
                    self.remember_capability_context(&term_params.session_id, context.clone());
                }
                Ok(InterceptResult::Forward(message.clone()))
            }
            Err(err) => {
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(command = %term_params.command, "terminal create blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    /// Intercept a `session/request_permission` message.
    ///
    /// The Chio capability mapping performed here is for **audit logging
    /// only**. The actual enforcement decision is made by the user
    /// through the editor/IDE UI -- the proxy does not approve or
    /// reject permissions on behalf of the user. It maps ACP
    /// permission kinds to Chio capability decisions so that the audit
    /// trail records what the Chio-equivalent grant would be.
    fn intercept_permission_request(
        &self,
        message: &Value,
    ) -> Result<InterceptResult, AcpProxyError> {
        // Parse permission params for logging/mapping.
        if let Some(params) = message.get("params") {
            if let Ok(perm_params) =
                serde_json::from_value::<RequestPermissionParams>(params.clone())
            {
                for option in &perm_params.options {
                    let mapped = self.permission_mapper.map_option(option);
                    tracing::info!(
                        option_id = %mapped.original_option_id,
                        decision = ?mapped.chio_decision,
                        "permission mapped"
                    );
                }
            }
        }
        // Forward the permission request to the client for user decision.
        Ok(InterceptResult::Forward(message.clone()))
    }

    fn intercept_session_update(&self, message: &Value) -> Result<InterceptResult, AcpProxyError> {
        let params = message.get("params");
        let notification = params
            .and_then(|p| serde_json::from_value::<SessionUpdateNotification>(p.clone()).ok());

        if let Some(ref notif) = notification {
            let update = parse_session_update(&notif.update);
            match update {
                SessionUpdate::ToolCall(ref event) => {
                    let capability_context =
                        self.take_next_capability_context(&notif.session_id).inspect(|context| {
                            self.remember_tool_capability_context(
                                &notif.session_id,
                                &event.tool_call_id,
                                (*context).clone(),
                            );
                        });
                    let receipt = self.receipt_logger.log_tool_call(
                        &notif.session_id,
                        event,
                        capability_context.as_ref(),
                    );
                    tracing::info!(
                        tool_call_id = %receipt.tool_call_id,
                        status = %receipt.status,
                        "tool call receipt"
                    );
                    return Ok(InterceptResult::ForwardWithReceipt(
                        message.clone(),
                        Box::new(receipt),
                    ));
                }
                SessionUpdate::ToolCallUpdate(ref event) => {
                    let capability_context =
                        self.lookup_tool_capability_context(&notif.session_id, &event.tool_call_id);
                    if let Some(receipt) = self.receipt_logger.log_tool_call_update(
                        &notif.session_id,
                        event,
                        capability_context.as_ref(),
                    ) {
                        if should_clear_capability_context(&receipt.status) {
                            self.clear_tool_capability_context(
                                &notif.session_id,
                                &event.tool_call_id,
                            );
                        }
                        tracing::info!(
                            tool_call_id = %receipt.tool_call_id,
                            status = %receipt.status,
                            "tool call update receipt"
                        );
                        return Ok(InterceptResult::ForwardWithReceipt(
                            message.clone(),
                            Box::new(receipt),
                        ));
                    }
                }
                SessionUpdate::AgentMessageChunk(_)
                | SessionUpdate::AgentThoughtChunk(_)
                | SessionUpdate::Plan(_)
                | SessionUpdate::AvailableCommandsUpdate(_)
                | SessionUpdate::CurrentModeUpdate(_)
                | SessionUpdate::ConfigOptionUpdate(_)
                | SessionUpdate::SessionInfoUpdate(_)
                | SessionUpdate::Other(_) => {}
            }
        }

        Ok(InterceptResult::Forward(message.clone()))
    }

    fn check_capability_gate(
        &self,
        id: Option<&Value>,
        request: AcpCapabilityRequest,
    ) -> CapabilityGate {
        let Some(checker) = self.capability_checker.as_ref() else {
            return CapabilityGate::Skip;
        };

        match checker.check_access(&request) {
            Ok(verdict) if verdict.allowed => {
                let Some(capability_id) = verdict.capability_id else {
                    return CapabilityGate::Block(json_rpc_error(
                        id,
                        ACP_ERROR_ACCESS_DENIED,
                        "capability checker allowed access without a capability_id",
                    ));
                };
                CapabilityGate::Allow(AcpCapabilityAuditContext {
                    capability_id,
                    enforcement_mode: AcpEnforcementMode::CryptographicallyEnforced,
                    authorization_receipt_id: verdict.receipt_id,
                    authorization_request_id: verdict.receipt_request_id,
                })
            }
            Ok(verdict) => {
                CapabilityGate::Block(json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &verdict.reason))
            }
            Err(err) => CapabilityGate::Block(json_rpc_error(
                id,
                ACP_ERROR_ACCESS_DENIED,
                &format!("capability check failed closed: {err}"),
            )),
        }
    }

    fn remember_capability_context(&self, session_id: &str, context: AcpCapabilityAuditContext) {
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            contexts
                .entry(pending_capability_context_key(session_id))
                .or_default()
                .push_back(context);
        }
    }

    fn take_next_capability_context(&self, session_id: &str) -> Option<AcpCapabilityAuditContext> {
        let Ok(mut contexts) = self.live_capability_contexts.lock() else {
            return None;
        };
        let key = pending_capability_context_key(session_id);
        let next = contexts.get_mut(&key).and_then(VecDeque::pop_front);
        if contexts.get(&key).is_some_and(VecDeque::is_empty) {
            contexts.remove(&key);
        }
        next
    }

    fn remember_tool_capability_context(
        &self,
        session_id: &str,
        tool_call_id: &str,
        context: AcpCapabilityAuditContext,
    ) {
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            contexts.insert(
                tool_capability_context_key(session_id, tool_call_id),
                VecDeque::from([context]),
            );
        }
    }

    fn lookup_tool_capability_context(
        &self,
        session_id: &str,
        tool_call_id: &str,
    ) -> Option<AcpCapabilityAuditContext> {
        self.live_capability_contexts
            .lock()
            .ok()
            .and_then(|contexts| {
                contexts
                    .get(&tool_capability_context_key(session_id, tool_call_id))
                    .and_then(|queue| queue.front().cloned())
            })
    }

    fn clear_tool_capability_context(&self, session_id: &str, tool_call_id: &str) {
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            contexts.remove(&tool_capability_context_key(session_id, tool_call_id));
        }
    }
}

fn pending_capability_context_key(session_id: &str) -> String {
    format!("pending:{session_id}")
}

fn tool_capability_context_key(session_id: &str, tool_call_id: &str) -> String {
    format!("tool:{session_id}:{tool_call_id}")
}

fn extract_capability_token(params: &Value) -> Option<String> {
    extract_token_value(params.get("capabilityToken"))
        .or_else(|| extract_token_value(params.get("capability_token")))
        .or_else(|| {
            params
                .get("chio")
                .and_then(|chio| extract_token_value(chio.get("capabilityToken")))
        })
        .or_else(|| {
            params
                .get("chio")
                .and_then(|chio| extract_token_value(chio.get("capability_token")))
        })
}

fn extract_token_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(raw) if raw.trim().is_empty() => None,
        Value::String(raw) => Some(raw.clone()),
        other => serde_json::to_string(other).ok(),
    }
}

fn should_clear_capability_context(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "error" | "cancelled" | "canceled"
    )
}
