use std::collections::HashMap;

/// Maximum number of pending capability contexts buffered per session.
///
/// Pending contexts accumulate when ACP `fs/read_text_file`,
/// `fs/write_text_file`, or `terminal/create` requests pass the capability
/// gate but their matching `session/update` `toolCallId` never arrives
/// (the agent ignores the result, the session crashes, the IDE closes the
/// tab) or arrives ambiguously (zero or several matching pending
/// contexts). Without a bound the per-session FIFO would grow indefinitely
/// across the lifetime of long-running sessions.
///
/// 32 is comfortably above any plausible in-flight depth for normal ACP
/// agents -- a single tool call cycle queues at most one pending context,
/// and even bursty editors do not pre-fetch dozens of files before any
/// `session/update` arrives. When the cap is exceeded the oldest entry is
/// evicted in FIFO order, preserving the most recent authorizations.
const MAX_PENDING_CAPABILITY_CONTEXTS_PER_SESSION: usize = 32;

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
    /// Active contexts are keyed by `tool:<session_id>:<tool_call_id>` so
    /// interleaved calls cannot overwrite each other's authorization.
    live_capability_contexts: std::sync::Mutex<HashMap<String, AcpCapabilityAuditContext>>,
    /// Pending capability contexts captured from successful live-path checks
    /// for requests that do not yet carry a `toolCallId`.
    ///
    /// ACP `fs/read_text_file`, `fs/write_text_file`, and `terminal/create`
    /// requests do not carry a `toolCallId` in their params: the agent picks
    /// the call id and emits it later in a `session/update` notification.
    /// The corresponding `CryptographicallyEnforced` context is buffered
    /// here per session, in FIFO order, until the first matching
    /// `session/update` ToolCall event arrives. When exactly one pending
    /// context matches the event's `kind`, it is popped and re-indexed by
    /// `(session_id, tool_call_id)`. When zero or more than one match, the
    /// receipt deliberately drops to `AuditOnly` rather than guessing
    /// (preserves the ambiguity property tested in
    /// `interceptor_does_not_bind_ambiguous_pending_contexts_to_tool_calls`).
    pending_capability_contexts:
        std::sync::Mutex<HashMap<String, Vec<PendingCapabilityContext>>>,
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
            pending_capability_contexts: std::sync::Mutex::new(HashMap::new()),
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
            pending_capability_contexts: std::sync::Mutex::new(HashMap::new()),
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
            // -- Agent-to-client: terminal kill --
            (Direction::AgentToClient, Some(AcpMethod::TerminalKill)) => {
                self.intercept_terminal_lifecycle(message, TerminalLifecycleOp::Kill)
            }
            // -- Agent-to-client: terminal release --
            (Direction::AgentToClient, Some(AcpMethod::TerminalRelease)) => {
                self.intercept_terminal_lifecycle(message, TerminalLifecycleOp::Release)
            }
            // -- Agent-to-client: permission requests --
            (Direction::AgentToClient, Some(AcpMethod::SessionRequestPermission)) => {
                self.intercept_permission_request(message)
            }
            // -- Agent-to-client: session updates (receipt generation) --
            (Direction::AgentToClient, Some(AcpMethod::SessionUpdate)) => {
                self.intercept_session_update(message)
            }
            // -- Client-to-agent or agent-to-client: session cancel --
            //
            // session/cancel marks the end of a logical session: any
            // pending capability contexts that have not been bound by
            // now never will be (no future session/update can carry
            // their toolCallId), so the per-session pending buffer is
            // purged to release the captured authorization material.
            // The live capability index is also dropped because every
            // in-flight tool call associated with the session is
            // implicitly cancelled.
            (_, Some(AcpMethod::SessionCancel)) => {
                self.intercept_session_cancel(message);
                Ok(InterceptResult::Forward(message.clone()))
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

    /// Inspect the per-session pending capability buffer size for tests.
    #[cfg(test)]
    pub fn pending_capability_context_count(&self, session_id: &str) -> usize {
        self.pending_capability_contexts
            .lock()
            .ok()
            .and_then(|pending| pending.get(session_id).map(Vec::len))
            .unwrap_or(0)
    }

    /// Inspect the live capability buffer size for tests.
    #[cfg(test)]
    pub fn live_capability_context_count_for_session(&self, session_id: &str) -> usize {
        self.live_capability_contexts
            .lock()
            .ok()
            .map(|contexts| {
                let prefix = format!("tool:{session_id}:");
                contexts.keys().filter(|key| key.starts_with(&prefix)).count()
            })
            .unwrap_or(0)
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
        let authorization_parameter_hash = authorization_parameter_hash(params)?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: read_params.session_id.clone(),
                tool_call_id: extract_tool_call_id(params),
                authorization_correlation_id: Some(authorization_correlation_id(
                    message.get("id"),
                    &read_params.session_id,
                    "fs_read",
                    &read_params.path,
                )),
                operation: "fs_read".to_string(),
                resource: read_params.path.clone(),
                authorization_parameter_hash,
                operation_payload: params.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                self.clear_capability_context(&read_params.session_id);
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
                self.clear_capability_context(&read_params.session_id);
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
        let authorization_parameter_hash = authorization_parameter_hash(params)?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: write_params.session_id.clone(),
                tool_call_id: extract_tool_call_id(params),
                authorization_correlation_id: Some(authorization_correlation_id(
                    message.get("id"),
                    &write_params.session_id,
                    "fs_write",
                    &write_params.path,
                )),
                operation: "fs_write".to_string(),
                resource: write_params.path.clone(),
                authorization_parameter_hash,
                operation_payload: params.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                self.clear_capability_context(&write_params.session_id);
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
                self.clear_capability_context(&write_params.session_id);
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
        let authorization_parameter_hash = authorization_parameter_hash(params)?;

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: term_params.session_id.clone(),
                tool_call_id: extract_tool_call_id(params),
                authorization_correlation_id: Some(authorization_correlation_id(
                    message.get("id"),
                    &term_params.session_id,
                    "terminal",
                    &term_params.command,
                )),
                operation: "terminal".to_string(),
                resource: term_params.command.clone(),
                authorization_parameter_hash,
                operation_payload: params.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => None,
            CapabilityGate::Allow(context) => Some(context),
            CapabilityGate::Block(response) => {
                self.clear_capability_context(&term_params.session_id);
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
                self.clear_capability_context(&term_params.session_id);
                let id = message.get("id");
                let error_response = json_rpc_error(id, ACP_ERROR_ACCESS_DENIED, &err.to_string());
                tracing::warn!(command = %term_params.command, "terminal create blocked");
                Ok(InterceptResult::Block(error_response))
            }
        }
    }

    /// Gate `terminal/kill` and `terminal/release` against the capability
    /// checker. These operations mutate subagent process state without
    /// going through the normal tool-call mediation path, so they fail
    /// closed when no checker is installed and require a parameter-bound
    /// Chio receipt that names the targeted session and terminal.
    fn intercept_terminal_lifecycle(
        &self,
        message: &Value,
        op: TerminalLifecycleOp,
    ) -> Result<InterceptResult, AcpProxyError> {
        let method_name = op.method_name();
        let params = message
            .get("params")
            .ok_or_else(|| AcpProxyError::Protocol(format!("missing params in {method_name}")))?;

        let (session_id, terminal_id) = match op {
            TerminalLifecycleOp::Kill => {
                let parsed: KillTerminalParams =
                    serde_json::from_value(params.clone()).map_err(|e| {
                        AcpProxyError::Protocol(format!("invalid {method_name} params: {e}"))
                    })?;
                (parsed.session_id, parsed.terminal_id)
            }
            TerminalLifecycleOp::Release => {
                let parsed: ReleaseTerminalParams =
                    serde_json::from_value(params.clone()).map_err(|e| {
                        AcpProxyError::Protocol(format!("invalid {method_name} params: {e}"))
                    })?;
                (parsed.session_id, parsed.terminal_id)
            }
        };

        // Fail-closed: lifecycle operations require a capability checker to
        // be installed. Without one, the proxy cannot bind the request to a
        // signed Chio receipt, so the operation is denied. The built-in
        // command allowlist guard does not cover process lifecycle.
        if !self.has_capability_checker() {
            let id = message.get("id");
            let error_response = json_rpc_error(
                id,
                ACP_ERROR_ACCESS_DENIED,
                &format!(
                    "{method_name} denied: capability checker is required for terminal lifecycle operations"
                ),
            );
            tracing::warn!(
                method = method_name,
                session_id = %session_id,
                terminal_id = %terminal_id,
                "terminal lifecycle blocked: no capability checker installed"
            );
            return Ok(InterceptResult::Block(error_response));
        }

        let authorization_parameter_hash = authorization_parameter_hash(params)?;
        let operation = op.operation_label().to_string();

        let capability_context = match self.check_capability_gate(
            message.get("id"),
            AcpCapabilityRequest {
                session_id: session_id.clone(),
                tool_call_id: extract_tool_call_id(params).or_else(|| Some(terminal_id.clone())),
                authorization_correlation_id: Some(authorization_correlation_id(
                    message.get("id"),
                    &session_id,
                    &operation,
                    &terminal_id,
                )),
                operation,
                resource: terminal_id.clone(),
                authorization_parameter_hash,
                operation_payload: params.clone(),
                token: extract_capability_token(params),
            },
        ) {
            CapabilityGate::Skip => {
                // Skip should not occur because we just verified the checker
                // is installed; treat it as fail-closed if it ever does.
                let id = message.get("id");
                let error_response = json_rpc_error(
                    id,
                    ACP_ERROR_ACCESS_DENIED,
                    &format!(
                        "{method_name} denied: capability gate skipped despite checker being installed"
                    ),
                );
                return Ok(InterceptResult::Block(error_response));
            }
            CapabilityGate::Allow(context) => context,
            CapabilityGate::Block(response) => {
                tracing::warn!(
                    method = method_name,
                    session_id = %session_id,
                    terminal_id = %terminal_id,
                    "terminal lifecycle blocked by capability gate"
                );
                return Ok(InterceptResult::Block(response));
            }
        };

        // Remember the live authorization so a follow-up session/update
        // tool_call (if any) can be promoted to a mediated/prevent receipt.
        self.remember_capability_context(&session_id, capability_context);
        Ok(InterceptResult::Forward(message.clone()))
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
                    let capability_context = self
                        .lookup_tool_capability_context(&notif.session_id, &event.tool_call_id)
                        .or_else(|| {
                            // The originating ACP fs/terminal-create request had
                            // no toolCallId, so the CryptographicallyEnforced
                            // context was buffered per session. Bind it now when
                            // exactly one pending context matches the event's
                            // kind (and re-index it under the resolved
                            // tool_call_id so the terminal session/update can
                            // find it the same way).
                            self.bind_pending_capability_context(
                                &notif.session_id,
                                &event.tool_call_id,
                                event.kind.as_deref(),
                            )
                        });
                    let receipt = self.receipt_logger.log_tool_call(
                        &notif.session_id,
                        event,
                        capability_context.as_ref(),
                    );
                    if let Some(block) = self.sign_or_block(message.get("id"), &receipt) {
                        return Ok(InterceptResult::Block(block));
                    }
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
                        if let Some(block) = self.sign_or_block(message.get("id"), &receipt) {
                            return Ok(InterceptResult::Block(block));
                        }
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
                if request
                    .authorization_correlation_id
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    return CapabilityGate::Block(json_rpc_error(
                        id,
                        ACP_ERROR_ACCESS_DENIED,
                        "capability checker allowed access without an authorization correlation id",
                    ));
                }
                // ACP fs/read_text_file, fs/write_text_file, and terminal/create
                // requests do not carry a toolCallId: those parameter structs
                // expose only sessionId / path / content / command. The matching
                // toolCallId arrives later on the session/update notification.
                // Only the lifecycle operations that mutate an existing tool
                // call (terminal_kill, terminal_release) and other future
                // explicitly-bound operations must carry the binding here.
                if requires_tool_call_id_binding(&request.operation)
                    && request
                        .tool_call_id
                        .as_deref()
                        .is_none_or(str::is_empty)
                {
                    return CapabilityGate::Block(json_rpc_error(
                        id,
                        ACP_ERROR_ACCESS_DENIED,
                        "capability checker allowed access without a tool_call_id binding",
                    ));
                }
                if verdict.receipt_id.as_deref().is_none_or(str::is_empty)
                    || verdict
                        .receipt_request_id
                        .as_deref()
                        .is_none_or(str::is_empty)
                {
                    return CapabilityGate::Block(json_rpc_error(
                        id,
                        ACP_ERROR_ACCESS_DENIED,
                        "capability checker allowed access without a signed authorization receipt and request id",
                    ));
                }
                CapabilityGate::Allow(AcpCapabilityAuditContext {
                    capability_id,
                    enforcement_mode: AcpEnforcementMode::CryptographicallyEnforced,
                    authorization_tool_call_id: request.tool_call_id.clone(),
                    authorization_correlation_id: request.authorization_correlation_id.clone(),
                    authorization_operation: Some(request.operation.clone()),
                    authorization_resource: Some(request.resource.clone()),
                    authorization_parameter_hash: Some(request.authorization_parameter_hash.clone()),
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

    fn sign_or_block(&self, id: Option<&Value>, entry: &AcpToolCallAuditEntry) -> Option<Value> {
        let Some(signer) = self.receipt_signer.as_ref() else {
            if self.attestation_mode == AcpAttestationMode::Required {
                return Some(json_rpc_error(
                    id,
                    ACP_ERROR_ACCESS_DENIED,
                    "ACP attestation required but receipt signer is required and unavailable",
                ));
            }
            return None;
        };

        let request = AcpReceiptRequest {
            audit_entry: entry.clone(),
            tool_server: self.config.server_id().to_string(),
            tool_name: acp_receipt_tool_name(entry),
        };
        match signer.sign_acp_receipt(&request) {
            Ok(receipt) => {
                tracing::info!(
                    receipt_id = %receipt.id,
                    tool_call_id = %entry.tool_call_id,
                    "signed ACP audit entry"
                );
                None
            }
            Err(error) if self.attestation_mode == AcpAttestationMode::Required => {
                Some(json_rpc_error(
                    id,
                    ACP_ERROR_ACCESS_DENIED,
                    &format!("receipt signing failed closed: {error}"),
                ))
            }
            Err(error) => {
                tracing::warn!(
                    tool_call_id = %entry.tool_call_id,
                    error = %error,
                    "ACP receipt signing failed in best-effort mode"
                );
                None
            }
        }
    }

    fn remember_capability_context(&self, session_id: &str, context: AcpCapabilityAuditContext) {
        let tool_call_id = context
            .authorization_tool_call_id
            .clone()
            .filter(|tool_call_id| !tool_call_id.trim().is_empty());
        if let Some(tool_call_id) = tool_call_id {
            if let Ok(mut contexts) = self.live_capability_contexts.lock() {
                contexts.insert(tool_capability_context_key(session_id, &tool_call_id), context);
            }
            return;
        }
        // No tool_call_id on the originating request (the ACP fs/read,
        // fs/write, and terminal/create shapes). Buffer the context per
        // session in FIFO order so the matching session/update can later
        // link it to a concrete tool_call_id. Without this, the
        // CryptographicallyEnforced verdict would be silently downgraded
        // to AuditOnly when the receipt is signed.
        let Some(operation) = context.authorization_operation.clone() else {
            return;
        };
        if operation.trim().is_empty() {
            return;
        }
        if let Ok(mut pending) = self.pending_capability_contexts.lock() {
            let entry = pending.entry(session_id.to_string()).or_default();
            entry.push(PendingCapabilityContext { operation, context });
            // Cap the per-session pending buffer at
            // MAX_PENDING_CAPABILITY_CONTEXTS_PER_SESSION. When the cap is
            // exceeded the oldest (FIFO) entry is evicted so unmatched
            // contexts cannot grow without bound across long-lived
            // sessions. The most recent authorizations are preserved
            // because they are most likely to match the next
            // session/update event.
            while entry.len() > MAX_PENDING_CAPABILITY_CONTEXTS_PER_SESSION {
                let _evicted = entry.remove(0);
                tracing::warn!(
                    session_id = %session_id,
                    cap = MAX_PENDING_CAPABILITY_CONTEXTS_PER_SESSION,
                    "evicted oldest pending capability context to enforce per-session cap"
                );
            }
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
                    .cloned()
            })
    }

    /// Attempt to bind a pending capability context (captured from a
    /// toolCallId-less request) to the resolved `tool_call_id` from a
    /// `session/update` ToolCall event.
    ///
    /// Pops exactly one pending context whose `authorization_operation`
    /// matches the event's `kind`. When zero or more than one pending
    /// contexts match, returns `None` so the receipt falls back to
    /// `AuditOnly` rather than guessing which pre-authorized request the
    /// event corresponds to.
    fn bind_pending_capability_context(
        &self,
        session_id: &str,
        tool_call_id: &str,
        event_kind: Option<&str>,
    ) -> Option<AcpCapabilityAuditContext> {
        if tool_call_id.trim().is_empty() {
            return None;
        }
        let event_kind = event_kind.filter(|kind| !kind.trim().is_empty())?;
        let mut pending = self.pending_capability_contexts.lock().ok()?;
        let entry = pending.get_mut(session_id)?;
        let matching_indices: Vec<usize> = entry
            .iter()
            .enumerate()
            .filter_map(|(index, pending_context)| {
                pending_operation_matches_event_kind(&pending_context.operation, event_kind)
                    .then_some(index)
            })
            .collect();
        if matching_indices.len() != 1 {
            // Ambiguous (>1) or empty (0) -- do not guess. The receipt
            // intentionally drops to AuditOnly to preserve the security
            // property exercised by
            // `interceptor_does_not_bind_ambiguous_pending_contexts_to_tool_calls`.
            return None;
        }
        let removed = entry.remove(matching_indices[0]);
        if entry.is_empty() {
            pending.remove(session_id);
        }
        drop(pending);
        let mut bound_context = removed.context;
        bound_context.authorization_tool_call_id = Some(tool_call_id.to_string());
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            contexts.insert(
                tool_capability_context_key(session_id, tool_call_id),
                bound_context.clone(),
            );
        }
        Some(bound_context)
    }

    fn clear_capability_context(&self, session_id: &str) {
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            let tool_prefix = format!("tool:{session_id}:");
            contexts.retain(|key, _| !key.starts_with(&tool_prefix));
        }
        if let Ok(mut pending) = self.pending_capability_contexts.lock() {
            pending.remove(session_id);
        }
    }

    fn clear_tool_capability_context(&self, session_id: &str, tool_call_id: &str) {
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            contexts.remove(&tool_capability_context_key(session_id, tool_call_id));
        }
    }

    /// Clear all pending and live capability contexts for a session.
    ///
    /// Called on `session/cancel` so the per-session pending FIFO and the
    /// `tool:<session>:*` live entries are released as soon as the agent
    /// signals the session is over. Without this, sessions that cancel
    /// before their pending `fs/read` / `terminal/create` requests bind to
    /// a `session/update` would leak captured authorization material for
    /// the lifetime of the proxy.
    fn intercept_session_cancel(&self, message: &Value) {
        let Some(params) = message.get("params") else {
            return;
        };
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .or_else(|| params.get("session_id").and_then(Value::as_str));
        let Some(session_id) = session_id else {
            return;
        };
        if session_id.trim().is_empty() {
            return;
        }
        let pending_drained = self
            .pending_capability_contexts
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(session_id))
            .map(|entries| entries.len())
            .unwrap_or(0);
        if let Ok(mut contexts) = self.live_capability_contexts.lock() {
            let tool_prefix = format!("tool:{session_id}:");
            contexts.retain(|key, _| !key.starts_with(&tool_prefix));
        }
        if pending_drained > 0 {
            tracing::info!(
                session_id = %session_id,
                pending_drained,
                "session/cancel cleared pending capability contexts"
            );
        }
    }
}

fn tool_capability_context_key(session_id: &str, tool_call_id: &str) -> String {
    format!("tool:{session_id}:{tool_call_id}")
}

/// A `CryptographicallyEnforced` capability context that was approved by the
/// live checker for an ACP request that did not carry a `toolCallId`.
///
/// Buffered until the matching `session/update` arrives carrying the
/// agent-assigned `tool_call_id`, at which point the binding is established.
#[derive(Debug, Clone)]
struct PendingCapabilityContext {
    /// The Chio operation label assigned at the capability gate
    /// (`fs_read`, `fs_write`, `terminal`).
    operation: String,
    context: AcpCapabilityAuditContext,
}

/// Returns true when an ACP `session/update` ToolCall event's `kind` plausibly
/// refers to a pending capability context with the given Chio operation label.
///
/// The set of accepted `kind` values follows the canonical ACP
/// `ToolKind` enum: `read`, `edit`, `execute`, `delete`, `move`,
/// `search`, `fetch`, `think`, `switch_mode`, and `other` (with `read`
/// reserved for file reads, `edit` for file writes, and `execute` for
/// terminal/process invocations).
fn pending_operation_matches_event_kind(operation: &str, event_kind: &str) -> bool {
    let event_kind = event_kind.trim();
    match operation {
        "fs_read" => matches!(event_kind, "read"),
        "fs_write" => matches!(event_kind, "edit"),
        "terminal" => matches!(event_kind, "execute"),
        _ => false,
    }
}

/// Discriminator for the two ACP terminal lifecycle methods that must be
/// gated by a parameter-bound Chio receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalLifecycleOp {
    Kill,
    Release,
}

impl TerminalLifecycleOp {
    fn method_name(self) -> &'static str {
        match self {
            Self::Kill => "terminal/kill",
            Self::Release => "terminal/release",
        }
    }

    fn operation_label(self) -> &'static str {
        match self {
            Self::Kill => "terminal_kill",
            Self::Release => "terminal_release",
        }
    }
}

fn acp_receipt_tool_name(entry: &AcpToolCallAuditEntry) -> String {
    let operation = entry
        .authorization_operation
        .as_deref()
        .or(entry.kind.as_deref());
    match operation {
        Some("fs_read") => "fs/read_text_file",
        Some("fs_write") => "fs/write_text_file",
        Some("terminal") => "terminal/create",
        Some("terminal_kill") => "terminal/kill",
        Some("terminal_release") => "terminal/release",
        Some(other) if !other.trim().is_empty() => other,
        _ => "session/update",
    }
    .to_string()
}

fn authorization_parameter_hash(params: &Value) -> Result<String, AcpProxyError> {
    let bytes = chio_core::canonical::canonical_json_bytes(params)
        .map_err(|e| AcpProxyError::Protocol(format!("hash ACP authorization params: {e}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

/// Returns true for ACP capability requests whose source parameters carry a
/// `toolCallId` and therefore require it to be bound at authorization time.
///
/// The fs/read_text_file, fs/write_text_file, and terminal/create ACP request
/// shapes do not carry a `toolCallId` field; the matching call id arrives later
/// on the `session/update` notification. Only the lifecycle operations that
/// mutate an existing tool call (terminal_kill, terminal_release) require the
/// binding at the capability gate.
fn requires_tool_call_id_binding(operation: &str) -> bool {
    matches!(operation, "terminal_kill" | "terminal_release")
}

fn authorization_correlation_id(
    id: Option<&Value>,
    session_id: &str,
    operation: &str,
    resource: &str,
) -> String {
    let payload = serde_json::json!({
        "id": id.cloned().unwrap_or(Value::Null),
        "sessionId": session_id,
        "operation": operation,
        "resource": resource,
    });
    let bytes = chio_core::canonical::canonical_json_bytes(&payload).unwrap_or_default();
    format!("acp-auth-{}", chio_core::sha256_hex(&bytes))
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

fn extract_tool_call_id(params: &Value) -> Option<String> {
    extract_string_value(params.get("toolCallId"))
        .or_else(|| extract_string_value(params.get("tool_call_id")))
        .or_else(|| {
            params
                .get("toolCall")
                .and_then(|tool_call| extract_string_value(tool_call.get("toolCallId")))
        })
        .or_else(|| {
            params
                .get("tool_call")
                .and_then(|tool_call| extract_string_value(tool_call.get("tool_call_id")))
        })
}

fn extract_string_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(raw) if raw.trim().is_empty() => None,
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    }
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
