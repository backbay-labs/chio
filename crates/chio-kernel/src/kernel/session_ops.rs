use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::mapref::entry::Entry;

use crate::session::{SessionAnchorSnapshot, SessionRequestStart};

use super::*;

static GLOBAL_SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn bump_session_counter_from_id(session_id: &SessionId) {
    let Some(number) = session_id
        .as_str()
        .strip_prefix("sess-")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return;
    };

    let mut current = GLOBAL_SESSION_COUNTER.load(Ordering::SeqCst);
    while current < number {
        match GLOBAL_SESSION_COUNTER.compare_exchange(
            current,
            number,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn map_session_persist_error(error: SessionPersistError<KernelError>) -> KernelError {
    match error {
        SessionPersistError::Session(error) => KernelError::Session(error),
        SessionPersistError::Persist(error) => error,
    }
}

impl ChioKernel {
    pub fn open_session(
        &self,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> SessionId {
        let session_number = GLOBAL_SESSION_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
        let session_id = SessionId::new(format!("sess-{}", session_number));

        self.open_session_with_id(session_id, agent_id, issued_capabilities)
            .unwrap_or_else(|error| panic!("failed to open session: {error}"))
    }

    pub fn open_session_with_id(
        &self,
        session_id: SessionId,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> Result<SessionId, KernelError> {
        bump_session_counter_from_id(&session_id);

        info!(session_id = %session_id, agent_id = %agent_id, "opening session");
        let session = self.with_sessions_write(|sessions| {
            let session = Arc::new(Session::new(
                session_id.clone(),
                agent_id,
                issued_capabilities,
            ));
            match sessions.entry(session_id.clone()) {
                Entry::Occupied(_) => Err(KernelError::SessionAlreadyExists(session_id.clone())),
                Entry::Vacant(entry) => {
                    entry.insert(Arc::clone(&session));
                    Ok(session)
                }
            }
        })?;
        let session_snapshot = session.session_anchor_snapshot();
        if let Err(error) = self.persist_session_anchor_snapshot(&session_snapshot, None) {
            self.with_sessions_write(|sessions| {
                sessions.remove(&session_id);
                Ok(())
            })?;
            return Err(error);
        }

        Ok(session_id)
    }

    /// Transition a session into the `ready` state once setup is complete.
    pub fn activate_session(&self, session_id: &SessionId) -> Result<(), KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.with_session_mut(session_id, |session| {
            session.activate()?;
            Ok(())
        })
    }

    /// Persist transport/session authentication context for a session.
    pub fn set_session_auth_context(
        &self,
        session_id: &SessionId,
        auth_context: SessionAuthContext,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session
                .set_auth_context_persisted(auth_context, |session_snapshot, supersedes| {
                    self.persist_session_anchor_snapshot(session_snapshot, supersedes)
                })
                .map_err(map_session_persist_error)
        })
    }

    /// Persist peer capabilities negotiated at the edge for a session.
    pub fn set_session_peer_capabilities(
        &self,
        session_id: &SessionId,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.set_peer_capabilities(peer_capabilities);
            Ok(())
        })
    }

    /// Replace the session's current root snapshot.
    pub fn replace_session_roots(
        &self,
        session_id: &SessionId,
        roots: Vec<RootDefinition>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.replace_roots(roots);
            Ok(())
        })
    }

    /// Return the runtime's normalized root view for a session.
    pub fn normalized_session_roots(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<NormalizedRoot>, KernelError> {
        self.with_session(session_id, |session| Ok(session.normalized_roots()))
    }

    /// Return only the enforceable filesystem root paths for a session.
    pub fn enforceable_filesystem_root_paths(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<String>, KernelError> {
        self.with_session(session_id, |session| {
            Ok(session
                .enforceable_filesystem_roots()
                .into_iter()
                .filter_map(|root| root.normalized_filesystem_path().map(str::to_string))
                .collect())
        })
    }

    pub(crate) fn session_enforceable_filesystem_root_paths_owned(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<String>, KernelError> {
        self.with_session(session_id, |session| {
            Ok(session
                .enforceable_filesystem_roots()
                .into_iter()
                .filter_map(|root| root.normalized_filesystem_path().map(str::to_string))
                .collect())
        })
    }

    pub(crate) fn resource_path_within_root(candidate: &str, root: &str) -> bool {
        if candidate == root {
            return true;
        }

        if root == "/" {
            return candidate.starts_with('/');
        }

        candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
    }

    pub(crate) fn resource_path_matches_session_roots(
        path: &str,
        session_roots: &[String],
    ) -> bool {
        if session_roots.is_empty() {
            return false;
        }

        session_roots
            .iter()
            .any(|root| Self::resource_path_within_root(path, root))
    }

    pub(crate) fn enforce_resource_roots(
        &self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<(), KernelError> {
        match operation.classify_uri_for_runtime() {
            ResourceUriClassification::NonFileSystem { .. } => Ok(()),
            ResourceUriClassification::EnforceableFileSystem {
                normalized_path, ..
            } => {
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                if Self::resource_path_matches_session_roots(&normalized_path, &session_roots) {
                    Ok(())
                } else {
                    let reason = if session_roots.is_empty() {
                        "no enforceable filesystem roots are available for this session".to_string()
                    } else {
                        format!(
                            "filesystem-backed resource path {normalized_path} is outside the negotiated roots"
                        )
                    };

                    Err(KernelError::ResourceRootDenied {
                        uri: operation.uri.clone(),
                        reason,
                    })
                }
            }
            ResourceUriClassification::UnenforceableFileSystem { reason, .. } => {
                Err(KernelError::ResourceRootDenied {
                    uri: operation.uri.clone(),
                    reason: format!(
                        "filesystem-backed resource URI could not be enforced: {reason}"
                    ),
                })
            }
        }
    }

    pub(crate) fn build_resource_read_deny_receipt(
        &self,
        operation: &ReadResourceOperation,
        reason: &str,
    ) -> Result<ChioReceipt, KernelError> {
        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "uri": &operation.uri,
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash resource read parameters: {error}"
            ))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &operation.capability.id,
            tool_name: "resources/read",
            server_id: "session",
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "session_roots".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                Some(serde_json::json!({
                    "resource": {
                        "uri": &operation.uri,
                    }
                })),
                receipt_attribution_metadata(&operation.capability, None),
            ),
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Subscribe the session to update notifications for a concrete resource URI.
    pub fn subscribe_session_resource(
        &self,
        session_id: &SessionId,
        capability: &CapabilityToken,
        agent_id: &str,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.validate_non_tool_capability(capability, agent_id)?;

        if !capability_matches_resource_subscription(capability, uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: uri.to_string(),
            });
        }

        if !self.resource_exists(uri)? {
            return Err(KernelError::ResourceNotRegistered(uri.to_string()));
        }

        self.with_session_mut(session_id, |session| {
            session.subscribe_resource(uri.to_string());
            Ok(())
        })
    }

    /// Remove a session-scoped resource subscription. Missing subscriptions are ignored.
    pub fn unsubscribe_session_resource(
        &self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.unsubscribe_resource(uri);
            Ok(())
        })
    }

    /// Check whether a session currently holds a resource subscription.
    pub fn session_has_resource_subscription(
        &self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<bool, KernelError> {
        self.with_session(
            session_id,
            |session| Ok(session.is_resource_subscribed(uri)),
        )
    }

    /// Mark a session as draining. New tool calls are rejected after this point.
    pub fn begin_draining_session(&self, session_id: &SessionId) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.begin_draining()?;
            Ok(())
        })
    }

    /// Close a session and clear transient session-scoped state.
    pub fn close_session(&self, session_id: &SessionId) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session
                .close_persisted(|session_snapshot, supersedes| {
                    self.persist_session_anchor_snapshot(session_snapshot, supersedes)
                })
                .map_err(map_session_persist_error)
        })
    }

    /// Inspect an existing session.
    pub fn session(&self, session_id: &SessionId) -> Option<Session> {
        self.with_sessions_read(|sessions| {
            Ok(sessions
                .get(session_id)
                .map(|session| session.value().as_ref().clone()))
        })
        .ok()
        .flatten()
    }

    pub fn session_count(&self) -> usize {
        self.with_sessions_read(|sessions| Ok(sessions.len()))
            .unwrap_or(0)
    }

    pub fn resource_provider_count(&self) -> usize {
        self.resource_providers.len()
    }

    pub fn prompt_provider_count(&self) -> usize {
        self.prompt_providers.len()
    }

    /// Validate a session-scoped operation and register it as in flight.
    pub fn begin_session_request(
        &self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<(), KernelError> {
        let start = self.with_sessions_write(|sessions| {
            begin_session_request_in_sessions(sessions, context, operation_kind, cancellable)
        })?;
        if let Err(error) = self.persist_request_lineage_snapshot(&start) {
            let _ = self.with_sessions_write(|sessions| {
                if let Ok(session) = session_from_map(sessions, &start.session.session_id) {
                    session.discard_unpersisted_request_start(&start.lineage.request_id);
                }
                Ok(())
            });
            return Err(error);
        }
        Ok(())
    }

    /// Construct and register a child request under an existing parent request.
    pub fn begin_child_request(
        &self,
        parent_context: &OperationContext,
        request_id: RequestId,
        operation_kind: OperationKind,
        progress_token: Option<ProgressToken>,
        cancellable: bool,
    ) -> Result<OperationContext, KernelError> {
        let (child_context, start) = self.with_sessions_write(|sessions| {
            begin_child_request_in_sessions(
                sessions,
                parent_context,
                request_id,
                operation_kind,
                progress_token,
                cancellable,
            )
        })?;
        if let Err(error) = self.persist_request_lineage_snapshot(&start) {
            let _ = self.with_sessions_write(|sessions| {
                if let Ok(session) = session_from_map(sessions, &start.session.session_id) {
                    session.discard_unpersisted_request_start(&start.lineage.request_id);
                }
                Ok(())
            });
            return Err(error);
        }
        Ok(child_context)
    }

    /// Complete an in-flight session request.
    pub fn complete_session_request(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.complete_session_request_with_terminal_state(
            session_id,
            request_id,
            OperationTerminalState::Completed,
        )
    }

    /// Complete an in-flight session request with an explicit terminal state.
    pub fn complete_session_request_with_terminal_state(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<(), KernelError> {
        self.with_sessions_write(|sessions| {
            complete_session_request_with_terminal_state_in_sessions(
                sessions,
                session_id,
                request_id,
                terminal_state,
            )
        })
    }

    fn signed_session_anchor_for_snapshot(
        &self,
        snapshot: &SessionAnchorSnapshot,
    ) -> Result<chio_core::session::SessionAnchor, KernelError> {
        let body = chio_core::session::SessionAnchorBody::new(
            snapshot.session_anchor.id().to_string(),
            chio_core::session::SessionAnchorContext::new(
                snapshot.session_id.clone(),
                snapshot.agent_id.clone(),
                snapshot.auth_context.clone(),
                chio_core::session::SessionProofBinding::from_auth_context(&snapshot.auth_context),
            ),
            snapshot.session_anchor.auth_epoch(),
            snapshot.session_anchor.issued_at(),
            self.config.keypair.public_key(),
        )
        .map_err(|error| {
            KernelError::Internal(format!("failed to build session anchor body: {error}"))
        })?;

        chio_core::session::SessionAnchor::sign(body, &self.config.keypair).map_err(|error| {
            KernelError::Internal(format!("failed to sign session anchor: {error}"))
        })
    }

    fn persist_session_anchor_snapshot(
        &self,
        session: &SessionAnchorSnapshot,
        supersedes_anchor_id: Option<&str>,
    ) -> Result<(), KernelError> {
        let anchor = self.signed_session_anchor_for_snapshot(session)?;
        let anchor_json = serde_json::to_value(&anchor).map_err(|error| {
            KernelError::Internal(format!("failed to serialize session anchor: {error}"))
        })?;
        self.with_receipt_store(|store| {
            Ok(store.record_session_anchor(
                session.session_id.as_str(),
                &anchor.id,
                &anchor.auth_context_hash,
                anchor.issued_at,
                supersedes_anchor_id,
                &anchor_json,
            )?)
        })?;
        Ok(())
    }

    fn persist_request_lineage_snapshot(
        &self,
        start: &SessionRequestStart,
    ) -> Result<(), KernelError> {
        let local_lineage = &start.lineage;
        let anchor = self.signed_session_anchor_for_snapshot(&start.session)?;
        let anchor_reference = anchor.reference().map_err(|error| {
            KernelError::Internal(format!(
                "failed to derive session anchor reference: {error}"
            ))
        })?;
        let lineage_mode = if local_lineage.parent_request_id.is_some() {
            chio_core::session::RequestLineageMode::LocalChild
        } else {
            chio_core::session::RequestLineageMode::Root
        };
        let mut lineage_record = chio_core::session::RequestLineageRecord::new(
            local_lineage.request_id.clone(),
            anchor_reference,
            local_lineage.operation_kind,
            lineage_mode,
            local_lineage.started_at,
        );
        if let Some(parent_request_id) = local_lineage.parent_request_id.clone() {
            lineage_record = lineage_record.with_parent_request_id(parent_request_id);
        }
        let lineage_json = serde_json::to_value(&lineage_record).map_err(|error| {
            KernelError::Internal(format!("failed to serialize request lineage: {error}"))
        })?;
        self.with_receipt_store(|store| {
            Ok(store.record_request_lineage(
                start.session.session_id.as_str(),
                local_lineage.request_id.as_str(),
                local_lineage
                    .parent_request_id
                    .as_ref()
                    .map(|value| value.as_str()),
                Some(anchor.id.as_str()),
                local_lineage.started_at,
                None,
                &lineage_json,
            )?)
        })?;
        Ok(())
    }

    /// Mark an in-flight session request as cancelled.
    pub fn request_session_cancellation(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session
                .request_cancellation(request_id)
                .map_err(KernelError::from)
        })
    }

    /// Validate whether a sampling child request is allowed for this session.
    pub fn validate_sampling_request(
        &self,
        context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<(), KernelError> {
        self.with_sessions_read(|sessions| {
            validate_sampling_request_in_sessions(
                sessions,
                self.config.allow_sampling,
                self.config.allow_sampling_tool_use,
                context,
                operation,
            )
        })
    }

    /// Validate whether an elicitation child request is allowed for this session.
    pub fn validate_elicitation_request(
        &self,
        context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<(), KernelError> {
        self.with_sessions_read(|sessions| {
            validate_elicitation_request_in_sessions(
                sessions,
                self.config.allow_elicitation,
                context,
                operation,
            )
        })
    }

    /// Evaluate a session-scoped tool call while allowing the target tool server to proxy
    /// negotiated nested flows back through a client transport owned by the edge.
    pub fn evaluate_tool_call_operation_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.begin_session_request(context, OperationKind::ToolCall, true)?;

        let request = ToolCallRequest {
            request_id: context.request_id.to_string(),
            capability: operation.capability.clone(),
            tool_name: operation.tool_name.clone(),
            server_id: operation.server_id.clone(),
            agent_id: context.agent_id.clone(),
            arguments: operation.arguments.clone(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: operation.model_metadata.clone(),
            federated_origin_kernel_id: None,
        };

        let result = self.evaluate_tool_call_with_nested_flow_client(context, &request, client);
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.with_session_mut(&context.session_id, |session| {
                    session.request_cancellation(&context.request_id)?;
                    Ok(())
                })?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.complete_session_request_with_terminal_state(
            &context.session_id,
            &context.request_id,
            terminal_state,
        )?;
        result
    }

    /// Evaluate a normalized operation against a specific session.
    ///
    /// This is the higher-level entry point that future JSON-RPC or MCP edges
    /// should target. The current stdio loop normalizes raw frames into these
    /// operations before invoking the kernel.
    pub fn evaluate_session_operation(
        &self,
        context: &OperationContext,
        operation: &SessionOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        // Phase 1.5: install tenant_id scope for the duration of this
        // session-scoped evaluation so every receipt signed here (tool
        // call, resource read deny, etc.) is tagged with the session's
        // tenant. The ToolCall branch also installs a scope via its
        // sync_with_session_context path; the nested scope is a no-op
        // because the value matches, but it keeps non-tool-call branches
        // (e.g. evaluate_resource_read) covered.
        let tenant_id = self.resolve_tenant_id_for_session(Some(&context.session_id));
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);

        self.validate_web3_evidence_prerequisites()?;
        let operation_kind = operation.kind();
        let should_track_inflight = matches!(
            operation,
            SessionOperation::ToolCall(_)
                | SessionOperation::ReadResource(_)
                | SessionOperation::GetPrompt(_)
                | SessionOperation::Complete(_)
        );

        if should_track_inflight {
            self.begin_session_request(context, operation_kind, true)?;
        } else {
            self.with_session_mut(&context.session_id, |session| {
                session.validate_context(context)?;
                session.ensure_operation_allowed(operation_kind)?;
                Ok(())
            })?;
        }

        let evaluation = match operation {
            SessionOperation::ToolCall(tool_call) => {
                let request = ToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability.clone(),
                    tool_name: tool_call.tool_name.clone(),
                    server_id: tool_call.server_id.clone(),
                    agent_id: context.agent_id.clone(),
                    arguments: tool_call.arguments.clone(),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: tool_call.model_metadata.clone(),
                    federated_origin_kernel_id: None,
                };
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                // Phase 1.5: pass the session_id so the evaluate path can
                // resolve tenant_id from session.auth_context for every
                // receipt signed during this tool call.
                self.evaluate_tool_call_sync_with_session_context(
                    &request,
                    Some(session_roots.as_slice()),
                    None,
                    Some(&context.session_id),
                )
                .map(SessionOperationResponse::ToolCall)
            }
            SessionOperation::CreateMessage(_) => Err(KernelError::Internal(
                "sampling/createMessage must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::CreateElicitation(_) => Err(KernelError::Internal(
                "elicitation/create must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::ListRoots => {
                let roots = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .roots();
                Ok(SessionOperationResponse::RootList { roots })
            }
            SessionOperation::ListResources => {
                let resources = self
                    .list_resources_for_session(&context.session_id)?
                    .into_iter()
                    .collect();
                Ok(SessionOperationResponse::ResourceList { resources })
            }
            SessionOperation::ReadResource(resource_read) => {
                self.evaluate_resource_read(context, resource_read)
            }
            SessionOperation::ListResourceTemplates => {
                let templates = self.list_resource_templates_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::ResourceTemplateList { templates })
            }
            SessionOperation::ListPrompts => {
                let prompts = self.list_prompts_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::PromptList { prompts })
            }
            SessionOperation::GetPrompt(prompt_get) => self
                .evaluate_prompt_get(context, prompt_get)
                .map(|prompt| SessionOperationResponse::PromptGet { prompt }),
            SessionOperation::Complete(complete) => self
                .evaluate_completion(context, complete)
                .map(|completion| SessionOperationResponse::Completion { completion }),
            SessionOperation::ListCapabilities => {
                let capabilities = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .capabilities()
                    .to_vec();

                Ok(SessionOperationResponse::CapabilityList { capabilities })
            }
            SessionOperation::Heartbeat => Ok(SessionOperationResponse::Heartbeat),
        };

        if should_track_inflight {
            let terminal_state = match &evaluation {
                Ok(SessionOperationResponse::ToolCall(response)) => response.terminal_state.clone(),
                _ => OperationTerminalState::Completed,
            };
            self.complete_session_request_with_terminal_state(
                &context.session_id,
                &context.request_id,
                terminal_state,
            )?;
        }

        evaluation
    }

    pub(crate) fn list_resources_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut resources = Vec::new();
        for provider in &self.resource_providers {
            resources.extend(provider.list_resources().into_iter().filter(|resource| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_resource_request(capability, &resource.uri).unwrap_or(false)
                })
            }));
        }

        Ok(resources)
    }

    pub(crate) fn resource_exists(&self, uri: &str) -> Result<bool, KernelError> {
        for provider in &self.resource_providers {
            if provider
                .list_resources()
                .iter()
                .any(|resource| resource.uri == uri)
            {
                return Ok(true);
            }

            if provider.read_resource(uri)?.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub(crate) fn list_resource_templates_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceTemplateDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut templates = Vec::new();
        for provider in &self.resource_providers {
            templates.extend(
                provider
                    .list_resource_templates()
                    .into_iter()
                    .filter(|template| {
                        session.capabilities().iter().any(|capability| {
                            capability_matches_resource_pattern(capability, &template.uri_template)
                                .unwrap_or(false)
                        })
                    }),
            );
        }

        Ok(templates)
    }

    pub(crate) fn evaluate_resource_read(
        &self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_resource_request(&operation.capability, &operation.uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: operation.uri.clone(),
            });
        }

        match self.enforce_resource_roots(context, operation) {
            Ok(()) => {}
            Err(KernelError::ResourceRootDenied { reason, .. }) => {
                let receipt = self.build_resource_read_deny_receipt(operation, &reason)?;
                return Ok(SessionOperationResponse::ResourceReadDenied { receipt });
            }
            Err(error) => return Err(error),
        }

        for provider in &self.resource_providers {
            if let Some(contents) = provider.read_resource(&operation.uri)? {
                return Ok(SessionOperationResponse::ResourceRead { contents });
            }
        }

        Err(KernelError::ResourceNotRegistered(operation.uri.clone()))
    }

    pub(crate) fn list_prompts_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<PromptDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut prompts = Vec::new();
        for provider in &self.prompt_providers {
            prompts.extend(provider.list_prompts().into_iter().filter(|prompt| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_prompt_request(capability, &prompt.name).unwrap_or(false)
                })
            }));
        }

        Ok(prompts)
    }

    pub(crate) fn evaluate_prompt_get(
        &self,
        context: &OperationContext,
        operation: &GetPromptOperation,
    ) -> Result<PromptResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_prompt_request(&operation.capability, &operation.prompt_name)? {
            return Err(KernelError::OutOfScopePrompt {
                prompt: operation.prompt_name.clone(),
            });
        }

        for provider in &self.prompt_providers {
            if let Some(prompt) =
                provider.get_prompt(&operation.prompt_name, operation.arguments.clone())?
            {
                return Ok(prompt);
            }
        }

        Err(KernelError::PromptNotRegistered(
            operation.prompt_name.clone(),
        ))
    }

    pub(crate) fn evaluate_completion(
        &self,
        context: &OperationContext,
        operation: &CompleteOperation,
    ) -> Result<CompletionResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        match &operation.reference {
            CompletionReference::Prompt { name } => {
                if !capability_matches_prompt_request(&operation.capability, name)? {
                    return Err(KernelError::OutOfScopePrompt {
                        prompt: name.clone(),
                    });
                }

                for provider in &self.prompt_providers {
                    if let Some(completion) = provider.complete_prompt_argument(
                        name,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::PromptNotRegistered(name.clone()))
            }
            CompletionReference::Resource { uri } => {
                if !capability_matches_resource_pattern(&operation.capability, uri)? {
                    return Err(KernelError::OutOfScopeResource { uri: uri.clone() });
                }

                for provider in &self.resource_providers {
                    if let Some(completion) = provider.complete_resource_argument(
                        uri,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::ResourceNotRegistered(uri.clone()))
            }
        }
    }
}
