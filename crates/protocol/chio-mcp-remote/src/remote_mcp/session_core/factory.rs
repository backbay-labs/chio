use super::*;

impl RemoteSessionFactory {
    pub(super) fn new(config: RemoteServeHttpConfig) -> Result<Self, CliError> {
        let loaded_policy = load_policy(&config.policy_path)?;
        validate_durable_admission_participant_paths(
            loaded_policy.kernel.durable_admission_mode,
            config.control_url.as_deref(),
            config.revocation_db_path.as_deref(),
            config.budget_db_path.as_deref(),
        )?;
        let local_admission_database = if config.control_url.is_none() {
            config
                .session_db_path
                .as_deref()
                .map(durable_admission_sidecar_path)
                .transpose()?
        } else {
            None
        };
        if let Some(admission_database) = local_admission_database.as_deref() {
            let mut paths = vec![("durable admission database", admission_database)];
            for (label, path) in [
                ("remote session database", config.session_db_path.as_deref()),
                ("receipt database", config.receipt_db_path.as_deref()),
                ("revocation database", config.revocation_db_path.as_deref()),
                (
                    "capability authority database",
                    config.authority_db_path.as_deref(),
                ),
                ("budget database", config.budget_db_path.as_deref()),
            ] {
                if let Some(path) = path {
                    paths.push((label, path));
                }
            }
            validate_distinct_database_paths(&paths)?;
        }
        let durable_admission = match (
            loaded_policy.kernel.durable_admission_mode,
            config.control_url.as_deref(),
        ) {
            (chio_kernel::admission_operation::DurableAdmissionMode::Off, _) => None,
            (_, Some(control_url)) => {
                let identity_path = config.session_db_path.as_deref().ok_or_else(|| {
                    CliError::cli_other_error(
                        "hosted MCP durable admission requires --session-db".to_string(),
                    )
                })?;
                let control_token = require_control_token(config.control_token.as_deref())?;
                Some(DurableAdmissionRuntime::open_remote(
                    identity_path,
                    control_url,
                    control_token,
                )?)
            }
            (mode, None) => {
                open_durable_admission_runtime(mode, local_admission_database.as_deref())?
            }
        };
        Ok(Self {
            config,
            durable_admission,
            shared_upstream_owner: Arc::new(StdMutex::new(None)),
            lifecycle_policy: read_session_lifecycle_policy(),
        })
    }

    fn kernel_keypair(
        &self,
        mode: chio_kernel::admission_operation::DurableAdmissionMode,
    ) -> Result<Keypair, CliError> {
        match self.durable_admission.as_ref() {
            Some(runtime) => Ok(runtime.kernel_keypair()),
            None if mode == chio_kernel::admission_operation::DurableAdmissionMode::Off => {
                Ok(Keypair::generate())
            }
            None => Err(CliError::cli_other_error(
                "hosted MCP durable admission runtime is unavailable".to_string(),
            )),
        }
    }

    fn attach_durable_admission(&self, kernel: &mut ChioKernel) -> Result<(), CliError> {
        if kernel.durable_admission_mode()
            == chio_kernel::admission_operation::DurableAdmissionMode::Off
        {
            return Ok(());
        }
        self.durable_admission
            .as_ref()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "hosted MCP durable admission runtime is unavailable".to_string(),
                )
            })?
            .attach(kernel)
    }

    pub(super) fn build_session_upstream_server(&self) -> Result<Arc<AdaptedMcpServer>, CliError> {
        let wrapped_arg_refs = self
            .config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = self
            .config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let adapted_server = AdaptedMcpServer::from_command(
            &self.config.wrapped_command,
            &wrapped_arg_refs,
            McpAdapterConfig {
                server_id: self.config.server_id.clone(),
                server_name: self.config.server_name.clone(),
                server_version: self.config.server_version.clone(),
                public_key: manifest_public_key,
            },
        )?;

        Ok(Arc::new(adapted_server))
    }

    pub(super) fn shared_upstream_owner(&self) -> Result<Arc<SharedUpstreamOwner>, CliError> {
        let mut guard = self.shared_upstream_owner.lock().map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to lock shared remote MCP upstream owner cache: {error}"
            ))
        })?;
        if let Some(owner) = guard.as_ref() {
            return Ok(owner.clone());
        }

        let owner = Arc::new(SharedUpstreamOwner::new(&self.config)?);
        info!(
            server_id = %self.config.server_id,
            "created shared remote MCP hosted owner"
        );
        *guard = Some(owner.clone());
        Ok(owner)
    }

    pub(super) fn configured_hosted_isolation(&self) -> RemoteHostedIsolationMode {
        if self.config.shared_hosted_owner {
            RemoteHostedIsolationMode::SharedHostedOwnerCompatibility
        } else {
            RemoteHostedIsolationMode::DedicatedPerSession
        }
    }

    pub(super) fn spawn_session(
        &self,
        auth_context: SessionAuthContext,
    ) -> Result<Arc<RemoteSession>, CliError> {
        let session_id = Keypair::generate().public_key().to_hex();
        let loaded_policy = load_policy(&self.config.policy_path)?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(&self.config)?;
        let policy_fingerprint = fingerprint_remote_policy_contract(&loaded_policy)?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        let resume_integrity_secret = derive_resume_record_integrity_seed(&self.config)?;
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let upstream_capabilities = upstream_server.upstream_capabilities();
        let manifest = upstream_server.manifest_clone();

        let kernel_kp = self.kernel_keypair(loaded_policy.kernel.durable_admission_mode)?;
        let mut kernel = build_kernel(loaded_policy, &kernel_kp);
        configure_receipt_store(
            &mut kernel,
            self.config.receipt_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if self.durable_admission.is_none() {
            configure_revocation_store(
                &mut kernel,
                self.config.revocation_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
            )?;
        }
        self.attach_durable_admission(&mut kernel)?;
        configure_capability_authority(
            &mut kernel,
            &kernel_kp,
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
            self.config.receipt_db_path.as_deref(),
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
            issuance_policy,
            runtime_assurance_policy,
        )?;
        if self.durable_admission.is_none() {
            configure_budget_store(
                &mut kernel,
                self.config.budget_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
            )?;
        }
        if let Some(resource_provider) = upstream_server.resource_provider() {
            kernel.register_resource_provider(Box::new(resource_provider));
        }
        if let Some(prompt_provider) = upstream_server.prompt_provider() {
            kernel.register_prompt_provider(Box::new(prompt_provider));
        }
        kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
            upstream_server.clone(),
        )));

        let hosted_isolation = self.configured_hosted_isolation();
        let session_auth_context = hosted_isolation.snapshot_auth_context(auth_context);

        let agent_kp = derive_session_agent_keypair(&self.config, &session_auth_context)?;
        let agent_pk = agent_kp.public_key();
        let agent_id = agent_pk.to_hex();
        let capabilities: Vec<CapabilityToken> =
            issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
        let session_capabilities = capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect();

        let mut edge = ChioMcpEdge::new(
            McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            },
            kernel,
            agent_id.clone(),
            capabilities.clone(),
            vec![manifest],
        )?;
        edge.set_session_auth_context(session_auth_context.clone());
        edge.set_initial_session_id(restored_kernel_session_id(&session_id))?;
        edge.attach_upstream_transport(upstream_notification_source);

        let (input_tx, input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let writer = BroadcastJsonRpcWriter::new(
            event_tx.clone(),
            retained_notification_events.clone(),
            next_event_id.clone(),
            session_id.clone(),
        );

        std::thread::spawn(move || {
            if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                error!(error = %error, "remote MCP edge session worker exited with error");
            }
        });

        Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
            session_id,
            agent_id,
            capabilities: session_capabilities,
            issued_capabilities: capabilities,
            auth_context: session_auth_context,
            auth_mode_fingerprint,
            policy_fingerprint,
            hosted_isolation,
            lifecycle_policy: self.lifecycle_policy.clone(),
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: None,
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: self.config.session_db_path.clone(),
            resume_integrity_secret,
        })))
    }

    pub(super) fn restore_session(
        &self,
        record: &RemoteSessionResumeRecord,
    ) -> Result<Arc<RemoteSession>, CliError> {
        validate_resume_record_integrity(&self.config, record)?;
        let configured_hosted_isolation = self.configured_hosted_isolation();
        if configured_hosted_isolation != record.hosted_isolation {
            return Err(CliError::cli_other_error(format!(
                "stored MCP session {} expects hosted isolation {:?} but the server is configured for {:?}",
                record.session_id, record.hosted_isolation, configured_hosted_isolation
            )));
        }
        if let Some(expected_agent_id) =
            expected_resume_agent_id(&self.config, &record.auth_context)?
        {
            if expected_agent_id != record.agent_id {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} failed authenticated principal re-validation during restore",
                    record.session_id
                )));
            }
        }

        let loaded_policy = load_policy(&self.config.policy_path)?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(&self.config)?;
        let policy_fingerprint = fingerprint_remote_policy_contract(&loaded_policy)?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        let resume_integrity_secret = derive_resume_record_integrity_seed(&self.config)?;
        match record.auth_mode_fingerprint.as_deref() {
            Some(stored) if stored == auth_mode_fingerprint => {}
            Some(_) => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} was created under different serve-http auth settings",
                    record.session_id
                )));
            }
            None => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} predates auth contract fingerprinting and must be re-initialized",
                    record.session_id
                )));
            }
        }
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let upstream_capabilities = upstream_server.upstream_capabilities();
        let manifest = upstream_server.manifest_clone();

        let kernel_kp = self.kernel_keypair(loaded_policy.kernel.durable_admission_mode)?;
        let mut kernel = build_kernel(loaded_policy, &kernel_kp);
        configure_receipt_store(
            &mut kernel,
            self.config.receipt_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if self.durable_admission.is_none() {
            configure_revocation_store(
                &mut kernel,
                self.config.revocation_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
            )?;
        }
        self.attach_durable_admission(&mut kernel)?;
        configure_capability_authority(
            &mut kernel,
            &kernel_kp,
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
            self.config.receipt_db_path.as_deref(),
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
            issuance_policy,
            runtime_assurance_policy,
        )?;
        if self.durable_admission.is_none() {
            configure_budget_store(
                &mut kernel,
                self.config.budget_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
            )?;
        }
        if let Some(resource_provider) = upstream_server.resource_provider() {
            kernel.register_resource_provider(Box::new(resource_provider));
        }
        if let Some(prompt_provider) = upstream_server.prompt_provider() {
            kernel.register_prompt_provider(Box::new(prompt_provider));
        }
        kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
            upstream_server.clone(),
        )));

        let agent_public_key = PublicKey::from_hex(&record.agent_id)?;
        let restored_peer_capabilities = validate_restored_peer_capabilities(record)?;
        let issued_capabilities = match record.policy_fingerprint.as_deref() {
            Some(stored)
                if stored == policy_fingerprint
                    && stored_capabilities_are_current(&record.issued_capabilities)
                    && stored_capability_issuers_are_trusted(&kernel, &record.issued_capabilities)
                    && record
                        .issued_capabilities
                        .iter()
                        .all(|capability| capability.subject == agent_public_key) =>
            {
                record.issued_capabilities.clone()
            }
            _ => issue_default_capabilities(&kernel, &agent_public_key, &default_capabilities)?,
        };
        let session_capabilities = issued_capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect::<Vec<_>>();

        let mut edge = ChioMcpEdge::new(
            McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            },
            kernel,
            record.agent_id.clone(),
            issued_capabilities.clone(),
            vec![manifest],
        )?;
        edge.set_session_auth_context(record.auth_context.clone());
        edge.attach_upstream_transport(upstream_notification_source);
        edge.restore_ready_session(
            restored_kernel_session_id(&record.session_id),
            restored_peer_capabilities.clone(),
        )?;

        let (input_tx, input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let writer = BroadcastJsonRpcWriter::new(
            event_tx.clone(),
            retained_notification_events.clone(),
            next_event_id.clone(),
            record.session_id.clone(),
        );

        std::thread::spawn(move || {
            if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                error!(error = %error, "remote MCP edge session worker exited with error");
            }
        });

        Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
            session_id: record.session_id.clone(),
            agent_id: record.agent_id.clone(),
            capabilities: session_capabilities,
            issued_capabilities,
            auth_context: record.auth_context.clone(),
            auth_mode_fingerprint,
            policy_fingerprint,
            hosted_isolation: record.hosted_isolation,
            lifecycle_policy: self.lifecycle_policy.clone(),
            protocol_version: record.protocol_version.clone(),
            peer_capabilities: Some(restored_peer_capabilities),
            initialize_params: Some(record.initialize_params.clone()),
            lifecycle_snapshot: Some(record.lifecycle.clone()),
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: self.config.session_db_path.clone(),
            resume_integrity_secret,
        })))
    }
}
