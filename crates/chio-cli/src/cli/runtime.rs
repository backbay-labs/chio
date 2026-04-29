fn cmd_run(
    policy_path: &Path,
    command: &[String],
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps.clone());

    info!(
        capability_count = initial_caps.len(),
        agent_id = %session_agent_id,
        "issued initial capabilities to agent"
    );

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty command".to_string()))?;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdout".to_string()))?;

    let mut transport = ChioTransport::new(child_stdout, child_stdin);

    let init_msg = KernelMessage::CapabilityList {
        capabilities: initial_caps.clone(),
    };
    transport.send(&init_msg)?;
    kernel.activate_session(&session_id)?;

    info!("sent initial capabilities to agent, entering message loop");

    let mut stats = SessionStats::default();

    loop {
        let agent_msg = match transport.recv() {
            Ok(msg) => msg,
            Err(TransportError::ConnectionClosed) => {
                debug!("agent closed connection");
                break;
            }
            Err(e) => {
                warn!(error = %e, "transport read error");
                break;
            }
        };

        let kernel_msgs = handle_agent_message(
            &mut kernel,
            &agent_msg,
            &session_id,
            &session_agent_id,
            &mut stats,
        );

        let mut write_failed = false;
        for kernel_msg in kernel_msgs {
            if let Err(e) = transport.send(&kernel_msg) {
                warn!(error = %e, "transport write error");
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }
    }

    if let Err(e) = kernel.begin_draining_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to mark session draining");
    }

    if let Err(e) = kernel.close_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to close session");
    }

    let status = child.wait()?;
    print_summary(&stats, status.code(), json_output);

    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        Err(CliError::Other(format!("agent exited with code {code}")))
    }
}

fn cmd_api_protect(
    upstream: &str,
    spec_path: Option<&Path>,
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::Other(format!("failed to start async runtime: {error}")))?;

    runtime.block_on(async move {
        let sidecar_control_token = std::env::var("CHIO_SIDECAR_CONTROL_TOKEN")
            .ok()
            .or_else(|| std::env::var("CHIO_API_PROTECT_CONTROL_TOKEN").ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let signer_seed_hex = authority_seed_path
            .map(load_or_create_authority_keypair)
            .transpose()?
            .map(|keypair| keypair.seed_hex());
        let trusted_capability_issuers = parse_trusted_capability_issuers_from_env()?;
        let config = ProtectConfig {
            upstream: upstream.to_string(),
            spec_content: None,
            spec_path: spec_path.map(|path| path.display().to_string()),
            listen_addr: listen_addr.to_string(),
            receipt_db: receipt_store.map(|path| path.display().to_string()),
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
        };
        ProtectProxy::new(config)
            .run()
            .await
            .map_err(|error| CliError::Other(format!("failed to start chio api protect: {error}")))
    })
}

fn parse_trusted_capability_issuers_from_env() -> Result<Vec<chio_core::PublicKey>, CliError> {
    let mut issuers = Vec::new();

    if let Ok(single_issuer) = std::env::var("CHIO_TRUSTED_ISSUER_KEY") {
        let single_issuer = single_issuer.trim();
        if !single_issuer.is_empty() {
            issuers.push(
                chio_core::PublicKey::from_hex(single_issuer).map_err(|error| {
                    CliError::Other(format!(
                        "failed to parse CHIO_TRUSTED_ISSUER_KEY as a public key: {error}"
                    ))
                })?,
            );
        }
    }

    if let Ok(multiple_issuers) = std::env::var("CHIO_TRUSTED_ISSUER_KEYS") {
        for issuer in multiple_issuers
            .split(',')
            .map(str::trim)
            .filter(|issuer| !issuer.is_empty())
        {
            let parsed = chio_core::PublicKey::from_hex(issuer).map_err(|error| {
                CliError::Other(format!(
                    "failed to parse CHIO_TRUSTED_ISSUER_KEYS entry as a public key: {error}"
                ))
            })?;
            if !issuers.contains(&parsed) {
                issuers.push(parsed);
            }
        }
    }

    Ok(issuers)
}

fn cmd_check(
    policy_path: &Path,
    tool: &str,
    params_str: &str,
    server: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    kernel.register_tool_server(Box::new(StubToolServer {
        id: server.to_string(),
    }));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let params: serde_json::Value = serde_json::from_str(params_str)?;
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let cap = match select_capability_for_request(&initial_caps, tool, server, &params) {
        Some(capability) => capability,
        None => kernel
            .issue_capability(&agent_pk, ChioScope::default(), 300)
            .map_err(|error| {
                CliError::Other(format!(
                    "failed to issue fallback empty capability: {error}"
                ))
            })?,
    };
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps);
    kernel.activate_session(&session_id)?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("check-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        arguments: params.clone(),
        model_metadata: None,
    });

    let response = match kernel.evaluate_session_operation(&context, &operation)? {
        SessionOperationResponse::ToolCall(response) => response,
        SessionOperationResponse::RootList { .. }
        | SessionOperationResponse::ResourceList { .. }
        | SessionOperationResponse::ResourceRead { .. }
        | SessionOperationResponse::ResourceReadDenied { .. }
        | SessionOperationResponse::ResourceTemplateList { .. }
        | SessionOperationResponse::PromptList { .. }
        | SessionOperationResponse::PromptGet { .. }
        | SessionOperationResponse::Completion { .. }
        | SessionOperationResponse::CapabilityList { .. }
        | SessionOperationResponse::Heartbeat => {
            return Err(CliError::Other(
                "unexpected non-tool response while evaluating check command".to_string(),
            ));
        }
    };

    kernel.begin_draining_session(&session_id)?;
    kernel.close_session(&session_id)?;

    let verdict_str = verdict_label(response.verdict);

    if json_output {
        let output = serde_json::json!({
            "verdict": verdict_str,
            "tool": tool,
            "server": server,
            "params": params,
            "reason": response.reason,
            "receipt_id": response.receipt.id,
            "policy_hash": policy_identity.runtime_hash,
            "policy_source_hash": policy_identity.source_hash,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("verdict:    {verdict_str}");
        println!("tool:       {tool}");
        println!("server:     {server}");
        if let Some(reason) = &response.reason {
            println!("reason:     {reason}");
        }
        println!("receipt_id: {}", response.receipt.id);
        println!("policy:     {}", policy_identity.runtime_hash);
        println!("source:     {}", policy_identity.source_hash);
    }

    match response.verdict {
        chio_kernel::Verdict::Allow => Ok(()),
        chio_kernel::Verdict::Deny => {
            std::process::exit(2);
        }
        chio_kernel::Verdict::PendingApproval => {
            // Treat approval-pending as a soft deny from the CLI
            // perspective; the orchestrator can resume once the
            // human has approved out-of-band.
            std::process::exit(3);
        }
    }
}

fn verdict_label(verdict: chio_kernel::Verdict) -> &'static str {
    match verdict {
        chio_kernel::Verdict::Allow => "ALLOW",
        chio_kernel::Verdict::Deny => "DENY",
        chio_kernel::Verdict::PendingApproval => "PENDING_APPROVAL",
    }
}

fn cmd_mcp_serve(
    policy_path: Option<&Path>,
    preset: Option<&str>,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    // Resolve `--preset` to a materialized YAML on disk so the rest
    // of the plumbing can use `load_policy` unchanged. Keeping the
    // preset on disk also keeps the source_policy_hash deterministic
    // across runs so receipt verification continues to work.
    let materialized_preset = match (policy_path, preset) {
        (Some(_), None) => None,
        (None, Some(name)) => {
            let preset = policies::McpPreset::from_name(name).ok_or_else(|| {
                CliError::Other(format!(
                    "unknown --preset {name:?} (known: code-agent)"
                ))
            })?;
            Some(preset.materialize_to_temp()?)
        }
        (Some(_), Some(_)) => {
            // clap's `conflicts_with` should prevent this, but we
            // guard defensively in case the CLI wiring ever drifts.
            return Err(CliError::Other(
                "--policy and --preset are mutually exclusive".to_string(),
            ));
        }
        (None, None) => {
            return Err(CliError::Other(
                "either --policy <path> or --preset <name> is required".to_string(),
            ));
        }
    };

    let resolved_policy_path: &Path = match (policy_path, &materialized_preset) {
        (Some(p), _) => p,
        (None, Some(m)) => m.path(),
        _ => unreachable!("policy path resolution validated above"),
    };

    let loaded_policy = load_policy(resolved_policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    info!(
        policy_path = %resolved_policy_path.display(),
        preset = preset.unwrap_or(""),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        server_id = server_id,
        "loaded policy for MCP edge"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;
    let wrapped_arg_refs = wrapped_args.iter().map(String::as_str).collect::<Vec<_>>();

    let manifest_public_key = manifest_public_key
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
    let adapted_server = AdaptedMcpServer::from_command(
        wrapped_cmd,
        &wrapped_arg_refs,
        McpAdapterConfig {
            server_id: server_id.to_string(),
            server_name: server_name.unwrap_or(server_id).to_string(),
            server_version: server_version
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            public_key: manifest_public_key,
        },
    )?;
    let upstream_notification_source = adapted_server.notification_source();
    let upstream_capabilities = adapted_server.upstream_capabilities();
    let manifest = adapted_server.manifest_clone();
    if let Some(resource_provider) = adapted_server.resource_provider() {
        kernel.register_resource_provider(Box::new(resource_provider));
    }
    if let Some(prompt_provider) = adapted_server.prompt_provider() {
        kernel.register_prompt_provider(Box::new(prompt_provider));
    }
    kernel.register_tool_server(Box::new(adapted_server));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let agent_id = agent_pk.to_hex();
    let capabilities = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;

    info!(
        capability_count = capabilities.len(),
        upstream_resources = upstream_capabilities.resources_supported,
        upstream_prompts = upstream_capabilities.prompts_supported,
        upstream_completions = upstream_capabilities.completions_supported,
        wrapped_command = wrapped_cmd,
        "initialized MCP edge session"
    );

    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            page_size,
            tools_list_changed: tools_list_changed || upstream_capabilities.tools_list_changed,
            completion_enabled: Some(upstream_capabilities.completions_supported),
            resources_subscribe: upstream_capabilities.resources_subscribe,
            resources_list_changed: upstream_capabilities.resources_list_changed,
            prompts_list_changed: upstream_capabilities.prompts_list_changed,
            logging_enabled: true,
        },
        kernel,
        agent_id,
        capabilities,
        vec![manifest],
    )?;
    edge.attach_upstream_transport(upstream_notification_source);

    edge.serve_stdio(std::io::BufReader::new(std::io::stdin()), std::io::stdout())?;
    Ok(())
}

fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_introspection_client_id: Option<&str>,
    auth_introspection_client_secret: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_server_seed_file: Option<&Path>,
    identity_federation_seed_file: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token: auth_token.map(ToOwned::to_owned),
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_jwt_discovery_url: auth_jwt_discovery_url.map(ToOwned::to_owned),
        auth_introspection_url: auth_introspection_url.map(ToOwned::to_owned),
        auth_introspection_client_id: auth_introspection_client_id.map(ToOwned::to_owned),
        auth_introspection_client_secret: auth_introspection_client_secret.map(ToOwned::to_owned),
        auth_jwt_provider_profile,
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        identity_federation_seed_path: identity_federation_seed_file.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token: admin_token.map(ToOwned::to_owned),
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
    })
}

fn require_revocation_db_path(revocation_db_path: Option<&Path>) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::Other(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::Other(
            "shared evidence commands require --receipt-db <path> when --control-url is not set"
                .to_string(),
        )
    })
}

fn cmd_trust_serve(
    listen: SocketAddr,
    service_token: &str,
    policy_path: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    federation_policies_file: Option<&Path>,
    scim_lifecycle_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    certification_registry_file: Option<&Path>,
    certification_discovery_file: Option<&Path>,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    allow_local_peer_urls: bool,
    certification_public_metadata_ttl_seconds: u64,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
) -> Result<(), CliError> {
    let (issuance_policy, runtime_assurance_policy) = policy_path
        .map(load_policy)
        .transpose()?
        .map(|loaded| (loaded.issuance_policy, loaded.runtime_assurance_policy))
        .unwrap_or((None, None));
    trust_control::serve(trust_control::TrustServiceConfig {
        listen,
        service_token: service_token.to_string(),
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(Path::to_path_buf),
        authority_db_path: authority_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        federation_policies_file: federation_policies_file.map(Path::to_path_buf),
        scim_lifecycle_file: scim_lifecycle_file.map(Path::to_path_buf),
        verifier_policies_file: verifier_policies_file.map(Path::to_path_buf),
        verifier_challenge_db_path: verifier_challenge_db.map(Path::to_path_buf),
        passport_statuses_file: passport_statuses_file.map(Path::to_path_buf),
        passport_issuance_offers_file: passport_issuance_offers_file.map(Path::to_path_buf),
        certification_registry_file: certification_registry_file.map(Path::to_path_buf),
        certification_discovery_file: certification_discovery_file.map(Path::to_path_buf),
        issuance_policy,
        runtime_assurance_policy,
        advertise_url: advertise_url.map(ToOwned::to_owned),
        allow_local_peer_urls,
        certification_public_metadata_ttl_seconds,
        peer_urls: peer_urls.to_vec(),
        cluster_sync_interval: std::time::Duration::from_millis(cluster_sync_interval_ms.max(50)),
    })
}

fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.list_revocations(
            &trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            },
        )?;
        (response.revoked.unwrap_or(false), url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

struct SharedEvidenceListArgs<'a> {
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    issuer: Option<&'a str>,
    partner: Option<&'a str>,
    limit: usize,
}

struct AuthorizationContextListArgs<'a> {
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
}

struct BehavioralFeedExportArgs<'a> {
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
}

struct ExposureLedgerQueryArgs<'a> {
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
}

struct AgentExposureLedgerQueryArgs<'a> {
    agent_subject: &'a str,
    capability_id: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
}

struct CapitalBookExportArgs<'a> {
    agent_subject: &'a str,
    capability_id: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    facility_limit: usize,
    bond_limit: usize,
    loss_event_limit: usize,
}

struct CreditFacilityIssueArgs<'a> {
    query: AgentExposureLedgerQueryArgs<'a>,
    supersedes_facility_id: Option<&'a str>,
}

struct CreditFacilityListArgs<'a> {
    facility_id: Option<&'a str>,
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    disposition: Option<&'a str>,
    lifecycle_state: Option<&'a str>,
    limit: usize,
}

struct CreditBondIssueArgs<'a> {
    query: AgentExposureLedgerQueryArgs<'a>,
    supersedes_bond_id: Option<&'a str>,
}

struct CreditBondListArgs<'a> {
    bond_id: Option<&'a str>,
    facility_id: Option<&'a str>,
    capability_id: Option<&'a str>,
    agent_subject: Option<&'a str>,
    tool_server: Option<&'a str>,
    tool_name: Option<&'a str>,
    disposition: Option<&'a str>,
    lifecycle_state: Option<&'a str>,
    limit: usize,
}

fn build_exposure_ledger_query(
    args: &ExposureLedgerQueryArgs<'_>,
) -> chio_kernel::ExposureLedgerQuery {
    chio_kernel::ExposureLedgerQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
    }
}

fn build_agent_exposure_ledger_query(
    args: &AgentExposureLedgerQueryArgs<'_>,
) -> chio_kernel::ExposureLedgerQuery {
    chio_kernel::ExposureLedgerQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        decision_limit: Some(args.decision_limit),
    }
}

fn cmd_trust_evidence_share_list(
    args: SharedEvidenceListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::SharedEvidenceQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        issuer: args.issuer.map(ToOwned::to_owned),
        partner: args.partner.map(ToOwned::to_owned),
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.shared_evidence_report(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_shared_evidence_report(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_shares:         {}",
            report.summary.matching_shares
        );
        println!(
            "matching_references:     {}",
            report.summary.matching_references
        );
        println!(
            "matching_local_receipts: {}",
            report.summary.matching_local_receipts
        );
        println!(
            "remote_tool_receipts:    {}",
            report.summary.remote_tool_receipts
        );
        println!(
            "remote_lineage_records:  {}",
            report.summary.remote_lineage_records
        );
        for reference in report.references {
            println!(
                "- {} partner={} remote_capability={} local_anchor={} receipts={}",
                reference.share.share_id,
                reference.share.partner,
                reference.capability_id,
                reference
                    .local_anchor_capability_id
                    .as_deref()
                    .unwrap_or("n/a"),
                reference.matched_local_receipts
            );
        }
    }

    Ok(())
}

fn cmd_trust_authorization_context_metadata(
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.authorization_profile_metadata()?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.authorization_profile_metadata_report()
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("generated_at:               {}", report.generated_at);
        println!("profile_id:                 {}", report.profile.id);
        println!("profile_schema:             {}", report.profile.schema);
        println!("report_schema:              {}", report.report_schema);
        println!(
            "discovery_informational:    {}",
            report.discovery.discovery_informational_only
        );
        println!(
            "auth_server_metadata_path:  {}",
            report.discovery.authorization_server_metadata_path_template
        );
        for path in report.discovery.protected_resource_metadata_paths {
            println!("protected_resource_path:    {path}");
        }
        println!(
            "sender_constrained:         {}",
            report.support_boundary.sender_constrained_projection
        );
        println!(
            "runtime_assurance:          {}",
            report.support_boundary.runtime_assurance_projection
        );
        println!(
            "delegated_call_chain:       {}",
            report.support_boundary.delegated_call_chain_projection
        );
    }

    Ok(())
}

fn cmd_trust_authorization_context_list(
    args: AuthorizationContextListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::OperatorReportQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        authorization_limit: Some(args.limit),
        ..chio_kernel::OperatorReportQuery::default()
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.authorization_context_report(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_context_report(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("profile_id:                 {}", report.profile.id);
        println!(
            "profile_source:             {}",
            report.profile.authoritative_source
        );
        println!(
            "matching_receipts:          {}",
            report.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            report.summary.returned_receipts
        );
        println!(
            "approval_receipts:          {}",
            report.summary.approval_receipts
        );
        println!(
            "approved_receipts:          {}",
            report.summary.approved_receipts
        );
        println!(
            "call_chain_receipts:        {}",
            report.summary.call_chain_receipts
        );
        println!(
            "metered_billing_receipts:   {}",
            report.summary.metered_billing_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            report.summary.runtime_assurance_receipts
        );
        println!(
            "sender_bound_receipts:      {}",
            report.summary.sender_bound_receipts
        );
        println!(
            "dpop_bound_receipts:        {}",
            report.summary.dpop_bound_receipts
        );
        for row in report.receipts {
            println!(
                "- {} intent={} tool={}/{} details={} sender={} proof={} call_chain={}",
                row.receipt_id,
                row.transaction_context.intent_id,
                row.tool_server,
                row.tool_name,
                row.authorization_details.len(),
                row.sender_constraint.subject_key,
                row.sender_constraint
                    .proof_type
                    .as_deref()
                    .unwrap_or("none"),
                row.transaction_context
                    .call_chain
                    .as_ref()
                    .map(|value| value.chain_id.as_str())
                    .unwrap_or("n/a")
            );
        }
    }

    Ok(())
}

fn cmd_trust_authorization_context_review_pack(
    args: AuthorizationContextListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::OperatorReportQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        authorization_limit: Some(args.limit),
        ..chio_kernel::OperatorReportQuery::default()
    };

    let pack = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.authorization_review_pack(&query)?
    } else {
        let path = require_receipt_db_path(backend.receipt_db_path)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_review_pack(&query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&pack)?);
    } else {
        println!("schema:                     {}", pack.schema);
        println!("generated_at:               {}", pack.generated_at);
        println!("profile_id:                 {}", pack.metadata.profile.id);
        println!(
            "matching_receipts:          {}",
            pack.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            pack.summary.returned_receipts
        );
        println!(
            "dpop_required_receipts:     {}",
            pack.summary.dpop_required_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            pack.summary.runtime_assurance_receipts
        );
        println!(
            "delegated_call_chain:       {}",
            pack.summary.delegated_call_chain_receipts
        );
        for record in pack.records {
            println!(
                "- {} intent={} tool={}/{} approval={} sender={}",
                record.receipt_id,
                record.governed_transaction.intent_id,
                record.authorization_context.tool_server,
                record.authorization_context.tool_name,
                record
                    .governed_transaction
                    .approval
                    .as_ref()
                    .map(|value| value.token_id.as_str())
                    .unwrap_or("none"),
                record.authorization_context.sender_constraint.subject_key
            );
        }
    }

    Ok(())
}

fn cmd_trust_behavioral_feed_export(
    args: BehavioralFeedExportArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::BehavioralFeedQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
    };

    let feed = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.behavioral_feed(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "behavioral feed export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_behavioral_feed(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&feed)?);
    } else {
        println!("schema:                 {}", feed.body.schema);
        println!("generated_at:           {}", feed.body.generated_at);
        println!("signer_key:             {}", feed.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            feed.body.privacy.matching_receipts
        );
        println!(
            "returned_receipts:      {}",
            feed.body.privacy.returned_receipts
        );
        println!(
            "allow_count:            {}",
            feed.body.decisions.allow_count
        );
        println!("deny_count:             {}", feed.body.decisions.deny_count);
        println!(
            "governed_receipts:      {}",
            feed.body.governed_actions.governed_receipts
        );
        if let Some(reputation) = feed.body.reputation.as_ref() {
            println!("subject_key:            {}", reputation.subject_key);
            println!("effective_score:        {:.4}", reputation.effective_score);
            println!(
                "imported_signals:       {}",
                reputation.imported_signal_count
            );
            println!(
                "accepted_imported:      {}",
                reputation.accepted_imported_signal_count
            );
        }
    }

    Ok(())
}

fn cmd_trust_exposure_ledger_export(
    args: ExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.exposure_ledger(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "exposure ledger export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_exposure_ledger_report(
            receipt_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        println!(
            "mixed_currency_book:    {}",
            report.body.summary.mixed_currency_book
        );
        for position in &report.body.positions {
            println!(
                "- {} governed={} reserved={} settled={} pending={} failed={} loss={} quoted_premium={} active_premium={}",
                position.currency,
                position.governed_max_exposure_units,
                position.reserved_units,
                position.settled_units,
                position.pending_units,
                position.failed_units,
                position.provisional_loss_units,
                position.quoted_premium_units,
                position.active_quoted_premium_units
            );
        }
    }

    Ok(())
}

fn cmd_trust_credit_scorecard_export(
    agent_subject: &str,
    args: ExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.credit_scorecard(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit scorecard export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_credit_scorecard_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!("subject_key:            {}", agent_subject);
        println!(
            "overall_score:          {:.4}",
            report.body.summary.overall_score
        );
        println!(
            "confidence:             {:?}",
            report.body.summary.confidence
        );
        println!("band:                   {:?}", report.body.summary.band);
        println!(
            "probationary:           {}",
            report.body.summary.probationary
        );
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "anomaly_count:          {}",
            report.body.summary.anomaly_count
        );
    }

    Ok(())
}

fn cmd_trust_capital_book_export(
    args: CapitalBookExportArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CapitalBookQuery {
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: Some(args.agent_subject.to_string()),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        since: args.since,
        until: args.until,
        receipt_limit: Some(args.receipt_limit),
        facility_limit: Some(args.facility_limit),
        bond_limit: Some(args.bond_limit),
        loss_event_limit: Some(args.loss_event_limit),
    };

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.capital_book(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital book export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_capital_book_report(
            receipt_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("subject_key:            {}", report.body.subject_key);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "funding_sources:        {}",
            report.body.summary.funding_sources
        );
        println!(
            "ledger_events:          {}",
            report.body.summary.ledger_events
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        for source in &report.body.sources {
            println!(
                "- {} kind={:?} owner={:?} committed={} held={} drawn={} disbursed={} released={} repaid={} impaired={}",
                source.source_id,
                source.kind,
                source.owner_role,
                source.committed_amount.as_ref().map_or(0, |amount| amount.units),
                source.held_amount.as_ref().map_or(0, |amount| amount.units),
                source.drawn_amount.as_ref().map_or(0, |amount| amount.units),
                source.disbursed_amount.as_ref().map_or(0, |amount| amount.units),
                source.released_amount.as_ref().map_or(0, |amount| amount.units),
                source.repaid_amount.as_ref().map_or(0, |amount| amount.units),
                source.impaired_amount.as_ref().map_or(0, |amount| amount.units),
            );
        }
    }

    Ok(())
}

fn cmd_trust_capital_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalExecutionInstructionRequest = load_json_or_yaml(input_file)?;

    let instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_capital_execution_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_capital_execution_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&instruction)?);
    } else {
        println!("schema:                 {}", instruction.body.schema);
        println!(
            "instruction_id:         {}",
            instruction.body.instruction_id
        );
        println!("issued_at:              {}", instruction.body.issued_at);
        println!("subject_key:            {}", instruction.body.subject_key);
        println!("source_id:              {}", instruction.body.source_id);
        println!("action:                 {:?}", instruction.body.action);
        println!(
            "reconciled_state:       {:?}",
            instruction.body.reconciled_state
        );
        println!(
            "signer_key:             {}",
            instruction.signer_key.to_hex()
        );
    }

    Ok(())
}

fn cmd_trust_capital_allocation_issue(
    input_file: &Path,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalAllocationDecisionRequest = load_json_or_yaml(input_file)?;

    let allocation = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.issue_capital_allocation_decision(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital allocation issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_capital_allocation_decision(
            receipt_db_path,
            backend.budget_db_path,
            backend.authority_seed_path,
            backend.authority_db_path,
            backend.certification_registry_file,
            &request,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&allocation)?);
    } else {
        println!("schema:                 {}", allocation.body.schema);
        println!("allocation_id:          {}", allocation.body.allocation_id);
        println!("issued_at:              {}", allocation.body.issued_at);
        println!("subject_key:            {}", allocation.body.subject_key);
        println!(
            "governed_receipt_id:    {}",
            allocation.body.governed_receipt_id
        );
        println!("outcome:                {:?}", allocation.body.outcome);
        println!(
            "facility_id:            {}",
            allocation.body.facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "source_id:              {}",
            allocation.body.source_id.as_deref().unwrap_or("<none>")
        );
        println!("signer_key:             {}", allocation.signer_key.to_hex());
    }

    Ok(())
}

fn cmd_trust_credit_facility_evaluate(
    args: AgentExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_agent_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.credit_facility_report(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_facility_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.certification_registry_file,
            None,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", args.agent_subject);
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "overall_score:          {:.4}",
            report.scorecard.overall_score
        );
        println!(
            "runtime_prerequisite:   {:?}",
            report.prerequisites.minimum_runtime_assurance_tier
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

fn cmd_trust_credit_facility_issue(
    args: CreditFacilityIssueArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = trust_control::CreditFacilityIssueRequest {
        query: build_agent_exposure_ledger_query(&args.query),
        supersedes_facility_id: args.supersedes_facility_id.map(ToOwned::to_owned),
    };

    let facility = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.issue_credit_facility(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_facility(trust_control::CreditIssuanceArgs {
            receipt_db_path,
            budget_db_path: backend.budget_db_path,
            authority_seed_path: backend.authority_seed_path,
            authority_db_path: backend.authority_db_path,
            certification_registry_file: backend.certification_registry_file,
            issuance_policy: None,
            query: &request.query,
            supersedes_artifact_id: request.supersedes_facility_id.as_deref(),
        })?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&facility)?);
    } else {
        println!("schema:                 {}", facility.body.schema);
        println!("facility_id:            {}", facility.body.facility_id);
        println!("issued_at:              {}", facility.body.issued_at);
        println!("expires_at:             {}", facility.body.expires_at);
        println!("signer_key:             {}", facility.signer_key.to_hex());
        println!(
            "disposition:            {:?}",
            facility.body.report.disposition
        );
        println!(
            "lifecycle_state:        {:?}",
            facility.body.lifecycle_state
        );
    }

    Ok(())
}

fn cmd_trust_credit_facility_list(
    args: CreditFacilityListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditFacilityListQuery {
        facility_id: args.facility_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        disposition: args.disposition
            .map(parse_credit_facility_disposition)
            .transpose()?,
        lifecycle_state: args.lifecycle_state
            .map(parse_credit_facility_lifecycle_state)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.list_credit_facilities(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_facilities(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_facilities:    {}",
            report.summary.matching_facilities
        );
        println!(
            "returned_facilities:    {}",
            report.summary.returned_facilities
        );
        println!(
            "active_facilities:      {}",
            report.summary.active_facilities
        );
        println!(
            "manual_review_rows:     {}",
            report.summary.manual_review_facilities
        );
        for row in report.facilities {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.facility.body.facility_id,
                row.facility.body.report.disposition,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

fn cmd_trust_credit_bond_evaluate(
    args: AgentExposureLedgerQueryArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let query = build_agent_exposure_ledger_query(&args);

    let report = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.credit_bond_report(&query)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_bond_report(
            receipt_db_path,
            backend.budget_db_path,
            backend.certification_registry_file,
            None,
            &query,
        )?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", args.agent_subject);
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "latest_facility_id:     {}",
            report.latest_facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "active_facility_met:    {}",
            report.prerequisites.active_facility_met
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

fn cmd_trust_credit_bond_issue(
    args: CreditBondIssueArgs<'_>,
    backend: SignedQueryBackend<'_>,
) -> Result<(), CliError> {
    let request = trust_control::CreditBondIssueRequest {
        query: build_agent_exposure_ledger_query(&args.query),
        supersedes_bond_id: args.supersedes_bond_id.map(ToOwned::to_owned),
    };

    let bond = if let Some(url) = backend.query.control_url {
        let token = require_control_token(backend.query.control_token)?;
        trust_control::build_client(url, token)?.issue_credit_bond(&request)?
    } else {
        let receipt_db_path = backend.query.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_bond(trust_control::CreditIssuanceArgs {
            receipt_db_path,
            budget_db_path: backend.budget_db_path,
            authority_seed_path: backend.authority_seed_path,
            authority_db_path: backend.authority_db_path,
            certification_registry_file: backend.certification_registry_file,
            issuance_policy: None,
            query: &request.query,
            supersedes_artifact_id: request.supersedes_bond_id.as_deref(),
        })?
    };

    if backend.query.json_output {
        println!("{}", serde_json::to_string_pretty(&bond)?);
    } else {
        println!("schema:                 {}", bond.body.schema);
        println!("bond_id:                {}", bond.body.bond_id);
        println!("issued_at:              {}", bond.body.issued_at);
        println!("expires_at:             {}", bond.body.expires_at);
        println!("signer_key:             {}", bond.signer_key.to_hex());
        println!("disposition:            {:?}", bond.body.report.disposition);
        println!("lifecycle_state:        {:?}", bond.body.lifecycle_state);
    }

    Ok(())
}

fn cmd_trust_credit_bond_simulate(
    bond_id: &str,
    autonomy_tier: &str,
    runtime_assurance_tier: &str,
    call_chain_present: bool,
    policy_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = chio_kernel::CreditBondedExecutionSimulationRequest {
        query: chio_kernel::CreditBondedExecutionSimulationQuery {
            bond_id: bond_id.to_string(),
            autonomy_tier: parse_governed_autonomy_tier(autonomy_tier)?,
            runtime_assurance_tier: parse_runtime_assurance_tier(runtime_assurance_tier)?,
            call_chain_present,
        },
        policy: load_credit_bonded_execution_control_policy(policy_file)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.simulate_credit_bonded_execution(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond simulation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_bonded_execution_simulation_report(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("bond_id:                {}", report.bond.body.bond_id);
        println!(
            "baseline_decision:      {:?}",
            report.default_evaluation.decision
        );
        println!(
            "simulated_decision:     {:?}",
            report.simulated_evaluation.decision
        );
        println!("decision_changed:       {}", report.delta.decision_changed);
        println!(
            "sandbox_ready:          {}",
            report.simulated_evaluation.sandbox_integration_ready
        );
        println!(
            "findings:               {}",
            report.simulated_evaluation.findings.len()
        );
    }

    Ok(())
}

fn cmd_trust_credit_bond_list(
    args: CreditBondListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::CreditBondListQuery {
        bond_id: args.bond_id.map(ToOwned::to_owned),
        facility_id: args.facility_id.map(ToOwned::to_owned),
        capability_id: args.capability_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        tool_server: args.tool_server.map(ToOwned::to_owned),
        tool_name: args.tool_name.map(ToOwned::to_owned),
        disposition: args.disposition.map(parse_credit_bond_disposition).transpose()?,
        lifecycle_state: args
            .lifecycle_state
            .map(parse_credit_bond_lifecycle_state)
            .transpose()?,
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::build_client(url, token)?.list_credit_bonds(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_bonds(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_bonds:         {}", report.summary.matching_bonds);
        println!("returned_bonds:         {}", report.summary.returned_bonds);
        println!("active_bonds:           {}", report.summary.active_bonds);
        println!("locked_bonds:           {}", report.summary.locked_bonds);
        println!("held_bonds:             {}", report.summary.held_bonds);
        for row in report.bonds {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.bond.body.bond_id, row.bond.body.report.disposition, row.lifecycle_state
            );
        }
    }

    Ok(())
}

fn build_credit_loss_lifecycle_query(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
) -> Result<chio_kernel::CreditLossLifecycleQuery, CliError> {
    let amount =
        match (amount_units, amount_currency) {
            (Some(units), Some(currency)) => Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            (None, None) => None,
            _ => return Err(CliError::Other(
                "credit loss lifecycle amount requires both --amount-units and --amount-currency"
                    .to_string(),
            )),
        };

    Ok(chio_kernel::CreditLossLifecycleQuery {
        bond_id: bond_id.to_string(),
        event_kind: parse_credit_loss_lifecycle_event_kind(event_kind)?,
        amount,
    })
}
