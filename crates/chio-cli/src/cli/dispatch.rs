fn main() {
    let cli = Cli::parse();
    let receipt_db = cli.receipt_db.clone();
    let revocation_db = cli.revocation_db.clone();
    let authority_seed_file = cli.authority_seed_file.clone();
    let authority_db = cli.authority_db.clone();
    let budget_db = cli.budget_db.clone();
    let session_db = cli.session_db.clone();
    let control_url = cli.control_url.clone();
    let control_token = cli.control_token.clone();
    let json_output = cli.json_output();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Commands::Run { policy, command } => cmd_run(
            &policy,
            &command,
            json_output,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Check {
            policy,
            tool,
            params,
            server,
        } => cmd_check(
            &policy,
            &tool,
            &params,
            &server,
            json_output,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Init { path } => scaffold::cmd_init(&path),
        Commands::Api { command } => match command {
            ApiCommands::Protect {
                upstream,
                spec,
                listen,
                receipt_store,
            } => cmd_api_protect(
                &upstream,
                spec.as_deref(),
                &listen,
                receipt_store.as_deref().or(receipt_db.as_deref()),
                authority_seed_file.as_deref(),
            ),
        },
        Commands::Mcp { command } => match command {
            McpCommands::Wrap(args) => cmd_mcp_wrap(&args),
            McpCommands::Serve {
                policy,
                preset,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                command,
            } => cmd_mcp_serve(
                policy.as_deref(),
                preset.as_deref(),
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            McpCommands::ServeHttp {
                policy,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token,
                auth_jwt_public_key,
                auth_jwt_discovery_url,
                auth_introspection_url,
                auth_introspection_client_id,
                auth_introspection_client_secret,
                auth_jwt_provider_profile,
                auth_server_seed_file,
                identity_federation_seed_file,
                enterprise_providers_file,
                auth_jwt_issuer,
                auth_jwt_audience,
                admin_token,
                public_base_url,
                auth_servers,
                auth_authorization_endpoint,
                auth_token_endpoint,
                auth_registration_endpoint,
                auth_jwks_uri,
                auth_scopes,
                auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                command,
            } => cmd_mcp_serve_http(
                &policy,
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token.as_deref(),
                auth_jwt_public_key.as_deref(),
                auth_jwt_discovery_url.as_deref(),
                auth_introspection_url.as_deref(),
                auth_introspection_client_id.as_deref(),
                auth_introspection_client_secret.as_deref(),
                auth_jwt_provider_profile,
                auth_server_seed_file.as_deref(),
                identity_federation_seed_file.as_deref(),
                enterprise_providers_file.as_deref(),
                auth_jwt_issuer.as_deref(),
                auth_jwt_audience.as_deref(),
                admin_token.as_deref(),
                public_base_url.as_deref(),
                &auth_servers,
                auth_authorization_endpoint.as_deref(),
                auth_token_endpoint.as_deref(),
                auth_registration_endpoint.as_deref(),
                auth_jwks_uri.as_deref(),
                &auth_scopes,
                &auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Trust { command } => match command {
            TrustCommands::Serve {
                listen,
                service_token,
                advertise_url,
                peer_urls,
                allow_local_peer_urls,
                cluster_sync_interval_ms,
                policy,
                enterprise_providers_file,
                federation_policies_file,
                scim_lifecycle_file,
                verifier_policies_file,
                verifier_challenge_db,
                passport_statuses_file,
                passport_issuance_offers_file,
                certification_registry_file,
                certification_discovery_file,
                certification_public_metadata_ttl_seconds,
            } => cmd_trust_serve(
                listen,
                &service_token,
                policy.as_deref(),
                enterprise_providers_file.as_deref(),
                federation_policies_file.as_deref(),
                scim_lifecycle_file.as_deref(),
                verifier_policies_file.as_deref(),
                verifier_challenge_db.as_deref(),
                passport_statuses_file.as_deref(),
                passport_issuance_offers_file.as_deref(),
                certification_registry_file.as_deref(),
                certification_discovery_file.as_deref(),
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                advertise_url.as_deref(),
                allow_local_peer_urls,
                certification_public_metadata_ttl_seconds,
                &peer_urls,
                cluster_sync_interval_ms,
            ),
            TrustCommands::Provider { command } => match command {
                TrustProviderCommands::List {
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_list(
                    json_output,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Get {
                    provider_id,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_get(
                    &provider_id,
                    json_output,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Upsert {
                    input,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_upsert(
                    &input,
                    json_output,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Delete {
                    provider_id,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_delete(
                    &provider_id,
                    json_output,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::FederationPolicy { command } => match command {
                TrustFederationPolicyCommands::List {
                    federation_policies_file,
                } => admin::cmd_trust_federation_policy_list(
                    json_output,
                    federation_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustFederationPolicyCommands::Get {
                    policy_id,
                    federation_policies_file,
                } => admin::cmd_trust_federation_policy_get(
                    &policy_id,
                    json_output,
                    federation_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustFederationPolicyCommands::Upsert {
                    input,
                    federation_policies_file,
                } => admin::cmd_trust_federation_policy_upsert(
                    &input,
                    json_output,
                    federation_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustFederationPolicyCommands::Delete {
                    policy_id,
                    federation_policies_file,
                } => admin::cmd_trust_federation_policy_delete(
                    &policy_id,
                    json_output,
                    federation_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustFederationPolicyCommands::Evaluate { input } => {
                    admin::cmd_trust_federation_policy_evaluate(
                        &input,
                        json_output,
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
            },
            TrustCommands::EvidenceShare { command } => match command {
                TrustEvidenceShareCommands::List {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    issuer,
                    partner,
                    limit,
                } => cmd_trust_evidence_share_list(
                    SharedEvidenceListArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        issuer: issuer.as_deref(),
                        partner: partner.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::AuthorizationContext { command } => match command {
                TrustAuthorizationContextCommands::Metadata => {
                    cmd_trust_authorization_context_metadata(
                        json_output,
                        receipt_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustAuthorizationContextCommands::List {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    limit,
                } => cmd_trust_authorization_context_list(
                    AuthorizationContextListArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                TrustAuthorizationContextCommands::ReviewPack {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    limit,
                } => cmd_trust_authorization_context_review_pack(
                    AuthorizationContextListArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::Appraisal { command } => match command {
                TrustRuntimeAttestationAppraisalCommands::Export { input, policy_file } => {
                    cmd_trust_runtime_attestation_appraisal_export(
                        &input,
                        policy_file.as_deref(),
                        json_output,
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustRuntimeAttestationAppraisalCommands::ExportResult {
                    issuer,
                    input,
                    policy_file,
                } => cmd_trust_runtime_attestation_appraisal_result_export(
                    issuer.as_str(),
                    &input,
                    policy_file.as_deref(),
                    json_output,
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustRuntimeAttestationAppraisalCommands::Import { input, policy_file } => {
                    cmd_trust_runtime_attestation_appraisal_import(
                        &input,
                        &policy_file,
                        json_output,
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
            },
            TrustCommands::BehavioralFeed { command } => match command {
                TrustBehavioralFeedCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                } => cmd_trust_behavioral_feed_export(
                    BehavioralFeedExportArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: None,
                    },
                ),
            },
            TrustCommands::ExposureLedger { command } => match command {
                TrustExposureLedgerCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                } => cmd_trust_exposure_ledger_export(
                    ExposureLedgerQueryArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: None,
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: None,
                    },
                ),
            },
            TrustCommands::CreditScorecard { command } => match command {
                TrustCreditScorecardCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                } => cmd_trust_credit_scorecard_export(
                    &agent_subject,
                    ExposureLedgerQueryArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: Some(&agent_subject),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: None,
                    },
                ),
            },
            TrustCommands::CapitalBook { command } => match command {
                TrustCapitalBookCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    facility_limit,
                    bond_limit,
                    loss_event_limit,
                } => cmd_trust_capital_book_export(
                    CapitalBookExportArgs {
                        agent_subject: &agent_subject,
                        capability_id: capability.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        facility_limit,
                        bond_limit,
                        loss_event_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: None,
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: None,
                    },
                ),
            },
            TrustCommands::CapitalInstruction { command } => match command {
                TrustCapitalInstructionCommands::Issue { input_file } => {
                    cmd_trust_capital_instruction_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
            },
            TrustCommands::CapitalAllocation { command } => match command {
                TrustCapitalAllocationCommands::Issue {
                    input_file,
                    certification_registry_file,
                } => cmd_trust_capital_allocation_issue(
                    &input_file,
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
            },
            TrustCommands::Facility { command } => match command {
                TrustCreditFacilityCommands::Evaluate {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    certification_registry_file,
                } => cmd_trust_credit_facility_evaluate(
                    AgentExposureLedgerQueryArgs {
                        agent_subject: &agent_subject,
                        capability_id: capability.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: None,
                        authority_db_path: None,
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustCreditFacilityCommands::Issue {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_facility_id,
                    certification_registry_file,
                } => cmd_trust_credit_facility_issue(
                    CreditFacilityIssueArgs {
                        query: AgentExposureLedgerQueryArgs {
                            agent_subject: &agent_subject,
                            capability_id: capability.as_deref(),
                            tool_server: tool_server.as_deref(),
                            tool_name: tool_name.as_deref(),
                            since,
                            until,
                            receipt_limit,
                            decision_limit,
                        },
                        supersedes_facility_id: supersedes_facility_id.as_deref(),
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustCreditFacilityCommands::List {
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    disposition,
                    lifecycle_state,
                    limit,
                } => cmd_trust_credit_facility_list(
                    CreditFacilityListArgs {
                        facility_id: facility_id.as_deref(),
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        disposition: disposition.as_deref(),
                        lifecycle_state: lifecycle_state.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::Bond { command } => match command {
                TrustCreditBondCommands::Evaluate {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    certification_registry_file,
                } => cmd_trust_credit_bond_evaluate(
                    AgentExposureLedgerQueryArgs {
                        agent_subject: &agent_subject,
                        capability_id: capability.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: None,
                        authority_db_path: None,
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustCreditBondCommands::Issue {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_bond_id,
                    certification_registry_file,
                } => cmd_trust_credit_bond_issue(
                    CreditBondIssueArgs {
                        query: AgentExposureLedgerQueryArgs {
                            agent_subject: &agent_subject,
                            capability_id: capability.as_deref(),
                            tool_server: tool_server.as_deref(),
                            tool_name: tool_name.as_deref(),
                            since,
                            until,
                            receipt_limit,
                            decision_limit,
                        },
                        supersedes_bond_id: supersedes_bond_id.as_deref(),
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustCreditBondCommands::Simulate {
                    bond_id,
                    autonomy_tier,
                    runtime_assurance_tier,
                    call_chain_present,
                    policy_file,
                } => cmd_trust_credit_bond_simulate(
                    &bond_id,
                    &autonomy_tier,
                    &runtime_assurance_tier,
                    call_chain_present,
                    &policy_file,
                    json_output,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditBondCommands::List {
                    bond_id,
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    disposition,
                    lifecycle_state,
                    limit,
                } => cmd_trust_credit_bond_list(
                    CreditBondListArgs {
                        bond_id: bond_id.as_deref(),
                        facility_id: facility_id.as_deref(),
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        disposition: disposition.as_deref(),
                        lifecycle_state: lifecycle_state.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::Loss { command } => match command {
                TrustCreditLossLifecycleCommands::Evaluate {
                    bond_id,
                    event_kind,
                    amount_units,
                    amount_currency,
                } => cmd_trust_credit_loss_lifecycle_evaluate(
                    &bond_id,
                    &event_kind,
                    amount_units,
                    amount_currency.as_deref(),
                    json_output,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditLossLifecycleCommands::Issue {
                    bond_id,
                    event_kind,
                    amount_units,
                    amount_currency,
                    authority_chain_file,
                    execution_window_file,
                    rail_file,
                    observed_execution_file,
                    appeal_window_ends_at,
                    description,
                } => cmd_trust_credit_loss_lifecycle_issue(
                    &bond_id,
                    &event_kind,
                    amount_units,
                    amount_currency.as_deref(),
                    authority_chain_file.as_deref(),
                    execution_window_file.as_deref(),
                    rail_file.as_deref(),
                    observed_execution_file.as_deref(),
                    appeal_window_ends_at,
                    description.as_deref(),
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditLossLifecycleCommands::List {
                    event_id,
                    bond_id,
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    event_kind,
                    limit,
                } => cmd_trust_credit_loss_lifecycle_list(
                    CreditLossLifecycleListArgs {
                        event_id: event_id.as_deref(),
                        bond_id: bond_id.as_deref(),
                        facility_id: facility_id.as_deref(),
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        event_kind: event_kind.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::CreditBacktest { command } => match command {
                TrustCreditBacktestCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    window_seconds,
                    window_count,
                    stale_after_seconds,
                    certification_registry_file,
                } => cmd_trust_credit_backtest_export(
                    CreditBacktestExportArgs {
                        agent_subject: &agent_subject,
                        capability_id: capability.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                        window_seconds,
                        window_count,
                        stale_after_seconds,
                    },
                    BudgetQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
            },
            TrustCommands::ProviderRiskPackage { command } => match command {
                TrustProviderRiskPackageCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    recent_loss_limit,
                    certification_registry_file,
                } => cmd_trust_provider_risk_package_export(
                    ProviderRiskPackageExportArgs {
                        agent_subject: &agent_subject,
                        capability_id: capability.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                        decision_limit,
                        recent_loss_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
            },
            TrustCommands::LiabilityProvider { command } => match command {
                TrustLiabilityProviderCommands::Issue {
                    input_file,
                    supersedes_provider_record_id,
                } => cmd_trust_liability_provider_issue(
                    &input_file,
                    supersedes_provider_record_id.as_deref(),
                    json_output,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustLiabilityProviderCommands::List {
                    provider_id,
                    jurisdiction,
                    coverage_class,
                    currency,
                    lifecycle_state,
                    limit,
                } => cmd_trust_liability_provider_list(
                    provider_id.as_deref(),
                    jurisdiction.as_deref(),
                    coverage_class.as_deref(),
                    currency.as_deref(),
                    lifecycle_state.as_deref(),
                    limit,
                    json_output,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustLiabilityProviderCommands::Resolve {
                    provider_id,
                    jurisdiction,
                    coverage_class,
                    currency,
                } => cmd_trust_liability_provider_resolve(
                    &provider_id,
                    &jurisdiction,
                    &coverage_class,
                    &currency,
                    json_output,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::LiabilityMarket { command } => match command {
                TrustLiabilityMarketCommands::QuoteRequestIssue { input_file } => {
                    cmd_trust_liability_quote_request_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::QuoteResponseIssue { input_file } => {
                    cmd_trust_liability_quote_response_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::PricingAuthorityIssue { input_file } => {
                    cmd_trust_liability_pricing_authority_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::PlacementIssue { input_file } => {
                    cmd_trust_liability_placement_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::BoundCoverageIssue { input_file } => {
                    cmd_trust_liability_bound_coverage_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::AutoBindIssue { input_file } => {
                    cmd_trust_liability_auto_bind_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimIssue { input_file } => {
                    cmd_trust_liability_claim_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimResponseIssue { input_file } => {
                    cmd_trust_liability_claim_response_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::DisputeIssue { input_file } => {
                    cmd_trust_liability_claim_dispute_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::AdjudicationIssue { input_file } => {
                    cmd_trust_liability_claim_adjudication_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimPayoutInstructionIssue { input_file } => {
                    cmd_trust_liability_claim_payout_instruction_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimPayoutReceiptIssue { input_file } => {
                    cmd_trust_liability_claim_payout_receipt_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimSettlementInstructionIssue { input_file } => {
                    cmd_trust_liability_claim_settlement_instruction_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimSettlementReceiptIssue { input_file } => {
                    cmd_trust_liability_claim_settlement_receipt_issue(
                        &input_file,
                        json_output,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::List {
                    quote_request_id,
                    provider_id,
                    agent_subject,
                    jurisdiction,
                    coverage_class,
                    currency,
                    limit,
                } => cmd_trust_liability_market_list(
                    LiabilityMarketListArgs {
                        quote_request_id: quote_request_id.as_deref(),
                        provider_id: provider_id.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        jurisdiction: jurisdiction.as_deref(),
                        coverage_class: coverage_class.as_deref(),
                        currency: currency.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                TrustLiabilityMarketCommands::ClaimsList {
                    claim_id,
                    provider_id,
                    agent_subject,
                    jurisdiction,
                    policy_number,
                    limit,
                } => cmd_trust_liability_claims_list(
                    LiabilityClaimsListArgs {
                        claim_id: claim_id.as_deref(),
                        provider_id: provider_id.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        jurisdiction: jurisdiction.as_deref(),
                        policy_number: policy_number.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::UnderwritingInput { command } => match command {
                TrustUnderwritingInputCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                } => cmd_trust_underwriting_input_export(
                    UnderwritingPolicyInputArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
            },
            TrustCommands::UnderwritingDecision { command } => match command {
                TrustUnderwritingDecisionCommands::Evaluate {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                } => cmd_trust_underwriting_decision_evaluate(
                    UnderwritingPolicyInputArgs {
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        since,
                        until,
                        receipt_limit,
                    },
                    BudgetQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustUnderwritingDecisionCommands::Simulate {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    policy_file,
                    certification_registry_file,
                } => cmd_trust_underwriting_decision_simulate(
                    UnderwritingDecisionSimulateArgs {
                        input: UnderwritingPolicyInputArgs {
                            capability_id: capability.as_deref(),
                            agent_subject: agent_subject.as_deref(),
                            tool_server: tool_server.as_deref(),
                            tool_name: tool_name.as_deref(),
                            since,
                            until,
                            receipt_limit,
                        },
                        policy_file: &policy_file,
                    },
                    BudgetQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustUnderwritingDecisionCommands::Issue {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                    supersedes_decision_id,
                } => cmd_trust_underwriting_decision_issue(
                    UnderwritingDecisionIssueArgs {
                        input: UnderwritingPolicyInputArgs {
                            capability_id: capability.as_deref(),
                            agent_subject: agent_subject.as_deref(),
                            tool_server: tool_server.as_deref(),
                            tool_name: tool_name.as_deref(),
                            since,
                            until,
                            receipt_limit,
                        },
                        supersedes_decision_id: supersedes_decision_id.as_deref(),
                    },
                    SignedQueryBackend {
                        query: QueryBackend {
                            json_output,
                            receipt_db_path: receipt_db.as_deref(),
                            control_url: control_url.as_deref(),
                            control_token: control_token.as_deref(),
                        },
                        budget_db_path: budget_db.as_deref(),
                        authority_seed_path: authority_seed_file.as_deref(),
                        authority_db_path: authority_db.as_deref(),
                        certification_registry_file: certification_registry_file.as_deref(),
                    },
                ),
                TrustUnderwritingDecisionCommands::List {
                    decision_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    outcome,
                    lifecycle_state,
                    appeal_status,
                    limit,
                } => cmd_trust_underwriting_decision_list(
                    UnderwritingDecisionListArgs {
                        decision_id: decision_id.as_deref(),
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        tool_server: tool_server.as_deref(),
                        tool_name: tool_name.as_deref(),
                        outcome: outcome.as_deref(),
                        lifecycle_state: lifecycle_state.as_deref(),
                        appeal_status: appeal_status.as_deref(),
                        limit,
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::UnderwritingAppeal { command } => match command {
                TrustUnderwritingAppealCommands::Create {
                    decision_id,
                    requested_by,
                    reason,
                    note,
                } => cmd_trust_underwriting_appeal_create(
                    &decision_id,
                    &requested_by,
                    &reason,
                    note.as_deref(),
                    json_output,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustUnderwritingAppealCommands::Resolve {
                    appeal_id,
                    resolution,
                    resolved_by,
                    note,
                    replacement_decision_id,
                } => cmd_trust_underwriting_appeal_resolve(
                    UnderwritingAppealResolveArgs {
                        appeal_id: &appeal_id,
                        resolution: &resolution,
                        resolved_by: &resolved_by,
                        note: note.as_deref(),
                        replacement_decision_id: replacement_decision_id.as_deref(),
                    },
                    QueryBackend {
                        json_output,
                        receipt_db_path: receipt_db.as_deref(),
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
            },
            TrustCommands::Revoke { capability_id } => cmd_trust_revoke(
                &capability_id,
                json_output,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            TrustCommands::FederatedIssue {
                presentation_response,
                challenge,
                capability_policy,
                enterprise_identity,
                delegation_policy,
                upstream_capability_id,
            } => admin::cmd_trust_federated_issue(
                &presentation_response,
                &challenge,
                &capability_policy,
                enterprise_identity.as_deref(),
                delegation_policy.as_deref(),
                upstream_capability_id.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            TrustCommands::FederatedDelegationPolicyCreate {
                output,
                signing_seed_file,
                issuer,
                partner,
                verifier,
                capability_policy,
                expires_at,
                purpose,
                parent_capability_id,
            } => admin::cmd_trust_federated_delegation_policy_create(
                &output,
                &signing_seed_file,
                &issuer,
                &partner,
                &verifier,
                &capability_policy,
                expires_at,
                purpose.as_deref(),
                parent_capability_id.as_deref(),
                json_output,
            ),
            TrustCommands::Status { capability_id } => cmd_trust_status(
                &capability_id,
                json_output,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Receipt { command } => match command {
            ReceiptCommands::List {
                capability,
                tool_server,
                tool_name,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                limit,
                cursor,
            } => cmd_receipt_list(
                ReceiptListArgs {
                    capability: capability.as_deref(),
                    tool_server: tool_server.as_deref(),
                    tool_name: tool_name.as_deref(),
                    outcome: outcome.as_deref(),
                    since,
                    until,
                    min_cost,
                    max_cost,
                    limit,
                    cursor,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            ReceiptCommands::Explain {
                receipt_id,
                input_file,
                depth,
                fanout_limit,
                inspect_bilateral,
            } => cmd_receipt_explain(
                ReceiptExplainArgs {
                    receipt_id: &receipt_id,
                    input_file: input_file.as_deref(),
                    depth,
                    fanout_limit,
                    inspect_bilateral,
                },
                QueryBackend {
                    json_output,
                    receipt_db_path: receipt_db.as_deref(),
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
        },
        Commands::Evidence { command } => match command {
            EvidenceCommands::Export {
                output,
                capability,
                agent_subject,
                since,
                until,
                policy_file,
                federation_policy,
                require_proofs,
            } => evidence_export::cmd_evidence_export(
                &output,
                capability.as_deref(),
                agent_subject.as_deref(),
                since,
                until,
                policy_file.as_deref(),
                federation_policy.as_deref(),
                require_proofs,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            EvidenceCommands::Verify { input } => {
                evidence_export::cmd_evidence_verify(&input, json_output)
            }
            EvidenceCommands::Import { input } => evidence_export::cmd_evidence_import(
                &input,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                json_output,
            ),
            EvidenceCommands::FederationPolicy { command } => match command {
                EvidenceFederationPolicyCommands::Create {
                    output,
                    signing_seed_file,
                    issuer,
                    partner,
                    capability,
                    agent_subject,
                    since,
                    until,
                    expires_at,
                    require_proofs,
                    purpose,
                } => evidence_export::cmd_evidence_federation_policy_create(
                    evidence_export::EvidenceFederationPolicyCreateArgs {
                        output: &output,
                        signing_seed_file: &signing_seed_file,
                        issuer: &issuer,
                        partner: &partner,
                        capability_id: capability.as_deref(),
                        agent_subject: agent_subject.as_deref(),
                        since,
                        until,
                        expires_at,
                        require_proofs,
                        purpose: purpose.as_deref(),
                        json_output,
                    },
                ),
            },
        },
        Commands::Certify { command } => match command {
            CertifyCommands::Check {
                scenarios_dir,
                results_dir,
                output,
                tool_server_id,
                tool_server_name,
                report_output,
                criteria_profile,
                signing_seed_file,
            } => certify::cmd_certify_check(
                &scenarios_dir,
                &results_dir,
                &output,
                &tool_server_id,
                tool_server_name.as_deref(),
                report_output.as_deref(),
                &criteria_profile,
                &signing_seed_file,
                json_output,
            ),
            CertifyCommands::Verify { input } => certify::cmd_certify_verify(&input, json_output),
            CertifyCommands::Registry { command } => match command {
                CertifyRegistryCommands::Publish {
                    input,
                    certification_registry_file,
                } => admin::cmd_certify_registry_publish(
                    &input,
                    certification_registry_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::PublishNetwork {
                    input,
                    certification_discovery_file,
                    operator_ids,
                } => certify::cmd_certify_registry_publish_network(
                    &input,
                    certification_discovery_file.as_deref(),
                    &operator_ids,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::List {
                    certification_registry_file,
                } => admin::cmd_certify_registry_list(
                    certification_registry_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Get {
                    artifact_id,
                    certification_registry_file,
                } => admin::cmd_certify_registry_get(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Resolve {
                    tool_server_id,
                    certification_registry_file,
                } => admin::cmd_certify_registry_resolve(
                    &tool_server_id,
                    certification_registry_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Discover {
                    tool_server_id,
                    certification_discovery_file,
                } => certify::cmd_certify_registry_discover(
                    &tool_server_id,
                    certification_discovery_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Search {
                    certification_discovery_file,
                    tool_server_id,
                    criteria_profile,
                    evidence_profile,
                    status,
                    operator_ids,
                } => certify::cmd_certify_registry_search(
                    certification_discovery_file.as_deref(),
                    tool_server_id.as_deref(),
                    criteria_profile.as_deref(),
                    evidence_profile.as_deref(),
                    status.as_deref(),
                    &operator_ids,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Transparency {
                    certification_discovery_file,
                    tool_server_id,
                    operator_ids,
                } => certify::cmd_certify_registry_transparency(
                    certification_discovery_file.as_deref(),
                    tool_server_id.as_deref(),
                    &operator_ids,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Consume {
                    tool_server_id,
                    certification_discovery_file,
                    operator_ids,
                    allowed_criteria_profiles,
                    allowed_evidence_profiles,
                } => certify::cmd_certify_registry_consume(
                    certification_discovery_file.as_deref(),
                    &tool_server_id,
                    &operator_ids,
                    &allowed_criteria_profiles,
                    &allowed_evidence_profiles,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Revoke {
                    artifact_id,
                    reason,
                    revoked_at,
                    certification_registry_file,
                } => admin::cmd_certify_registry_revoke(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    reason.as_deref(),
                    revoked_at,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Dispute {
                    artifact_id,
                    state,
                    note,
                    updated_at,
                    certification_registry_file,
                } => certify::cmd_certify_registry_dispute(
                    &artifact_id,
                    &state,
                    note.as_deref(),
                    updated_at,
                    certification_registry_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
        },
        Commands::Did { command } => match command {
            DidCommands::Resolve {
                did,
                public_key,
                receipt_log_urls,
                passport_status_urls,
            } => did::cmd_did_resolve(
                did.as_deref(),
                public_key.as_deref(),
                &receipt_log_urls,
                &passport_status_urls,
                json_output,
            ),
        },
        Commands::Passport { command } => match command {
            PassportCommands::Generate {
                agent,
                output,
                compliance_score,
                behavioral_anomaly,
                validity_days,
            } => passport::cmd_passport_generate(
                &agent,
                output.as_deref(),
                compliance_score,
                behavioral_anomaly,
                validity_days,
                json_output,
            ),
            PassportCommands::Create {
                subject_public_key,
                output,
                signing_seed_file,
                validity_days,
                since,
                until,
                receipt_log_urls,
                require_checkpoints,
                enterprise_identity,
            } => passport::cmd_passport_create(
                &subject_public_key,
                &output,
                &signing_seed_file,
                validity_days,
                since,
                until,
                &receipt_log_urls,
                require_checkpoints,
                enterprise_identity.as_deref(),
                receipt_db.as_deref(),
                budget_db.as_deref(),
                json_output,
            ),
            PassportCommands::Verify {
                input,
                at,
                passport_statuses_file,
            } => passport::cmd_passport_verify(
                &input,
                at,
                passport_statuses_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportCommands::Evaluate {
                input,
                policy,
                at,
                passport_statuses_file,
            } => passport::cmd_passport_evaluate(
                &input,
                &policy,
                at,
                passport_statuses_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportCommands::Present {
                input,
                output,
                issuers,
                max_credentials,
            } => passport::cmd_passport_present(
                &input,
                &output,
                &issuers,
                max_credentials,
                json_output,
            ),
            PassportCommands::Policy { command } => match command {
                PassportPolicyCommands::Create {
                    output,
                    policy_id,
                    verifier,
                    signing_seed_file,
                    policy,
                    expires_at,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_create(passport::PassportPolicyCreateArgs {
                    output: &output,
                    policy_id: &policy_id,
                    verifier: &verifier,
                    signing_seed_file: &signing_seed_file,
                    policy_path: &policy,
                    expires_at,
                    verifier_policies_file: verifier_policies_file.as_deref(),
                    json_output,
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                }),
                PassportPolicyCommands::Verify { input, at } => {
                    passport::cmd_passport_policy_verify(&input, at, json_output)
                }
                PassportPolicyCommands::List {
                    verifier_policies_file,
                } => passport::cmd_passport_policy_list(
                    json_output,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Get {
                    policy_id,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_get(
                    &policy_id,
                    json_output,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Upsert {
                    input,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_upsert(
                    &input,
                    json_output,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Delete {
                    policy_id,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_delete(
                    &policy_id,
                    json_output,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Challenge { command } => match command {
                PassportChallengeCommands::Create {
                    output,
                    verifier,
                    ttl_secs,
                    issuers,
                    max_credentials,
                    policy,
                    policy_id,
                    verifier_policies_file,
                    verifier_challenge_db,
                } => passport::cmd_passport_challenge_create(
                    passport::PassportChallengeCreateArgs {
                        output: &output,
                        verifier: &verifier,
                        ttl_secs,
                        issuers: &issuers,
                        max_credentials,
                        policy_path: policy.as_deref(),
                        policy_id: policy_id.as_deref(),
                        verifier_policies_file: verifier_policies_file.as_deref(),
                        verifier_challenge_db: verifier_challenge_db.as_deref(),
                        json_output,
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                PassportChallengeCommands::Respond {
                    input,
                    challenge,
                    challenge_url,
                    holder_seed_file,
                    output,
                    at,
                } => passport::cmd_passport_challenge_respond(
                    &input,
                    challenge.as_deref(),
                    challenge_url.as_deref(),
                    &holder_seed_file,
                    &output,
                    at,
                    json_output,
                ),
                PassportChallengeCommands::Submit { input, submit_url } => {
                    passport::cmd_passport_challenge_submit(&input, &submit_url, json_output)
                }
                PassportChallengeCommands::Verify {
                    input,
                    challenge,
                    verifier_policies_file,
                    verifier_challenge_db,
                    passport_statuses_file,
                    at,
                } => passport::cmd_passport_challenge_verify(
                    &input,
                    challenge.as_deref(),
                    verifier_policies_file.as_deref(),
                    verifier_challenge_db.as_deref(),
                    passport_statuses_file.as_deref(),
                    at,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Status { command } => match command {
                PassportStatusCommands::Publish {
                    input,
                    passport_statuses_file,
                    resolve_urls,
                    cache_ttl_secs,
                } => passport::cmd_passport_status_publish(
                    &input,
                    passport_statuses_file.as_deref(),
                    &resolve_urls,
                    cache_ttl_secs,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::List {
                    passport_statuses_file,
                } => passport::cmd_passport_status_list(
                    passport_statuses_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Get {
                    passport_id,
                    passport_statuses_file,
                } => passport::cmd_passport_status_get(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Resolve {
                    passport_id,
                    passport_statuses_file,
                } => passport::cmd_passport_status_resolve(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Revoke {
                    passport_id,
                    passport_statuses_file,
                    reason,
                    revoked_at,
                } => passport::cmd_passport_status_revoke(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    reason.as_deref(),
                    revoked_at,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Issuance { command } => match command {
                PassportIssuanceCommands::Metadata {
                    issuer_url,
                    signing_seed_file,
                    passport_status_url,
                    passport_status_cache_ttl_secs,
                } => passport::cmd_passport_issuance_metadata(
                    issuer_url.as_deref(),
                    signing_seed_file.as_deref(),
                    passport_status_url.as_deref(),
                    passport_status_cache_ttl_secs,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Offer {
                    input,
                    output,
                    issuer_url,
                    passport_issuance_offers_file,
                    passport_statuses_file,
                    signing_seed_file,
                    credential_configuration_id,
                    ttl_secs,
                } => passport::cmd_passport_issuance_offer_create(
                    &input,
                    output.as_deref(),
                    issuer_url.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    passport_statuses_file.as_deref(),
                    signing_seed_file.as_deref(),
                    credential_configuration_id.as_deref(),
                    ttl_secs,
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Token {
                    offer,
                    output,
                    passport_issuance_offers_file,
                } => passport::cmd_passport_issuance_token_redeem(
                    &offer,
                    output.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Credential {
                    offer,
                    token,
                    output,
                    passport_issuance_offers_file,
                    passport_statuses_file,
                    signing_seed_file,
                    credential_configuration_id,
                    credential_format,
                } => passport::cmd_passport_issuance_credential_redeem(
                    &offer,
                    &token,
                    output.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    passport_statuses_file.as_deref(),
                    signing_seed_file.as_deref(),
                    credential_configuration_id.as_deref(),
                    credential_format.as_deref(),
                    json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Oid4vp { command } => match command {
                PassportOid4vpCommands::Create {
                    output,
                    disclosure_claims,
                    issuer_allowlist,
                    ttl_secs,
                    identity_subject,
                    identity_continuity_id,
                    identity_provider,
                    identity_session_hint,
                    identity_ttl_secs,
                } => passport::cmd_passport_oid4vp_request_create(
                    passport::PassportOid4vpRequestCreateArgs {
                        output: output.as_deref(),
                        disclosure_claims: &disclosure_claims,
                        issuer_allowlist: &issuer_allowlist,
                        ttl_secs,
                        identity_subject: identity_subject.as_deref(),
                        identity_continuity_id: identity_continuity_id.as_deref(),
                        identity_provider: identity_provider.as_deref(),
                        identity_session_hint: identity_session_hint.as_deref(),
                        identity_ttl_secs,
                        json_output,
                        control_url: control_url.as_deref(),
                        control_token: control_token.as_deref(),
                    },
                ),
                PassportOid4vpCommands::Respond {
                    input,
                    request_url,
                    same_device_url,
                    cross_device_url,
                    holder_seed_file,
                    output,
                    submit,
                    submit_url,
                    at,
                } => passport::cmd_passport_oid4vp_respond(passport::PassportOid4vpRespondArgs {
                    input: &input,
                    request_url: request_url.as_deref(),
                    same_device_url: same_device_url.as_deref(),
                    cross_device_url: cross_device_url.as_deref(),
                    holder_seed_file: &holder_seed_file,
                    output: output.as_deref(),
                    submit,
                    submit_url: submit_url.as_deref(),
                    at,
                    json_output,
                }),
                PassportOid4vpCommands::Submit { input, submit_url } => {
                    passport::cmd_passport_oid4vp_submit(&input, &submit_url, json_output)
                }
                PassportOid4vpCommands::Metadata { verifier_url } => {
                    passport::cmd_passport_oid4vp_metadata(&verifier_url, json_output)
                }
            },
        },
        Commands::Cert { command } => match command {
            CertCommands::Generate {
                session_id,
                receipt_db: cert_receipt_db,
                budget_limit,
                output,
            } => cert::cmd_cert_generate(
                &session_id,
                &cert_receipt_db,
                budget_limit,
                output.as_deref(),
                authority_seed_file.as_deref(),
                json_output,
            ),
            CertCommands::Verify {
                certificate,
                full,
                receipt_db: cert_receipt_db,
            } => cert::cmd_cert_verify(&certificate, full, cert_receipt_db.as_deref(), json_output),
            CertCommands::Inspect { certificate } => {
                cert::cmd_cert_inspect(&certificate, json_output)
            }
        },
        Commands::Reputation { command } => match command {
            ReputationCommands::Local {
                subject_public_key,
                since,
                until,
                policy,
            } => reputation::cmd_reputation_local(reputation::ReputationLocalCommand {
                subject_public_key: &subject_public_key,
                since,
                until,
                policy_path: policy.as_deref(),
                json_output,
                receipt_db_path: receipt_db.as_deref(),
                budget_db_path: budget_db.as_deref(),
                control_url: control_url.as_deref(),
                control_token: control_token.as_deref(),
            }),
            ReputationCommands::Compare {
                subject_public_key,
                passport,
                since,
                until,
                local_policy,
                verifier_policy,
            } => reputation::cmd_reputation_compare(reputation::ReputationCompareCommand {
                subject_public_key: &subject_public_key,
                passport_path: &passport,
                since,
                until,
                local_policy_path: local_policy.as_deref(),
                verifier_policy_path: verifier_policy.as_deref(),
                json_output,
                receipt_db_path: receipt_db.as_deref(),
                budget_db_path: budget_db.as_deref(),
                control_url: control_url.as_deref(),
                control_token: control_token.as_deref(),
            }),
        },
        Commands::Guard { command } => match command {
            GuardCommands::New { name } => guard::cmd_guard_new(&name),
            GuardCommands::Build => guard::cmd_guard_build(),
            GuardCommands::Inspect { path } => guard::cmd_guard_inspect(&path),
            GuardCommands::Test { wasm, fixtures, fuel_limit } => guard::cmd_guard_test(&wasm, &fixtures, fuel_limit),
            GuardCommands::Bench { path, iterations, fuel_limit } => guard::cmd_guard_bench(&path, iterations, fuel_limit),
            GuardCommands::Pack => guard::cmd_guard_pack(),
            GuardCommands::Publish {
                project,
                reference,
                wit,
                signer_public_key,
                signer_subject,
                fuel_limit,
                memory_limit_bytes,
                epoch_id_seed,
                username,
                password,
                allow_http_registry,
            } => guard::cmd_guard_publish(guard::GuardPublishCommand {
                project_dir: &project,
                reference: &reference,
                wit_path: &wit,
                signer_public_key: signer_public_key.as_deref(),
                signer_subject: signer_subject.as_deref(),
                fuel_limit,
                memory_limit_bytes,
                epoch_id_seed: &epoch_id_seed,
                username: username.as_deref(),
                password: password.as_deref(),
                allow_http_registry: allow_http_registry.clone(),
            }),
            GuardCommands::Pull {
                reference,
                username,
                password,
                allow_http_registry,
            } => guard::cmd_guard_pull(guard::GuardPullCommand {
                reference: &reference,
                username: username.as_deref(),
                password: password.as_deref(),
                allow_http_registry: allow_http_registry.clone(),
            }),
            GuardCommands::Blocklist { command } => match command {
                GuardBlocklistCommands::Remove { digest } => {
                    commands::guard_blocklist::cmd_guard_blocklist_remove(&digest)
                }
            },
            GuardCommands::Install { path, target_dir } => guard::cmd_guard_install(&path, &target_dir),
            GuardCommands::Sign { wasm, key, name, version } => {
                guards::sign::cmd_guard_sign(&wasm, &key, &name, &version)
            }
            GuardCommands::Verify { wasm } => guards::sign::cmd_guard_verify(&wasm),
            GuardCommands::Market { command } => match command {
                GuardMarketCommands::List {
                    catalog,
                    tenant,
                    tier,
                    currency,
                    json,
                } => cmd_market_list(&catalog, &tenant, &tier, &currency, json || json_output),
                GuardMarketCommands::Info {
                    catalog,
                    reference,
                    tenant,
                    tier,
                    currency,
                    publisher_revoked,
                    json,
                } => cmd_market_info(
                    &catalog,
                    &reference,
                    &tenant,
                    &tier,
                    &currency,
                    publisher_revoked,
                    json || json_output,
                ),
                GuardMarketCommands::Install {
                    catalog,
                    bundle_dir,
                    reference,
                    tenant,
                    tier,
                    currency,
                    publisher_revoked,
                    json,
                } => cmd_market_install(
                    &catalog,
                    &bundle_dir,
                    &reference,
                    &tenant,
                    &tier,
                    &currency,
                    publisher_revoked,
                    json || json_output,
                ),
            },
        },
        Commands::Conformance { command } => match command {
            ConformanceCommands::Run {
                peer,
                report,
                scenario,
                output,
            } => cmd_conformance_run(
                &peer,
                report.as_deref(),
                scenario.as_deref(),
                output.as_deref(),
            ),
            ConformanceCommands::FetchPeers {
                check,
                out,
                language,
                lockfile,
            } => cmd_conformance_fetch_peers(
                check,
                &out,
                language.as_deref(),
                lockfile.as_deref(),
            ),
        },
        Commands::Chiodos { command } => match command {
            ChiodosCommands::Verify {
                package,
                trust_bundle,
                context,
                report,
            } => cmd_chiodos_verify(&package, &trust_bundle, &context, &report),
            ChiodosCommands::Authority { command } => match command {
                ChiodosAuthorityCommands::Issue {
                    profile,
                    request,
                    signing_keys,
                    out_dir,
                } => cmd_chiodos_authority_issue(&profile, &request, &signing_keys, &out_dir),
                ChiodosAuthorityCommands::Checkpoint {
                    profile,
                    revocations,
                    signing_keys,
                    out,
                } => cmd_chiodos_authority_checkpoint(
                    &profile,
                    &revocations,
                    &signing_keys,
                    &out,
                ),
                ChiodosAuthorityCommands::TrustBundle { command } => match command {
                    ChiodosTrustBundleCommands::Assemble {
                        profile,
                        peer_pins,
                        workflow_intersection,
                        disclosure_policy,
                        checkpoint,
                        out,
                    } => cmd_chiodos_authority_trust_bundle_assemble(
                        &profile,
                        &peer_pins,
                        &workflow_intersection,
                        &disclosure_policy,
                        &checkpoint,
                        &out,
                    ),
                },
            },
            ChiodosCommands::Pheromone { command } => match command {
                ChiodosPheromoneCommands::Receive {
                    batch,
                    transit_policy,
                    proof_package,
                    trust_bundle,
                    context,
                    store,
                    now_unix_ms,
                    report,
                } => cmd_chiodos_pheromone_receive(
                    &batch,
                    &transit_policy,
                    &proof_package,
                    &trust_bundle,
                    &context,
                    &store,
                    now_unix_ms,
                    &report,
                ),
                ChiodosPheromoneCommands::Query {
                    store,
                    subject_class,
                    namespace,
                    reputation_epoch,
                    peer_weights,
                    now_unix_ms,
                    report,
                } => cmd_chiodos_pheromone_query(
                    &store,
                    &subject_class,
                    &namespace,
                    reputation_epoch,
                    &peer_weights,
                    now_unix_ms,
                    &report,
                ),
                ChiodosPheromoneCommands::Relay { command } => match command {
                    ChiodosPheromoneRelayCommands::Lint {
                        peer_directory,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        report,
                    } => cmd_chiodos_pheromone_relay_lint(
                        peer_directory.as_deref(),
                        peer_directory_state.as_deref(),
                        profile.into(),
                        trusted_issuers.as_deref(),
                        &report,
                    ),
                    ChiodosPheromoneRelayCommands::Serve {
                        listen,
                        store,
                        peer_directory,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        transit_policy,
                        proof_package,
                        trust_bundle,
                        context,
                        report_dir,
                        operator_token_env,
                    } => cmd_chiodos_pheromone_relay_serve(
                        &listen,
                        &store,
                        peer_directory.as_deref(),
                        peer_directory_state.as_deref(),
                        profile.into(),
                        trusted_issuers.as_deref(),
                        &transit_policy,
                        &proof_package,
                        &trust_bundle,
                        &context,
                        &report_dir,
                        operator_token_env.as_deref(),
                    ),
                    ChiodosPheromoneRelayCommands::Enqueue {
                        store,
                        peer_directory,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_pheromone_relay_enqueue(
                        &store,
                        peer_directory.as_deref(),
                        peer_directory_state.as_deref(),
                        profile.into(),
                        trusted_issuers.as_deref(),
                        now_unix_ms,
                        &report,
                    ),
                    ChiodosPheromoneRelayCommands::Tick {
                        store,
                        peer_directory,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        now_unix_ms,
                        max_batches,
                        signing_key,
                        report,
                        report_dir,
                    } => cmd_chiodos_pheromone_relay_tick(
                        &store,
                        peer_directory.as_deref(),
                        peer_directory_state.as_deref(),
                        profile.into(),
                        trusted_issuers.as_deref(),
                        now_unix_ms,
                        max_batches,
                        &signing_key,
                        &report,
                        report_dir.as_deref(),
                    ),
                    ChiodosPheromoneRelayCommands::Catchup {
                        store,
                        peer,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        now_unix_ms,
                        treaty,
                        after_cursor,
                        limit,
                        report,
                    } => cmd_chiodos_pheromone_relay_catchup(
                        &store,
                        &peer,
                        peer_directory_state.as_deref(),
                        profile.into(),
                        trusted_issuers.as_deref(),
                        now_unix_ms,
                        &treaty,
                        &after_cursor,
                        limit,
                        &report,
                    ),
                    ChiodosPheromoneRelayCommands::Status { store, report } => {
                        cmd_chiodos_pheromone_relay_status(&store, &report)
                    }
                    ChiodosPheromoneRelayCommands::Observe {
                        store,
                        peer_directory_state,
                        profile,
                        trusted_issuers,
                        report_dir,
                        limit,
                        report,
                    } => cmd_chiodos_pheromone_relay_observe(
                        &store,
                        &peer_directory_state,
                        profile.into(),
                        &trusted_issuers,
                        &report_dir,
                        limit,
                        &report,
                    ),
                    ChiodosPheromoneRelayCommands::Metrics {
                        store,
                        format,
                        output,
                    } => cmd_chiodos_pheromone_relay_metrics(&store, format.into(), &output),
                    ChiodosPheromoneRelayCommands::Alert { command } => match command {
                        ChiodosPheromoneRelayAlertCommands::Evaluate {
                            observability_report,
                            event_dir,
                            routing_profile,
                            suppression_state,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_pheromone_relay_alert_evaluate(
                            &observability_report,
                            &event_dir,
                            &routing_profile,
                            &suppression_state,
                            now_unix_ms,
                            &report,
                        ),
                        ChiodosPheromoneRelayAlertCommands::Handoff {
                            alert_report,
                            trend_report,
                            routing_profile,
                            handoff_profile,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_pheromone_relay_alert_handoff(
                            &alert_report,
                            &trend_report,
                            &routing_profile,
                            &handoff_profile,
                            now_unix_ms,
                            &report,
                        ),
                        ChiodosPheromoneRelayAlertCommands::Delivery { command } => match command {
                            ChiodosPheromoneRelayAlertDeliveryCommands::Import {
                                handoff_report,
                                delivery_profile,
                                evidence_dir,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_delivery_import(
                                &handoff_report,
                                &delivery_profile,
                                &evidence_dir,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertDeliveryCommands::Acknowledge {
                                handoff_report,
                                delivery_report,
                                delivery_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_delivery_acknowledge(
                                &handoff_report,
                                &delivery_report,
                                &delivery_profile,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertDeliveryCommands::Drift {
                                handoff_reports_dir,
                                delivery_reports_dir,
                                delivery_profile,
                                since_unix_ms,
                                until_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_delivery_drift(
                                &handoff_reports_dir,
                                &delivery_reports_dir,
                                &delivery_profile,
                                since_unix_ms,
                                until_unix_ms,
                                &report,
                            ),
                        },
                    },
                    ChiodosPheromoneRelayCommands::Trend {
                        reports_dir,
                        event_dir,
                        routing_profile,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chiodos_pheromone_relay_trend(
                        &reports_dir,
                        &event_dir,
                        &routing_profile,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                    ChiodosPheromoneRelayCommands::Directory { command } => match command {
                        ChiodosPheromoneRelayDirectoryCommands::Inspect { state, report } => {
                            cmd_chiodos_pheromone_relay_directory_inspect(&state, &report)
                        }
                        ChiodosPheromoneRelayDirectoryCommands::Promote {
                            state,
                            candidate,
                            trusted_issuers,
                            profile,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_pheromone_relay_directory_promote(
                            &state,
                            &candidate,
                            &trusted_issuers,
                            profile.into(),
                            now_unix_ms,
                            &report,
                        ),
                        ChiodosPheromoneRelayDirectoryCommands::Reject {
                            state,
                            candidate,
                            reason,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_pheromone_relay_directory_reject(
                            &state,
                            &candidate,
                            &reason,
                            now_unix_ms,
                            &report,
                        ),
                    },
                    ChiodosPheromoneRelayCommands::Supervisor { command } => match command {
                        ChiodosPheromoneRelaySupervisorCommands::Lint { profile, report } => {
                            cmd_chiodos_pheromone_relay_supervisor_lint(&profile, &report)
                        }
                    },
                },
            },
        },
        Commands::Replay(args) => cmd_replay(&args),
        Commands::Lineage { command } => dispatch_lineage(command, json_output),
        Commands::Settle { command } => match command {
            SettleCommands::Status { store, json } => {
                let resolved = store.or_else(|| receipt_db.clone());
                match resolved {
                    Some(path) => match settle::cmd_settle_status(&path, json || json_output) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(CliError::Other(format!("settle status: {err}"))),
                    },
                    None => Err(CliError::Other(
                        "settle status: no store path supplied; pass --store or set --receipt-db"
                            .to_string(),
                    )),
                }
            }
        },
        Commands::Doctor(args) => cmd_doctor(&args, json_output),
        Commands::Arena { command } => match command {
            ArenaCommands::Run {
                scenario,
                output_root,
                json,
            } => cmd_arena_run(&scenario, output_root.as_deref(), json || json_output),
            ArenaCommands::Replay {
                scenario_id,
                output_root,
                bundle_dir,
                json,
            } => cmd_arena_replay(
                &scenario_id,
                output_root.as_deref(),
                bundle_dir.as_deref(),
                json || json_output,
            ),
            ArenaCommands::Evolve {
                seed,
                generations,
                wall_seconds,
                output_root,
                json,
            } => cmd_arena_evolve(
                &seed,
                generations,
                wall_seconds,
                output_root.as_deref(),
                json || json_output,
            ),
        },
        Commands::Bind {
            provider,
            card,
            bundle,
            issuer_san_regex,
            issuer_oidc,
        } => commands::bind::cmd_bind(
            &provider,
            &card,
            bundle.as_deref(),
            issuer_san_regex.as_deref(),
            issuer_oidc.as_deref(),
            json_output,
        ),
    };

    if let Err(e) = result {
        let mut stderr = std::io::stderr();
        let _ = write_cli_error(&mut stderr, &e, json_output);
        std::process::exit(1);
    }
}

fn write_cli_error(
    writer: &mut impl Write,
    error: &CliError,
    json_output: bool,
) -> std::io::Result<()> {
    let report = error.report();
    if json_output {
        serde_json::to_writer(&mut *writer, &report)
            .map_err(std::io::Error::other)?;
        writeln!(writer)
    } else {
        writeln!(writer, "error [{}]: {}", report.code, report.message)?;
        writeln!(writer, "context: {}", report.context)?;
        writeln!(writer, "suggested fix: {}", report.suggested_fix)
    }
}

fn parse_market_tier(value: &str) -> Result<chio_reputation::ReputationTier, CliError> {
    match value {
        "tier0" | "tier_0" => Ok(chio_reputation::ReputationTier::Tier0),
        "tier1" | "tier_1" => Ok(chio_reputation::ReputationTier::Tier1),
        "tier2" | "tier_2" => Ok(chio_reputation::ReputationTier::Tier2),
        "tier3" | "tier_3" => Ok(chio_reputation::ReputationTier::Tier3),
        other => Err(CliError::Other(format!(
            "unknown reputation tier '{other}'; expected tier0..tier3"
        ))),
    }
}

fn cmd_market_list(
    catalog: &Path,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let report = market::market_list(catalog, &context)
        .map_err(|err| CliError::Other(format!("market list: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&report)
            .map_err(|err| CliError::Other(format!("market list serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
    } else {
        let table = market::render_list_table(&report);
        std::io::Write::write_all(&mut std::io::stdout(), table.as_bytes())
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
    }
    Ok(())
}

fn cmd_market_info(
    catalog: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let report = market::market_info(catalog, &context, reference, publisher_revoked)
        .map_err(|err| CliError::Other(format!("market info: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&report)
            .map_err(|err| CliError::Other(format!("market info serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
    } else {
        let text = market::render_info_text(&report);
        std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_market_install(
    catalog: &Path,
    bundle_dir: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let record =
        market::market_install(catalog, bundle_dir, &context, reference, publisher_revoked)
            .map_err(|err| CliError::Other(format!("market install: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|err| CliError::Other(format!("market install serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
    } else {
        let line = format!(
            "installed {} for tenant {} at {} {} (limit {} {})\n",
            record.reference,
            record.tenant_id,
            record.registered_price_units,
            record.registered_price_currency,
            record.credit_limit_units,
            record.credit_limit_currency,
        );
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
    }
    Ok(())
}

fn dispatch_lineage(command: LineageCommands, json_output: bool) -> Result<(), CliError> {
    use crate::lineage as ln;
    use chio_lineage::query::QueryBounds;
    match command {
        LineageCommands::Query {
            graph,
            seeds,
            direction,
            depth_limit,
            row_limit,
            json,
        } => {
            let dir = match direction.as_str() {
                "forward" => ln::Direction::Forward,
                "reverse" => ln::Direction::Reverse,
                other => {
                    return Err(CliError::Other(format!(
                        "lineage query: unknown direction {other:?}; expected forward or reverse"
                    )));
                }
            };
            let bounds = QueryBounds {
                depth_limit,
                row_limit,
            };
            let report = ln::cmd_query(&graph, &seeds, dir, bounds)
                .map_err(|e| CliError::Other(format!("lineage query: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!(
                    "lineage {}: nodes={} edges={}\n",
                    report.direction,
                    report.graph.nodes.len(),
                    report.graph.edges.len(),
                );
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage query write: {e}")))
            }
        }
        LineageCommands::Diff {
            left_label,
            left,
            right_label,
            right,
            json,
        } => {
            let report = ln::cmd_diff(&left_label, &left, &right_label, &right)
                .map_err(|e| CliError::Other(format!("lineage diff: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let text = ln::render_diff_text(&report);
                std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage diff write: {e}")))
            }
        }
        LineageCommands::Roots { dir, json } => {
            let report =
                ln::cmd_roots(&dir).map_err(|e| CliError::Other(format!("lineage roots: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!("anchored roots: {}\n", report.roots.len());
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage roots write: {e}")))
            }
        }
    }
}

fn emit_lineage_report<T: serde::Serialize>(report: &T, json: bool) -> Result<(), CliError> {
    if json {
        let bytes = serde_json::to_vec_pretty(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    } else {
        let line = serde_json::to_string(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    }
    Ok(())
}

fn cmd_chiodos_verify(
    package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let package_bytes = fs::read(package).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos proof package {}: {error}",
            package.display()
        ))
    })?;
    let package = chio_chiodos::proof_package_from_json(
        std::str::from_utf8(&package_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos proof package {} is not UTF-8 JSON: {error}",
                package.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_bytes = fs::read(trust_bundle).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos verifier trust bundle {}: {error}",
            trust_bundle.display()
        ))
    })?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(
        std::str::from_utf8(&trust_bundle_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos verifier trust bundle {} is not UTF-8 JSON: {error}",
                trust_bundle.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}")))?;
    let context_bytes = fs::read(context).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos verification context {}: {error}",
            context.display()
        ))
    })?;
    let context = chio_chiodos::verification_context_from_json(
        std::str::from_utf8(&context_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos verification context {} is not UTF-8 JSON: {error}",
                context.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
    let verifier_report = chio_chiodos::verify_package_report(&package, &trust_bundle, &context);
    if let Some(parent) = report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create report directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    let report_json = chio_chiodos::report_json(&verifier_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos report JSON: {error}")))?;
    fs::write(report, report_json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chiodos verifier report {}: {error}",
            report.display()
        ))
    })?;
    if verifier_report.accepted {
        Ok(())
    } else {
        let failure = verifier_report.failure.as_ref().map_or_else(
            || "unknown verifier rejection".to_string(),
            |failure| format!("{}: {}", failure.code, failure.detail),
        );
        Err(CliError::cli_other_error(format!(
            "Chiodos verify rejected package: {failure}"
        )))
    }
}

fn cmd_chiodos_pheromone_receive(
    batch: &Path,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    store: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let batch_json = read_utf8_json_file(batch, "Chiodos pheromone gossip batch")?;
    let batch: chio_federation::PheromoneGossipBatch = serde_json::from_str(&batch_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone batch: {error}")))?;
    let policy_json = read_utf8_json_file(transit_policy, "Chiodos pheromone transit policy")?;
    let now_unix_ms = now_unix_ms.unwrap_or(batch.flushed_at_unix_ms);
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(&policy_json, now_unix_ms).map_err(
            |error| {
                CliError::cli_other_error(format!("Chiodos pheromone runtime policy: {error}"))
            },
        )?;
    let package_json = read_utf8_json_file(proof_package, "Chiodos proof package")?;
    let package = chio_chiodos::proof_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle, "Chiodos verifier trust bundle")?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context, "Chiodos verification context")?;
    let context = chio_chiodos::verification_context_from_json(&context_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
    let resolver = chio_pheromone_runtime::VerifiedChiodosWorkflowResolver::from_verified_package(
        &package,
        &trust_bundle,
        &context,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos workflow resolver: {error}")))?;
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let receiver = chio_pheromone_runtime::PheromoneReceiver::new(
        store,
        resolver,
        receiver_config,
    );
    let receive_report = receiver
        .receive_batch(&batch, &transit_policy)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone receive: {error}")))?;
    let report_json = serde_json::to_string_pretty(&receive_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))?;
    if receive_report.accepted {
        Ok(())
    } else {
        let failure = receive_report
            .frames
            .iter()
            .find(|frame| !frame.accepted)
            .map_or_else(
                || "unknown pheromone receiver rejection".to_string(),
                |frame| format!("{}: {}", frame.code, frame.detail),
            );
        Err(CliError::cli_other_error(format!(
            "Chiodos pheromone receive rejected batch: {failure}"
        )))
    }
}

fn cmd_chiodos_pheromone_query(
    store: &Path,
    subject_class: &str,
    namespace: &str,
    reputation_epoch: u64,
    peer_weights: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let weights_json = read_utf8_json_file(peer_weights, "Chiodos pheromone peer weights")?;
    let weights = chio_pheromone_runtime::peer_weights_from_json(&weights_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer weights: {error}")))?;
    let validation_context = chio_pheromone::PheromoneValidationContext {
        now_unix_ms: now_unix_ms.unwrap_or_else(unix_now_ms),
        replay_window_ms: 0,
        active_peers_in_treaty: 0,
        known_reputation_epochs: vec![reputation_epoch],
        passports: Vec::new(),
        kernel_public_keys: Vec::new(),
        subject_classes: Vec::new(),
        max_deposits_per_pair: 0,
    };
    let concentration = chio_pheromone_runtime::PheromoneRuntimeStore::query_concentration(
        &store,
        subject_class,
        namespace,
        validation_context.now_unix_ms,
        reputation_epoch,
        &validation_context,
        &weights,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone query: {error}")))?;
    let query_report = chio_pheromone_runtime::PheromoneQueryReport {
        schema: chio_pheromone_runtime::PHEROMONE_QUERY_REPORT_SCHEMA.to_string(),
        accepted: true,
        concentration,
    };
    let report_json = serde_json::to_string_pretty(&query_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))
}

#[derive(Clone)]
struct CliRelayBatchReceiver {
    store: std::path::PathBuf,
    transit_policy: chio_federation::PheromoneTransitPolicy,
    receiver_config: chio_pheromone_runtime::PheromoneReceiverConfig,
    resolver: chio_pheromone_runtime::VerifiedChiodosWorkflowResolver,
}

#[async_trait::async_trait]
impl chio_pheromone_relay::RelayBatchReceiver for CliRelayBatchReceiver {
    async fn receive_batch(
        &self,
        batch: chio_federation::PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, chio_pheromone_relay::PheromoneRelayError>
    {
        let mut config = self.receiver_config.clone();
        config.authenticated_sender_kernel_id = authenticated_sender_kernel_id;
        config.validation_context.now_unix_ms = received_at_unix_ms;
        let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(&self.store)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))?;
        let receiver =
            chio_pheromone_runtime::PheromoneReceiver::new(store, self.resolver.clone(), config);
        receiver
            .receive_batch(&batch, &self.transit_policy)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayTrustedIssuersDocument {
    issuers: Vec<RelayTrustedIssuerDocument>,
    min_version: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayTrustedIssuerDocument {
    issuer: String,
    key_id: String,
    public_key: chio_core::crypto::PublicKey,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelaySigningKeyDocument {
    kernel_id: String,
    seed_hex: String,
}

fn cmd_chiodos_pheromone_relay_lint(
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    report: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let result = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    );
    let (accepted, code, detail, local_kernel_id, peer_directory_version) = match result {
        Ok(directory) => (
            true,
            "accepted".to_string(),
            "peer directory satisfies relay profile".to_string(),
            directory.local_kernel_id().to_string(),
            directory.version(),
        ),
        Err(error) => (
            false,
            "relay_profile_denied".to_string(),
            error.to_string(),
            "unknown".to_string(),
            None,
        ),
    };
    let lint_report = chio_pheromone_relay::RelayHealthReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA.to_string(),
        accepted,
        code: code.clone(),
        detail,
        local_kernel_id,
        generated_at_unix_ms: now,
        peer_directory_version,
        queue_depth: 0,
        oldest_pending_age_ms: None,
        retry_count: 0,
        dead_letter_count: 0,
        inbox_count: 0,
        cursor_count: 0,
        stale_lease_count: 0,
        checks: vec![chio_pheromone_relay::RelayHealthCheck {
            code,
            accepted,
            detail: "relay profile lint".to_string(),
        }],
    };
    let json = serde_json::to_string_pretty(&lint_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay lint: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_pheromone_relay_serve(
    listen: &str,
    store: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report_dir: &Path,
    operator_token_env: Option<&str>,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to create Chiodos pheromone relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let operator_token = if let Some(env_name) = operator_token_env {
        Some(std::env::var(env_name).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos pheromone relay operator token env {env_name}: {error}"
            ))
        })?)
    } else {
        None
    };
    if matches!(profile, chio_pheromone_relay::RelayProfile::Production)
        && operator_token.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(CliError::cli_other_error(
            "Chiodos pheromone relay production serve requires --operator-token-env".to_string(),
        ));
    }
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let policy_json = read_utf8_json_file(transit_policy, "Chiodos pheromone transit policy")?;
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(&policy_json, now).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone runtime policy: {error}"))
        })?;
    let package_json = read_utf8_json_file(proof_package, "Chiodos proof package")?;
    let package = chio_chiodos::proof_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle, "Chiodos verifier trust bundle")?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context, "Chiodos verification context")?;
    let context = chio_chiodos::verification_context_from_json(&context_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
    let resolver = chio_pheromone_runtime::VerifiedChiodosWorkflowResolver::from_verified_package(
        &package,
        &trust_bundle,
        &context,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos workflow resolver: {error}")))?;
    let relay_store = std::sync::Arc::new(
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}"))
        })?,
    );
    let receiver = std::sync::Arc::new(CliRelayBatchReceiver {
        store: store.to_path_buf(),
        transit_policy,
        receiver_config,
        resolver,
    });
    let service = chio_pheromone_relay::PheromoneRelayService::new(
        chio_pheromone_relay::PheromoneRelayConfig {
            local_kernel_id: peer_directory.local_kernel_id().to_string(),
            profile,
            now_unix_ms: now,
            freshness_window_ms: 60_000,
            max_body_bytes: 1_048_576,
            use_system_clock: true,
            operator_token,
            report_dir: Some(report_dir.to_path_buf()),
        },
        peer_directory,
        receiver,
        relay_store,
    );
    let address = listen.parse::<std::net::SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("Chiodos pheromone relay listen address: {error}"))
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay runtime: {error}")))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await.map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone relay bind: {error}"))
        })?;
        service
            .serve(listener)
            .await
            .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone relay: {error}")))
    })
}

fn cmd_chiodos_pheromone_relay_enqueue(
    store: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now_unix_ms,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let status = relay_store
        .operator_report("local", now_unix_ms)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay enqueue: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_pheromone_relay_tick(
    store: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: Option<u64>,
    max_batches: usize,
    signing_key: &Path,
    report: &Path,
    report_dir: Option<&Path>,
) -> Result<(), CliError> {
    let now_unix_ms = now_unix_ms.unwrap_or_else(unix_now_ms);
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now_unix_ms,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let (sender_kernel_id, keypair) = load_relay_signing_key(signing_key)?;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay runtime: {error}")))?;
    let tick_report = runtime
        .block_on(chio_pheromone_relay::deliver_due_batches(
            &relay_store,
            peer_directory,
            keypair,
            &sender_kernel_id,
            now_unix_ms,
            max_batches,
        ))
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay tick: {error}")))?;
    let json = serde_json::to_string_pretty(&tick_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))?;
    if let Some(report_dir) = report_dir {
        write_relay_outbound_event_report(
            report_dir,
            &sender_kernel_id,
            now_unix_ms,
            &tick_report,
        )?;
    }
    Ok(())
}

fn write_relay_outbound_event_report(
    report_dir: &Path,
    local_kernel_id: &str,
    generated_at_unix_ms: u64,
    tick_report: &chio_pheromone_relay::RelayTickReport,
) -> Result<(), CliError> {
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay event report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let code = if tick_report.accepted {
        "accepted".to_string()
    } else {
        tick_report
            .failures
            .first()
            .and_then(|failure| failure.split_once(": "))
            .map(|(_, code)| code.to_string())
            .unwrap_or_else(|| "outbound_delivery_failed".to_string())
    };
    let detail = format!(
        "delivered={} retried={} deadLettered={} duplicateIdempotent={}",
        tick_report.delivered,
        tick_report.retried,
        tick_report.dead_lettered,
        tick_report.duplicate_idempotent
    );
    let report = chio_pheromone_relay::RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: tick_report.accepted,
        code: code.clone(),
        detail,
        local_kernel_id: local_kernel_id.to_string(),
        generated_at_unix_ms,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: if tick_report.accepted {
            None
        } else {
            Some(code)
        },
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay event report: {error}")))?;
    let path = report_dir.join(format!("{generated_at_unix_ms}-outbound-delivery.json"));
    write_json_string(&path, &format!("{json}\n"))
}

fn cmd_chiodos_pheromone_relay_catchup(
    store: &Path,
    peer: &str,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: Option<u64>,
    treaty: &str,
    after_cursor: &str,
    limit: usize,
    report: &Path,
) -> Result<(), CliError> {
    let mut max_catchup_bytes = usize::MAX;
    if let Some(state_path) = peer_directory_state {
        let directory = load_relay_peer_directory_from_paths(
            None,
            Some(state_path),
            now_unix_ms.unwrap_or_else(unix_now_ms),
            profile,
            trusted_issuers,
            "Chiodos peer directory state",
        )?;
        let peer_entry = directory.peer(peer).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos catch-up peer directory: {error}"))
        })?;
        if !peer_entry.treaty_subscriptions.iter().any(|id| id == treaty) {
            return Err(CliError::cli_other_error(format!(
                "Chiodos catch-up peer directory: {}",
                chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                    "peer {peer} is not subscribed to treaty {treaty}"
                ))
            )));
        }
        if limit > peer_entry.max_catchup_frames {
            return Err(CliError::cli_other_error(format!(
                "Chiodos catch-up peer directory: {}",
                chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                    "requested limit {limit} exceeds peer bound {}",
                    peer_entry.max_catchup_frames
                ))
            )));
        }
        max_catchup_bytes = peer_entry.max_catchup_bytes;
    }
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}"))
    })?;
    let (frames, next_cursor) = relay_store
        .catchup_batches(peer, treaty, after_cursor, limit, max_catchup_bytes)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos catch-up: {error}")))?;
    let catchup = chio_pheromone_relay::CatchupResponse {
        schema: chio_pheromone_relay::PHEROMONE_CATCHUP_RESPONSE_SCHEMA.to_string(),
        accepted: true,
        responder_kernel_id: "local".to_string(),
        requester_kernel_id: peer.to_string(),
        treaty_id: treaty.to_string(),
        frames,
        next_cursor,
        code: format!("accepted_limit_{limit}"),
    };
    let json = serde_json::to_string_pretty(&catchup)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos catch-up report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_pheromone_relay_status(store: &Path, report: &Path) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let status = relay_store
        .operator_report("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay status: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_pheromone_relay_observe(
    store: &Path,
    peer_directory_state: &Path,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: &Path,
    report_dir: &Path,
    limit: usize,
    report: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to create Chiodos relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let state_json = read_utf8_json_file(peer_directory_state, "Chiodos peer-directory state")?;
    let state = chio_pheromone_relay::peer_directory_state_from_json(&state_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let directory = state
        .active_directory(&trust)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))?;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let report_document = relay_store
        .relay_observability_report(chio_pheromone_relay::RelayObservabilityInput {
            local_kernel_id: directory.local_kernel_id(),
            generated_at_unix_ms: now,
            peer_directory: Some(&directory),
            peer_directory_state: Some(&state),
            profile,
            recent_failure_limit: limit,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay observability: {error}")))?;
    write_pretty_json(report, &report_document, "Chiodos relay observability")
}

fn cmd_chiodos_pheromone_relay_metrics(
    store: &Path,
    format: chio_pheromone_relay::RelayMetricsFormat,
    output: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let snapshot = relay_store
        .relay_metrics_snapshot("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay metrics: {error}")))?;
    write_json_string(output, &snapshot.render(format))
}

fn cmd_chiodos_pheromone_relay_alert_evaluate(
    observability_report: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    suppression_state: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let observability: chio_pheromone_relay::RelayObservabilityReport = serde_json::from_str(
        &read_utf8_json_file(observability_report, "Chiodos relay observability report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay observability report: {error}"))
    })?;
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let suppression = chio_pheromone_relay::relay_alert_suppression_state_from_json(
        &read_utf8_json_file(suppression_state, "Chiodos relay alert suppression state")?,
        &profile,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert suppression state: {error}"))
    })?;
    let events = read_relay_event_reports(event_dir)?;
    let alert_report =
        chio_pheromone_relay::evaluate_relay_alerts(chio_pheromone_relay::RelayAlertEvaluationInput {
            observability: &observability,
            routing_profile: &profile,
            suppression_state: Some(&suppression),
            event_reports: &events,
            now_unix_ms,
            expected_source_report_sha256: None,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert evaluate: {error}")))?;
    write_pretty_json(report, &alert_report, "Chiodos relay alert report")
}

fn cmd_chiodos_pheromone_relay_alert_handoff(
    alert_report: &Path,
    trend_report: &Path,
    routing_profile: &Path,
    handoff_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let alert_report: chio_pheromone_relay::RelayAlertReport = serde_json::from_str(
        &read_utf8_json_file(alert_report, "Chiodos relay alert report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert report: {error}")))?;
    let trend_report: chio_pheromone_relay::RelayTrendReport = serde_json::from_str(
        &read_utf8_json_file(trend_report, "Chiodos relay trend report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend report: {error}")))?;
    let routing_profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let handoff_profile = chio_pheromone_relay::relay_alert_handoff_profile_from_json(
        &read_utf8_json_file(handoff_profile, "Chiodos relay alert handoff profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff profile: {error}"))
    })?;
    let handoff_report = chio_pheromone_relay::evaluate_relay_alert_handoff(
        chio_pheromone_relay::RelayAlertHandoffInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            routing_profile: &routing_profile,
            handoff_profile: &handoff_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert handoff: {error}")))?;
    write_pretty_json(
        report,
        &handoff_report,
        "Chiodos relay alert handoff report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_import(
    handoff_report: &Path,
    delivery_profile: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let evidence = read_relay_alert_delivery_evidence(evidence_dir)?;
    let delivery_report = chio_pheromone_relay::evaluate_relay_alert_delivery(
        chio_pheromone_relay::RelayAlertDeliveryInput {
            handoff_report: &handoff_report,
            delivery_profile: &delivery_profile,
            evidence: &evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery import: {error}"))
    })?;
    write_pretty_json(
        report,
        &delivery_report,
        "Chiodos relay alert delivery report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_acknowledge(
    handoff_report: &Path,
    delivery_report: &Path,
    delivery_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let acknowledgement_report = chio_pheromone_relay::evaluate_relay_alert_acknowledgement(
        chio_pheromone_relay::RelayAlertAcknowledgementInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            delivery_profile: &delivery_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert delivery acknowledgement: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &acknowledgement_report,
        "Chiodos relay alert acknowledgement report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_drift(
    handoff_reports_dir: &Path,
    delivery_reports_dir: &Path,
    delivery_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let handoff_reports = read_relay_alert_handoff_reports(handoff_reports_dir)?;
    let delivery_reports = read_relay_alert_delivery_reports(delivery_reports_dir)?;
    let drift_report = chio_pheromone_relay::generate_relay_alert_handoff_drift_report(
        chio_pheromone_relay::RelayAlertHandoffDriftInput {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery drift: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chiodos relay alert handoff drift report",
    )
}

fn cmd_chiodos_pheromone_relay_trend(
    reports_dir: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let reports = read_relay_observability_reports(reports_dir)?;
    let events = read_relay_event_reports(event_dir)?;
    let trend = chio_pheromone_relay::generate_relay_trend_report(
        chio_pheromone_relay::RelayTrendInput {
            local_kernel_id: &profile.local_kernel_id,
            observability_reports: &reports,
            event_reports: &events,
            routing_profile: &profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend: {error}")))?;
    write_pretty_json(report, &trend, "Chiodos relay trend report")
}

fn read_relay_observability_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayObservabilityReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay observability report",
        chio_pheromone_relay::PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    )
}

fn read_relay_event_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayEventReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay event report",
        chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA,
    )
}

fn read_relay_alert_delivery_evidence(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryEvidence>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert delivery evidence dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert delivery evidence dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut evidence = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert delivery evidence")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery evidence {}: {error}",
                path.display()
            ))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str())
            != Some(chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
        {
            continue;
        }
        evidence.push(
            chio_pheromone_relay::relay_alert_delivery_evidence_from_json(&json).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos relay alert delivery evidence {}: {error}",
                        path.display()
                    ))
                },
            )?,
        );
    }
    Ok(evidence)
}

fn read_relay_alert_handoff_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertHandoffReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert handoff report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    )
}

fn read_relay_alert_delivery_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert delivery report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    )
}

fn read_json_documents_from_dir<T: DeserializeOwned>(
    dir: &Path,
    label: &str,
    schema: &str,
) -> Result<Vec<T>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!("failed to read Chiodos {label} dir {}: {error}", dir.display()))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos {label} dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, label)?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str()) != Some(schema) {
            continue;
        }
        let document = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        documents.push(document);
    }
    Ok(documents)
}

fn cmd_chiodos_pheromone_relay_directory_inspect(
    state: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let json = read_utf8_json_file(state, "Chiodos peer-directory state")?;
    let state = chio_pheromone_relay::peer_directory_state_from_json(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos peer-directory state: {error}"))
    })?;
    let inspection = chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: state.active.is_some(),
        code: if state.active.is_some() {
            "accepted".to_string()
        } else {
            "peer_directory_state_invalid".to_string()
        },
        detail: if state.active.is_some() {
            "peer-directory state has an active directory".to_string()
        } else {
            "peer-directory state has no active directory".to_string()
        },
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: unix_now_ms(),
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: state
            .candidate
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: state
            .active
            .as_ref()
            .map(|entry| entry.removed_peer_ids.clone())
            .unwrap_or_default(),
    };
    write_pretty_json(report, &inspection, "Chiodos peer-directory inspection")
}

fn cmd_chiodos_pheromone_relay_directory_promote(
    state: &Path,
    candidate: &Path,
    trusted_issuers: &Path,
    profile: chio_pheromone_relay::RelayProfile,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let result = chio_pheromone_relay::promote_peer_directory_candidate(
        &mut state_document,
        candidate,
        &trust,
        now,
    );
    let report_document = match result {
        Ok(report_document) => report_document,
        Err(error) => {
            let report_document =
                peer_directory_rotation_error_report(&state_document, now, &error);
            write_peer_directory_state(state, &state_document)?;
            write_pretty_json(report, &report_document, "Chiodos peer-directory rotation")?;
            return Err(CliError::cli_other_error(format!(
                "Chiodos peer-directory candidate promote: {error}"
            )));
        }
    };
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chiodos peer-directory rotation")
}

fn cmd_chiodos_pheromone_relay_directory_reject(
    state: &Path,
    candidate: &Path,
    reason: &str,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let report_document = chio_pheromone_relay::reject_peer_directory_candidate(
        &mut state_document,
        candidate,
        reason,
        now,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos peer-directory candidate reject: {error}"))
    })?;
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chiodos peer-directory rejection")
}

fn cmd_chiodos_pheromone_relay_supervisor_lint(
    profile: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile_json = read_utf8_json_file(profile, "Chiodos relay supervisor profile")?;
    let lint_report = match chio_pheromone_relay::relay_supervisor_profile_from_json(&profile_json)
    {
        Ok(profile_document) => {
            chio_pheromone_relay::lint_relay_supervisor_profile(&profile_document, unix_now_ms())
        }
        Err(error) => chio_pheromone_relay::RelayDrillReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_DRILL_REPORT_SCHEMA.to_string(),
            accepted: false,
            code: error.code().to_string(),
            detail: error.to_string(),
            generated_at_unix_ms: unix_now_ms(),
            checks: vec![chio_pheromone_relay::RelayDrillCheck {
                code: error.code().to_string(),
                accepted: false,
                detail: "relay supervisor profile could not be parsed".to_string(),
            }],
        },
    };
    write_pretty_json(report, &lint_report, "Chiodos relay supervisor lint")
}

fn load_relay_peer_directory_from_paths(
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    label: &str,
) -> Result<chio_pheromone_relay::PeerDirectory, CliError> {
    if let Some(state_path) = peer_directory_state {
        let state_json = read_utf8_json_file(state_path, "Chiodos peer-directory state")?;
        let state = chio_pheromone_relay::peer_directory_state_from_json(&state_json)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
        let trusted_issuers = trusted_issuers.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "{label}: signed peer-directory state requires trusted issuers"
            ))
        })?;
        let trust = build_peer_directory_bundle_trust(trusted_issuers, now_unix_ms, profile)?;
        return state
            .active_directory(&trust)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")));
    }
    let peer_directory = peer_directory.ok_or_else(|| {
        CliError::cli_other_error(format!("{label}: peer directory or state is required"))
    })?;
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(CliError::cli_other_error(format!(
            "{label}: production profile requires peer-directory state"
        )));
    }
    let json = read_utf8_json_file(peer_directory, label)?;
    let trusted = load_optional_relay_trusted_issuers(trusted_issuers)?;
    parse_relay_peer_directory_json(&json, now_unix_ms, profile, trusted)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))
}

fn parse_relay_peer_directory_json(
    json: &str,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>,
) -> Result<chio_pheromone_relay::PeerDirectory, chio_pheromone_relay::PheromoneRelayError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
        chio_pheromone_relay::PheromoneRelayError::Json(error.to_string())
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema == chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA {
        let bundle: chio_pheromone_relay::PeerDirectoryBundleDocument =
            serde_json::from_value(value).map_err(chio_pheromone_relay::PheromoneRelayError::from)?;
        let (issuers, min_version) = trusted_issuers.ok_or_else(|| {
            chio_pheromone_relay::PheromoneRelayError::UnknownPeerDirectoryIssuer(
                "signed peer-directory bundle requires trusted issuers".to_string(),
            )
        })?;
        let trust = chio_pheromone_relay::PeerDirectoryBundleTrust {
            issuers,
            min_version,
            now_unix_ms,
            profile,
            limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
        };
        return bundle.verify(&trust);
    }
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(chio_pheromone_relay::PheromoneRelayError::PeerDirectoryUnsigned(
            "production profile requires a signed peer-directory bundle".to_string(),
        ));
    }
    chio_pheromone_relay::peer_directory_from_json_with_profile(
        json,
        now_unix_ms,
        profile,
        &chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    )
}

fn load_optional_relay_trusted_issuers(
    path: Option<&Path>,
) -> Result<Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>, CliError> {
    path.map(load_relay_trusted_issuers).transpose()
}

fn load_relay_trusted_issuers(
    path: &Path,
) -> Result<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64), CliError> {
    let json = read_utf8_json_file(path, "Chiodos relay trusted issuers")?;
    let document: RelayTrustedIssuersDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay trusted issuers: {error}"))
    })?;
    let issuers = document
        .issuers
        .into_iter()
        .map(|issuer| chio_pheromone_relay::TrustedPeerDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect();
    Ok((issuers, document.min_version.unwrap_or(0)))
}

fn build_peer_directory_bundle_trust(
    trusted_issuers: &Path,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleTrust, CliError> {
    let (issuers, min_version) = load_relay_trusted_issuers(trusted_issuers)?;
    Ok(chio_pheromone_relay::PeerDirectoryBundleTrust {
        issuers,
        min_version,
        now_unix_ms,
        profile,
        limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    })
}

fn load_relay_peer_directory_bundle(
    path: &Path,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleDocument, CliError> {
    let json = read_utf8_json_file(path, "Chiodos peer-directory bundle")?;
    serde_json::from_str(&json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory bundle: {error}")))
}

fn load_or_create_peer_directory_state(
    path: &Path,
    candidate: &chio_pheromone_relay::PeerDirectoryBundleDocument,
    now_unix_ms: u64,
) -> Result<chio_pheromone_relay::PeerDirectoryStateDocument, CliError> {
    if path.exists() {
        let json = read_utf8_json_file(path, "Chiodos peer-directory state")?;
        chio_pheromone_relay::peer_directory_state_from_json(&json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))
    } else {
        Ok(chio_pheromone_relay::PeerDirectoryStateDocument::new(
            &candidate.directory.local_kernel_id,
            now_unix_ms,
        ))
    }
}

fn write_peer_directory_state(
    path: &Path,
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
) -> Result<(), CliError> {
    write_pretty_json(path, state, "Chiodos peer-directory state")
}

fn peer_directory_rotation_error_report(
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
    now_unix_ms: u64,
    error: &chio_pheromone_relay::PheromoneRelayError,
) -> chio_pheromone_relay::PeerDirectoryRotationReport {
    let rejected = state.rejected.last();
    chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: error.code().to_string(),
        detail: error.to_string(),
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: rejected.and_then(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: Vec::new(),
    }
}

fn write_pretty_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
    label: &str,
) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    write_json_string(path, &format!("{json}\n"))
}

fn load_relay_signing_key(path: &Path) -> Result<(String, Keypair), CliError> {
    let json = read_utf8_json_file(path, "Chiodos relay signing key")?;
    let document: RelaySigningKeyDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay signing key: {error}"))
    })?;
    if document.kernel_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "Chiodos relay signing key: kernel id is empty",
        ));
    }
    let keypair = Keypair::from_seed_hex(document.seed_hex.trim())
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay signing key: {error}")))?;
    Ok((document.kernel_id, keypair))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

fn cmd_chiodos_authority_issue(
    profile: &Path,
    request: &Path,
    signing_keys: &Path,
    out_dir: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let request = chio_chiodos_authority::issuance_request_from_json(&read_utf8_json_file(
        request,
        "Chiodos issuance request",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos issuance request: {error}")))?;
    let signing_keys = chio_chiodos_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chiodos local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos local signing keys: {error}")))?;
    let bundle = chio_chiodos_authority::issue_authority_bundle(
        &profile,
        &request,
        &signing_keys,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority issue: {error}")))?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos authority output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    write_json_string(
        &out_dir.join("issuance-bundle.json"),
        &chio_chiodos_authority::issuance_bundle_json(&bundle)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos issuance bundle: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("capability-leases.json"),
        &serde_json::to_string_pretty(&bundle.capability_leases)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos leases JSON: {error}")))?,
    )?;
    write_json_string(
        &out_dir.join("lease-scope-bindings.json"),
        &serde_json::to_string_pretty(&bundle.lease_scope_bindings).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos lease scope bindings JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("governance-receipts.json"),
        &serde_json::to_string_pretty(&bundle.governance_receipts).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos governance receipts JSON: {error}"))
        })?,
    )?;
    write_json_string(
        &out_dir.join("verification-context.json"),
        &chio_chiodos::verification_context_json(&bundle.verification_context)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos context JSON: {error}")))?,
    )?;
    Ok(())
}

fn cmd_chiodos_authority_checkpoint(
    profile: &Path,
    revocations: &Path,
    signing_keys: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let revocations =
        chio_chiodos_authority::revocation_publication_request_from_json(&read_utf8_json_file(
            revocations,
            "Chiodos revocation publication request",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos revocation publication request: {error}"))
        })?;
    let signing_keys = chio_chiodos_authority::signing_keys_from_json(&read_utf8_json_file(
        signing_keys,
        "Chiodos local signing keys",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos local signing keys: {error}")))?;
    let checkpoint = chio_chiodos_authority::publish_revocation_checkpoint(
        &profile,
        &revocations,
        &signing_keys,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos checkpoint publish: {error}")))?;
    write_json_string(
        out,
        &chio_chiodos_authority::signed_revocation_checkpoint_json(&checkpoint)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos checkpoint JSON: {error}")))?,
    )
}

fn cmd_chiodos_authority_trust_bundle_assemble(
    profile: &Path,
    peer_pins: &Path,
    workflow_intersection: &Path,
    disclosure_policy: &Path,
    checkpoint: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_authority::authority_profile_from_json(&read_utf8_json_file(
        profile,
        "Chiodos authority profile",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos authority profile: {error}")))?;
    let peer_pins = chio_chiodos_authority::peer_pins_from_json(&read_utf8_json_file(
        peer_pins,
        "Chiodos peer pins",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chiodos peer pins: {error}")))?;
    let workflow_intersection: chio_chiodos::WorkflowIntersectionArtifact =
        serde_json::from_str(&read_utf8_json_file(
            workflow_intersection,
            "Chiodos workflow intersection",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos workflow intersection JSON: {error}"))
        })?;
    let disclosure_policy: chio_chiodos::ChiodosDisclosurePolicy =
        serde_json::from_str(&read_utf8_json_file(
            disclosure_policy,
            "Chiodos disclosure policy",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos disclosure policy JSON: {error}"))
        })?;
    let checkpoint: chio_chiodos::SignedChiodosRevocationCheckpoint =
        serde_json::from_str(&read_utf8_json_file(
            checkpoint,
            "Chiodos revocation checkpoint",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos revocation checkpoint JSON: {error}"))
        })?;
    let document = chio_chiodos_authority::assemble_verifier_trust_bundle(
        &profile,
        &peer_pins,
        &workflow_intersection,
        disclosure_policy,
        checkpoint,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos trust bundle assemble: {error}")))?;
    write_json_string(
        out,
        &chio_chiodos::verifier_trust_bundle_json(&document).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos verifier trust bundle JSON: {error}"))
        })?,
    )
}

fn read_utf8_json_file(path: &Path, label: &str) -> Result<String, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError::cli_io_error(format!("failed to read {label} {}: {error}", path.display()))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        CliError::cli_other_error(format!("{label} {} is not UTF-8 JSON: {error}", path.display()))
    })
}

fn write_json_string(path: &Path, json: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chiodos output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    fs::write(path, json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chiodos JSON {}: {error}",
            path.display()
        ))
    })
}
