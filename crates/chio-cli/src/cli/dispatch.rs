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
            ChiodosCommands::Runtime { command } => match command {
                ChiodosRuntimeCommands::Admit {
                    request,
                    admission_profile,
                    admission_bundle,
                    runtime_trust_input,
                    trusted_verifiers,
                    pheromone_query_report,
                    runtime_pheromone_policy,
                    runtime_peer_weights,
                    trust_floor_state,
                    store,
                    now_unix_ms,
                    report,
                } => cmd_chiodos_runtime_admit(
                    &request,
                    &admission_profile,
                    &admission_bundle,
                    runtime_trust_input.as_deref(),
                    trusted_verifiers.as_deref(),
                    pheromone_query_report.as_deref(),
                    runtime_pheromone_policy.as_deref(),
                    runtime_peer_weights.as_deref(),
                    trust_floor_state.as_deref(),
                    &store,
                    now_unix_ms,
                    &report,
                ),
                ChiodosRuntimeCommands::SignTrustInput {
                    body,
                    signing_seed_file,
                    out,
                } => cmd_chiodos_runtime_sign_trust_input(&body, &signing_seed_file, &out),
                ChiodosRuntimeCommands::Policy { command } => match command {
                    ChiodosRuntimePolicyCommands::Sign {
                        body,
                        signing_seed_file,
                        out,
                    } => cmd_chiodos_runtime_sign_policy(&body, &signing_seed_file, &out),
                },
                ChiodosRuntimeCommands::PeerWeights { command } => match command {
                    ChiodosRuntimePeerWeightsCommands::Sign {
                        body,
                        signing_seed_file,
                        out,
                    } => cmd_chiodos_runtime_sign_peer_weights(&body, &signing_seed_file, &out),
                },
                ChiodosRuntimeCommands::Pheromone { command } => match command {
                    ChiodosRuntimePheromoneCommands::Evaluate {
                        admission_bundle,
                        runtime_trust_input,
                        trusted_verifiers,
                        pheromone_query_report,
                        runtime_pheromone_policy,
                        runtime_peer_weights,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_pheromone_evaluate(
                        &admission_bundle,
                        &runtime_trust_input,
                        &trusted_verifiers,
                        &pheromone_query_report,
                        &runtime_pheromone_policy,
                        &runtime_peer_weights,
                        now_unix_ms,
                        &report,
                    ),
                },
                ChiodosRuntimeCommands::Orchestrate { command } => match command {
                    ChiodosRuntimeOrchestrateCommands::Lint { profile, report } => {
                        cmd_chiodos_runtime_orchestrate_lint(&profile, &report)
                    }
                    ChiodosRuntimeOrchestrateCommands::Plan {
                        profile,
                        run_contract,
                        store,
                        evidence_dir,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_orchestrate_plan(
                        &profile,
                        &run_contract,
                        &store,
                        &evidence_dir,
                        now_unix_ms,
                        &report,
                    ),
                    ChiodosRuntimeOrchestrateCommands::Run {
                        profile,
                        run_contract,
                        store,
                        evidence_dir,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_orchestrate_run(
                        &profile,
                        &run_contract,
                        &store,
                        &evidence_dir,
                        now_unix_ms,
                        &report,
                    ),
                    ChiodosRuntimeOrchestrateCommands::Resume {
                        profile,
                        resume_plan,
                        store,
                        evidence_dir,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_orchestrate_resume(
                        &profile,
                        &resume_plan,
                        &store,
                        &evidence_dir,
                        now_unix_ms,
                        &report,
                    ),
                    ChiodosRuntimeOrchestrateCommands::Status {
                        profile,
                        store,
                        evidence_dir,
                        report,
                    } => cmd_chiodos_runtime_orchestrate_status(
                        &profile,
                        &store,
                        &evidence_dir,
                        &report,
                    ),
                    ChiodosRuntimeOrchestrateCommands::Drift {
                        profile,
                        runs_dir,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_orchestrate_drift(
                        &profile,
                        &runs_dir,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                },
                ChiodosRuntimeCommands::Ops { command } => match command {
                    ChiodosRuntimeOpsCommands::Supervise {
                        supervisor_profile,
                        store,
                        evidence_root,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_ops_status(
                        &supervisor_profile,
                        &store,
                        &evidence_root,
                        Some(now_unix_ms),
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::Tick {
                        supervisor_profile,
                        store,
                        evidence_root,
                        owner_id,
                        now_unix_ms,
                        max_runs,
                        report,
                    } => cmd_chiodos_runtime_ops_tick(
                        &supervisor_profile,
                        &store,
                        &evidence_root,
                        &owner_id,
                        now_unix_ms,
                        max_runs,
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::Status {
                        supervisor_profile,
                        store,
                        evidence_root,
                        report,
                    } => cmd_chiodos_runtime_ops_status(
                        &supervisor_profile,
                        &store,
                        &evidence_root,
                        None,
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::RecoveryDrill {
                        supervisor_profile,
                        run_id,
                        store,
                        evidence_root,
                        now_unix_ms,
                        report,
                    } => cmd_chiodos_runtime_ops_recovery_drill(
                        &supervisor_profile,
                        &run_id,
                        &store,
                        &evidence_root,
                        now_unix_ms,
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::EvidenceHealth {
                        supervisor_profile,
                        run_id,
                        store,
                        evidence_root,
                        report,
                    } => cmd_chiodos_runtime_ops_evidence_health(
                        &supervisor_profile,
                        &run_id,
                        &store,
                        &evidence_root,
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::ProviderHealth {
                        supervisor_profile,
                        provider_bindings,
                        report,
                    } => cmd_chiodos_runtime_ops_provider_health(
                        &supervisor_profile,
                        &provider_bindings,
                        &report,
                    ),
                    ChiodosRuntimeOpsCommands::Retention { command } => match command {
                        ChiodosRuntimeOpsRetentionCommands::Plan {
                            retention_profile,
                            store,
                            evidence_root,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_runtime_ops_retention_plan(
                            &retention_profile,
                            &store,
                            &evidence_root,
                            now_unix_ms,
                            &report,
                        ),
                    },
                },
                ChiodosRuntimeCommands::RunLoopback {
                    scenario,
                    store_dir,
                    now_unix_ms,
                    out_dir,
                } => cmd_chiodos_runtime_run_loopback(
                    &scenario,
                    &store_dir,
                    now_unix_ms,
                    &out_dir,
                ),
            },
            ChiodosCommands::Treaty { command } => match command {
                ChiodosTreatyCommands::Intersect {
                    treaty_scope,
                    manifest,
                    now_unix_ms,
                    report,
                } => cmd_chiodos_treaty_intersect(
                    &treaty_scope,
                    &manifest,
                    now_unix_ms,
                    &report,
                ),
                ChiodosTreatyCommands::Admit {
                    treaty_scope,
                    ladder_intersection,
                    expected_ladder_intersection_sha256,
                    action_class_id,
                    evidence,
                    now_unix_ms,
                    report,
                } => cmd_chiodos_treaty_admit(
                    &treaty_scope,
                    &ladder_intersection,
                    &expected_ladder_intersection_sha256,
                    &action_class_id,
                    &evidence,
                    now_unix_ms,
                    &report,
                ),
                ChiodosTreatyCommands::VerifyPacket {
                    packet,
                    lineage_statement,
                    continuation,
                    admission_report,
                    bilateral_invocation,
                    report,
                } => cmd_chiodos_treaty_verify_packet(
                    &packet,
                    &lineage_statement,
                    &continuation,
                    &admission_report,
                    &bilateral_invocation,
                    &report,
                ),
            },
            ChiodosCommands::Buyer { command } => match command {
                ChiodosBuyerCommands::Package { run_output, out } => {
                    cmd_chiodos_buyer_package(&run_output, &out)
                }
                ChiodosBuyerCommands::Verify {
                    package,
                    trust_bundle,
                    context,
                    report,
                } => cmd_chiodos_buyer_verify(&package, &trust_bundle, &context, &report),
                ChiodosBuyerCommands::Explain {
                    report,
                    format,
                    out,
                } => cmd_chiodos_buyer_explain(&report, &format, &out),
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
                        ChiodosPheromoneRelayAlertCommands::Normalize {
                            profile,
                            input_dir,
                            now_unix_ms,
                            out_dir,
                            report,
                        } => cmd_chiodos_pheromone_relay_alert_normalize(
                            &profile,
                            &input_dir,
                            now_unix_ms,
                            &out_dir,
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
                            ChiodosPheromoneRelayAlertDeliveryCommands::DriftWindow {
                                handoff_reports_dir,
                                delivery_reports_dir,
                                delivery_profile,
                                since_unix_ms,
                                until_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_delivery_drift_window(
                                &handoff_reports_dir,
                                &delivery_reports_dir,
                                &delivery_profile,
                                since_unix_ms,
                                until_unix_ms,
                                &report,
                            ),
                        },
                        ChiodosPheromoneRelayAlertCommands::Review {
                            handoff_report,
                            delivery_report,
                            acknowledgement_report,
                            drift_report,
                            route_owner_profile,
                            now_unix_ms,
                            report,
                        } => cmd_chiodos_pheromone_relay_alert_review(
                            &handoff_report,
                            &delivery_report,
                            &acknowledgement_report,
                            &drift_report,
                            &route_owner_profile,
                            now_unix_ms,
                            &report,
                        ),
                        ChiodosPheromoneRelayAlertCommands::Assurance { command } => match command {
                            ChiodosPheromoneRelayAlertAssuranceCommands::Package {
                                alert_report,
                                trend_report,
                                handoff_report,
                                normalization_report,
                                delivery_report,
                                acknowledgement_report,
                                drift_report,
                                review_packet,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_assurance_package(
                                &alert_report,
                                &trend_report,
                                &handoff_report,
                                &normalization_report,
                                &delivery_report,
                                &acknowledgement_report,
                                &drift_report,
                                &review_packet,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertAssuranceCommands::Export {
                                package,
                                alert_report,
                                trend_report,
                                handoff_report,
                                normalization_report,
                                delivery_report,
                                acknowledgement_report,
                                drift_report,
                                review_packet,
                                retention_profile,
                                signing_key,
                                now_unix_ms,
                                out_dir,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_assurance_export(
                                &package,
                                &alert_report,
                                &trend_report,
                                &handoff_report,
                                &normalization_report,
                                &delivery_report,
                                &acknowledgement_report,
                                &drift_report,
                                &review_packet,
                                &retention_profile,
                                &signing_key,
                                now_unix_ms,
                                &out_dir,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertAssuranceCommands::Verify {
                                bundle_dir,
                                trusted_exporters,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_assurance_verify(
                                &bundle_dir,
                                &trusted_exporters,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertAssuranceCommands::Replay {
                                bundle_dir,
                                trusted_exporters,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_assurance_replay(
                                &bundle_dir,
                                &trusted_exporters,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertAssuranceCommands::Retention {
                                command,
                            } => match command {
                                ChiodosPheromoneRelayAlertAssuranceRetentionCommands::Plan {
                                    bundle_root,
                                    retention_profile,
                                    now_unix_ms,
                                    report,
                                } => cmd_chiodos_pheromone_relay_alert_assurance_retention_plan(
                                    &bundle_root,
                                    &retention_profile,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
                            ChiodosPheromoneRelayAlertAssuranceCommands::RecoveryDrill {
                                bundle_dir,
                                trusted_exporters,
                                case,
                                now_unix_ms,
                                report,
                            } => cmd_chiodos_pheromone_relay_alert_assurance_recovery_drill(
                                &bundle_dir,
                                &trusted_exporters,
                                &case,
                                now_unix_ms,
                                &report,
                            ),
                            ChiodosPheromoneRelayAlertAssuranceCommands::Archive {
                                command,
                            } => match command {
                                ChiodosPheromoneRelayAlertAssuranceArchiveCommands::Plan {
                                    bundle_root,
                                    trusted_exporters,
                                    archive_profile,
                                    retention_profile,
                                    now_unix_ms,
                                    report,
                                } => cmd_chiodos_pheromone_relay_alert_assurance_archive_plan(
                                    &bundle_root,
                                    &trusted_exporters,
                                    &archive_profile,
                                    &retention_profile,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
                            ChiodosPheromoneRelayAlertAssuranceCommands::Closeout {
                                command,
                            } => match command {
                                ChiodosPheromoneRelayAlertAssuranceCloseoutCommands::Review {
                                    bundle_root,
                                    trusted_exporters,
                                    closeout_profile,
                                    retention_profile,
                                    now_unix_ms,
                                    report,
                                } => cmd_chiodos_pheromone_relay_alert_assurance_closeout_review(
                                    &bundle_root,
                                    &trusted_exporters,
                                    &closeout_profile,
                                    &retention_profile,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
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
        Commands::Start {
            listen,
            receipt_store,
            print_config,
        } => cmd_start(
            &listen,
            receipt_store.as_deref().or(receipt_db.as_deref()),
            authority_seed_file.as_deref(),
            print_config,
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

fn cmd_chiodos_treaty_intersect(
    treaty_scope_path: &Path,
    manifest_paths: &[PathBuf],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    if manifest_paths.is_empty() {
        return Err(CliError::cli_other_error(
            "Chiodos treaty intersect requires at least one --manifest",
        ));
    }
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chiodos treaty scope")?;
    let treaty_scope = chio_chiodos_runtime::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty scope: {error}")))?;
    let mut manifests = Vec::new();
    for manifest_path in manifest_paths {
        let manifest_json =
            read_utf8_json_file(manifest_path, "Chiodos governance ladder manifest")?;
        manifests.push(
            chio_chiodos_runtime::governance_ladder_manifest_from_json(&manifest_json).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos governance ladder manifest: {error}"
                    ))
                },
            )?,
        );
    }
    let intersection =
        chio_chiodos_runtime::compute_ladder_intersection(&treaty_scope, &manifests, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos treaty intersection: {error}"))
            })?;
    let json = chio_chiodos_runtime::ladder_intersection_json(&intersection)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty intersection: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_treaty_admit(
    treaty_scope_path: &Path,
    ladder_intersection_path: &Path,
    expected_ladder_intersection_sha256: &str,
    action_class_id: &str,
    evidence: &[String],
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let treaty_scope_json = read_utf8_json_file(treaty_scope_path, "Chiodos treaty scope")?;
    let treaty_scope = chio_chiodos_runtime::treaty_scope_from_json(&treaty_scope_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty scope: {error}")))?;
    let intersection_json =
        read_utf8_json_file(ladder_intersection_path, "Chiodos ladder intersection")?;
    let ladder_intersection =
        chio_chiodos_runtime::ladder_intersection_from_json(&intersection_json).map_err(
            |error| CliError::cli_other_error(format!("Chiodos ladder intersection: {error}")),
        )?;
    let verified_evidence = evidence
        .iter()
        .map(|item| {
            let Some((evidence_class, artifact_sha256)) = item.split_once('=') else {
                return Err(CliError::cli_other_error(
                    "Chiodos treaty evidence must use evidence_class=artifact_sha256",
                ));
            };
            Ok(chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                evidence_class: evidence_class.to_string(),
                artifact_sha256: artifact_sha256.to_string(),
                verified: true,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let admission = chio_chiodos_runtime::evaluate_cross_boundary_admission(
        chio_chiodos_runtime::CrossBoundaryAdmissionInput {
            treaty_scope: &treaty_scope,
            ladder_intersection: &ladder_intersection,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256.to_string()),
            action_class_id,
            present_evidence: verified_evidence
                .iter()
                .map(|item| item.evidence_class.clone())
                .collect(),
            verified_evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty admission: {error}")))?;
    let json = chio_chiodos_runtime::cross_boundary_admission_report_json(&admission)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos treaty admission: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

fn cmd_chiodos_treaty_verify_packet(
    packet_path: &Path,
    lineage_statement_path: &Path,
    continuation_path: &Path,
    admission_report_path: &Path,
    bilateral_invocation_path: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let packet_json = read_utf8_json_file(packet_path, "Chiodos buyer attestation packet")?;
    let packet = chio_chiodos_runtime::buyer_attestation_packet_from_json(&packet_json).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer attestation packet: {error}")),
    )?;
    let lineage_json =
        read_utf8_json_file(lineage_statement_path, "Chiodos receipt lineage statement")?;
    let lineage =
        chio_chiodos_runtime::receipt_lineage_statement_from_json(&lineage_json).map_err(
            |error| {
                CliError::cli_other_error(format!("Chiodos receipt lineage statement: {error}"))
            },
        )?;
    let continuation_json =
        read_utf8_json_file(continuation_path, "Chiodos cross-kernel continuation")?;
    let continuation: chio_chiodos_runtime::CrossKernelContinuation =
        serde_json::from_str(&continuation_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos cross-kernel continuation: {error}"))
        })?;
    let admission_json =
        read_utf8_json_file(admission_report_path, "Chiodos cross-boundary admission report")?;
    let admission: chio_chiodos_runtime::CrossBoundaryAdmissionReport =
        serde_json::from_str(&admission_json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos cross-boundary admission report: {error}"
            ))
        })?;
    let bilateral_json =
        read_utf8_json_file(bilateral_invocation_path, "Chiodos bilateral invocation")?;
    let bilateral: chio_chiodos_runtime::BilateralInvocation =
        serde_json::from_str(&bilateral_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos bilateral invocation: {error}"))
        })?;
    let verification = chio_chiodos_runtime::verify_buyer_attestation_packet(
        &packet,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos buyer attestation verification: {error}"))
    })?;
    let json = chio_chiodos_runtime::buyer_attestation_verification_report_json(&verification)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer attestation verification: {error}"))
        })?;
    write_json_string(report, &format!("{json}\n"))
}

const BUYER_REVIEW_ARTIFACT_FILES: &[(&str, &str)] = &[
    ("buyer_attestation_packet", "buyer-attestation-packet.json"),
    ("receipt_lineage_statement", "receipt-lineage-statement.json"),
    ("receipt_lineage_bundle", "receipt-lineage-bundle.json"),
    ("cross_kernel_continuation", "cross-kernel-continuation.json"),
    (
        "cross_boundary_admission_report",
        "cross-boundary-admission-report.json",
    ),
    ("bilateral_invocation", "bilateral-invocation.json"),
    ("bilateral_dsse_envelope", "bilateral-dsse-envelope.json"),
    ("workflow_receipt", "workflow-receipt.json"),
    ("proof_package", "proof-package.json"),
    ("verifier_report", "verifier-report.json"),
    (
        "proof_regeneration_report",
        "proof-regeneration-report.json",
    ),
    ("runtime_run_report", "runtime-run-report.json"),
    (
        "runtime_evidence_manifest",
        "runtime-evidence-manifest.json",
    ),
    (
        "proof_regeneration_input",
        "runtime-proof-regeneration-input.json",
    ),
];

fn cmd_chiodos_buyer_package(run_output: &Path, out: &Path) -> Result<(), CliError> {
    let mut artifacts = Vec::new();
    let mut packet_json = None;
    for (role, relative_path) in BUYER_REVIEW_ARTIFACT_FILES {
        validate_runtime_relative_path(relative_path)?;
        let path = run_output.join(relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        if *role == "buyer_attestation_packet" {
            packet_json = Some(String::from_utf8(bytes.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos buyer attestation packet {} is not UTF-8 JSON: {error}",
                    path.display()
                ))
            })?);
        }
        let byte_count = u64::try_from(bytes.len()).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer artifact byte count: {error}"))
        })?;
        artifacts.push(chio_chiodos_runtime::BuyerAttestationReviewArtifactRef {
            role: (*role).to_string(),
            relative_path: (*relative_path).to_string(),
            artifact_sha256: chio_core::sha256_hex(&bytes),
            byte_count,
        });
    }
    let packet_json = packet_json.ok_or_else(|| {
        CliError::cli_other_error("Chiodos buyer package is missing buyer packet artifact")
    })?;
    let packet = chio_chiodos_runtime::buyer_attestation_packet_from_json(&packet_json).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer attestation packet: {error}")),
    )?;
    let package = chio_chiodos_runtime::BuyerAttestationReviewPackage {
        schema: chio_chiodos_runtime::CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!("buyer-review:{}", packet.packet_id),
        packet_id: packet.packet_id,
        buyer_id: packet.buyer_id,
        generated_at_unix_ms: 0,
        artifacts,
    };
    let json = serde_json::to_string_pretty(&package)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos buyer package JSON: {error}")))?;
    write_json_string(out, &format!("{json}\n"))
}

fn cmd_chiodos_buyer_verify(
    package_path: &Path,
    trust_bundle_path: &Path,
    context_path: &Path,
    report_path: &Path,
) -> Result<(), CliError> {
    let package_json = read_utf8_json_file(package_path, "Chiodos buyer review package")?;
    let package = chio_chiodos_runtime::buyer_attestation_review_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos buyer review package: {error}")))?;
    let base_dir = package_path.parent().unwrap_or_else(|| Path::new("."));
    let sources = read_buyer_review_sources(base_dir, &package)?;
    let trust_bundle_json =
        read_utf8_json_file(trust_bundle_path, "Chiodos verifier trust bundle")?;
    let verifier_trust_bundle_value: serde_json::Value =
        serde_json::from_str(&trust_bundle_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle JSON parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context_path, "Chiodos verification context")?;
    let verification_context_value: serde_json::Value =
        serde_json::from_str(&context_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos context JSON parse: {error}"))
        })?;
    let trust_context = chio_chiodos_runtime::BuyerAttestationReviewTrustContext {
        verifier_trust_bundle: &verifier_trust_bundle_value,
        verification_context: &verification_context_value,
    };
    let mut report = chio_chiodos_runtime::verify_buyer_attestation_review_package_with_trust(
        &package,
        &sources,
        &trust_context,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos buyer review verification: {error}"))
    })?;
    if report.accepted {
        let proof_package_bytes = buyer_review_source_bytes(&sources, "proof_package").ok_or_else(|| {
            CliError::cli_other_error("Chiodos buyer package is missing proof_package artifact")
        })?;
        let proof_package_json = std::str::from_utf8(proof_package_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos buyer proof package artifact is not UTF-8 JSON: {error}"
            ))
        })?;
        let proof_package = chio_chiodos::proof_package_from_json(proof_package_json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
        let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
            })?;
        let context = chio_chiodos::verification_context_from_json(&context_json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
        let verifier_report =
            chio_chiodos::verify_package_report(&proof_package, &trust_bundle, &context);
        if verifier_report.accepted {
            report
                .checks
                .push(chio_chiodos_runtime::BuyerAttestationReviewCheck {
                    code: "chiodos_buyer_review.existing_verifier_replayed".to_string(),
                    passed: true,
                    severity: "info".to_string(),
                    artifact_role: "proof_package".to_string(),
                    expected_sha256: None,
                    observed_sha256: None,
                    message: "existing Chiodos verifier accepted the bundled proof package"
                        .to_string(),
                });
        } else {
            report.accepted = false;
            report.failure_code = Some("chiodos_buyer_review_verifier_report_rejected".to_string());
            report
                .checks
                .push(chio_chiodos_runtime::BuyerAttestationReviewCheck {
                    code: "chiodos_buyer_review.existing_verifier_replayed".to_string(),
                    passed: false,
                    severity: "error".to_string(),
                    artifact_role: "proof_package".to_string(),
                    expected_sha256: None,
                    observed_sha256: None,
                    message: "existing Chiodos verifier rejected the bundled proof package"
                        .to_string(),
                });
        }
    }
    let json = chio_chiodos_runtime::buyer_attestation_review_report_json(&report).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer review report: {error}")),
    )?;
    write_json_string(report_path, &format!("{json}\n"))?;
    if report.accepted {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "Chiodos buyer verification rejected package: {}",
            report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_buyer_review_rejection")
        )))
    }
}

fn cmd_chiodos_buyer_explain(report_path: &Path, format: &str, out: &Path) -> Result<(), CliError> {
    let report_json = read_utf8_json_file(report_path, "Chiodos buyer review report")?;
    let report: chio_chiodos_runtime::BuyerAttestationReviewReport =
        serde_json::from_str(&report_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer review report: {error}"))
        })?;
    let verification_state = buyer_review_verification_state(&report);
    match format {
        "json" => {
            let explanation = serde_json::json!({
                "schema": "chio.chiodos.buyer-attestation-explanation.v1",
                "packageId": report.package_id,
                "packetId": report.packet_id,
                "accepted": report.accepted,
                "verificationState": verification_state,
                "failureCode": report.failure_code,
                "checks": report.checks,
            });
            let json = serde_json::to_string_pretty(&explanation).map_err(|error| {
                CliError::cli_other_error(format!("Chiodos buyer explanation: {error}"))
            })?;
            write_json_string(out, &format!("{json}\n"))
        }
        "text" => {
            let mut text = String::new();
            text.push_str(&format!("Buyer review package: {}\n", report.package_id));
            text.push_str(&format!("Packet: {}\n", report.packet_id));
            text.push_str(&format!("Accepted: {}\n", report.accepted));
            text.push_str(&format!("Verification state: {verification_state}\n"));
            if let Some(code) = report.failure_code.as_deref() {
                text.push_str(&format!("Failure code: {code}\n"));
            }
            text.push_str("Checks:\n");
            for check in &report.checks {
                text.push_str(&format!(
                    "- [{}] {} ({}) - {}\n",
                    if check.passed { "pass" } else { "fail" },
                    check.code,
                    check.artifact_role,
                    check.message
                ));
            }
            write_json_string(out, &text)
        }
        other => Err(CliError::cli_other_error(format!(
            "unknown Chiodos buyer explain format {other}"
        ))),
    }
}

fn buyer_review_verification_state(
    report: &chio_chiodos_runtime::BuyerAttestationReviewReport,
) -> &'static str {
    if report.failure_code.as_deref().is_some_and(|code| {
        code.contains("unsupported_claim")
            || code.contains("settlement_claim")
            || code.contains("hidden_predicate")
            || code.contains("dynamic_trust")
    }) || report.checks.iter().any(|check| {
        !check.passed
            && (check.code.contains("unsupported_claim")
                || check.code.contains("settlement_claim")
                || check.code.contains("hidden_predicate")
                || check.code.contains("dynamic_trust"))
    }) {
        return "unsupported_claim";
    }
    if !report.accepted {
        return "rejected";
    }
    if report
        .checks
        .iter()
        .any(|check| !check.passed && check.code.contains("fixture"))
    {
        return "fixture_only";
    }
    let has_strict_dsse = report.checks.iter().any(|check| {
        check.passed && check.code == "chiodos_buyer_review.strict_dsse_treaty_bound"
    });
    let proof_accepted = report.checks.iter().any(|check| {
        check.passed && check.code == "chiodos_buyer_review.proof_verifier_accepted"
    });
    let existing_verifier_replayed = report.checks.iter().any(|check| {
        check.passed && check.code == "chiodos_buyer_review.existing_verifier_replayed"
    });
    if has_strict_dsse && proof_accepted && existing_verifier_replayed {
        "strict_verified"
    } else {
        "hash_only"
    }
}

fn read_buyer_review_sources(
    base_dir: &Path,
    package: &chio_chiodos_runtime::BuyerAttestationReviewPackage,
) -> Result<Vec<chio_chiodos_runtime::BuyerAttestationReviewSource>, CliError> {
    let mut sources = Vec::new();
    let mut roles = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for artifact in &package.artifacts {
        validate_runtime_relative_path(&artifact.relative_path)?;
        if !roles.insert(artifact.role.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chiodos buyer artifact role {}",
                artifact.role
            )));
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chiodos buyer artifact path {}",
                artifact.relative_path
            )));
        }
        let path = base_dir.join(&artifact.relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        sources.push(chio_chiodos_runtime::BuyerAttestationReviewSource {
            role: artifact.role.clone(),
            relative_path: artifact.relative_path.clone(),
            bytes,
        });
    }
    Ok(sources)
}

fn buyer_review_source_bytes<'a>(
    sources: &'a [chio_chiodos_runtime::BuyerAttestationReviewSource],
    role: &str,
) -> Option<&'a [u8]> {
    sources
        .iter()
        .find(|source| source.role == role)
        .map(|source| source.bytes.as_slice())
}

fn cmd_chiodos_runtime_sign_trust_input(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimeVerifierTrustBundleV4 =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime trust input body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trust input body parse: {error}"))
        })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chiodos runtime trust signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime trust signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime trust input signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime trust input")
}

fn cmd_chiodos_runtime_sign_policy(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimePheromonePolicy =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime pheromone policy body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime pheromone policy parse: {error}"))
        })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chiodos runtime policy signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime policy signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone policy signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime pheromone policy")
}

fn cmd_chiodos_runtime_sign_peer_weights(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimePeerWeights =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime peer weights body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime peer weights parse: {error}"))
        })?;
    let seed_hex =
        read_utf8_json_file(signing_seed_file, "Chiodos runtime peer weights signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos runtime peer weights signing seed: {error}"
        ))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime peer weights signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime peer weights")
}

fn cmd_chiodos_runtime_admit(
    request: &Path,
    admission_profile: &Path,
    admission_bundle: &Path,
    runtime_trust_input: Option<&Path>,
    trusted_verifiers: Option<&Path>,
    pheromone_query_report: Option<&Path>,
    runtime_pheromone_policy: Option<&Path>,
    runtime_peer_weights: Option<&Path>,
    trust_floor_state: Option<&Path>,
    store: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_runtime::runtime_admission_profile_from_json(&read_utf8_json_file(
        admission_profile,
        "Chiodos runtime admission profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission profile parse: {error}"))
    })?;
    let bundle = chio_chiodos_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chiodos runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission bundle parse: {error}"))
    })?;
    let request = chio_chiodos_runtime::runtime_request_binding_from_json(&read_utf8_json_file(
        request,
        "Chiodos runtime request binding",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime request binding parse: {error}"))
    })?;
    let runtime_trust_input = runtime_trust_input
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_verifier_trust_bundle_from_json(
                &read_utf8_json_file(path, "Chiodos runtime trust input")?,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime trust input parse: {error}"))
            })
        })
        .transpose()?;
    let trusted_verifiers = trusted_verifiers
        .map(|path| {
            chio_chiodos_runtime::runtime_trusted_verifier_keys_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime trusted verifiers",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime trusted verifiers parse: {error}"))
            })
        })
        .transpose()?;
    if runtime_trust_input.is_some() != trusted_verifiers.is_some() {
        return Err(CliError::cli_other_error(
            "Chiodos runtime strict trust requires both --runtime-trust-input and --trusted-verifiers"
                .to_string(),
        ));
    }
    let trusted_verifier_keys = trusted_verifiers
        .as_ref()
        .map_or(&[][..], |document| document.verifier_keys.as_slice());
    let pheromone_advisory = pheromone_query_report
        .map(|path| {
            chio_chiodos_runtime::runtime_pheromone_advisory_from_query_report_json(
                &read_utf8_json_file(path, "Chiodos pheromone query report")?,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos pheromone advisory parse: {error}"))
            })
        })
        .transpose()?;
    let runtime_pheromone_policy = runtime_pheromone_policy
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_pheromone_policy_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime pheromone policy",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime pheromone policy parse: {error}"
                ))
            })
        })
        .transpose()?;
    let runtime_peer_weights = runtime_peer_weights
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_peer_weights_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime peer weights",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime peer weights parse: {error}"
                ))
            })
        })
        .transpose()?;
    let store_path = trust_floor_state.unwrap_or(store);
    let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(store_path).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission store open: {error}"))
    })?;
    let admission_id = bundle.admission_id.clone();
    store.insert_bundle(bundle).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission store update: {error}"))
    })?;
    let admission_report =
        chio_chiodos_runtime::evaluate_runtime_admission(chio_chiodos_runtime::RuntimeAdmissionInput {
            profile: &profile,
            store: &store,
            admission_id: &admission_id,
            request: &request,
            runtime_trust_input: runtime_trust_input.as_ref(),
            trusted_verifier_keys,
            pheromone_advisory: pheromone_advisory.as_ref(),
            runtime_pheromone_policy: runtime_pheromone_policy.as_ref(),
            runtime_peer_weights: runtime_peer_weights.as_ref(),
            now_unix_ms,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime admission evaluation: {error}"))
        })?;
    write_pretty_json(report, &admission_report, "Chiodos runtime admission report")?;
    if admission_report.accepted {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "Chiodos runtime admission rejected request: {}",
            admission_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_admission_failure")
        )))
    }
}

fn cmd_chiodos_runtime_pheromone_evaluate(
    admission_bundle: &Path,
    runtime_trust_input: &Path,
    trusted_verifiers: &Path,
    pheromone_query_report: &Path,
    runtime_pheromone_policy: &Path,
    runtime_peer_weights: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = chio_chiodos_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chiodos runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission bundle parse: {error}"))
    })?;
    let profile = chio_chiodos_runtime::RuntimeAdmissionProfile {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "policy-evaluate".to_string(),
        local_kernel_id: bundle.binding.host_kernel_id.clone(),
        verifier_id: "policy-evaluate".to_string(),
        issued_at_unix_ms: now_unix_ms.saturating_sub(1),
        expires_at_unix_ms: now_unix_ms.saturating_add(1),
    };
    let runtime_trust_input =
        chio_chiodos_runtime::signed_runtime_verifier_trust_bundle_from_json(
            &read_utf8_json_file(runtime_trust_input, "Chiodos runtime trust input")?,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trust input parse: {error}"))
        })?;
    let trusted_verifiers =
        chio_chiodos_runtime::runtime_trusted_verifier_keys_from_json(&read_utf8_json_file(
            trusted_verifiers,
            "Chiodos runtime trusted verifiers",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trusted verifiers parse: {error}"))
        })?;
    let advisory = chio_chiodos_runtime::runtime_pheromone_advisory_from_query_report_json(
        &read_utf8_json_file(pheromone_query_report, "Chiodos pheromone query report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos pheromone advisory parse: {error}"))
    })?;
    let policy = chio_chiodos_runtime::signed_runtime_pheromone_policy_from_json(
        &read_utf8_json_file(runtime_pheromone_policy, "Chiodos runtime pheromone policy")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone policy parse: {error}"))
    })?;
    let weights = chio_chiodos_runtime::signed_runtime_peer_weights_from_json(
        &read_utf8_json_file(runtime_peer_weights, "Chiodos runtime peer weights")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime peer weights parse: {error}"))
    })?;
    let store = chio_chiodos_runtime::InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime policy store update: {error}"))
    })?;
    let report_value = chio_chiodos_runtime::evaluate_runtime_admission(
        chio_chiodos_runtime::RuntimeAdmissionInput {
            profile: &profile,
            store: &store,
            admission_id: &bundle.admission_id,
            request: &bundle.binding,
            runtime_trust_input: Some(&runtime_trust_input),
            trusted_verifier_keys: &trusted_verifiers.verifier_keys,
            pheromone_advisory: Some(&advisory),
            runtime_pheromone_policy: Some(&policy),
            runtime_peer_weights: Some(&weights),
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone evaluation: {error}"))
    })?;
    let decision = report_value.pheromone_policy_decision.ok_or_else(|| {
        CliError::cli_other_error("Chiodos runtime pheromone evaluation produced no decision")
    })?;
    write_pretty_json(report, &decision, "Chiodos runtime pheromone policy decision")
}

fn cmd_chiodos_runtime_orchestrate_lint(profile: &Path, report: &Path) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let report_value = chio_chiodos_runtime::RuntimeOrchestrationStatusReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA
            .to_string(),
        accepted: true,
        generated_at_unix_ms: profile.issued_at_unix_ms,
        profile_sha256: profile_sha256.clone(),
        store_backend: "profile_lint".to_string(),
        store_path_sha256: profile_sha256,
        run_counts: std::collections::BTreeMap::new(),
        consumed_lease_count: 0,
        trust_floor_count: 0,
        latest_failure_code: None,
        evidence_sink_healthy: true,
        ready: true,
        degraded: false,
    };
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration lint report",
    )
}

fn cmd_chiodos_runtime_orchestrate_plan(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let plan = chio_chiodos_runtime::build_runtime_orchestration_plan(
        &profile,
        &run_contract,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration plan: {error}"))
    })?;
    write_pretty_json(report, &plan, "Chiodos runtime orchestration plan")
}

fn cmd_chiodos_runtime_orchestrate_run(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let run_contract_sha256 =
        chio_chiodos_runtime::runtime_run_contract_sha256(&run_contract).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime run contract hash: {error}"))
        })?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let evidence = load_runtime_orchestration_evidence(evidence_dir)?;
    let mut accepted = evidence.proof_regeneration_report.accepted;
    let mut failure_code = evidence.proof_regeneration_report.failure_code.clone();
    if profile_sha256 != run_contract.profile_sha256 {
        accepted = false;
        failure_code = Some("runtime_orchestration_profile_hash_mismatch".to_string());
    }
    let status = if accepted {
        "proof_accepted"
    } else {
        "terminal_failure"
    };
    store
        .record_run_state(&run_contract.run_id, status, failure_code.as_deref(), now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime orchestration run state: {error}"))
        })?;
    let mut step_states = Vec::new();
    for step in evidence.workflow_run_report.step_evidence {
        let state = chio_chiodos_runtime::RuntimeOrchestrationStepState {
            step_index: step.step_index,
            admission_id: step.admission_id,
            state: status.to_string(),
            destructive: step.destructive,
            admission_report_sha256: Some(step.admission_report_sha256),
            tool_receipt_sha256: Some(step.tool_receipt_sha256),
            lease_id: step.lease_id,
        };
        store
            .record_run_step_state(&run_contract.run_id, state.clone())
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration step state: {error}"
                ))
            })?;
        step_states.push(state);
    }
    for entry in &evidence.manifest.entries {
        store
            .record_evidence_artifact(&run_contract.run_id, entry, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration evidence artifact: {error}"
                ))
            })?;
    }
    let report_value = chio_chiodos_runtime::RuntimeOrchestrationRunReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
        run_id: run_contract.run_id,
        accepted,
        failure_code,
        status: status.to_string(),
        generated_at_unix_ms: now_unix_ms,
        profile_sha256,
        run_contract_sha256,
        workflow_run_report_sha256: Some(evidence.workflow_report_sha256),
        evidence_manifest_sha256: Some(evidence.manifest_sha256),
        proof_regeneration_report_sha256: Some(evidence.proof_report_sha256),
        verifier_report_sha256: Some(evidence.verifier_report_sha256),
        step_states,
        checks: vec![
            "runtime_orchestration.evidence_sink_loaded".to_string(),
            "runtime_orchestration.proof_regeneration_bound".to_string(),
        ],
    };
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration run report",
    )
}

fn cmd_chiodos_runtime_orchestrate_resume(
    profile: &Path,
    resume_plan: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let _profile = load_runtime_orchestration_profile(profile)?;
    let input: chio_chiodos_runtime::RuntimeOrchestrationResumePlan =
        serde_json::from_str(&read_utf8_json_file(
            resume_plan,
            "Chiodos runtime orchestration resume plan",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime orchestration resume plan parse: {error}"
            ))
        })?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let resolved = chio_chiodos_runtime::RuntimeOrchestrationResumePlan {
        generated_at_unix_ms: now_unix_ms,
        checks: {
            let mut checks = input.checks;
            checks.push("runtime_orchestration.resume_inputs_loaded".to_string());
            checks
        },
        ..input
    };
    write_pretty_json(
        report,
        &resolved,
        "Chiodos runtime orchestration resume report",
    )
}

fn cmd_chiodos_runtime_orchestrate_status(
    profile: &Path,
    store: &Path,
    evidence_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    let report_value = store
        .status_report(
            &profile.profile_id,
            profile_sha256,
            profile.issued_at_unix_ms,
            evidence_dir.is_dir(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime orchestration status: {error}"))
        })?;
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration status report",
    )
}

fn cmd_chiodos_runtime_orchestrate_drift(
    profile: &Path,
    runs_dir: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let _profile = load_runtime_orchestration_profile(profile)?;
    if since_unix_ms > until_unix_ms {
        return Err(CliError::cli_other_error(
            "Chiodos runtime drift since-unix-ms must not exceed until-unix-ms".to_string(),
        ));
    }
    let run_dirs = sorted_child_dirs(runs_dir)?;
    if run_dirs.len() < 2 {
        return Err(CliError::cli_other_error(
            "Chiodos runtime drift requires at least two run directories".to_string(),
        ));
    }
    let baseline = load_runtime_orchestration_evidence(&run_dirs[0])?;
    let candidate = load_runtime_orchestration_evidence(&run_dirs[1])?;
    let drift = chio_chiodos_runtime::generate_runtime_proof_drift_report(
        &baseline.manifest,
        &candidate.manifest,
        &baseline.proof_regeneration_report,
        &candidate.proof_regeneration_report,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime proof drift report: {error}"))
    })?;
    write_pretty_json(report, &drift, "Chiodos runtime proof drift report")
}

struct RuntimeOrchestrationEvidence {
    workflow_run_report: chio_chiodos_runtime::RuntimeWorkflowRunReport,
    proof_regeneration_report: chio_chiodos_runtime::RuntimeProofRegenerationReport,
    manifest: chio_chiodos_runtime::RuntimeEvidenceManifest,
    workflow_report_sha256: String,
    proof_report_sha256: String,
    manifest_sha256: String,
    verifier_report_sha256: String,
}

fn load_runtime_orchestration_profile(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeOrchestrationProfile, CliError> {
    let profile = chio_chiodos_runtime::runtime_orchestration_profile_from_json(
        &read_utf8_json_file(path, "Chiodos runtime orchestration profile")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration profile: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_orchestration_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration profile: {error}"))
    })?;
    Ok(profile)
}

fn load_runtime_run_contract(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeRunContract, CliError> {
    let contract = chio_chiodos_runtime::runtime_run_contract_from_json(&read_utf8_json_file(
        path,
        "Chiodos runtime run contract",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime run contract: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_run_contract(&contract).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime run contract: {error}"))
    })?;
    Ok(contract)
}

fn ensure_runtime_evidence_dir(evidence_dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(evidence_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos runtime evidence directory {}: {error}",
            evidence_dir.display()
        ))
    })
}

fn load_runtime_orchestration_evidence(
    evidence_dir: &Path,
) -> Result<RuntimeOrchestrationEvidence, CliError> {
    let workflow_report_path = evidence_dir.join("workflow-run-report.json");
    let proof_report_path = evidence_dir.join("proof-regeneration-report.json");
    let manifest_path = evidence_dir.join("runtime-evidence-manifest.json");
    let verifier_report_path = evidence_dir.join("verifier-report.json");
    let workflow_json = read_utf8_json_file(&workflow_report_path, "Chiodos runtime workflow report")?;
    let proof_json = read_utf8_json_file(&proof_report_path, "Chiodos runtime proof report")?;
    let manifest_json =
        read_utf8_json_file(&manifest_path, "Chiodos runtime evidence manifest")?;
    let verifier_json = read_utf8_json_file(&verifier_report_path, "Chiodos verifier report")?;
    let workflow_run_report: chio_chiodos_runtime::RuntimeWorkflowRunReport =
        serde_json::from_str(&workflow_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime workflow report: {error}"))
        })?;
    let proof_regeneration_report: chio_chiodos_runtime::RuntimeProofRegenerationReport =
        serde_json::from_str(&proof_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime proof report: {error}"))
        })?;
    let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
        serde_json::from_str(&manifest_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
        })?;
    chio_chiodos_runtime::validate_runtime_workflow_run_report(&workflow_run_report).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime workflow report: {error}")),
    )?;
    chio_chiodos_runtime::validate_runtime_proof_regeneration_report(&proof_regeneration_report)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime proof report: {error}"))
        })?;
    chio_chiodos_runtime::validate_runtime_evidence_manifest(&manifest).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
    })?;
    Ok(RuntimeOrchestrationEvidence {
        workflow_run_report,
        proof_regeneration_report,
        manifest,
        workflow_report_sha256: chio_core::sha256_hex(workflow_json.as_bytes()),
        proof_report_sha256: chio_core::sha256_hex(proof_json.as_bytes()),
        manifest_sha256: chio_core::sha256_hex(manifest_json.as_bytes()),
        verifier_report_sha256: chio_core::sha256_hex(verifier_json.as_bytes()),
    })
}

fn sorted_child_dirs(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos runtime runs directory {}: {error}",
            path.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos runtime runs directory entry: {error}"
            ))
        })?;
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn cmd_chiodos_runtime_ops_tick(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    owner_id: &str,
    now_unix_ms: u64,
    max_runs: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let tick = store
        .scheduler_tick_report(&profile, owner_id, now_unix_ms, max_runs)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime scheduler tick: {error}"))
        })?;
    write_pretty_json(report, &tick, "Chiodos runtime scheduler tick report")
}

fn cmd_chiodos_runtime_ops_status(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let generated_at = now_unix_ms.unwrap_or(profile.issued_at_unix_ms);
    let status = store
        .ops_status_report(&profile, generated_at, evidence_root.is_dir(), true)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos runtime ops status: {error}")))?;
    write_pretty_json(report, &status, "Chiodos runtime ops status report")
}

fn cmd_chiodos_runtime_ops_recovery_drill(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let _profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let drill = store.recovery_drill_report(run_id, now_unix_ms).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime recovery drill: {error}"))
    })?;
    write_pretty_json(report, &drill, "Chiodos runtime recovery drill report")
}

fn cmd_chiodos_runtime_ops_evidence_health(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let run_root = evidence_root.join(run_id);
    let evidence_dir = if run_root.is_dir() {
        run_root
    } else {
        evidence_root.to_path_buf()
    };
    let manifest_json = read_utf8_json_file(
        &evidence_dir.join("runtime-evidence-manifest.json"),
        "Chiodos runtime evidence manifest",
    )?;
    let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
        serde_json::from_str(&manifest_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
        })?;
    let health = chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
        run_id,
        &evidence_dir,
        &manifest,
        &profile.evidence_required_roles,
        profile.issued_at_unix_ms,
        true,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime evidence health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime evidence health report")
}

fn cmd_chiodos_runtime_ops_provider_health(
    supervisor_profile: &Path,
    provider_bindings: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let bindings =
        chio_chiodos_runtime::runtime_provider_bindings_from_json(&read_utf8_json_file(
            provider_bindings,
            "Chiodos runtime provider bindings",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime provider bindings: {error}"))
        })?;
    let health = chio_chiodos_runtime::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        profile.issued_at_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime provider health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime provider health report")
}

fn cmd_chiodos_runtime_ops_retention_plan(
    retention_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile =
        chio_chiodos_runtime::runtime_artifact_retention_profile_from_json(&read_utf8_json_file(
            retention_profile,
            "Chiodos runtime artifact retention profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime artifact retention profile: {error}"))
        })?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let run_ids = sorted_child_dirs(evidence_root)?
        .into_iter()
        .filter_map(|path| path.file_name().map(|name| name.to_string_lossy().to_string()))
        .collect::<Vec<_>>();
    let plan =
        chio_chiodos_runtime::generate_runtime_artifact_retention_plan(&profile, &run_ids, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime retention plan: {error}"))
            })?;
    write_pretty_json(report, &plan, "Chiodos runtime retention plan")
}

fn load_runtime_supervisor_profile(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeSupervisorProfile, CliError> {
    let profile = chio_chiodos_runtime::runtime_supervisor_profile_from_json(&read_utf8_json_file(
        path,
        "Chiodos runtime supervisor profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_supervisor_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    Ok(profile)
}

fn cmd_chiodos_runtime_run_loopback(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), CliError> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RuntimeLoopbackScenario {
        run_id: String,
        #[serde(default)]
        admission_profile: Option<chio_chiodos_runtime::RuntimeAdmissionProfile>,
        #[serde(default)]
        admission_bundle: Option<chio_chiodos_runtime::RuntimeAdmissionBundle>,
        #[serde(default)]
        request: Option<chio_chiodos_runtime::RuntimeRequestBinding>,
        #[serde(default)]
        steps: Vec<RuntimeLoopbackStep>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RuntimeLoopbackStep {
        admission_profile: chio_chiodos_runtime::RuntimeAdmissionProfile,
        admission_bundle: chio_chiodos_runtime::RuntimeAdmissionBundle,
        request: chio_chiodos_runtime::RuntimeRequestBinding,
        #[serde(default)]
        arguments: Option<serde_json::Value>,
    }

    #[derive(Clone)]
    struct RuntimeLoopbackTreatyContext {
        treaty_scope: chio_chiodos_runtime::TreatyScope,
        treaty_scope_sha256: String,
        ladder_intersection: chio_chiodos_runtime::LadderIntersection,
        ladder_intersection_sha256: String,
        continuation: chio_chiodos_runtime::CrossKernelContinuation,
        continuation_sha256: String,
        lineage_bundle_id: String,
        intent_context: serde_json::Value,
    }

    struct RuntimeLoopbackExecution {
        receipt: chio_core::receipt::ChioReceipt,
        treaty: Option<RuntimeLoopbackTreatyContext>,
    }

    struct RuntimeLoopbackBuyerClosure {
        step_index: usize,
        admission_report: chio_chiodos_runtime::CrossBoundaryAdmissionReport,
        admission_report_sha256: String,
        continuation: chio_chiodos_runtime::CrossKernelContinuation,
        lineage_statement: chio_chiodos_runtime::ReceiptLineageStatement,
        lineage_statement_sha256: String,
        lineage_bundle: chio_chiodos_runtime::ReceiptLineageBundle,
        bilateral_invocation: chio_chiodos_runtime::BilateralInvocation,
        bilateral_invocation_sha256: String,
        bilateral_dsse: chio_federation::DsseEnvelope,
        bilateral_dsse_sha256: String,
    }

    struct RuntimeLoopbackToolServer {
        id: String,
        tool_name: String,
        step_index: usize,
    }

    #[async_trait::async_trait]
    impl chio_kernel::ToolServerConnection for RuntimeLoopbackToolServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec![self.tool_name.clone()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
        ) -> Result<serde_json::Value, chio_kernel::KernelError> {
            if tool_name != self.tool_name {
                return Err(chio_kernel::KernelError::ToolServerError(format!(
                    "runtime loopback tool {tool_name} is not registered on {}",
                    self.id
                )));
            }
            Ok(serde_json::json!({
                "stepIndex": self.step_index,
                "serverId": self.id,
                "toolName": tool_name,
                "arguments": arguments,
                "runtimeReceiptSource": "chio_kernel_live_loopback"
            }))
        }
    }

    fn runtime_loopback_capability(
        issuer: &chio_core::Keypair,
        subject: &chio_core::Keypair,
        capability_id: &str,
        server_id: &str,
        tool_name: &str,
    ) -> Result<chio_core::capability::CapabilityToken, CliError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime loopback clock: {error}"))
            })?
            .as_secs();
        let scope = chio_core::capability::ChioScope {
            grants: vec![chio_core::capability::ToolGrant {
                server_id: server_id.to_string(),
                tool_name: tool_name.to_string(),
                operations: vec![chio_core::capability::Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        };
        let body = chio_core::capability::CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: now.saturating_sub(60),
            expires_at: now.saturating_add(600),
            delegation_chain: Vec::new(),
        };
        chio_core::capability::CapabilityToken::sign(body, issuer).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime loopback capability signing: {error}"))
        })
    }

    fn runtime_loopback_policy_summary(
        step: &RuntimeLoopbackStep,
    ) -> chio_federation::PolicyEvaluationSummary {
        let policy_version = "chiodos-ladder-v1".to_string();
        chio_federation::PolicyEvaluationSummary {
            server_a_verdict: chio_federation::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: format!("buyer-policy:{}", step.request.tool_name),
                policy_version: policy_version.clone(),
                rationale_code: Some("lease-bound".to_string()),
            },
            server_b_verdict: chio_federation::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: format!(
                    "{}-policy:{}",
                    step.request.host_kernel_id, step.request.tool_name
                ),
                policy_version,
                rationale_code: Some("manifest-bound".to_string()),
            },
            joint_disposition: Some("allow".to_string()),
        }
    }

    fn execute_runtime_loopback_step(
        step_index: usize,
        step: &RuntimeLoopbackStep,
        arguments: serde_json::Value,
    ) -> Result<RuntimeLoopbackExecution, CliError> {
        let (expected_kernel_id, expected_server_id, expected_tool_name) =
            chiodos_three_vendor_example::runtime_vendor_binding(step_index).map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime loopback vendor binding: {error}"))
            })?;
        if step.request.server_id != expected_server_id || step.request.tool_name != expected_tool_name
        {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime loopback step {} targets {}:{} but expected {}:{}",
                step_index,
                step.request.server_id,
                step.request.tool_name,
                expected_server_id,
                expected_tool_name
            )));
        }
        if step.request.host_kernel_id != expected_kernel_id {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime loopback step {} host kernel {} does not match {}",
                step_index, step.request.host_kernel_id, expected_kernel_id
            )));
        }
        let actual_args_sha256 =
            chio_chiodos_runtime::tool_args_sha256(&arguments).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback argument hash for step {}: {error}",
                    step_index
                ))
            })?;
        if actual_args_sha256 != step.request.tool_args_sha256 {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime loopback step {} arguments hash {} does not match request {}",
                step_index, actual_args_sha256, step.request.tool_args_sha256
            )));
        }
        let vendor_key =
            chiodos_three_vendor_example::runtime_vendor_keypair(step_index).map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime loopback vendor key: {error}"))
            })?;
        let agent_key = chio_core::Keypair::generate();
        let capability = runtime_loopback_capability(
            &vendor_key,
            &agent_key,
            &step.request.capability_id,
            &step.request.server_id,
            &step.request.tool_name,
        )?;
        let mut kernel = ChioKernel::new(chio_kernel::KernelConfig {
            keypair: vendor_key.clone(),
            ca_public_keys: vec![vendor_key.public_key()],
            max_delegation_depth: 5,
            policy_hash: format!("chiodos-runtime-loopback-policy:{}", step_index),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.set_federation_local_kernel_id(step.request.host_kernel_id.clone());
        let receipt_store_path = std::env::temp_dir().join(format!(
            "chio-runtime-loopback-{}-{}.sqlite3",
            std::process::id(),
            step_index
        ));
        if receipt_store_path.exists() {
            fs::remove_file(&receipt_store_path).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to clear Chiodos runtime loopback receipt store {}: {error}",
                    receipt_store_path.display()
                ))
            })?;
        }
        let receipt_store = chio_store_sqlite::SqliteReceiptStore::open(&receipt_store_path)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback receipt store open: {error}"
                ))
            })?;
        kernel.set_receipt_store(Box::new(receipt_store));
        if let Some(origin_kernel_id) = step.request.origin_kernel_id.as_deref() {
            let origin_key = chiodos_three_vendor_example::runtime_buyer_keypair();
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime loopback federation clock: {error}"
                    ))
                })?
                .as_secs();
            let trust = chio_federation::KernelTrustExchange::new(
                &step.request.host_kernel_id,
                vendor_key.clone(),
            )
            .with_trusted_peer(origin_kernel_id, origin_key.public_key());
            let envelope = chio_federation::PeerHandshakeEnvelope::sign(
                origin_kernel_id,
                &step.request.host_kernel_id,
                &format!("loopback-origin-nonce-{step_index}"),
                now_secs,
                &origin_key,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback peer handshake signing: {error}"
                ))
            })?;
            let peer = trust
                .accept_envelope(&envelope, origin_kernel_id, now_secs)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime loopback peer pinning: {error}"
                    ))
                })?;
            kernel = kernel.with_federation_peers(vec![peer]);
            kernel.set_federation_cosigner(std::sync::Arc::new(
                chio_federation::InProcessCoSigner::new(
                    origin_kernel_id,
                    origin_key,
                    vendor_key.public_key(),
                ),
            ));
        }
        let hook_store = chio_chiodos_runtime::InMemoryRuntimeAdmissionStore::new();
        hook_store
            .insert_bundle(step.admission_bundle.clone())
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback hook store update: {error}"
                ))
            })?;
        let chiodos_treaty = if step.request.origin_kernel_id.is_some() {
            Some(insert_runtime_loopback_treaty_context(
                &hook_store,
                step_index,
                step,
                &vendor_key,
                &arguments,
            )?)
        } else {
            None
        };
        kernel.set_runtime_admission_hook(std::sync::Arc::new(
            chio_chiodos_runtime::ChiodosRuntimeAdmissionHook::new(
                step.admission_profile.clone(),
                hook_store,
            ),
        ));
        kernel.register_tool_server(Box::new(RuntimeLoopbackToolServer {
            id: step.request.server_id.clone(),
            tool_name: step.request.tool_name.clone(),
            step_index,
        }));
        let bundle_sha256 =
            chio_chiodos_runtime::runtime_admission_bundle_sha256(&step.admission_bundle).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime loopback bundle hash for step {}: {error}",
                        step_index
                    ))
                },
            )?;
        let governed_intent = chio_core::capability::GovernedTransactionIntent {
            id: format!("intent:chiodos-runtime-loopback:{}", step_index),
            server_id: step.request.server_id.clone(),
            tool_name: step.request.tool_name.clone(),
            purpose: "Chiodos live runtime loopback proof regeneration".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(if let Some(chiodos_treaty) = chiodos_treaty.as_ref() {
                serde_json::json!({
                    "chiodosAdmission": {
                        "admissionId": step.admission_bundle.admission_id,
                        "bundleSha256": bundle_sha256
                    },
                    "chiodosTreaty": chiodos_treaty.intent_context
                })
            } else {
                serde_json::json!({
                "chiodosAdmission": {
                    "admissionId": step.admission_bundle.admission_id,
                    "bundleSha256": bundle_sha256
                }
                })
            }),
        };
        let request = KernelToolCallRequest {
            request_id: step.request.request_id.clone(),
            capability,
            tool_name: step.request.tool_name.clone(),
            server_id: step.request.server_id.clone(),
            agent_id: agent_key.public_key().to_hex(),
            arguments,
            dpop_proof: None,
            governed_intent: Some(governed_intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: step.request.origin_kernel_id.clone(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime loopback executor: {error}"))
            })?;
        let response = runtime
            .block_on(kernel.evaluate_tool_call(&request))
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback kernel evaluation step {}: {error}",
                    step_index
                ))
            })?;
        if !matches!(response.verdict, chio_kernel::Verdict::Allow) {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime loopback kernel denied step {}: {}",
                step_index,
                response
                    .reason
                    .as_deref()
                    .unwrap_or("unknown_runtime_loopback_denial")
            )));
        }
        Ok(RuntimeLoopbackExecution {
            receipt: response.receipt,
            treaty: chiodos_treaty,
        })
    }

    fn insert_runtime_loopback_treaty_context(
        hook_store: &chio_chiodos_runtime::InMemoryRuntimeAdmissionStore,
        step_index: usize,
        step: &RuntimeLoopbackStep,
        vendor_key: &chio_core::Keypair,
        _arguments: &serde_json::Value,
    ) -> Result<RuntimeLoopbackTreatyContext, CliError> {
        let source_kernel_id = step.request.origin_kernel_id.clone().ok_or_else(|| {
            CliError::cli_other_error(
                "Chiodos runtime loopback treaty context requires an origin kernel",
            )
        })?;
        let target_kernel_id = step.request.host_kernel_id.clone();
        let action_class_id = format!("workflow.cross_kernel.{}", step.request.tool_name);
        let issued_at_unix_ms = 1_700_000_000_000_u64;
        let expires_at_unix_ms = 1_900_000_000_000_u64;
        let origin_key = chiodos_three_vendor_example::runtime_buyer_keypair();
        let manifest_hashes = vec![
            chio_core::sha256_hex(
                format!("runtime-loopback:{source_kernel_id}:manifest").as_bytes(),
            ),
            chio_core::sha256_hex(
                format!("runtime-loopback:{target_kernel_id}:manifest").as_bytes(),
            ),
        ];
        let treaty_scope = chio_chiodos_runtime::TreatyScope {
            schema: chio_chiodos_runtime::CHIODOS_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: format!("treaty:runtime-loopback:{step_index}"),
            participant_kernel_ids: vec![source_kernel_id.clone(), target_kernel_id.clone()],
            participant_public_keys: vec![origin_key.public_key(), vendor_key.public_key()],
            ladder_manifest_sha256s: manifest_hashes.clone(),
            allowed_action_classes: vec![action_class_id.clone()],
            issued_at_unix_ms,
            expires_at_unix_ms,
            revocation_epoch_sha256: chio_core::sha256_hex(
                format!("runtime-loopback:{step_index}:revocations").as_bytes(),
            ),
            trust_bundle_sha256: step.admission_bundle.trust_bundle_sha256.clone(),
        };
        let treaty_scope_sha256 =
            chio_chiodos_runtime::treaty_scope_sha256(&treaty_scope).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback treaty scope hash: {error}"
                ))
            })?;
        let mut participant_modes = std::collections::BTreeMap::new();
        participant_modes.insert(source_kernel_id.clone(), "receipt_backed".to_string());
        participant_modes.insert(target_kernel_id.clone(), "receipt_backed".to_string());
        let ladder_intersection = chio_chiodos_runtime::LadderIntersection {
            schema: chio_chiodos_runtime::CHIODOS_LADDER_INTERSECTION_SCHEMA.to_string(),
            intersection_id: format!("intersection:runtime-loopback:{step_index}"),
            treaty_id: treaty_scope.treaty_id.clone(),
            participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
            ladder_manifest_sha256s: manifest_hashes,
            generated_at_unix_ms: issued_at_unix_ms,
            expires_at_unix_ms,
            action_classes: vec![chio_chiodos_runtime::LadderIntersectionActionClass {
                action_class_id: action_class_id.clone(),
                mode: "receipt_backed".to_string(),
                destructive: step.admission_bundle.destructive,
                consistency_model: "totally_ordered".to_string(),
                co_sign: "bilateral_required".to_string(),
                evidence_required: vec![
                    "receipt_lineage".to_string(),
                    "bilateral_invocation".to_string(),
                ],
                participant_modes,
            }],
        };
        let ladder_intersection_sha256 =
            chio_chiodos_runtime::ladder_intersection_sha256(&ladder_intersection).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime loopback ladder intersection hash: {error}"
                    ))
                },
            )?;
        let parent_receipt_sha256 = chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:parent-receipt").as_bytes(),
        );
        let child_receipt_sha256 = chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:child-receipt").as_bytes(),
        );
        let continuation = chio_chiodos_runtime::CrossKernelContinuation {
            schema: chio_chiodos_runtime::CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
            continuation_id: format!("continuation:runtime-loopback:{step_index}"),
            source_kernel_id: source_kernel_id.clone(),
            target_kernel_id: target_kernel_id.clone(),
            parent_receipt_sha256: parent_receipt_sha256.clone(),
            parent_session_anchor_sha256: chio_core::sha256_hex(
                format!("runtime-loopback:{step_index}:session-anchor").as_bytes(),
            ),
            capability_id: step.request.capability_id.clone(),
            action_class_id: action_class_id.clone(),
            audience_tool: format!("{}.{}", step.request.server_id, step.request.tool_name),
            nonce: format!("runtime-loopback-continuation-nonce-{step_index}"),
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        let continuation_sha256 =
            canonical_sha256_json(&continuation, "Chiodos runtime loopback continuation hash")?;
        let outcome_sha256 = chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:pre-dispatch-outcome").as_bytes(),
        );
        let mut bilateral_invocation = chio_chiodos_runtime::BilateralInvocation {
            schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: format!("bilateral:runtime-loopback:{step_index}"),
            treaty_id: treaty_scope.treaty_id.clone(),
            ladder_intersection_sha256: ladder_intersection_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: action_class_id.clone(),
            consistency_model: "totally_ordered".to_string(),
            capability_id: step.request.capability_id.clone(),
            request_sha256: step.request.tool_args_sha256.clone(),
            outcome_sha256: outcome_sha256.clone(),
            local_receipt_sha256: parent_receipt_sha256.clone(),
            remote_receipt_sha256: child_receipt_sha256,
            signer_kernel_ids: vec![source_kernel_id.clone(), target_kernel_id.clone()],
        };
        let bilateral_invocation_binding_sha256 =
            chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime loopback bilateral invocation binding hash: {error}"
                    ))
                })?;
        let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: format!("lineage:runtime-loopback:{step_index}"),
            parent_receipt_sha256: parent_receipt_sha256.clone(),
            child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            bilateral_invocation_sha256: bilateral_invocation_binding_sha256,
            evidence_class: "verified".to_string(),
            source_kernel_id: source_kernel_id.clone(),
            target_kernel_id: target_kernel_id.clone(),
        };
        let lineage_statement_sha256 = canonical_sha256_json(
            &lineage_statement,
            "Chiodos runtime loopback lineage statement hash",
        )?;
        bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
        let bilateral_invocation_sha256 = canonical_sha256_json(
            &bilateral_invocation,
            "Chiodos runtime loopback bilateral invocation hash",
        )?;
        let lineage_bundle = chio_chiodos_runtime::ReceiptLineageBundle {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: format!("lineage-bundle:runtime-loopback:{step_index}"),
            root_receipt_sha256: parent_receipt_sha256.clone(),
            leaf_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
            statements: vec![lineage_statement],
        };
        let lineage_bundle_sha256 =
            canonical_sha256_json(&lineage_bundle, "Chiodos runtime loopback lineage bundle hash")?;
        hook_store
            .insert_treaty_runtime_artifact("treaty_scope", &treaty_scope.treaty_id, &treaty_scope)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback treaty scope store: {error}"
                ))
            })?;
        hook_store
            .insert_treaty_runtime_artifact(
                "ladder_intersection",
                &ladder_intersection.intersection_id,
                &ladder_intersection,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback ladder intersection store: {error}"
                ))
            })?;
        hook_store
            .insert_treaty_runtime_artifact(
                "cross_kernel_continuation",
                &continuation.continuation_id,
                &continuation,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback continuation store: {error}"
                ))
            })?;
        hook_store
            .insert_treaty_runtime_artifact(
                "receipt_lineage_bundle",
                &lineage_bundle.bundle_id,
                &lineage_bundle,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback lineage bundle store: {error}"
                ))
            })?;
        hook_store
            .insert_treaty_runtime_artifact(
                "bilateral_invocation",
                &bilateral_invocation.invocation_id,
                &bilateral_invocation,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback bilateral invocation store: {error}"
                ))
            })?;

        let intent_context = serde_json::json!({
            "treatyScopeId": treaty_scope.treaty_id,
            "treatyScopeSha256": treaty_scope_sha256,
            "ladderIntersectionId": ladder_intersection.intersection_id,
            "ladderIntersectionSha256": ladder_intersection_sha256,
            "actionClassId": action_class_id,
            "crossKernelContinuation": {
                "id": continuation.continuation_id,
                "sha256": continuation_sha256
            },
            "receiptLineageBundle": {
                "id": lineage_bundle.bundle_id,
                "sha256": lineage_bundle_sha256
            },
            "bilateralInvocation": {
                "id": bilateral_invocation.invocation_id,
                "sha256": bilateral_invocation_sha256
            }
        });
        Ok(RuntimeLoopbackTreatyContext {
            treaty_scope,
            treaty_scope_sha256,
            ladder_intersection,
            ladder_intersection_sha256,
            continuation,
            continuation_sha256,
            lineage_bundle_id: lineage_bundle.bundle_id,
            intent_context,
        })
    }

    fn build_runtime_loopback_buyer_closure(
        step_index: usize,
        step: &RuntimeLoopbackStep,
        treaty_context: &RuntimeLoopbackTreatyContext,
        baseline_package: &chio_chiodos::ChiodosProofPackage,
        now_unix_ms: u64,
    ) -> Result<
        (
            chio_chiodos::ChiodosProofPackage,
            RuntimeLoopbackBuyerClosure,
        ),
        CliError,
    > {
        let workflow_step = baseline_package
            .workflow_receipt
            .steps
            .get(step_index)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure missing workflow step {step_index}"
                ))
            })?;
        let tool_receipt_id = workflow_step.tool_receipt_id.as_ref().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure step {} is missing tool receipt id",
                workflow_step.step_index
            ))
        })?;
        let receipt = baseline_package
            .tool_receipts
            .iter()
            .find(|receipt| receipt.id == *tool_receipt_id)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure missing tool receipt {tool_receipt_id}"
                ))
            })?;
        let tool_receipt_sha256 =
            canonical_sha256_json(receipt, "Chiodos runtime buyer closure receipt hash")?;
        let local_receipt_sha256 = workflow_step
            .parent_receipt_sha256
            .clone()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime buyer closure requires a parent workflow receipt hash"
                        .to_string(),
                )
            })?;
        let outcome_sha256 = workflow_step.output_hash.clone().ok_or_else(|| {
            CliError::cli_other_error(
                "Chiodos runtime buyer closure step is missing an output hash".to_string(),
            )
        })?;
        let mut bilateral_invocation = chio_chiodos_runtime::BilateralInvocation {
            schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: format!("bilateral:runtime-loopback:closure:{step_index}"),
            treaty_id: treaty_context.treaty_scope.treaty_id.clone(),
            ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
            continuation_sha256: treaty_context.continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: format!("workflow.cross_kernel.{}", step.request.tool_name),
            consistency_model: "totally_ordered".to_string(),
            capability_id: step.request.capability_id.clone(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: outcome_sha256.clone(),
            local_receipt_sha256: local_receipt_sha256.clone(),
            remote_receipt_sha256: tool_receipt_sha256.clone(),
            signer_kernel_ids: vec![
                treaty_context.continuation.source_kernel_id.clone(),
                treaty_context.continuation.target_kernel_id.clone(),
            ],
        };
        let action_class_id = treaty_context
            .ladder_intersection
            .action_classes
            .first()
            .map(|action| action.action_class_id.clone())
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime buyer closure treaty intersection has no action class"
                        .to_string(),
                )
            })?;
        bilateral_invocation.action_class_id = action_class_id.clone();
        let bilateral_invocation_sha256 =
            chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime buyer closure bilateral invocation hash: {error}"
                    ))
                })?;
        let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: format!("lineage:runtime-loopback:closure:{step_index}"),
            parent_receipt_sha256: local_receipt_sha256.clone(),
            child_receipt_sha256: tool_receipt_sha256.clone(),
            continuation_sha256: treaty_context.continuation_sha256.clone(),
            bilateral_invocation_sha256: bilateral_invocation_sha256.clone(),
            evidence_class: "verified".to_string(),
            source_kernel_id: treaty_context.continuation.source_kernel_id.clone(),
            target_kernel_id: treaty_context.continuation.target_kernel_id.clone(),
        };
        let lineage_statement_sha256 = canonical_sha256_json(
            &lineage_statement,
            "Chiodos runtime buyer closure lineage statement hash",
        )?;
        bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
        let lineage_bundle = chio_chiodos_runtime::ReceiptLineageBundle {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: format!("{}:closure", treaty_context.lineage_bundle_id),
            root_receipt_sha256: local_receipt_sha256.clone(),
            leaf_receipt_sha256: tool_receipt_sha256.clone(),
            statements: vec![lineage_statement.clone()],
        };
        let lineage_bundle_sha256 = canonical_sha256_json(
            &lineage_bundle,
            "Chiodos runtime buyer closure lineage bundle hash",
        )?;
        let admission_report = chio_chiodos_runtime::evaluate_cross_boundary_admission(
            chio_chiodos_runtime::CrossBoundaryAdmissionInput {
                treaty_scope: &treaty_context.treaty_scope,
                ladder_intersection: &treaty_context.ladder_intersection,
                expected_ladder_intersection_sha256: Some(
                    treaty_context.ladder_intersection_sha256.clone(),
                ),
                action_class_id: &action_class_id,
                present_evidence: vec![
                    "receipt_lineage".to_string(),
                    "bilateral_invocation".to_string(),
                ],
                verified_evidence: vec![
                    chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                        evidence_class: "receipt_lineage".to_string(),
                        artifact_sha256: lineage_statement_sha256.clone(),
                        verified: true,
                    },
                    chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                        evidence_class: "bilateral_invocation".to_string(),
                        artifact_sha256: bilateral_invocation_sha256.clone(),
                        verified: true,
                    },
                ],
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure admission report: {error}"
            ))
        })?;
        if !admission_report.accepted {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure admission rejected: {}",
                admission_report
                    .failure_code
                    .as_deref()
                    .unwrap_or("unknown_treaty_closure_failure")
            )));
        }
        let admission_report_sha256 = canonical_sha256_json(
            &admission_report,
            "Chiodos runtime buyer closure admission report hash",
        )?;
        let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
            CliError::cli_other_error(
                "Chiodos runtime buyer closure requires a capability lease".to_string(),
            )
        })?;
        let lease = baseline_package
            .capability_leases
            .iter()
            .find(|lease| lease.body.lease_id == lease_id)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure missing lease {lease_id}"
                ))
            })?;
        let governance_receipt = workflow_step
            .governance_receipt_id
            .as_ref()
            .into_iter()
            .chain(step.admission_bundle.governance_receipt_id.as_ref())
            .find_map(|receipt_id| {
                baseline_package
                    .governance_receipts
                    .iter()
                    .find(|receipt| receipt.body.receipt_id == *receipt_id)
            })
            .or_else(|| {
                if baseline_package.governance_receipts.len() == 1 {
                    baseline_package.governance_receipts.first()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime buyer closure requires a package governance receipt"
                        .to_string(),
                )
            })?;
        let governance_digest = canonical_sha256_json(
            governance_receipt,
            "Chiodos runtime buyer closure governance receipt digest",
        )?;
        let buyer_key = chiodos_three_vendor_example::runtime_buyer_keypair();
        let vendor_key =
            chiodos_three_vendor_example::runtime_vendor_keypair(step_index).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure vendor key: {error}"
                ))
            })?;
        let bilateral_dsse = chio_federation::sign_chiodos_dsse_envelope(
            receipt,
            &buyer_key,
            &vendor_key,
            &treaty_context.continuation.source_kernel_id,
            &treaty_context.continuation.target_kernel_id,
            &step.request.tool_name,
            now_unix_ms,
            chio_federation::BilateralPredicateExtensions {
                capability_lease_ref: Some(chio_federation::CapabilityLeaseRef {
                    lease_id: lease.body.lease_id.clone(),
                    issuer: lease.body.issuer.clone(),
                    expires_at_unix_ms: lease.body.expires_at_unix_ms,
                    scope_digest: Some(chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: lease.body.scope_digest.clone(),
                    }),
                }),
                policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
                governance_receipt_ref: Some(chio_federation::GovernanceReceiptRef {
                    receipt_id: governance_receipt.body.receipt_id.clone(),
                    kernel_id: governance_receipt.body.authorizing_kernel.clone(),
                    digest: chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: governance_digest,
                    },
                }),
                consistency_anchor: workflow_step.consistency_anchor.clone(),
                consistency_model: Some(admission_report.consistency_model.clone()),
                cross_org_visibility: None,
                treaty_binding_ref: Some(chio_federation::TreatyBindingRef {
                    treaty_id: admission_report.treaty_id.clone(),
                    treaty_scope_sha256: treaty_context.treaty_scope_sha256.clone(),
                    ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
                    admission_report_sha256: admission_report_sha256.clone(),
                    continuation_sha256: treaty_context.continuation_sha256.clone(),
                    lineage_bundle_sha256,
                    action_class_id: admission_report.action_class_id.clone(),
                    consistency_model: admission_report.consistency_model.clone(),
                    request_sha256: bilateral_invocation.request_sha256.clone(),
                    outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                    local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec![lease.body.lease_id.clone()],
                    governance_refs: vec![governance_receipt.body.receipt_id.clone()],
                    signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
                }),
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure strict DSSE signing: {error}"
            ))
        })?;
        let bilateral_dsse_sha256 = canonical_sha256_json(
            &bilateral_dsse,
            "Chiodos runtime buyer closure DSSE hash",
        )?;
        let mut runtime_artifacts = baseline_package
            .tool_receipts
            .iter()
            .cloned()
            .zip(baseline_package.bilateral_envelopes.iter().cloned())
            .zip(baseline_package.workflow_receipt.steps.iter().cloned())
            .map(
                |((tool_receipt, bilateral_envelope), workflow_step)| {
                    chiodos_three_vendor_example::RuntimeProofArtifact {
                        tool_receipt,
                        bilateral_envelope,
                        workflow_step,
                    }
                },
            )
            .collect::<Vec<_>>();
        let artifact = runtime_artifacts.get_mut(step_index).ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure missing artifact {step_index}"
            ))
        })?;
        artifact.bilateral_envelope = bilateral_dsse.clone();
        artifact.workflow_step.bilateral_dsse_sha256 = Some(bilateral_dsse_sha256.clone());
        let mut parent = None;
        for artifact in &mut runtime_artifacts {
            artifact.workflow_step.parent_receipt_sha256 = parent.clone();
            parent = Some(canonical_sha256_json(
                &artifact.workflow_step,
                "Chiodos runtime buyer closure workflow step hash",
            )?);
        }
        let package = chiodos_three_vendor_example::proof_package_from_runtime_artifacts(
            runtime_artifacts,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime buyer closure proof package: {error}"
            ))
        })?;
        Ok((
            package,
            RuntimeLoopbackBuyerClosure {
                step_index,
                admission_report,
                admission_report_sha256,
                continuation: treaty_context.continuation.clone(),
                lineage_statement,
                lineage_statement_sha256,
                lineage_bundle,
                bilateral_invocation,
                bilateral_invocation_sha256,
                bilateral_dsse,
                bilateral_dsse_sha256,
            },
        ))
    }

    let scenario: RuntimeLoopbackScenario =
        serde_json::from_str(&read_utf8_json_file(scenario, "Chiodos runtime loopback scenario")?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime loopback scenario parse: {error}"))
            })?;
    let steps = if scenario.steps.is_empty() {
        let admission_profile = scenario.admission_profile.ok_or_else(|| {
            CliError::cli_other_error(
                "Chiodos runtime loopback scenario missing admissionProfile".to_string(),
            )
        })?;
        let admission_bundle = scenario.admission_bundle.ok_or_else(|| {
            CliError::cli_other_error(
                "Chiodos runtime loopback scenario missing admissionBundle".to_string(),
            )
        })?;
        let request = scenario.request.ok_or_else(|| {
            CliError::cli_other_error("Chiodos runtime loopback scenario missing request".to_string())
        })?;
        vec![RuntimeLoopbackStep {
            admission_profile,
            admission_bundle,
            request,
            arguments: None,
        }]
    } else {
        scenario.steps
    };
    fs::create_dir_all(store_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos runtime store directory {}: {error}",
            store_dir.display()
        ))
    })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos runtime output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    let store_path = store_dir.join("admission-store.json");
    let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime loopback admission store open: {error}"
            ))
        },
    )?;
    let mut accepted = true;
    let mut failure_code = None;
    let mut evidence_paths = Vec::new();
    let mut admission_hashes = Vec::new();
    let mut step_evidence = Vec::new();
    let mut source_records = Vec::new();
    let mut evidence_manifest_entries = Vec::new();
    let mut live_tool_receipts = Vec::new();
    let mut live_treaty_contexts = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let admission_id = step.admission_bundle.admission_id.clone();
        store
            .insert_bundle(step.admission_bundle.clone())
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime loopback admission store update: {error}"
                ))
            })?;
        let admission_report = chio_chiodos_runtime::evaluate_runtime_admission(
            chio_chiodos_runtime::RuntimeAdmissionInput {
                profile: &step.admission_profile,
                store: &store,
                admission_id: &admission_id,
                request: &step.request,
                runtime_trust_input: None,
                trusted_verifier_keys: &[],
                pheromone_advisory: None,
                runtime_pheromone_policy: None,
                runtime_peer_weights: None,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime loopback admission: {error}"))
        })?;
        let suffix = if steps.len() == 1 {
            String::new()
        } else {
            format!("-{}", index + 1)
        };
        let admission_report_name = format!("runtime-admission-report{suffix}.json");
        let admission_json = chio_chiodos_runtime::runtime_admission_report_json(&admission_report)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime admission report JSON: {error}"))
            })?;
        let admission_artifact_hash = write_runtime_json_artifact_string(
            out_dir,
            "admission_report",
            &admission_report_name,
            &admission_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let admission_hash = chio_core::sha256_hex(admission_json.as_bytes());
        if admission_artifact_hash.is_empty() {
            return Err(CliError::cli_other_error(
                "Chiodos runtime admission artifact hash was empty".to_string(),
            ));
        }
        admission_hashes.push(admission_hash.clone());
        if !admission_report.accepted {
            accepted = false;
            failure_code = admission_report.failure_code.clone();
            break;
        }
        let arguments = step.arguments.clone().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chiodos runtime accepted step {} did not carry executable arguments",
                step.admission_bundle.step_index
            ))
        })?;
        let execution = execute_runtime_loopback_step(index, step, arguments)?;
        live_tool_receipts.push(execution.receipt);
        live_treaty_contexts.push(execution.treaty);
    }
    let mut proof_package_sha256 = None;
    let mut verifier_report_sha256 = None;
    let mut workflow_receipt_sha256 = None;
    let mut trust_bundle_sha256 = None;
    let mut verification_context_sha256 = None;
    let mut parity_report: Option<chio_chiodos_runtime::RuntimeProofParityReport> = None;
    let mut principal_admission_report_sha256 = None;
    let mut proof_checks = vec!["runtime_source_records.bound".to_string()];

    if accepted {
        if live_tool_receipts.len() != steps.len() {
            return Err(CliError::cli_other_error(format!(
                "Chiodos runtime captured {} live receipts for {} accepted steps",
                live_tool_receipts.len(),
                steps.len()
            )));
        }
        let captured_receipt_hashes = live_tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime captured receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        proof_checks.push("runtime_kernel_receipts.captured".to_string());
        let baseline_package =
            chiodos_three_vendor_example::proof_package_from_runtime_receipts(
                live_tool_receipts.clone(),
            )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime proof package build from live receipts: {error}"
                    ))
                })?;
        let baseline_receipt_hashes = baseline_package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime package receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if baseline_receipt_hashes != captured_receipt_hashes {
            return Err(CliError::cli_other_error(
                "Chiodos runtime proof package did not preserve captured live receipts"
                    .to_string(),
            ));
        }
        proof_checks.push("runtime_live_receipts.bound_to_proof_package".to_string());
        let parity_package = baseline_package.clone();
        let buyer_closure_index = steps
            .iter()
            .enumerate()
            .find(|(index, step)| {
                step.admission_bundle.destructive
                    && step.admission_bundle.governance_receipt_id.is_some()
                    && live_treaty_contexts
                        .get(*index)
                        .and_then(Option::as_ref)
                        .is_some()
            })
            .map(|(index, _)| index);
        let (package, buyer_closure) = if let Some(index) = buyer_closure_index {
            let treaty_context = live_treaty_contexts
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime buyer closure missing treaty context for step {index}"
                    ))
                })?;
            let (package, closure) = build_runtime_loopback_buyer_closure(
                index,
                &steps[index],
                treaty_context,
                &baseline_package,
                now_unix_ms,
            )?;
            proof_checks.push("runtime_treaty_buyer_closure.bound".to_string());
            (package, Some(closure))
        } else {
            (baseline_package, None)
        };
        let package_receipt_hashes = package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime final package receipt hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if package_receipt_hashes != captured_receipt_hashes {
            return Err(CliError::cli_other_error(
                "Chiodos runtime final proof package did not preserve captured live receipts"
                    .to_string(),
            ));
        }
        let context = chiodos_three_vendor_example::verification_context();
        let trust_bundle_document =
            chiodos_three_vendor_example::verifier_trust_bundle_document_for_package(&package)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime verifier trust bundle build: {error}"
                    ))
                })?;
        let trust_bundle =
            chio_chiodos::ChiodosVerifierTrustBundle::from_document(trust_bundle_document.clone())
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime verifier trust bundle parse: {error}"
                    ))
                })?;
        let verifier_report = chio_chiodos::verify_package_report(&package, &trust_bundle, &context);

        let package_json = chio_chiodos::package_json(&package).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime proof package JSON: {error}"))
        })?;
        let package_json_value: serde_json::Value =
            serde_json::from_str(&package_json).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime proof package JSON value: {error}"
                ))
            })?;
        let trust_bundle_json =
            chio_chiodos::verifier_trust_bundle_json(&trust_bundle_document).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime verifier trust bundle JSON: {error}"
                ))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verifier_trust_bundle",
            "verifier-trust-bundle.json",
            &trust_bundle_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let context_json = chio_chiodos::verification_context_json(&context).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime verification context JSON: {error}"))
        })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verification_context",
            "verification-context.json",
            &context_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let verifier_report_json = chio_chiodos::report_json(&verifier_report).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime verifier report JSON: {error}"))
        })?;
        let verifier_report_artifact_sha256 = write_runtime_json_artifact_string(
            out_dir,
            "verifier_report",
            "verifier-report.json",
            &verifier_report_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        write_runtime_json_artifact(
            out_dir,
            "workflow_receipt",
            "workflow-receipt.json",
            &package.workflow_receipt,
            "Chiodos runtime workflow receipt JSON",
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;

        verifier_report_sha256 = Some(canonical_sha256_json(
            &verifier_report,
            "Chiodos runtime verifier report canonical hash",
        )?);
        workflow_receipt_sha256 = Some(canonical_sha256_json(
            &package.workflow_receipt,
            "Chiodos runtime workflow receipt canonical hash",
        )?);
        trust_bundle_sha256 = Some(trust_bundle.document_sha256().to_string());
        verification_context_sha256 =
            Some(chio_chiodos::verification_context_sha256(&context).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime verification context hash: {error}"
                ))
            })?);
        if verifier_report_sha256.as_deref() != Some(verifier_report_artifact_sha256.as_str()) {
            proof_checks.push("runtime_verifier_report.canonical_hash_recorded".to_string());
        }

        for (index, step) in package.workflow_receipt.steps.iter().enumerate() {
            let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime workflow step {} missing tool receipt id",
                    step.step_index
                ))
            })?;
            let receipt = package
                .tool_receipts
                .iter()
                .find(|receipt| receipt.id == *tool_receipt_id)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime package missing tool receipt {}",
                        tool_receipt_id
                    ))
                })?;
            let envelope = package.bilateral_envelopes.get(index).ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime package missing DSSE envelope for step {}",
                    step.step_index
                ))
            })?;
            let receipt_name = format!("tool-receipt-{}.json", index + 1);
            let dsse_name = format!("bilateral-dsse-{}.json", index + 1);
            let workflow_step_name = format!("workflow-step-{}.json", index + 1);
            let tool_receipt_sha256 = canonical_sha256_json(
                receipt,
                "Chiodos runtime tool receipt canonical hash",
            )?;
            let bilateral_dsse_sha256 = canonical_sha256_json(
                envelope,
                "Chiodos runtime bilateral DSSE canonical hash",
            )?;
            let workflow_step_sha256 = canonical_sha256_json(
                step,
                "Chiodos runtime workflow step canonical hash",
            )?;
            write_runtime_json_artifact(
                out_dir,
                "tool_receipt",
                &receipt_name,
                receipt,
                "Chiodos runtime tool receipt JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse",
                &dsse_name,
                envelope,
                "Chiodos runtime bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "workflow_step",
                &workflow_step_name,
                step,
                "Chiodos runtime workflow step JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            let admission_report_sha256 = admission_hashes
                .get(index)
                .or_else(|| admission_hashes.last())
                .cloned()
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "Chiodos runtime proof generation missing admission report hash"
                            .to_string(),
                    )
                })?;
            step_evidence.push(chio_chiodos_runtime::RuntimeStepEvidence {
                schema: chio_chiodos_runtime::CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime step index conversion failed: {error}"
                    ))
                })?,
                admission_id: steps
                    .get(index)
                    .or_else(|| steps.last())
                    .map(|runtime_step| runtime_step.admission_bundle.admission_id.clone())
                    .ok_or_else(|| {
                        CliError::cli_other_error(
                            "Chiodos runtime proof generation missing admission id".to_string(),
                        )
                    })?,
                admission_report_sha256: admission_report_sha256.clone(),
                tool_receipt_id: tool_receipt_id.clone(),
                tool_receipt_sha256: tool_receipt_sha256.clone(),
                output_sha256: step.output_hash.clone().ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime workflow step {} missing output hash",
                        step.step_index
                    ))
                })?,
                bilateral_dsse_sha256: bilateral_dsse_sha256.clone(),
                workflow_step_sha256: workflow_step_sha256.clone(),
                parent_receipt_sha256: step.parent_receipt_sha256.clone(),
                consistency_anchor: step.consistency_anchor.clone().ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime workflow step {} missing consistency anchor",
                        step.step_index
                    ))
                })?,
                destructive: step.destructive.unwrap_or(false),
                lease_id: package
                    .capability_leases
                    .get(index)
                    .map(|lease| lease.body.lease_id.clone()),
                governance_receipt_id: step.governance_receipt_id.clone(),
            });
            source_records.push(chio_chiodos_runtime::RuntimeProofSourceRecord {
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime source step conversion failed: {error}"
                    ))
                })?,
                admission_report_sha256,
                tool_receipt_sha256,
                bilateral_dsse_sha256,
                workflow_step_sha256,
            });
        }

        if let Some(closure) = buyer_closure.as_ref() {
            let step = step_evidence.get_mut(closure.step_index).ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure missing step evidence {}",
                    closure.step_index
                ))
            })?;
            step.admission_report_sha256 = closure.admission_report_sha256.clone();
            let source_record = source_records.get_mut(closure.step_index).ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime buyer closure missing source record {}",
                    closure.step_index
                ))
            })?;
            source_record.admission_report_sha256 = closure.admission_report_sha256.clone();
            principal_admission_report_sha256 = Some(closure.admission_report_sha256.clone());
            write_runtime_json_artifact(
                out_dir,
                "cross_boundary_admission_report",
                "cross-boundary-admission-report.json",
                &closure.admission_report,
                "Chiodos runtime buyer closure admission report JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "cross_kernel_continuation",
                "cross-kernel-continuation.json",
                &closure.continuation,
                "Chiodos runtime buyer closure continuation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_statement",
                "receipt-lineage-statement.json",
                &closure.lineage_statement,
                "Chiodos runtime buyer closure lineage statement JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_bundle",
                "receipt-lineage-bundle.json",
                &closure.lineage_bundle,
                "Chiodos runtime buyer closure lineage bundle JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_invocation",
                "bilateral-invocation.json",
                &closure.bilateral_invocation,
                "Chiodos runtime buyer closure bilateral invocation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse_envelope",
                "bilateral-dsse-envelope.json",
                &closure.bilateral_dsse,
                "Chiodos runtime buyer closure bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let proof_package_canonical_sha256 = canonical_sha256_json(
            &package_json_value,
            "Chiodos runtime proof package canonical hash",
        )?;
        proof_package_sha256 = Some(proof_package_canonical_sha256.clone());
        write_runtime_json_artifact_string(
            out_dir,
            "proof_package",
            "proof-package.json",
            &package_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        write_json_string(
            &out_dir.join("buyer-auditor-proof-package.json"),
            &format!("{package_json}\n"),
        )?;
        if let Some(closure) = buyer_closure.as_ref() {
            let workflow_sha256 = workflow_receipt_sha256.clone().ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime buyer packet missing workflow receipt hash".to_string(),
                )
            })?;
            let verifier_sha256 = verifier_report_sha256.clone().ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime buyer packet missing verifier report hash".to_string(),
                )
            })?;
            let packet = chio_chiodos_runtime::BuyerAttestationPacket {
                schema: chio_chiodos_runtime::CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA
                    .to_string(),
                packet_id: format!("buyer-packet:{}", scenario.run_id),
                buyer_id: closure.continuation.source_kernel_id.clone(),
                capability_id: closure.bilateral_invocation.capability_id.clone(),
                treaty_scope_sha256: closure.admission_report.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: closure
                    .admission_report
                    .ladder_intersection_sha256
                    .clone(),
                cross_boundary_admission_report_sha256: closure
                    .admission_report_sha256
                    .clone(),
                continuation_sha256: closure.bilateral_invocation.continuation_sha256.clone(),
                receipt_lineage_statement_sha256: closure.lineage_statement_sha256.clone(),
                bilateral_invocation_sha256: closure.bilateral_invocation_sha256.clone(),
                bilateral_dsse_sha256: closure.bilateral_dsse_sha256.clone(),
                workflow_receipt_sha256: workflow_sha256,
                proof_package_sha256: proof_package_canonical_sha256.clone(),
                verifier_report_sha256: verifier_sha256,
                budget_refs: vec![format!(
                    "budget.reserve:{}",
                    closure.bilateral_invocation.capability_id
                )],
                settlement_claimed: false,
            };
            write_runtime_json_artifact(
                out_dir,
                "buyer_attestation_packet",
                "buyer-attestation-packet.json",
                &packet,
                "Chiodos runtime buyer attestation packet JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let static_package = chiodos_three_vendor_example::fixture_proof_package().map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos static three-vendor proof package: {error}"
                ))
            },
        )?;
        let static_report = chiodos_three_vendor_example::fixture_verifier_report().map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos static three-vendor verifier report: {error}"
                ))
            },
        )?;
        let parity_trust_bundle_document =
            chiodos_three_vendor_example::verifier_trust_bundle_document_for_package(
                &parity_package,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime parity trust bundle build: {error}"
                ))
            })?;
        let parity_trust_bundle = chio_chiodos::ChiodosVerifierTrustBundle::from_document(
            parity_trust_bundle_document,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime parity trust bundle parse: {error}"
            ))
        })?;
        let parity_verifier_report =
            chio_chiodos::verify_package_report(&parity_package, &parity_trust_bundle, &context);
        let (compared_fields, mismatches) =
            runtime_proof_parity(&static_package, &parity_package).map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime proof parity: {error}"))
            })?;
        let parity_accepted = mismatches.is_empty() && parity_verifier_report.accepted;
        parity_report = Some(chio_chiodos_runtime::RuntimeProofParityReport {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
            run_id: scenario.run_id.clone(),
            accepted: parity_accepted,
            failure_code: if parity_accepted {
                None
            } else {
                Some("runtime_proof_semantic_parity_mismatch".to_string())
            },
            generated_at_unix_ms: now_unix_ms,
            static_proof_package_sha256: chio_chiodos::package_sha256(&static_package).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos static proof package hash: {error}"
                    ))
                },
            )?,
            runtime_proof_package_sha256: chio_chiodos::package_sha256(&parity_package).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime parity proof package hash: {error}"
                    ))
                },
            )?,
            static_verifier_report_sha256: canonical_sha256_json(
                &static_report,
                "Chiodos static verifier report canonical hash",
            )?,
            runtime_verifier_report_sha256: canonical_sha256_json(
                &parity_verifier_report,
                "Chiodos runtime parity verifier report hash",
            )?,
            compared_fields,
            mismatches,
        });

        if verifier_report.accepted && parity_report.as_ref().is_some_and(|report| report.accepted)
        {
            proof_checks.push("runtime_semantic_proof_regeneration.verified".to_string());
        } else {
            accepted = false;
            failure_code = if verifier_report.accepted {
                Some("runtime_proof_semantic_parity_mismatch".to_string())
            } else {
                verifier_report
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.clone())
                    .or_else(|| Some("runtime_proof_semantic_verifier_rejected".to_string()))
            };
        }
    } else {
        proof_checks.push("runtime_admission.denied".to_string());
    }

    let proof_regeneration_report =
        chio_chiodos_runtime::RuntimeProofRegenerationReport {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA
                .to_string(),
            run_id: scenario.run_id.clone(),
            accepted,
            failure_code: if accepted { None } else { failure_code.clone() },
            generated_at_unix_ms: now_unix_ms,
            proof_package_sha256,
            verifier_report_sha256,
            workflow_receipt_sha256,
            source_records: source_records.clone(),
            checks: proof_checks,
        };
    let proof_regeneration_json =
        chio_chiodos_runtime::runtime_proof_regeneration_report_json(
            &proof_regeneration_report,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime proof regeneration report: {error}"
            ))
        })?;
    write_runtime_json_artifact_string(
        out_dir,
        "proof_regeneration_report",
        "proof-regeneration-report.json",
        &proof_regeneration_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let proof_regeneration_report_sha256 = canonical_sha256_json(
        &proof_regeneration_report,
        "Chiodos runtime proof regeneration report canonical hash",
    )?;
    if let Some(parity_report) = parity_report.as_ref() {
        let parity_json = chio_chiodos_runtime::runtime_proof_parity_report_json(parity_report)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime proof parity report: {error}"
                ))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_parity_report",
            "runtime-proof-parity-report.json",
            &parity_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    let runtime_admission_report_sha256 = principal_admission_report_sha256
        .clone()
        .unwrap_or_else(|| chio_core::sha256_hex(admission_hashes.join(":").as_bytes()));
    let workflow_report = chio_chiodos_runtime::RuntimeWorkflowRunReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: scenario.run_id.clone(),
        accepted,
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        admission_report_sha256: runtime_admission_report_sha256.clone(),
        evidence_paths: evidence_paths.clone(),
        step_evidence,
        proof_regeneration_report_sha256: Some(proof_regeneration_report_sha256.clone()),
    };
    let workflow_report_json =
        chio_chiodos_runtime::runtime_workflow_run_report_json(&workflow_report).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime workflow run report: {error}"
                ))
            },
        )?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_run_report",
        "runtime-run-report.json",
        &workflow_report_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    write_json_string(
        &out_dir.join("workflow-run-report.json"),
        &format!("{workflow_report_json}\n"),
    )?;
    let workflow_run_report_sha256 = canonical_sha256_json(
        &workflow_report,
        "Chiodos runtime workflow run report canonical hash",
    )?;
    let manifest = chio_chiodos_runtime::RuntimeEvidenceManifest {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: scenario.run_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        workflow_run_report_sha256: workflow_run_report_sha256.clone(),
        proof_regeneration_report_sha256: proof_regeneration_report_sha256.clone(),
        entries: evidence_manifest_entries.clone(),
    };
    let manifest_json = chio_chiodos_runtime::runtime_evidence_manifest_json(&manifest).map_err(
        |error| {
            CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
        },
    )?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_evidence_manifest",
        "runtime-evidence-manifest.json",
        &manifest_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let evidence_manifest_sha256 = canonical_sha256_json(
        &manifest,
        "Chiodos runtime evidence manifest canonical hash",
    )?;
    if accepted {
        let regeneration_input = chio_chiodos_runtime::RuntimeProofRegenerationInput {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA
                .to_string(),
            run_id: scenario.run_id,
            evidence_manifest_sha256,
            workflow_run_report_sha256,
            admission_report_sha256: runtime_admission_report_sha256,
            trust_bundle_sha256: trust_bundle_sha256.ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime proof input missing trust bundle hash".to_string(),
                )
            })?,
            verification_context_sha256: verification_context_sha256.ok_or_else(|| {
                CliError::cli_other_error(
                    "Chiodos runtime proof input missing context hash".to_string(),
                )
            })?,
            source_records,
        };
        let input_json =
            chio_chiodos_runtime::runtime_proof_regeneration_input_json(&regeneration_input)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime proof regeneration input: {error}"
                    ))
                })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_regeneration_input",
            "runtime-proof-regeneration-input.json",
            &input_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    if workflow_report.accepted {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "Chiodos runtime loopback rejected request: {}",
            workflow_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_loopback_failure")
        )))
    }
}

fn write_runtime_json_artifact<T: serde::Serialize>(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    value: &T,
    label: &str,
    entries: &mut Vec<chio_chiodos_runtime::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, CliError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    write_runtime_json_artifact_string(out_dir, role, relative_path, &json, entries, evidence_paths)
}

fn write_runtime_json_artifact_string(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    json: &str,
    entries: &mut Vec<chio_chiodos_runtime::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, CliError> {
    validate_runtime_relative_path(relative_path)?;
    let json_with_newline = format!("{json}\n");
    let sha256 = chio_core::sha256_hex(json_with_newline.as_bytes());
    let byte_count = u64::try_from(json_with_newline.len()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime artifact byte count: {error}"))
    })?;
    write_json_string(&out_dir.join(relative_path), &json_with_newline)?;
    entries.push(chio_chiodos_runtime::RuntimeEvidenceManifestEntry {
        role: role.to_string(),
        path: relative_path.to_string(),
        sha256: sha256.clone(),
        byte_count,
    });
    if !evidence_paths.iter().any(|path| path == relative_path) {
        evidence_paths.push(relative_path.to_string());
    }
    Ok(sha256)
}

fn validate_runtime_relative_path(relative_path: &str) -> Result<(), CliError> {
    if relative_path.trim() != relative_path
        || relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime artifact path {relative_path:?} is not safe relative evidence"
        )));
    }
    Ok(())
}

fn canonical_sha256_json<T: serde::Serialize>(value: &T, label: &str) -> Result<String, CliError> {
    let bytes = chio_core_types::canonical::canonical_json_bytes(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

fn runtime_proof_parity(
    static_package: &chio_chiodos::ChiodosProofPackage,
    runtime_package: &chio_chiodos::ChiodosProofPackage,
) -> Result<
    (
        Vec<String>,
        Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
    ),
    CliError,
> {
    let compared_fields = vec![
        "proof_claims".to_string(),
        "workflow_id".to_string(),
        "workflow_step_count".to_string(),
        "workflow_step_semantics".to_string(),
        "workflow_intersection_id".to_string(),
        "workflow_step_class_bindings".to_string(),
        "workflow_required_vendor_signers".to_string(),
        "tool_receipt_targets".to_string(),
        "tool_receipt_semantics".to_string(),
        "bilateral_dsse_predicate_semantics".to_string(),
        "lease_scope_semantics".to_string(),
        "governance_authorization_presence".to_string(),
        "destructive_step_flags".to_string(),
    ];
    let mut mismatches = Vec::new();
    compare_runtime_proof_field(
        "proof_claims",
        &static_package.claims,
        &runtime_package.claims,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_id",
        &static_package.workflow_id,
        &runtime_package.workflow_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_count",
        &static_package.workflow_receipt.steps.len(),
        &runtime_package.workflow_receipt.steps.len(),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_semantics",
        &workflow_step_semantics(static_package),
        &workflow_step_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_intersection_id",
        &static_package.workflow_intersection.intersection_id,
        &runtime_package.workflow_intersection.intersection_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_class_bindings",
        &static_package.workflow_intersection.step_class_bindings,
        &runtime_package.workflow_intersection.step_class_bindings,
        &mut mismatches,
    )?;
    let static_signers: Vec<&str> = static_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    let runtime_signers: Vec<&str> = runtime_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    compare_runtime_proof_field(
        "workflow_required_vendor_signers",
        &static_signers,
        &runtime_signers,
        &mut mismatches,
    )?;
    let static_receipt_targets: Vec<(&str, &str, &str)> = static_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    let runtime_receipt_targets: Vec<(&str, &str, &str)> = runtime_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    compare_runtime_proof_field(
        "tool_receipt_targets",
        &static_receipt_targets,
        &runtime_receipt_targets,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "tool_receipt_semantics",
        &tool_receipt_semantics(static_package),
        &tool_receipt_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "bilateral_dsse_predicate_semantics",
        &bilateral_dsse_predicate_semantics(static_package)?,
        &bilateral_dsse_predicate_semantics(runtime_package)?,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "lease_scope_semantics",
        &lease_scope_semantics(static_package),
        &lease_scope_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "governance_authorization_presence",
        &governance_authorization_presence(static_package),
        &governance_authorization_presence(runtime_package),
        &mut mismatches,
    )?;
    let static_destructive: Vec<Option<bool>> = static_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    let runtime_destructive: Vec<Option<bool>> = runtime_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    compare_runtime_proof_field(
        "destructive_step_flags",
        &static_destructive,
        &runtime_destructive,
        &mut mismatches,
    )?;
    Ok((compared_fields, mismatches))
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WorkflowStepParityBinding {
    step_index: usize,
    server_id: String,
    tool_name: String,
    allowed: bool,
    has_tool_receipt: bool,
    has_output_hash: bool,
    has_bilateral_dsse: bool,
    has_governance_receipt: bool,
    has_parent_receipt: bool,
    has_consistency_anchor: bool,
    destructive: Option<bool>,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ToolReceiptParityBinding {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    action_parameter_hash: String,
    decision_allowed: bool,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct BilateralDssePredicateParityBinding {
    predicate_type: String,
    tool_server_a: String,
    tool_server_b: String,
    tool_name: String,
    co_sign: String,
    consistency_model: String,
    tool_args_hash: Option<String>,
    has_capability_lease_ref: bool,
    has_capability_lease_scope_digest: bool,
    has_governance_receipt_ref: bool,
    has_consistency_anchor: bool,
    has_treaty_binding: bool,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LeaseScopeParityBinding {
    workflow_id: String,
    workflow_grant_id: String,
    step_index: usize,
    tool_name: String,
    peer_kernel_id: String,
    action_class_id: String,
    subject: String,
    action_class: String,
    tool_args_hash: String,
    destructive: bool,
}

fn workflow_step_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<WorkflowStepParityBinding> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| WorkflowStepParityBinding {
            step_index: step.step_index,
            server_id: step.server_id.clone(),
            tool_name: step.tool_name.clone(),
            allowed: step.allowed,
            has_tool_receipt: step.tool_receipt_id.is_some(),
            has_output_hash: step.output_hash.is_some(),
            has_bilateral_dsse: step.bilateral_dsse_sha256.is_some(),
            has_governance_receipt: step.governance_receipt_id.is_some(),
            has_parent_receipt: step.parent_receipt_sha256.is_some(),
            has_consistency_anchor: step.consistency_anchor.is_some(),
            destructive: step.destructive,
        })
        .collect()
}

fn tool_receipt_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<ToolReceiptParityBinding> {
    package
        .tool_receipts
        .iter()
        .map(|receipt| ToolReceiptParityBinding {
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            action_parameter_hash: receipt.action.parameter_hash.clone(),
            decision_allowed: matches!(&receipt.decision, chio_core::receipt::Decision::Allow),
        })
        .collect()
}

fn bilateral_dsse_predicate_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Result<Vec<BilateralDssePredicateParityBinding>, CliError> {
    package
        .bilateral_envelopes
        .iter()
        .map(|envelope| {
            let (statement, _) = envelope.decode_statement().map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime parity DSSE statement decode: {error}"
                ))
            })?;
            let predicate = statement.predicate;
            Ok(BilateralDssePredicateParityBinding {
                predicate_type: statement.predicate_type,
                tool_server_a: predicate.tool_server_a.kernel_id,
                tool_server_b: predicate.tool_server_b.kernel_id,
                tool_name: predicate.tool_name,
                co_sign: predicate.co_sign,
                consistency_model: predicate.consistency_model,
                tool_args_hash: predicate.tool_args_hash.map(|hash| hash.value),
                has_capability_lease_ref: predicate.capability_lease_ref.is_some(),
                has_capability_lease_scope_digest: predicate
                    .capability_lease_ref
                    .is_some_and(|lease| lease.scope_digest.is_some()),
                has_governance_receipt_ref: predicate.governance_receipt_ref.is_some(),
                has_consistency_anchor: predicate.consistency_anchor.is_some(),
                has_treaty_binding: predicate.treaty_binding_ref.is_some(),
            })
        })
        .collect()
}

fn lease_scope_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<LeaseScopeParityBinding> {
    package
        .lease_scope_bindings
        .iter()
        .map(|binding| LeaseScopeParityBinding {
            workflow_id: binding.workflow_id.clone(),
            workflow_grant_id: binding.workflow_grant_id.clone(),
            step_index: binding.step_index,
            tool_name: binding.tool_name.clone(),
            peer_kernel_id: binding.peer_kernel_id.clone(),
            action_class_id: binding.action_class_id.clone(),
            subject: binding.subject.clone(),
            action_class: format!("{:?}", binding.action_class),
            tool_args_hash: binding.tool_args_hash.clone(),
            destructive: binding.destructive,
        })
        .collect()
}

fn governance_authorization_presence(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<bool> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.governance_receipt_id.is_some())
        .collect()
}

fn compare_runtime_proof_field<T: serde::Serialize + PartialEq>(
    field: &str,
    static_value: &T,
    runtime_value: &T,
    mismatches: &mut Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
) -> Result<(), CliError> {
    if static_value != runtime_value {
        mismatches.push(chio_chiodos_runtime::RuntimeProofParityMismatch {
            field: field.to_string(),
            static_value_sha256: canonical_sha256_json(
                static_value,
                "Chiodos runtime static parity field hash",
            )?,
            runtime_value_sha256: canonical_sha256_json(
                runtime_value,
                "Chiodos runtime regenerated parity field hash",
            )?,
        });
    }
    Ok(())
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

fn cmd_chiodos_pheromone_relay_alert_normalize(
    profile: &Path,
    input_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile: chio_pheromone_relay::RelayAlertNormalizationProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            profile,
            "Chiodos relay alert normalization profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization profile: {error}"
            ))
        })?;
    let sources = read_relay_alert_normalization_sources(input_dir)?;
    let normalization =
        chio_pheromone_relay::normalize_relay_alert_delivery_evidence(
            chio_pheromone_relay::RelayAlertNormalizationInput {
                profile: &profile,
                sources: &sources,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos relay alert normalize: {error}"))
        })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos relay alert normalized evidence dir {}: {error}",
            out_dir.display()
        ))
    })?;
    for (index, evidence) in normalization.evidence.iter().enumerate() {
        let path = out_dir.join(format!("relay-alert-delivery-evidence-{index:03}.json"));
        write_pretty_json(&path, evidence, "Chiodos relay alert delivery evidence")?;
    }
    write_pretty_json(
        report,
        &normalization,
        "Chiodos relay alert normalization report",
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

fn cmd_chiodos_pheromone_relay_alert_delivery_drift_window(
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
    let drift_report = chio_pheromone_relay::generate_relay_alert_delivery_drift_report_v2(
        chio_pheromone_relay::RelayAlertDeliveryDriftInputV2 {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery drift-window: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chiodos relay alert delivery drift report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_review(
    handoff_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    route_owner_profile: &Path,
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
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        serde_json::from_str(&read_utf8_json_file(
            drift_report,
            "Chiodos relay alert delivery drift report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery drift report: {error}"
            ))
        })?;
    let route_owner_profile: chio_pheromone_relay::RelayAlertRouteOwnerProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            route_owner_profile,
            "Chiodos relay alert route-owner profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert route-owner profile: {error}"
            ))
        })?;
    let review_packet = chio_pheromone_relay::generate_relay_alert_route_review_packet(
        chio_pheromone_relay::RelayAlertRouteReviewInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            route_owner_profile: &route_owner_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert review: {error}")))?;
    write_pretty_json(
        report,
        &review_packet,
        "Chiodos relay alert route review packet",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_package(
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
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
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        serde_json::from_str(&read_utf8_json_file(
            normalization_report,
            "Chiodos relay alert normalization report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization report: {error}"
            ))
        })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        serde_json::from_str(&read_utf8_json_file(
            drift_report,
            "Chiodos relay alert delivery drift report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery drift report: {error}"
            ))
        })?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket = serde_json::from_str(
        &read_utf8_json_file(review_packet, "Chiodos relay alert route review packet")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert route review packet: {error}"))
    })?;
    let package = chio_pheromone_relay::generate_relay_alert_assurance_package(
        chio_pheromone_relay::RelayAlertAssuranceInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance package: {error}"))
    })?;
    write_pretty_json(
        report,
        &package,
        "Chiodos relay alert assurance package",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_export(
    package: &Path,
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
    retention_profile: &Path,
    signing_key: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let assurance_package: chio_pheromone_relay::RelayAlertAssurancePackage =
        read_json_file(package, "Chiodos relay alert assurance package")?;
    let alert_report: chio_pheromone_relay::RelayAlertReport =
        read_json_file(alert_report, "Chiodos relay alert report")?;
    let trend_report: chio_pheromone_relay::RelayTrendReport =
        read_json_file(trend_report, "Chiodos relay trend report")?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport =
        read_json_file(handoff_report, "Chiodos relay alert handoff report")?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        read_json_file(normalization_report, "Chiodos relay alert normalization report")?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport =
        read_json_file(delivery_report, "Chiodos relay alert delivery report")?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        read_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        read_json_file(drift_report, "Chiodos relay alert delivery drift report")?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket =
        read_json_file(review_packet, "Chiodos relay alert route review packet")?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let (exporter_id, signing_key) = load_relay_signing_key(signing_key)?;
    let bundle = chio_pheromone_relay::sign_relay_alert_assurance_export_bundle(
        chio_pheromone_relay::RelayAlertAssuranceExportBuildInput {
            bundle_id: "relay-alert-assurance-export",
            exporter_id: &exporter_id,
            exporter_key_id: "default",
            signing_key: &signing_key,
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            assurance_package: &assurance_package,
            normalized_delivery_evidence: &normalization_report.evidence,
            retention_profile: &retention_profile,
            exported_at_unix_ms: now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance export: {error}"))
    })?;
    write_relay_alert_assurance_bundle(out_dir, &bundle)?;
    write_pretty_json(report, &bundle.report, "Chiodos relay alert assurance export report")
}

fn cmd_chiodos_pheromone_relay_alert_assurance_verify(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let verify_report = chio_pheromone_relay::verify_relay_alert_assurance_export_bundle(
        &bundle,
        &trusted_exporters,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance verify: {error}"))
    })?;
    write_pretty_json(
        report,
        &verify_report,
        "Chiodos relay alert assurance export report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_replay(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let replay_report = chio_pheromone_relay::generate_relay_alert_assurance_replay_report(
        chio_pheromone_relay::RelayAlertAssuranceReplayInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance replay: {error}"))
    })?;
    write_pretty_json(
        report,
        &replay_report,
        "Chiodos relay alert assurance replay report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_retention_plan(
    bundle_root: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_bundle_root(bundle_root)?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let retention_report = chio_pheromone_relay::generate_relay_alert_assurance_retention_report(
        chio_pheromone_relay::RelayAlertAssuranceRetentionInput {
            bundles: &bundles,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance retention plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &retention_report,
        "Chiodos relay alert assurance retention report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_recovery_drill(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    case_id: &str,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let drill_report = chio_pheromone_relay::generate_relay_alert_assurance_recovery_drill_report(
        chio_pheromone_relay::RelayAlertAssuranceRecoveryDrillInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            case_id,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance recovery drill: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &drill_report,
        "Chiodos relay alert assurance recovery drill report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_archive_plan(
    bundle_root: &Path,
    trusted_exporters: &Path,
    archive_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let archive_profile: chio_pheromone_relay::RelayAlertAssuranceArchiveProfileDocument =
        read_json_file(
            archive_profile,
            "Chiodos relay alert assurance archive profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let archive_report = chio_pheromone_relay::generate_relay_alert_assurance_archive_report(
        chio_pheromone_relay::RelayAlertAssuranceArchiveInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            archive_profile: &archive_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance archive plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &archive_report,
        "Chiodos relay alert assurance archive report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_closeout_review(
    bundle_root: &Path,
    trusted_exporters: &Path,
    closeout_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let closeout_profile: chio_pheromone_relay::RelayAlertAssuranceCloseoutProfileDocument =
        read_json_file(
            closeout_profile,
            "Chiodos relay alert assurance closeout profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let closeout_report = chio_pheromone_relay::generate_relay_alert_assurance_closeout_report(
        chio_pheromone_relay::RelayAlertAssuranceCloseoutInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            closeout_profile: &closeout_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance closeout review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &closeout_report,
        "Chiodos relay alert assurance closeout report",
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

fn read_relay_alert_normalization_sources(
    dir: &Path,
) -> Result<Vec<serde_json::Value>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert normalization input dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert normalization input dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut sources = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert normalization input")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization input {}: {error}",
                path.display()
            ))
        })?;
        sources.push(value);
    }
    Ok(sources)
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

fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, CliError> {
    serde_json::from_str(&read_utf8_json_file(path, label)?)
        .map_err(|error| CliError::cli_other_error(format!("{label} {}: {error}", path.display())))
}

fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    ensure_clean_output_dir(out_dir)?;
    write_pretty_json(
        &out_dir.join("manifest.json"),
        &bundle.manifest,
        "Chiodos relay alert assurance export manifest",
    )?;
    write_pretty_json(
        &out_dir.join("relay-alert-assurance-export-report.json"),
        &bundle.report,
        "Chiodos relay alert assurance export report",
    )?;
    for file in &bundle.files {
        let path = safe_bundle_path(out_dir, &file.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chiodos relay alert assurance export dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &file.bytes).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write Chiodos relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn read_relay_alert_assurance_bundle(
    bundle_dir: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    let manifest: chio_pheromone_relay::RelayAlertAssuranceExportManifest = read_json_file(
        &bundle_dir.join("manifest.json"),
        "Chiodos relay alert assurance export manifest",
    )?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport = read_json_file(
        &bundle_dir.join("relay-alert-assurance-export-report.json"),
        "Chiodos relay alert assurance export report",
    )?;
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = safe_bundle_path(bundle_dir, &artifact.path)?;
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
        files.push(chio_pheromone_relay::RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes,
        });
    }
    Ok(chio_pheromone_relay::RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

fn read_relay_alert_assurance_bundle_root(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceExportBundle>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_bundle(bundle_root)?]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut bundles = Vec::new();
    for dir in dirs {
        bundles.push(read_relay_alert_assurance_bundle(&dir)?);
    }
    if bundles.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(bundles)
}

fn read_relay_alert_assurance_archive_candidates(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_archive_candidate(
            bundle_root,
        )]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut candidates = Vec::new();
    for dir in dirs {
        candidates.push(read_relay_alert_assurance_archive_candidate(&dir));
    }
    if candidates.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(candidates)
}

fn read_relay_alert_assurance_archive_candidate(
    bundle_dir: &Path,
) -> chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
    let bundle_path = relay_alert_assurance_bundle_label(bundle_dir);
    match read_relay_alert_assurance_bundle(bundle_dir) {
        Ok(bundle) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: Some(bundle),
            error_code: None,
            error_detail: None,
        },
        Err(error) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: None,
            error_code: Some("bundle_read_failed".to_string()),
            error_detail: Some(error.to_string()),
        },
    }
}

fn relay_alert_assurance_bundle_label(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("export-bundle")
        .to_string()
}

fn ensure_clean_output_dir(out_dir: &Path) -> Result<(), CliError> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries.next().transpose().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?.is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chiodos output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn safe_bundle_path(root: &Path, relative: &str) -> Result<PathBuf, CliError> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || Path::new(relative).is_absolute()
    {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance export path {relative} is not relative"
        )));
    }
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "Chiodos relay alert assurance export path {relative} is unsafe"
            )));
        }
        path.push(segment);
    }
    Ok(path)
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
