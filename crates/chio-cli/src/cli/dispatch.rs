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

    let command = cli.command;
    let result = match command {
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
                tenant,
                admin_all,
                policy_file,
                federation_policy,
                require_proofs,
            } => evidence_export::cmd_evidence_export(
                &output,
                capability.as_deref(),
                agent_subject.as_deref(),
                since,
                until,
                tenant.as_deref(),
                admin_all,
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
                    tenant,
                    admin_all,
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
                        tenant: tenant.as_deref(),
                        admin_all,
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
                } => {
                    passport::cmd_passport_challenge_create(passport::PassportChallengeCreateArgs {
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
                    })
                }
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
            GuardCommands::Test {
                wasm,
                fixtures,
                fuel_limit,
            } => guard::cmd_guard_test(&wasm, &fixtures, fuel_limit),
            GuardCommands::Bench {
                path,
                iterations,
                fuel_limit,
            } => guard::cmd_guard_bench(&path, iterations, fuel_limit),
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
            GuardCommands::Install { path, target_dir } => {
                guard::cmd_guard_install(&path, &target_dir)
            }
            GuardCommands::Sign {
                wasm,
                key,
                name,
                version,
            } => guards::sign::cmd_guard_sign(&wasm, &key, &name, &version),
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
            } => cmd_conformance_fetch_peers(check, &out, language.as_deref(), lockfile.as_deref()),
        },
        Commands::Federation { command } => dispatch_chio_federation_command(command),
        Commands::Attest { command } => dispatch_chio_attest_command(command),
        Commands::Runtime { command } => dispatch_chio_runtime_command(command),
        Commands::Pheromone { command } => dispatch_chio_pheromone_command(command),
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
        serde_json::to_writer(&mut *writer, &report).map_err(std::io::Error::other)?;
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

fn dispatch_chio_federation_command(command: ChioFederationCommands) -> Result<(), CliError> {
    match command {
        ChioFederationCommands::Authority { command } => dispatch_chio_authority_command(command),
        ChioFederationCommands::Treaty { command } => dispatch_chio_treaty_command(command),
    }
}

fn dispatch_chio_authority_command(command: ChioAuthorityCommands) -> Result<(), CliError> {
    match command {
        ChioAuthorityCommands::Issue {
            profile,
            request,
            signing_keys,
            out_dir,
        } => cmd_chio_federation_authority_issue(&profile, &request, &signing_keys, &out_dir),
        ChioAuthorityCommands::Checkpoint {
            profile,
            revocations,
            signing_keys,
            out,
        } => cmd_chio_federation_authority_checkpoint(&profile, &revocations, &signing_keys, &out),
        ChioAuthorityCommands::TrustBundle { command } => match command {
            ChioTrustBundleCommands::Assemble {
                profile,
                peer_pins,
                workflow_intersection,
                disclosure_policy,
                checkpoint,
                out,
            } => cmd_chio_federation_authority_trust_bundle_assemble(
                &profile,
                &peer_pins,
                &workflow_intersection,
                &disclosure_policy,
                &checkpoint,
                &out,
            ),
        },
    }
}

fn dispatch_chio_treaty_command(command: ChioTreatyCommands) -> Result<(), CliError> {
    match command {
        ChioTreatyCommands::Intersect {
            treaty_scope,
            manifest,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_intersect(&treaty_scope, &manifest, now_unix_ms, &report),
        ChioTreatyCommands::Admit {
            treaty_scope,
            ladder_intersection,
            expected_ladder_intersection_sha256,
            action_class_id,
            evidence,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_admit(
            &treaty_scope,
            &ladder_intersection,
            &expected_ladder_intersection_sha256,
            &action_class_id,
            &evidence,
            now_unix_ms,
            &report,
        ),
        ChioTreatyCommands::VerifyPacket {
            packet,
            lineage_statement,
            continuation,
            admission_report,
            bilateral_invocation,
            report,
        } => cmd_chio_federation_treaty_verify_packet(
            &packet,
            &lineage_statement,
            &continuation,
            &admission_report,
            &bilateral_invocation,
            &report,
        ),
    }
}

fn dispatch_chio_attest_command(command: ChioAttestCommands) -> Result<(), CliError> {
    match command {
        ChioAttestCommands::Buyer { command } => dispatch_chio_buyer_command(command),
        ChioAttestCommands::SupplyChain { command } => match command {
            ChioSupplyChainCommands::Verify {
                artifact,
                bundle,
                issuer_san_regex,
                issuer_oidc,
                report,
            } => cmd_chio_attest_supply_chain_verify(
                &artifact,
                &bundle,
                &issuer_san_regex,
                &issuer_oidc,
                report.as_deref(),
            ),
        },
        ChioAttestCommands::RuntimeQuote { command } => match command {
            ChioRuntimeQuoteCommands::Verify {
                kernel_public_key,
                receipt_root,
                report_data,
                tee_kind,
                quote,
                collateral,
                report,
            } => cmd_chio_attest_runtime_quote_verify(
                &kernel_public_key,
                &receipt_root,
                report_data.as_deref(),
                tee_kind.as_deref(),
                quote.as_deref(),
                collateral.as_deref(),
                report.as_deref(),
            ),
        },
    }
}

fn dispatch_chio_buyer_command(command: ChioBuyerCommands) -> Result<(), CliError> {
    match command {
        ChioBuyerCommands::Packet { run_output, out } => {
            cmd_chio_attest_buyer_package(&run_output, &out)
        }
        ChioBuyerCommands::Verify {
            package,
            trust_bundle,
            context,
            report,
        } => cmd_chio_attest_buyer_verify(&package, &trust_bundle, &context, &report),
        ChioBuyerCommands::VerifyProof {
            package,
            trust_bundle,
            context,
            report,
        } => cmd_chio_attest_buyer_verify_proof(&package, &trust_bundle, &context, &report),
        ChioBuyerCommands::VerifyPacket {
            packet,
            lineage_statement,
            continuation,
            admission_report,
            bilateral_invocation,
            report,
        } => cmd_chio_attest_buyer_verify_packet(
            &packet,
            &lineage_statement,
            &continuation,
            &admission_report,
            &bilateral_invocation,
            &report,
        ),
        ChioBuyerCommands::Explain {
            report,
            format,
            out,
        } => cmd_chio_attest_buyer_explain(&report, &format, &out),
    }
}

fn dispatch_chio_runtime_command(command: ChioRuntimeCommands) -> Result<(), CliError> {
    match command {
        ChioRuntimeCommands::Admit {
            request,
            admission_profile,
            admission_bundle,
            runtime_trust_input,
            trusted_verifiers,
            pheromone_query_report,
            runtime_pheromone_policy,
            runtime_peer_weights,
            action_class_id,
            trust_floor_state,
            store,
            now_unix_ms,
            report,
        } => cmd_chio_runtime_admit(
            &request,
            &admission_profile,
            &admission_bundle,
            runtime_trust_input.as_deref(),
            trusted_verifiers.as_deref(),
            pheromone_query_report.as_deref(),
            runtime_pheromone_policy.as_deref(),
            runtime_peer_weights.as_deref(),
            action_class_id.as_deref(),
            trust_floor_state.as_deref(),
            &store,
            now_unix_ms,
            &report,
        ),
        ChioRuntimeCommands::SignTrustInput {
            body,
            signing_seed_file,
            out,
        } => cmd_chio_runtime_sign_trust_input(&body, &signing_seed_file, &out),
        ChioRuntimeCommands::Policy { command } => match command {
            ChioRuntimePolicyCommands::Sign {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_policy(&body, &signing_seed_file, &out),
        },
        ChioRuntimeCommands::PeerWeights { command } => match command {
            ChioRuntimePeerWeightsCommands::Hash { body, out } => {
                cmd_chio_runtime_peer_weights_hash(&body, &out)
            }
            ChioRuntimePeerWeightsCommands::Sign {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_peer_weights(&body, &signing_seed_file, &out),
        },
        ChioRuntimeCommands::Pheromone { command } => match command {
            ChioRuntimePheromoneCommands::SignQueryReport {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_pheromone_query_report(&body, &signing_seed_file, &out),
            ChioRuntimePheromoneCommands::Evaluate {
                admission_bundle,
                runtime_trust_input,
                trusted_verifiers,
                pheromone_query_report,
                runtime_pheromone_policy,
                runtime_peer_weights,
                action_class_id,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_pheromone_evaluate(
                &admission_bundle,
                &runtime_trust_input,
                &trusted_verifiers,
                &pheromone_query_report,
                &runtime_pheromone_policy,
                &runtime_peer_weights,
                action_class_id.as_deref(),
                now_unix_ms,
                &report,
            ),
        },
        ChioRuntimeCommands::Orchestrate { command } => match command {
            ChioRuntimeOrchestrateCommands::Lint { profile, report } => {
                cmd_chio_runtime_orchestrate_lint(&profile, &report)
            }
            ChioRuntimeOrchestrateCommands::Plan {
                profile,
                run_contract,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_plan(
                &profile,
                &run_contract,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Run {
                profile,
                run_contract,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_run(
                &profile,
                &run_contract,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Resume {
                profile,
                resume_plan,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_resume(
                &profile,
                &resume_plan,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Status {
                profile,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_status(
                &profile,
                &store,
                &evidence_dir,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Drift {
                profile,
                runs_dir,
                since_unix_ms,
                until_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_drift(
                &profile,
                &runs_dir,
                since_unix_ms,
                until_unix_ms,
                &report,
            ),
        },
        ChioRuntimeCommands::Ops { command } => match command {
            ChioRuntimeOpsCommands::Supervise {
                supervisor_profile,
                store,
                evidence_root,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_status(
                &supervisor_profile,
                &store,
                &evidence_root,
                provider_bindings.as_deref(),
                Some(now_unix_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::Tick {
                supervisor_profile,
                store,
                evidence_root,
                owner_id,
                now_unix_ms,
                max_runs,
                report,
            } => cmd_chio_runtime_ops_tick(
                &supervisor_profile,
                &store,
                &evidence_root,
                &owner_id,
                now_unix_ms,
                max_runs,
                &report,
            ),
            ChioRuntimeOpsCommands::Status {
                supervisor_profile,
                store,
                evidence_root,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_status(
                &supervisor_profile,
                &store,
                &evidence_root,
                provider_bindings.as_deref(),
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOpsCommands::RecoveryDrill {
                supervisor_profile,
                run_id,
                store,
                evidence_root,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_recovery_drill(
                &supervisor_profile,
                &run_id,
                &store,
                &evidence_root,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOpsCommands::EvidenceHealth {
                supervisor_profile,
                run_id,
                store,
                evidence_root,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_evidence_health(
                &supervisor_profile,
                &run_id,
                &store,
                &evidence_root,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::ProviderHealth {
                supervisor_profile,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_provider_health(
                &supervisor_profile,
                &provider_bindings,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::Retention { command } => match command {
                ChioRuntimeOpsRetentionCommands::Plan {
                    retention_profile,
                    store,
                    evidence_root,
                    now_unix_ms,
                    report,
                } => cmd_chio_runtime_ops_retention_plan(
                    &retention_profile,
                    &store,
                    &evidence_root,
                    now_unix_ms,
                    &report,
                ),
            },
        },
        ChioRuntimeCommands::RunLoopback {
            scenario,
            store_dir,
            now_unix_ms,
            out_dir,
        } => cmd_chio_runtime_run_loopback(&scenario, &store_dir, now_unix_ms, &out_dir),
    }
}

fn dispatch_chio_pheromone_command(command: ChioPheromoneCommands) -> Result<(), CliError> {
    match command {
        ChioPheromoneCommands::Receive {
            batch,
            transit_policy,
            proof_package,
            trust_bundle,
            context,
            store,
            now_unix_ms,
            report,
        } => cmd_chio_pheromone_receive(
            &batch,
            &transit_policy,
            &proof_package,
            &trust_bundle,
            &context,
            &store,
            now_unix_ms,
            &report,
        ),
        ChioPheromoneCommands::Query {
            store,
            subject_class,
            namespace,
            reputation_epoch,
            peer_weights,
            now_unix_ms,
            report,
        } => cmd_chio_pheromone_query(
            &store,
            &subject_class,
            &namespace,
            reputation_epoch,
            &peer_weights,
            now_unix_ms,
            &report,
        ),
        ChioPheromoneCommands::Relay { command } => match command {
            ChioPheromoneRelayCommands::Lint {
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                report,
            } => cmd_chio_pheromone_relay_lint(
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                &report,
            ),
            ChioPheromoneRelayCommands::Serve {
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
            } => cmd_chio_pheromone_relay_serve(
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
            ChioPheromoneRelayCommands::Enqueue {
                store,
                batch,
                transit_policy,
                trust_bundle,
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                now_unix_ms,
                report,
            } => cmd_chio_pheromone_relay_enqueue(
                &store,
                &batch,
                &transit_policy,
                &trust_bundle,
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                now_unix_ms,
                &report,
            ),
            ChioPheromoneRelayCommands::Tick {
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
            } => cmd_chio_pheromone_relay_tick(
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
            ChioPheromoneRelayCommands::Catchup {
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
            } => cmd_chio_pheromone_relay_catchup(
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
            ChioPheromoneRelayCommands::Status { store, report } => {
                cmd_chio_pheromone_relay_status(&store, &report)
            }
            ChioPheromoneRelayCommands::Observe {
                store,
                peer_directory_state,
                profile,
                trusted_issuers,
                report_dir,
                limit,
                report,
            } => cmd_chio_pheromone_relay_observe(
                &store,
                &peer_directory_state,
                profile.into(),
                &trusted_issuers,
                &report_dir,
                limit,
                &report,
            ),
            ChioPheromoneRelayCommands::Metrics {
                store,
                format,
                output,
            } => cmd_chio_pheromone_relay_metrics(&store, format.into(), &output),
            ChioPheromoneRelayCommands::Alert { command } => match command {
                ChioPheromoneRelayAlertCommands::Evaluate {
                    observability_report,
                    event_dir,
                    routing_profile,
                    suppression_state,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_evaluate(
                    &observability_report,
                    &event_dir,
                    &routing_profile,
                    &suppression_state,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Handoff {
                    alert_report,
                    trend_report,
                    routing_profile,
                    handoff_profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_handoff(
                    &alert_report,
                    &trend_report,
                    &routing_profile,
                    &handoff_profile,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Normalize {
                    profile,
                    input_dir,
                    now_unix_ms,
                    out_dir,
                    report,
                } => cmd_chio_pheromone_relay_alert_normalize(
                    &profile,
                    &input_dir,
                    now_unix_ms,
                    &out_dir,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Delivery { command } => match command {
                    ChioPheromoneRelayAlertDeliveryCommands::Import {
                        handoff_report,
                        delivery_profile,
                        evidence_dir,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_import(
                        &handoff_report,
                        &delivery_profile,
                        &evidence_dir,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::Acknowledge {
                        handoff_report,
                        delivery_report,
                        delivery_profile,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_acknowledge(
                        &handoff_report,
                        &delivery_report,
                        &delivery_profile,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::Drift {
                        handoff_reports_dir,
                        delivery_reports_dir,
                        delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_drift(
                        &handoff_reports_dir,
                        &delivery_reports_dir,
                        &delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::DriftWindow {
                        handoff_reports_dir,
                        delivery_reports_dir,
                        delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_drift_window(
                        &handoff_reports_dir,
                        &delivery_reports_dir,
                        &delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                },
                ChioPheromoneRelayAlertCommands::Review {
                    handoff_report,
                    delivery_report,
                    acknowledgement_report,
                    drift_report,
                    route_owner_profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_review(
                    &handoff_report,
                    &delivery_report,
                    &acknowledgement_report,
                    &drift_report,
                    &route_owner_profile,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Assurance { command } => match command {
                    ChioPheromoneRelayAlertAssuranceCommands::Package {
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
                    } => cmd_chio_pheromone_relay_alert_assurance_package(
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
                    ChioPheromoneRelayAlertAssuranceCommands::Export {
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
                    } => cmd_chio_pheromone_relay_alert_assurance_export(
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
                    ChioPheromoneRelayAlertAssuranceCommands::Verify {
                        bundle_dir,
                        trusted_exporters,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_verify(
                        &bundle_dir,
                        &trusted_exporters,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Replay {
                        bundle_dir,
                        trusted_exporters,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_replay(
                        &bundle_dir,
                        &trusted_exporters,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Retention { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceRetentionCommands::Plan {
                                bundle_root,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_retention_plan(
                                &bundle_root,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                        }
                    }
                    ChioPheromoneRelayAlertAssuranceCommands::RecoveryDrill {
                        bundle_dir,
                        trusted_exporters,
                        case,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_recovery_drill(
                        &bundle_dir,
                        &trusted_exporters,
                        &case,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Archive { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceArchiveCommands::Plan {
                                bundle_root,
                                trusted_exporters,
                                archive_profile,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_archive_plan(
                                &bundle_root,
                                &trusted_exporters,
                                &archive_profile,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                        }
                    }
                    ChioPheromoneRelayAlertAssuranceCommands::Closeout { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceCloseoutCommands::Review {
                                bundle_root,
                                trusted_exporters,
                                closeout_profile,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_closeout_review(
                                &bundle_root,
                                &trusted_exporters,
                                &closeout_profile,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                        }
                    }
                },
            },
            ChioPheromoneRelayCommands::Trend {
                reports_dir,
                event_dir,
                routing_profile,
                since_unix_ms,
                until_unix_ms,
                report,
            } => cmd_chio_pheromone_relay_trend(
                &reports_dir,
                &event_dir,
                &routing_profile,
                since_unix_ms,
                until_unix_ms,
                &report,
            ),
            ChioPheromoneRelayCommands::Directory { command } => match command {
                ChioPheromoneRelayDirectoryCommands::Inspect { state, report } => {
                    cmd_chio_pheromone_relay_directory_inspect(&state, &report)
                }
                ChioPheromoneRelayDirectoryCommands::Promote {
                    state,
                    candidate,
                    trusted_issuers,
                    profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_directory_promote(
                    &state,
                    &candidate,
                    &trusted_issuers,
                    profile.into(),
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayDirectoryCommands::Reject {
                    state,
                    candidate,
                    reason,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_directory_reject(
                    &state,
                    &candidate,
                    &reason,
                    now_unix_ms,
                    &report,
                ),
            },
            ChioPheromoneRelayCommands::Supervisor { command } => match command {
                ChioPheromoneRelaySupervisorCommands::Lint { profile, report } => {
                    cmd_chio_pheromone_relay_supervisor_lint(&profile, &report)
                }
            },
        },
    }
}

fn cmd_chio_attest_supply_chain_verify(
    artifact: &Path,
    bundle: &Path,
    issuer_san_regex: &str,
    issuer_oidc: &str,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let artifact_bytes = fs::read(artifact)?;
    let bundle_json = fs::read(bundle)?;
    let expected =
        chio_attest_verify::ExpectedIdentity::doc_hidden_inline(issuer_san_regex, issuer_oidc);
    let verifier = chio_attest_verify::SigstoreVerifier::with_embedded_root()
        .map_err(|error| CliError::Other(format!("supply-chain verifier init: {error}")))?;
    let verified = chio_attest_verify::AttestVerifier::verify_bundle(
        &verifier,
        &artifact_bytes,
        &bundle_json,
        &expected,
    )
    .map_err(|error| CliError::Other(format!("supply-chain verify: {error}")))?;
    let signed_at_unix_seconds = verified
        .signed_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::Other(format!("supply-chain signing time: {error}")))?
        .as_secs();
    let report_json = serde_json::json!({
        "schema": "chio.attest.supply-chain.verify-report.v1",
        "accepted": true,
        "artifact": artifact,
        "bundle": bundle,
        "subjectDigestSha256": hex::encode(verified.subject_digest_sha256),
        "certificateIdentity": verified.certificate_identity,
        "certificateOidcIssuer": verified.certificate_oidc_issuer,
        "rekorLogIndex": verified.rekor_log_index,
        "rekorInclusionVerified": verified.rekor_inclusion_verified,
        "signedAtUnixSeconds": signed_at_unix_seconds
    });
    write_chio_attest_report(&report_json, report)
}

fn cmd_chio_attest_runtime_quote_verify(
    kernel_public_key: &str,
    receipt_root: &str,
    report_data: Option<&str>,
    tee_kind: Option<&str>,
    quote: Option<&Path>,
    collateral: Option<&Path>,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let kernel_public_key = chio_core::crypto::PublicKey::from_hex(kernel_public_key)?;
    let receipt_root = decode_fixed_hex::<32>(receipt_root, "receipt-root")?;
    let observed_report_data = report_data
        .map(|value| decode_fixed_hex::<64>(value, "report-data"))
        .transpose()?;
    let expected_report_data =
        chio_attest_verify::expect_report_data(&kernel_public_key, &receipt_root);

    let Some(quote) = quote else {
        let report_json = serde_json::json!({
            "schema": "chio.attest.runtime-quote.verification-report.v1",
            "accepted": false,
            "verificationKind": "reportDataBindingOnly",
            "verificationState": "unresolved",
            "failureCode": "quote_evidence_missing",
            "detail": "report-data binding alone is not runtime quote verification",
            "kernelPublicKey": kernel_public_key.to_hex(),
            "receiptRoot": hex::encode(receipt_root),
            "expectedReportData": hex::encode(expected_report_data),
            "observedReportData": observed_report_data.map(hex::encode)
        });
        write_chio_attest_report(&report_json, report)?;
        return Err(CliError::Other(
            "runtime-quote verification requires full quote evidence".to_string(),
        ));
    };
    let tee_kind = tee_kind.ok_or_else(|| {
        CliError::Other("runtime-quote verification requires --tee-kind".to_string())
    })?;
    let collateral = collateral.ok_or_else(|| {
        CliError::Other("runtime-quote verification requires --collateral".to_string())
    })?;

    match verify_runtime_quote_with_backend(tee_kind, quote, collateral, &kernel_public_key, &receipt_root) {
        Ok(verified) => {
            if let Some(provided_report_data) = observed_report_data {
                if provided_report_data != verified.report_data {
                    let report_json = serde_json::json!({
                        "schema": "chio.attest.runtime-quote.verification-report.v1",
                        "accepted": false,
                        "verificationKind": "teeQuote",
                        "verificationState": "rejected",
                        "failureCode": "provided_report_data_mismatch",
                        "teeKind": verified.tee_kind,
                        "kernelPublicKey": kernel_public_key.to_hex(),
                        "receiptRoot": hex::encode(receipt_root),
                        "expectedReportData": hex::encode(expected_report_data),
                        "verifiedReportData": hex::encode(verified.report_data),
                        "observedReportData": hex::encode(provided_report_data)
                    });
                    write_chio_attest_report(&report_json, report)?;
                    return Err(CliError::Other(
                        "runtime-quote provided report-data does not match verified quote".to_string(),
                    ));
                }
            }
            let report_json = serde_json::json!({
                "schema": "chio.attest.runtime-quote.verification-report.v1",
                "accepted": true,
                "verificationKind": "teeQuote",
                "verificationState": "verified",
                "teeKind": verified.tee_kind,
                "tcbStatus": verified.tcb_status,
                "signedAtUnixSeconds": verified.signed_at_unix_seconds,
                "kernelPublicKey": kernel_public_key.to_hex(),
                "receiptRoot": hex::encode(receipt_root),
                "expectedReportData": hex::encode(expected_report_data),
                "observedReportData": hex::encode(verified.report_data)
            });
            write_chio_attest_report(&report_json, report)
        }
        Err(error) => {
            let failure_code = if error.to_string().contains("tee-quotes feature") {
                "tee_quote_feature_disabled"
            } else {
                "quote_verification_failed"
            };
            let report_json = serde_json::json!({
                "schema": "chio.attest.runtime-quote.verification-report.v1",
                "accepted": false,
                "verificationKind": "teeQuote",
                "verificationState": "rejected",
                "failureCode": failure_code,
                "detail": error.to_string(),
                "teeKind": tee_kind,
                "kernelPublicKey": kernel_public_key.to_hex(),
                "receiptRoot": hex::encode(receipt_root),
                "expectedReportData": hex::encode(expected_report_data),
                "observedReportData": observed_report_data.map(hex::encode)
            });
            write_chio_attest_report(&report_json, report)?;
            Err(error)
        }
    }
}

struct RuntimeQuoteBackendReport {
    tee_kind: String,
    report_data: [u8; 64],
    tcb_status: String,
    signed_at_unix_seconds: u64,
}

#[cfg(feature = "tee-quotes")]
fn verify_runtime_quote_with_backend(
    tee_kind: &str,
    quote: &Path,
    collateral: &Path,
    kernel_public_key: &chio_core::crypto::PublicKey,
    receipt_root: &[u8; 32],
) -> Result<RuntimeQuoteBackendReport, CliError> {
    use chio_attest_verify::QuoteVerifier;

    let quote_bytes = fs::read(quote)?;
    let collateral_bytes = fs::read(collateral)?;
    let collateral: RuntimeQuoteCollateralDocument = serde_json::from_slice(&collateral_bytes)?;
    let verification_time = collateral
        .verification_time_unix_seconds
        .map(unix_seconds_to_system_time)
        .transpose()?;
    let context = chio_attest_verify::QuoteVerificationContext::new(kernel_public_key, receipt_root);
    let verified = match tee_kind {
        "intel-tdx" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let verifier = chio_attest_verify::tdx::TdxDcapVerifier::with_verification_time(
                chio_attest_verify::tdx::TdxCollateral::new(
                    decode_hex_required(
                        collateral.intel_root_ca_der_hex.as_deref(),
                        "intelRootCaDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.pck_certificate_chain_der_hex.as_deref(),
                        "pckCertificateChainDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.tcb_info_issuer_chain_der_hex.as_deref(),
                        "tcbInfoIssuerChainDerHex",
                    )?,
                    collateral_required_u32(
                        collateral.tcb_recovery_event_id,
                        "tcbRecoveryEventId",
                    )?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                collateral_required_u32(
                    collateral.min_tcb_recovery_event_id,
                    "minTcbRecoveryEventId",
                )?,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        "amd-sev-snp" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let expected_launch_digest = decode_fixed_hex::<48>(
                collateral_required_str(
                    collateral.expected_launch_digest_hex.as_deref(),
                    "expectedLaunchDigestHex",
                )?,
                "expectedLaunchDigestHex",
            )?;
            let verifier = chio_attest_verify::sev_snp::SevSnpVerifier::with_verification_time(
                chio_attest_verify::sev_snp::SevSnpCollateral::new(
                    decode_hex_required(
                        collateral.amd_kds_root_der_hex.as_deref(),
                        "amdKdsRootDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.vcek_chain_der_hex.as_deref(),
                        "vcekChainDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.vlek_chain_der_hex.as_deref(),
                        "vlekChainDerHex",
                    )?,
                    collateral_required_u32(
                        collateral.tcb_recovery_event_id,
                        "tcbRecoveryEventId",
                    )?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                collateral_required_u32(
                    collateral.min_tcb_recovery_event_id,
                    "minTcbRecoveryEventId",
                )?,
                expected_launch_digest,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        "aws-nitro" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let expected_pcr0 = decode_fixed_hex::<48>(
                collateral_required_str(collateral.expected_pcr0_hex.as_deref(), "expectedPcr0Hex")?,
                "expectedPcr0Hex",
            )?;
            let verifier = chio_attest_verify::nitro::NitroVerifier::with_verification_time(
                chio_attest_verify::nitro::NitroCollateral::new(
                    decode_hex_required(
                        collateral.aws_nitro_root_der_hex.as_deref(),
                        "awsNitroRootDerHex",
                    )?,
                    decode_hex_vec_required(collateral.chain_der_hex.as_deref(), "chainDerHex")?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                expected_pcr0,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        other => {
            return Err(CliError::Other(format!(
                "unsupported runtime quote tee kind {other}"
            )));
        }
    };

    Ok(RuntimeQuoteBackendReport {
        tee_kind: verified.tee_kind.to_string(),
        report_data: verified.report_data,
        tcb_status: verified.tcb_status.to_string(),
        signed_at_unix_seconds: verified
            .signed_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|error| {
                CliError::Other(format!("runtime quote signed_at precedes unix epoch: {error}"))
            })?
            .as_secs(),
    })
}

#[cfg(not(feature = "tee-quotes"))]
fn verify_runtime_quote_with_backend(
    _tee_kind: &str,
    _quote: &Path,
    _collateral: &Path,
    _kernel_public_key: &chio_core::crypto::PublicKey,
    _receipt_root: &[u8; 32],
) -> Result<RuntimeQuoteBackendReport, CliError> {
    Err(CliError::Other(
        "runtime-quote TEE backend verification requires the tee-quotes feature".to_string(),
    ))
}

#[cfg(feature = "tee-quotes")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeQuoteCollateralDocument {
    #[serde(rename = "schema")]
    _schema: Option<String>,
    tcb_status: String,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
    verification_time_unix_seconds: Option<u64>,
    intel_root_ca_der_hex: Option<String>,
    pck_certificate_chain_der_hex: Option<Vec<String>>,
    tcb_info_issuer_chain_der_hex: Option<Vec<String>>,
    tcb_recovery_event_id: Option<u32>,
    min_tcb_recovery_event_id: Option<u32>,
    amd_kds_root_der_hex: Option<String>,
    vcek_chain_der_hex: Option<Vec<String>>,
    vlek_chain_der_hex: Option<Vec<String>>,
    expected_launch_digest_hex: Option<String>,
    aws_nitro_root_der_hex: Option<String>,
    chain_der_hex: Option<Vec<String>>,
    expected_pcr0_hex: Option<String>,
}

#[cfg(feature = "tee-quotes")]
fn parse_quote_tcb_status(
    value: &str,
) -> Result<chio_attest_verify::QuoteTcbStatus, CliError> {
    match value {
        "up-to-date" | "up_to_date" => Ok(chio_attest_verify::QuoteTcbStatus::UpToDate),
        "configuration-needed" | "configuration_needed" => {
            Ok(chio_attest_verify::QuoteTcbStatus::ConfigurationNeeded)
        }
        "out-of-date" | "out_of_date" => Ok(chio_attest_verify::QuoteTcbStatus::OutOfDate),
        "revoked" => Ok(chio_attest_verify::QuoteTcbStatus::Revoked),
        "unrecognized" => Ok(chio_attest_verify::QuoteTcbStatus::Unrecognized),
        other => Err(CliError::Other(format!(
            "unsupported runtime quote tcbStatus {other}"
        ))),
    }
}

#[cfg(feature = "tee-quotes")]
fn unix_seconds_to_system_time(seconds: u64) -> Result<std::time::SystemTime, CliError> {
    std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or_else(|| CliError::Other("runtime quote timestamp overflow".to_string()))
}

#[cfg(feature = "tee-quotes")]
fn collateral_required_str<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, CliError> {
    value.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))
}

#[cfg(feature = "tee-quotes")]
fn collateral_required_u32(value: Option<u32>, name: &str) -> Result<u32, CliError> {
    value.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))
}

#[cfg(feature = "tee-quotes")]
fn decode_hex_required(value: Option<&str>, name: &str) -> Result<Vec<u8>, CliError> {
    let value = collateral_required_str(value, name)?;
    hex::decode(value).map_err(|error| {
        CliError::Other(format!("runtime quote collateral {name} is not hex: {error}"))
    })
}

#[cfg(feature = "tee-quotes")]
fn decode_hex_vec_required(values: Option<&[String]>, name: &str) -> Result<Vec<Vec<u8>>, CliError> {
    let values =
        values.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            hex::decode(value).map_err(|error| {
                CliError::Other(format!(
                    "runtime quote collateral {name}[{index}] is not hex: {error}"
                ))
            })
        })
        .collect()
}

fn decode_fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], CliError> {
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|error| CliError::Other(format!("{name}: expected {N} bytes of hex: {error}")))?;
    Ok(bytes)
}

fn write_chio_attest_report(
    report_json: &serde_json::Value,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(report_json)?;
    if let Some(report) = report {
        fs::write(report, &bytes)?;
        fs::OpenOptions::new()
            .append(true)
            .open(report)?
            .write_all(b"\n")?;
    } else {
        std::io::stdout().write_all(&bytes)?;
        std::io::stdout().write_all(b"\n")?;
    }
    Ok(())
}
