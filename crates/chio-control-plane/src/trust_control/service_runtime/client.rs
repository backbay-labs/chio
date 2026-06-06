use super::*;

pub fn build_client(
    control_url: &str,
    control_token: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        None,
        ControlClientAuthKind::Service,
    )
}

pub fn build_public_client(control_url: &str) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(control_url, "", None, ControlClientAuthKind::Public)
}

pub(crate) fn build_cluster_peer_client(
    control_url: &str,
    control_token: &str,
    node_id: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        Some(ClusterPeerClientAuth {
            node_id: Arc::<str>::from(normalize_cluster_url(node_id)?),
        }),
        ControlClientAuthKind::Service,
    )
}

#[derive(Clone, Copy)]
enum ControlClientAuthKind {
    Service,
    Public,
}

fn build_client_with_cluster_peer(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
    auth_kind: ControlClientAuthKind,
) -> Result<TrustControlClient, CliError> {
    if matches!(auth_kind, ControlClientAuthKind::Service) {
        validate_control_token(control_token)?;
    }
    let endpoints = control_url
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_control_endpoint)
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.is_empty() {
        return Err(CliError::cli_other_error(
            "control URL must not be empty".to_string(),
        ));
    }
    let http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}

fn validate_control_token(control_token: &str) -> Result<(), CliError> {
    validate_control_secret(control_token, "control token")
}

fn normalize_control_endpoint(endpoint: &str) -> Result<String, CliError> {
    let parsed = Url::parse(endpoint).map_err(|error| {
        CliError::cli_other_error(format!(
            "control URL `{endpoint}` must be a valid URL: {error}"
        ))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CliError::cli_other_error(format!(
                "control URL `{endpoint}` scheme `{scheme}` must be http or https"
            )));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain username or password material"
        )));
    }
    if parsed.query().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain a query string"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(CliError::cli_other_error(format!(
            "control URL `{endpoint}` must not contain a fragment"
        )));
    }
    Ok(endpoint.trim_end_matches('/').to_string())
}

pub(crate) fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn path_with_encoded_param(template: &str, param_name: &str, value: &str) -> String {
    template.replace(&format!("{{{param_name}}}"), &encode_path_segment(value))
}

impl TrustControlClient {
    pub fn authority_status(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.get_json(AUTHORITY_PATH)
    }

    pub fn rotate_authority(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.post_json::<Value, TrustAuthorityStatus>(AUTHORITY_PATH, &json!({}))
    }

    pub fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, CliError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    pub fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, CliError> {
        let response: IssueCapabilityResponse = self.post_json(
            ISSUE_CAPABILITY_PATH,
            &IssueCapabilityRequest {
                subject_public_key: subject.to_hex(),
                scope,
                ttl_seconds,
                runtime_attestation,
            },
        )?;
        Ok(response.capability)
    }

    pub fn federated_issue(
        &self,
        request: &FederatedIssueRequest,
    ) -> Result<FederatedIssueResponse, CliError> {
        self.post_json(FEDERATED_ISSUE_PATH, request)
    }

    pub fn list_enterprise_providers(&self) -> Result<EnterpriseProviderListResponse, CliError> {
        self.get_json(FEDERATION_PROVIDERS_PATH)
    }

    pub fn get_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn upsert_enterprise_provider(
        &self,
        provider_id: &str,
        record: &EnterpriseProviderRecord,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.put_json(
            &path_with_encoded_param(FEDERATION_PROVIDER_PATH, "provider_id", provider_id),
            record,
        )
    }

    pub fn delete_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn list_federation_policies(
        &self,
    ) -> Result<FederationAdmissionPolicyListResponse, CliError> {
        self.get_json(FEDERATION_POLICIES_PATH)
    }

    pub fn get_federation_policy(
        &self,
        policy_id: &str,
    ) -> Result<FederationAdmissionPolicyRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            FEDERATION_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn upsert_federation_policy(
        &self,
        policy_id: &str,
        record: &FederationAdmissionPolicyRecord,
    ) -> Result<FederationAdmissionPolicyRecord, CliError> {
        self.put_json(
            &path_with_encoded_param(FEDERATION_POLICY_PATH, "policy_id", policy_id),
            record,
        )
    }

    pub fn delete_federation_policy(
        &self,
        policy_id: &str,
    ) -> Result<FederationAdmissionPolicyDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            FEDERATION_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn evaluate_federation_policy(
        &self,
        request: &FederationAdmissionEvaluationRequest,
    ) -> Result<FederationAdmissionEvaluationResponse, CliError> {
        self.post_json(FEDERATION_POLICY_EVALUATE_PATH, request)
    }

    pub fn issue_generic_trust_activation(
        &self,
        request: &GenericTrustActivationIssueRequest,
    ) -> Result<SignedGenericTrustActivation, CliError> {
        self.post_json(GENERIC_TRUST_ACTIVATION_ISSUE_PATH, request)
    }

    pub fn evaluate_generic_trust_activation(
        &self,
        request: &GenericTrustActivationEvaluationRequest,
    ) -> Result<GenericTrustActivationEvaluation, CliError> {
        self.post_json(GENERIC_TRUST_ACTIVATION_EVALUATE_PATH, request)
    }

    pub fn issue_generic_governance_charter(
        &self,
        request: &GenericGovernanceCharterIssueRequest,
    ) -> Result<SignedGenericGovernanceCharter, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH, request)
    }

    pub fn issue_generic_governance_case(
        &self,
        request: &GenericGovernanceCaseIssueRequest,
    ) -> Result<SignedGenericGovernanceCase, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CASE_ISSUE_PATH, request)
    }

    pub fn evaluate_generic_governance_case(
        &self,
        request: &GenericGovernanceCaseEvaluationRequest,
    ) -> Result<GenericGovernanceCaseEvaluation, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CASE_EVALUATE_PATH, request)
    }

    pub fn issue_open_market_fee_schedule(
        &self,
        request: &OpenMarketFeeScheduleIssueRequest,
    ) -> Result<SignedOpenMarketFeeSchedule, CliError> {
        self.post_json(OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH, request)
    }

    pub fn issue_open_market_penalty(
        &self,
        request: &OpenMarketPenaltyIssueRequest,
    ) -> Result<SignedOpenMarketPenalty, CliError> {
        self.post_json(OPEN_MARKET_PENALTY_ISSUE_PATH, request)
    }

    pub fn evaluate_open_market_penalty(
        &self,
        request: &OpenMarketPenaltyEvaluationRequest,
    ) -> Result<OpenMarketPenaltyEvaluation, CliError> {
        self.post_json(OPEN_MARKET_PENALTY_EVALUATE_PATH, request)
    }

    pub fn list_certifications(&self) -> Result<CertificationRegistryListResponse, CliError> {
        self.get_json(CERTIFICATIONS_PATH)
    }

    pub fn get_certification(
        &self,
        artifact_id: &str,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_PATH,
            "artifact_id",
            artifact_id,
        ))
    }

    pub fn publish_certification(
        &self,
        artifact: &SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(CERTIFICATIONS_PATH, artifact)
    }

    pub fn resolve_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationResolutionResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn discover_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationDiscoveryResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn publish_certification_network(
        &self,
        request: &CertificationNetworkPublishRequest,
    ) -> Result<CertificationNetworkPublishResponse, CliError> {
        self.post_json("/v1/certifications/discovery/publish", request)
    }

    pub fn search_certification_marketplace(
        &self,
        query: &CertificationMarketplaceSearchQuery,
    ) -> Result<CertificationPublicSearchResponse, CliError> {
        self.get_json(&certification_marketplace_search_path(query))
    }

    pub fn certification_marketplace_transparency(
        &self,
        query: &CertificationMarketplaceTransparencyQuery,
    ) -> Result<CertificationTransparencyResponse, CliError> {
        self.get_json(&certification_marketplace_transparency_path(query))
    }

    pub fn consume_certification_marketplace(
        &self,
        request: &CertificationConsumptionRequest,
    ) -> Result<CertificationConsumptionResponse, CliError> {
        self.post_json(CERTIFICATION_DISCOVERY_CONSUME_PATH, request)
    }

    pub fn revoke_certification(
        &self,
        artifact_id: &str,
        request: &CertificationRevocationRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_REVOKE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn dispute_certification(
        &self,
        artifact_id: &str,
        request: &CertificationDisputeRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_DISPUTE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn list_passport_statuses(&self) -> Result<PassportStatusListResponse, CliError> {
        self.get_json(PASSPORT_STATUSES_PATH)
    }

    pub fn passport_issuer_metadata(&self) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
        self.public_get_json(PASSPORT_ISSUER_METADATA_PATH)
    }

    pub fn create_passport_issuance_offer(
        &self,
        request: &CreatePassportIssuanceOfferRequest,
    ) -> Result<PassportIssuanceOfferRecord, CliError> {
        self.post_json(PASSPORT_ISSUANCE_OFFERS_PATH, request)
    }

    pub fn redeem_passport_issuance_token(
        &self,
        request: &Oid4vciTokenRequest,
    ) -> Result<Oid4vciTokenResponse, CliError> {
        self.public_post_json(PASSPORT_ISSUANCE_TOKEN_PATH, request)
    }

    pub fn redeem_passport_issuance_credential(
        &self,
        access_token: &str,
        request: &Oid4vciCredentialRequest,
    ) -> Result<Oid4vciCredentialResponse, CliError> {
        self.bearer_post_json(PASSPORT_ISSUANCE_CREDENTIAL_PATH, access_token, request)
    }

    pub fn get_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn publish_passport_status(
        &self,
        request: &PublishPassportStatusRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(PASSPORT_STATUSES_PATH, request)
    }

    pub fn resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn public_resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn revoke_passport_status(
        &self,
        passport_id: &str,
        request: &PassportStatusRevocationRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(
            &path_with_encoded_param(PASSPORT_STATUS_REVOKE_PATH, "passport_id", passport_id),
            request,
        )
    }

    pub fn list_verifier_policies(&self) -> Result<VerifierPolicyListResponse, CliError> {
        self.get_json(PASSPORT_VERIFIER_POLICIES_PATH)
    }

    pub fn get_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn upsert_verifier_policy(
        &self,
        policy_id: &str,
        document: &SignedPassportVerifierPolicy,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.put_json(
            &path_with_encoded_param(PASSPORT_VERIFIER_POLICY_PATH, "policy_id", policy_id),
            document,
        )
    }

    pub fn delete_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<VerifierPolicyDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn create_passport_challenge(
        &self,
        request: &CreatePassportChallengeRequest,
    ) -> Result<CreatePassportChallengeResponse, CliError> {
        self.post_json(PASSPORT_CHALLENGES_PATH, request)
    }

    pub fn verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.post_json(PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn public_get_passport_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<PassportPresentationChallenge, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            "challenge_id",
            challenge_id,
        ))
    }

    pub fn public_verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.public_post_json(PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn create_oid4vp_request(
        &self,
        request: &CreateOid4vpRequest,
    ) -> Result<CreateOid4vpRequestResponse, CliError> {
        self.post_json(PASSPORT_OID4VP_REQUESTS_PATH, request)
    }

    pub fn public_get_oid4vp_request(&self, request_id: &str) -> Result<String, CliError> {
        self.public_get_text(&path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_get_wallet_exchange(
        &self,
        request_id: &str,
    ) -> Result<WalletExchangeStatusResponse, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_submit_oid4vp_response(
        &self,
        response_jwt: &str,
    ) -> Result<Oid4vpPresentationVerification, CliError> {
        self.public_post_form(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            &[("response", response_jwt)],
        )
    }

    pub fn list_revocations(
        &self,
        query: &RevocationQuery,
    ) -> Result<RevocationListResponse, CliError> {
        self.get_json_with_query(REVOCATIONS_PATH, query)
    }

    pub fn revoke_capability(
        &self,
        capability_id: &str,
    ) -> Result<RevokeCapabilityResponse, CliError> {
        self.post_json(
            REVOCATIONS_PATH,
            &RevokeCapabilityRequest {
                capability_id: capability_id.to_string(),
            },
        )
    }

    pub fn list_tool_receipts(
        &self,
        query: &ToolReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(TOOL_RECEIPTS_PATH, query)
    }

    pub fn list_child_receipts(
        &self,
        query: &ChildReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(CHILD_RECEIPTS_PATH, query)
    }

    pub fn query_receipts(
        &self,
        query: &ReceiptQueryHttpQuery,
    ) -> Result<ReceiptQueryResponse, CliError> {
        self.get_json_with_query(RECEIPT_QUERY_PATH, query)
    }

    pub fn export_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceExportRequest,
    ) -> Result<evidence_export::RemoteEvidenceExportResponse, CliError> {
        self.post_json(EVIDENCE_EXPORT_PATH, request)
    }

    pub fn import_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceImportRequest,
    ) -> Result<evidence_export::RemoteEvidenceImportResponse, CliError> {
        self.post_json(EVIDENCE_IMPORT_PATH, request)
    }

    pub fn shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, CliError> {
        self.get_json_with_query(FEDERATION_EVIDENCE_SHARES_PATH, query)
    }

    // Kept for API parity with the trust-control service surface even though
    // the current CLI command set does not invoke it directly.
    #[allow(dead_code)]
    pub fn cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, CliError> {
        self.get_json_with_query(COST_ATTRIBUTION_PATH, query)
    }

    // Kept for API parity with the trust-control service surface even though
    // the current CLI command set does not invoke it directly.
    #[allow(dead_code)]
    pub fn operator_report(&self, query: &OperatorReportQuery) -> Result<OperatorReport, CliError> {
        self.get_json_with_query(OPERATOR_REPORT_PATH, query)
    }

    pub fn behavioral_feed(
        &self,
        query: &BehavioralFeedQuery,
    ) -> Result<SignedBehavioralFeed, CliError> {
        self.get_json_with_query(BEHAVIORAL_FEED_PATH, query)
    }

    pub fn exposure_ledger(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedExposureLedgerReport, CliError> {
        self.get_json_with_query(EXPOSURE_LEDGER_PATH, query)
    }

    pub fn credit_scorecard(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedCreditScorecardReport, CliError> {
        self.get_json_with_query(CREDIT_SCORECARD_PATH, query)
    }

    pub fn capital_book(
        &self,
        query: &CapitalBookQuery,
    ) -> Result<SignedCapitalBookReport, CliError> {
        self.get_json_with_query(CAPITAL_BOOK_PATH, query)
    }

    pub fn issue_capital_execution_instruction(
        &self,
        request: &CapitalExecutionInstructionRequest,
    ) -> Result<SignedCapitalExecutionInstruction, CliError> {
        self.post_json(CAPITAL_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_capital_allocation_decision(
        &self,
        request: &CapitalAllocationDecisionRequest,
    ) -> Result<SignedCapitalAllocationDecision, CliError> {
        self.post_json(CAPITAL_ALLOCATION_ISSUE_PATH, request)
    }

    pub fn credit_facility_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditFacilityReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITY_REPORT_PATH, query)
    }

    pub fn issue_credit_facility(
        &self,
        request: &CreditFacilityIssueRequest,
    ) -> Result<SignedCreditFacility, CliError> {
        self.post_json(CREDIT_FACILITY_ISSUE_PATH, request)
    }

    pub fn list_credit_facilities(
        &self,
        query: &CreditFacilityListQuery,
    ) -> Result<CreditFacilityListReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITIES_REPORT_PATH, query)
    }

    pub fn credit_bond_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditBondReport, CliError> {
        self.get_json_with_query(CREDIT_BOND_REPORT_PATH, query)
    }

    pub fn issue_credit_bond(
        &self,
        request: &CreditBondIssueRequest,
    ) -> Result<SignedCreditBond, CliError> {
        self.post_json(CREDIT_BOND_ISSUE_PATH, request)
    }

    pub fn list_credit_bonds(
        &self,
        query: &CreditBondListQuery,
    ) -> Result<CreditBondListReport, CliError> {
        self.get_json_with_query(CREDIT_BONDS_REPORT_PATH, query)
    }

    pub fn simulate_credit_bonded_execution(
        &self,
        request: &CreditBondedExecutionSimulationRequest,
    ) -> Result<CreditBondedExecutionSimulationReport, CliError> {
        self.post_json(CREDIT_BONDED_EXECUTION_SIMULATION_PATH, request)
    }

    pub fn credit_loss_lifecycle_report(
        &self,
        query: &CreditLossLifecycleQuery,
    ) -> Result<CreditLossLifecycleReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_REPORT_PATH, query)
    }

    pub fn issue_credit_loss_lifecycle(
        &self,
        request: &CreditLossLifecycleIssueRequest,
    ) -> Result<SignedCreditLossLifecycle, CliError> {
        self.post_json(CREDIT_LOSS_LIFECYCLE_ISSUE_PATH, request)
    }

    pub fn list_credit_loss_lifecycle(
        &self,
        query: &CreditLossLifecycleListQuery,
    ) -> Result<CreditLossLifecycleListReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_LIST_PATH, query)
    }

    pub fn credit_backtest(
        &self,
        query: &CreditBacktestQuery,
    ) -> Result<CreditBacktestReport, CliError> {
        self.get_json_with_query(CREDIT_BACKTEST_PATH, query)
    }

    pub fn credit_provider_risk_package(
        &self,
        query: &CreditProviderRiskPackageQuery,
    ) -> Result<SignedCreditProviderRiskPackage, CliError> {
        self.get_json_with_query(CREDIT_PROVIDER_RISK_PACKAGE_PATH, query)
    }

    pub fn issue_liability_provider(
        &self,
        request: &LiabilityProviderIssueRequest,
    ) -> Result<SignedLiabilityProvider, CliError> {
        self.post_json(LIABILITY_PROVIDER_ISSUE_PATH, request)
    }

    pub fn list_liability_providers(
        &self,
        query: &LiabilityProviderListQuery,
    ) -> Result<LiabilityProviderListReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDERS_REPORT_PATH, query)
    }

    pub fn resolve_liability_provider(
        &self,
        query: &LiabilityProviderResolutionQuery,
    ) -> Result<LiabilityProviderResolutionReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDER_RESOLVE_PATH, query)
    }

    pub fn issue_liability_quote_request(
        &self,
        request: &LiabilityQuoteRequestIssueRequest,
    ) -> Result<SignedLiabilityQuoteRequest, CliError> {
        self.post_json(LIABILITY_QUOTE_REQUEST_ISSUE_PATH, request)
    }

    pub fn issue_liability_quote_response(
        &self,
        request: &LiabilityQuoteResponseIssueRequest,
    ) -> Result<SignedLiabilityQuoteResponse, CliError> {
        self.post_json(LIABILITY_QUOTE_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_pricing_authority(
        &self,
        request: &LiabilityPricingAuthorityIssueRequest,
    ) -> Result<SignedLiabilityPricingAuthority, CliError> {
        self.post_json(LIABILITY_PRICING_AUTHORITY_ISSUE_PATH, request)
    }

    pub fn issue_liability_placement(
        &self,
        request: &LiabilityPlacementIssueRequest,
    ) -> Result<SignedLiabilityPlacement, CliError> {
        self.post_json(LIABILITY_PLACEMENT_ISSUE_PATH, request)
    }

    pub fn issue_liability_bound_coverage(
        &self,
        request: &LiabilityBoundCoverageIssueRequest,
    ) -> Result<SignedLiabilityBoundCoverage, CliError> {
        self.post_json(LIABILITY_BOUND_COVERAGE_ISSUE_PATH, request)
    }

    pub fn issue_liability_auto_bind(
        &self,
        request: &LiabilityAutoBindIssueRequest,
    ) -> Result<SignedLiabilityAutoBindDecision, CliError> {
        self.post_json(LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH, request)
    }

    pub fn liability_market_workflows(
        &self,
        query: &LiabilityMarketWorkflowQuery,
    ) -> Result<LiabilityMarketWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_MARKET_WORKFLOW_REPORT_PATH, query)
    }

    pub fn issue_liability_claim_package(
        &self,
        request: &LiabilityClaimPackageIssueRequest,
    ) -> Result<SignedLiabilityClaimPackage, CliError> {
        self.post_json(LIABILITY_CLAIM_PACKAGE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_response(
        &self,
        request: &LiabilityClaimResponseIssueRequest,
    ) -> Result<SignedLiabilityClaimResponse, CliError> {
        self.post_json(LIABILITY_CLAIM_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_dispute(
        &self,
        request: &LiabilityClaimDisputeIssueRequest,
    ) -> Result<SignedLiabilityClaimDispute, CliError> {
        self.post_json(LIABILITY_CLAIM_DISPUTE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_adjudication(
        &self,
        request: &LiabilityClaimAdjudicationIssueRequest,
    ) -> Result<SignedLiabilityClaimAdjudication, CliError> {
        self.post_json(LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_payout_instruction(
        &self,
        request: &LiabilityClaimPayoutInstructionIssueRequest,
    ) -> Result<SignedLiabilityClaimPayoutInstruction, CliError> {
        self.post_json(LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_payout_receipt(
        &self,
        request: &LiabilityClaimPayoutReceiptIssueRequest,
    ) -> Result<SignedLiabilityClaimPayoutReceipt, CliError> {
        self.post_json(LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_settlement_instruction(
        &self,
        request: &LiabilityClaimSettlementInstructionIssueRequest,
    ) -> Result<SignedLiabilityClaimSettlementInstruction, CliError> {
        self.post_json(LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_settlement_receipt(
        &self,
        request: &LiabilityClaimSettlementReceiptIssueRequest,
    ) -> Result<SignedLiabilityClaimSettlementReceipt, CliError> {
        self.post_json(LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH, request)
    }

    pub fn liability_claim_workflows(
        &self,
        query: &LiabilityClaimWorkflowQuery,
    ) -> Result<LiabilityClaimWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_CLAIM_WORKFLOW_REPORT_PATH, query)
    }

    pub fn runtime_attestation_appraisal(
        &self,
        request: &RuntimeAttestationAppraisalRequest,
    ) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_PATH, request)
    }

    pub fn runtime_attestation_appraisal_result(
        &self,
        request: &RuntimeAttestationAppraisalResultExportRequest,
    ) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH, request)
    }

    pub fn import_runtime_attestation_appraisal(
        &self,
        request: &RuntimeAttestationAppraisalImportRequest,
    ) -> Result<RuntimeAttestationAppraisalImportReport, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH, request)
    }

    pub fn metered_billing_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, CliError> {
        self.get_json_with_query(METERED_BILLING_REPORT_PATH, query)
    }

    pub fn authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, CliError> {
        self.get_json_with_query(AUTHORIZATION_CONTEXT_REPORT_PATH, query)
    }

    pub fn authorization_profile_metadata(
        &self,
    ) -> Result<ChioOAuthAuthorizationMetadataReport, CliError> {
        self.get_json(AUTHORIZATION_PROFILE_METADATA_PATH)
    }

    pub fn authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ChioOAuthAuthorizationReviewPack, CliError> {
        self.get_json_with_query(AUTHORIZATION_REVIEW_PACK_PATH, query)
    }

    pub fn underwriting_policy_input(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<SignedUnderwritingPolicyInput, CliError> {
        self.get_json_with_query(UNDERWRITING_INPUT_PATH, query)
    }

    pub fn underwriting_decision(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<UnderwritingDecisionReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISION_PATH, query)
    }

    pub fn simulate_underwriting_decision(
        &self,
        request: &UnderwritingSimulationRequest,
    ) -> Result<UnderwritingSimulationReport, CliError> {
        self.post_json(UNDERWRITING_SIMULATION_PATH, request)
    }

    pub fn issue_underwriting_decision(
        &self,
        request: &UnderwritingDecisionIssueRequest,
    ) -> Result<SignedUnderwritingDecision, CliError> {
        self.post_json(UNDERWRITING_DECISION_ISSUE_PATH, request)
    }

    pub fn list_underwriting_decisions(
        &self,
        query: &UnderwritingDecisionQuery,
    ) -> Result<UnderwritingDecisionListReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISIONS_REPORT_PATH, query)
    }

    pub fn create_underwriting_appeal(
        &self,
        request: &UnderwritingAppealCreateRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEALS_PATH, request)
    }

    pub fn resolve_underwriting_appeal(
        &self,
        request: &UnderwritingAppealResolveRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEAL_RESOLVE_PATH, request)
    }

    pub fn record_metered_billing_reconciliation(
        &self,
        request: &MeteredBillingReconciliationUpdateRequest,
    ) -> Result<MeteredBillingReconciliationUpdateResponse, CliError> {
        self.post_json(METERED_BILLING_RECONCILE_PATH, request)
    }

    pub fn local_reputation(
        &self,
        subject_key: &str,
        query: &LocalReputationQuery,
    ) -> Result<crate::issuance::LocalReputationInspection, CliError> {
        self.get_json_with_query(
            &path_with_encoded_param(LOCAL_REPUTATION_PATH, "subject_key", subject_key),
            query,
        )
    }

    pub fn reputation_compare(
        &self,
        subject_key: &str,
        request: &ReputationCompareRequest,
    ) -> Result<crate::reputation::PortableReputationComparison, CliError> {
        self.post_json(
            &path_with_encoded_param(REPUTATION_COMPARE_PATH, "subject_key", subject_key),
            request,
        )
    }

    pub fn issue_portable_reputation_summary(
        &self,
        request: &PortableReputationSummaryIssueRequest,
    ) -> Result<SignedPortableReputationSummary, CliError> {
        self.post_json(PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH, request)
    }

    pub fn issue_portable_negative_event(
        &self,
        request: &PortableNegativeEventIssueRequest,
    ) -> Result<SignedPortableNegativeEvent, CliError> {
        self.post_json(PORTABLE_NEGATIVE_EVENT_ISSUE_PATH, request)
    }

    pub fn evaluate_portable_reputation(
        &self,
        request: &PortableReputationEvaluationRequest,
    ) -> Result<PortableReputationEvaluation, CliError> {
        self.post_json(PORTABLE_REPUTATION_EVALUATE_PATH, request)
    }

    pub fn append_tool_receipt(&self, receipt: &ChioReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(TOOL_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(CHILD_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn record_capability_snapshot(
        &self,
        capability: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CliError> {
        let _: Value = self.post_json(
            LINEAGE_RECORD_PATH,
            &RecordCapabilitySnapshotRequest {
                capability: capability.clone(),
                parent_capability_id: parent_capability_id.map(ToOwned::to_owned),
            },
        )?;
        Ok(())
    }

    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    pub(crate) fn try_increment_budget(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<TryIncrementBudgetResponse, CliError> {
        self.post_json(
            BUDGET_INCREMENT_PATH,
            &TryIncrementBudgetRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
            },
        )
    }

    pub(crate) fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    pub(crate) fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &TryChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    pub(crate) fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RELEASE_EXPOSURE_PATH,
            &ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    pub(crate) fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reconcile_budget_spend(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids(
            capability_id,
            grant_index,
            authorized_exposure_units,
            realized_spend_units,
            None,
            None,
        )
    }

    pub(crate) fn reconcile_budget_spend_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let released_exposure_units = authorized_exposure_units
            .checked_sub(realized_spend_units)
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "realized spend cannot exceed authorized exposure during reconciliation"
                        .to_string(),
                )
            })?;
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units: released_exposure_units,
                exposure_units: Some(authorized_exposure_units),
                realized_spend_units: Some(realized_spend_units),
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn cluster_status(&self) -> Result<ClusterStatusResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_STATUS_PATH, None)
    }

    pub(crate) fn authority_snapshot(&self) -> Result<AuthoritySnapshotView, CliError> {
        self.get_internal_json(INTERNAL_AUTHORITY_SNAPSHOT_PATH, None)
    }

    pub(crate) fn cluster_snapshot(&self) -> Result<ClusterStateSnapshotResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_SNAPSHOT_PATH, None)
    }

    pub(crate) fn revocation_deltas(
        &self,
        query: &RevocationDeltaQuery,
    ) -> Result<RevocationDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_REVOCATIONS_DELTA_PATH, query, None)
    }

    pub(crate) fn tool_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_TOOL_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn child_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_CHILD_RECEIPTS_DELTA_PATH, query, None)
    }

    pub(crate) fn lineage_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<LineageDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_LINEAGE_DELTA_PATH, query, None)
    }

    pub(crate) fn budget_deltas(
        &self,
        query: &BudgetDeltaQuery,
    ) -> Result<BudgetDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_BUDGETS_DELTA_PATH, query, None)
    }

    fn get_internal_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        self.request_internal_get_json(path, path, term)
    }

    fn get_internal_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_internal_get_json(&url, path, term)
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .get(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn public_get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn public_get_text(&self, path: &str) -> Result<String, CliError> {
        self.request_text_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_json(
            |client, base_url, token| {
                client
                    .get(&format!("{base_url}{url}"))
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            "",
        )
    }

    pub(crate) fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    pub(crate) fn post_internal_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_internal_post_json(path, json, term)
    }

    fn public_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_without_service_auth(
            |client, url| client.post(url).send_json(json.clone()),
            path,
        )
    }

    fn public_post_form<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.post(url).send_form(body), path)
    }

    fn bearer_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer_token: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_with_bearer(
            |client, url| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {bearer_token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .put(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    pub(crate) fn delete_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .delete(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn request_internal_get_json<T>(
        &self,
        request_path: &str,
        auth_endpoint: &str,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], request_path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_get_request(&self.http, &url, auth_endpoint, term)?
            } else {
                self.http
                    .get(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.call() {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::cli_other_error(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    fn request_internal_post_json<T>(
        &self,
        path: &str,
        body: Value,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_post_request(&self.http, &url, path, term)?
            } else {
                self.http
                    .post(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.send_json(body.clone()) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::cli_other_error(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    fn build_internal_get_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .get(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .get(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    fn build_internal_post_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .post(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .post(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    pub(crate) fn request_json<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url, &self.token) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    fn request_json_without_service_auth<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    pub(crate) fn request_text_without_service_auth<F>(
        &self,
        request: F,
        path: &str,
    ) -> Result<String, CliError>
    where
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return response.into_string().map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to decode trust control text response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::cli_other_error(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::cli_other_error(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    fn request_json_with_bearer<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        self.request_json_without_service_auth(request, path)
    }

    pub(crate) fn endpoint_order(&self) -> Vec<usize> {
        let preferred = match self.preferred_index.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let total = self.endpoints.len();
        (0..total)
            .map(|offset| (preferred + offset) % total)
            .collect()
    }

    pub(crate) fn mark_preferred(&self, index: usize) {
        match self.preferred_index.lock() {
            Ok(mut guard) => *guard = index,
            Err(poisoned) => *poisoned.into_inner() = index,
        }
    }
}

pub(crate) fn certification_marketplace_search_path(
    query: &CertificationMarketplaceSearchQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(criteria_profile) = query.filters.criteria_profile.as_deref() {
        serializer.append_pair("criteriaProfile", criteria_profile);
    }
    if let Some(evidence_profile) = query.filters.evidence_profile.as_deref() {
        serializer.append_pair("evidenceProfile", evidence_profile);
    }
    if let Some(status) = query.filters.status {
        serializer.append_pair("status", status.label());
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_SEARCH_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_SEARCH_PATH}?{encoded}")
    }
}

pub(crate) fn certification_marketplace_transparency_path(
    query: &CertificationMarketplaceTransparencyQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH}?{encoded}")
    }
}

pub(crate) fn should_retry_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}
