use super::super::*;
use super::{
    certification_marketplace_search_path, certification_marketplace_transparency_path,
    path_with_encoded_param,
};

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
}
