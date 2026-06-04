// Trust-control service wire types and shared helpers.
//
// This module owns the data types for the trust-control surface. The shared
// import set lives in the parent `trust_control.rs` and is inherited here via
// `use super::*;` so every sibling module composes against the same scope.

use super::*;

// Content Security Policy applied to all responses from the dashboard/API server.
// Restricts resource loading to same-origin only; unsafe-inline is allowed for
// styles because Vite injects inline style tags at build time.
pub(crate) const CSP_VALUE: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:";

pub(crate) const HEALTH_PATH: &str = "/health";
pub(crate) const AUTHORITY_PATH: &str = "/v1/authority";
pub(crate) const ISSUE_CAPABILITY_PATH: &str = "/v1/capabilities/issue";
pub(crate) const FEDERATED_ISSUE_PATH: &str = "/v1/federation/capabilities/issue";
pub(crate) const FEDERATION_PROVIDERS_PATH: &str = "/v1/federation/providers";
pub(crate) const FEDERATION_PROVIDER_PATH: &str = "/v1/federation/providers/{provider_id}";
pub(crate) const FEDERATION_POLICIES_PATH: &str = "/v1/federation/open-admission-policies";
pub(crate) const FEDERATION_POLICY_PATH: &str =
    "/v1/federation/open-admission-policies/{policy_id}";
pub(crate) const FEDERATION_POLICY_EVALUATE_PATH: &str =
    "/v1/federation/open-admission-policies/evaluate";
pub(crate) const SCIM_USERS_PATH: &str = "/scim/v2/Users";
pub(crate) const SCIM_USER_PATH: &str = "/scim/v2/Users/{user_id}";
pub(crate) const CERTIFICATIONS_PATH: &str = "/v1/certifications";
pub(crate) const CERTIFICATION_PATH: &str = "/v1/certifications/{artifact_id}";
pub(crate) const CERTIFICATION_RESOLVE_PATH: &str = "/v1/certifications/resolve/{tool_server_id}";
pub(crate) const CERTIFICATION_REVOKE_PATH: &str = "/v1/certifications/{artifact_id}/revoke";
pub(crate) const CERTIFICATION_DISCOVERY_PATH: &str = "/v1/certifications/discovery/publish";
pub(crate) const CERTIFICATION_DISCOVERY_RESOLVE_PATH: &str =
    "/v1/certifications/discovery/resolve/{tool_server_id}";
pub(crate) const CERTIFICATION_DISCOVERY_SEARCH_PATH: &str = "/v1/certifications/discovery/search";
pub(crate) const CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH: &str =
    "/v1/certifications/discovery/transparency";
pub(crate) const CERTIFICATION_DISCOVERY_CONSUME_PATH: &str =
    "/v1/certifications/discovery/consume";
pub(crate) const CERTIFICATION_DISPUTE_PATH: &str = "/v1/certifications/{artifact_id}/dispute";
pub(crate) const PUBLIC_CERTIFICATION_METADATA_PATH: &str = "/v1/public/certifications/metadata";
pub(crate) const PUBLIC_CERTIFICATION_RESOLVE_PATH: &str =
    "/v1/public/certifications/resolve/{tool_server_id}";
pub(crate) const PUBLIC_CERTIFICATION_SEARCH_PATH: &str = "/v1/public/certifications/search";
pub(crate) const PUBLIC_CERTIFICATION_TRANSPARENCY_PATH: &str =
    "/v1/public/certifications/transparency";
pub(crate) const PUBLIC_GENERIC_NAMESPACE_PATH: &str = "/v1/public/registry/namespace";
pub(crate) const PUBLIC_GENERIC_LISTINGS_PATH: &str = "/v1/public/registry/listings/search";
pub(crate) const GENERIC_TRUST_ACTIVATION_ISSUE_PATH: &str = "/v1/registry/trust-activations/issue";
pub(crate) const GENERIC_TRUST_ACTIVATION_EVALUATE_PATH: &str =
    "/v1/registry/trust-activations/evaluate";
pub(crate) const GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH: &str =
    "/v1/registry/governance/charters/issue";
pub(crate) const GENERIC_GOVERNANCE_CASE_ISSUE_PATH: &str = "/v1/registry/governance/cases/issue";
pub(crate) const GENERIC_GOVERNANCE_CASE_EVALUATE_PATH: &str =
    "/v1/registry/governance/cases/evaluate";
pub(crate) const OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH: &str = "/v1/registry/market/fees/issue";
pub(crate) const OPEN_MARKET_PENALTY_ISSUE_PATH: &str = "/v1/registry/market/penalties/issue";
pub(crate) const OPEN_MARKET_PENALTY_EVALUATE_PATH: &str = "/v1/registry/market/penalties/evaluate";
pub(crate) const PASSPORT_ISSUER_METADATA_PATH: &str = OID4VCI_ISSUER_METADATA_PATH;
pub(crate) const PASSPORT_ISSUER_JWKS_PATH: &str = OID4VCI_JWKS_PATH;
pub(crate) const PASSPORT_SD_JWT_TYPE_METADATA_PATH: &str =
    CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH;
pub(crate) const PASSPORT_ISSUANCE_OFFERS_PATH: &str = OID4VCI_PASSPORT_OFFERS_PATH;
pub(crate) const PASSPORT_ISSUANCE_TOKEN_PATH: &str = OID4VCI_PASSPORT_TOKEN_PATH;
pub(crate) const PASSPORT_ISSUANCE_CREDENTIAL_PATH: &str = OID4VCI_PASSPORT_CREDENTIAL_PATH;
pub(crate) const PASSPORT_STATUSES_PATH: &str = "/v1/passport/statuses";
pub(crate) const PASSPORT_STATUS_PATH: &str = "/v1/passport/statuses/{passport_id}";
pub(crate) const PASSPORT_STATUS_RESOLVE_PATH: &str = "/v1/passport/statuses/resolve/{passport_id}";
pub(crate) const PUBLIC_PASSPORT_STATUS_RESOLVE_PATH: &str =
    "/v1/public/passport/statuses/resolve/{passport_id}";
pub(crate) const PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH: &str =
    "/v1/public/passport/discovery/issuer";
pub(crate) const PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH: &str =
    "/v1/public/passport/discovery/verifier";
pub(crate) const PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH: &str =
    "/v1/public/passport/discovery/transparency";
pub(crate) const PASSPORT_STATUS_REVOKE_PATH: &str = "/v1/passport/statuses/{passport_id}/revoke";
pub(crate) const PASSPORT_VERIFIER_POLICIES_PATH: &str = "/v1/passport/verifier-policies";
pub(crate) const PASSPORT_VERIFIER_POLICY_PATH: &str = "/v1/passport/verifier-policies/{policy_id}";
pub(crate) const PASSPORT_CHALLENGES_PATH: &str = "/v1/passport/challenges";
pub(crate) const PASSPORT_CHALLENGE_VERIFY_PATH: &str = "/v1/passport/challenges/verify";
pub(crate) const PUBLIC_PASSPORT_CHALLENGE_PATH: &str =
    "/v1/public/passport/challenges/{challenge_id}";
pub(crate) const PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH: &str =
    "/v1/public/passport/challenges/verify";
pub(crate) const PASSPORT_OID4VP_REQUESTS_PATH: &str = "/v1/passport/oid4vp/requests";
pub(crate) const PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH: &str =
    "/v1/public/passport/wallet-exchanges/{request_id}";
pub(crate) const PUBLIC_PASSPORT_OID4VP_REQUEST_PATH: &str =
    "/v1/public/passport/oid4vp/requests/{request_id}";
pub(crate) const PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH: &str =
    "/v1/public/passport/oid4vp/launch/{request_id}";
pub(crate) const PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH: &str =
    "/v1/public/passport/oid4vp/direct-post";
pub(crate) const PUBLIC_DISCOVERY_TTL_SECS: u64 = 300;
pub const FEDERATED_DELEGATION_POLICY_SCHEMA: &str = "chio.federated-delegation-policy.v1";
pub(crate) const REVOCATIONS_PATH: &str = "/v1/revocations";
pub(crate) const TOOL_RECEIPTS_PATH: &str = "/v1/receipts/tools";
pub(crate) const CHILD_RECEIPTS_PATH: &str = "/v1/receipts/children";
pub(crate) const BUDGETS_PATH: &str = "/v1/budgets";
pub(crate) const BUDGET_INCREMENT_PATH: &str = "/v1/budgets/increment";
pub(crate) const BUDGET_AUTHORIZE_EXPOSURE_PATH: &str = "/v1/budgets/authorize-exposure";
pub(crate) const BUDGET_RELEASE_EXPOSURE_PATH: &str = "/v1/budgets/release-exposure";
pub(crate) const BUDGET_RECONCILE_SPEND_PATH: &str = "/v1/budgets/reconcile-spend";
pub(crate) const INTERNAL_CLUSTER_STATUS_PATH: &str = "/v1/internal/cluster/status";
pub(crate) const INTERNAL_CLUSTER_SNAPSHOT_PATH: &str = "/v1/internal/cluster/snapshot";
pub(crate) const INTERNAL_CLUSTER_PARTITION_PATH: &str = "/v1/internal/cluster/partition";
pub(crate) const INTERNAL_AUTHORITY_SNAPSHOT_PATH: &str = "/v1/internal/authority/snapshot";
pub(crate) const INTERNAL_REVOCATIONS_DELTA_PATH: &str = "/v1/internal/revocations/delta";
pub(crate) const INTERNAL_TOOL_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/tools/delta";
pub(crate) const INTERNAL_CHILD_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/children/delta";
pub(crate) const INTERNAL_BUDGETS_DELTA_PATH: &str = "/v1/internal/budgets/delta";
pub(crate) const INTERNAL_LINEAGE_DELTA_PATH: &str = "/v1/internal/lineage/delta";
pub(crate) const CLUSTER_NODE_ID_HEADER: &str = "x-chio-cluster-node-id";
pub(crate) const CLUSTER_AUTH_ISSUED_AT_HEADER: &str = "x-chio-cluster-auth-issued-at";
pub(crate) const CLUSTER_AUTH_SIGNATURE_HEADER: &str = "x-chio-cluster-auth-signature";
pub(crate) const CLUSTER_AUTH_TERM_HEADER: &str = "x-chio-cluster-auth-term";
pub(crate) const CLUSTER_AUTH_SCHEME: &str = "chio.cluster.peer.v1";
pub(crate) const CLUSTER_AUTH_MAX_SKEW_SECS: i64 = 60;
pub(crate) const CLUSTER_AUTH_FAILURE_WINDOW_SECS: u64 = 60;
pub(crate) const CLUSTER_AUTH_FAILURE_BURST: usize = 8;
pub(crate) const RECEIPT_QUERY_PATH: &str = "/v1/receipts/query";
pub(crate) const RECEIPT_ANALYTICS_PATH: &str = "/v1/receipts/analytics";
pub(crate) const EVIDENCE_EXPORT_PATH: &str = "/v1/evidence/export";
pub(crate) const EVIDENCE_IMPORT_PATH: &str = "/v1/evidence/import";
pub(crate) const FEDERATION_EVIDENCE_SHARES_PATH: &str = "/v1/federation/evidence-shares";
pub(crate) const COST_ATTRIBUTION_PATH: &str = "/v1/reports/cost-attribution";
pub(crate) const OPERATOR_REPORT_PATH: &str = "/v1/reports/operator";
pub(crate) const RUNTIME_ATTESTATION_APPRAISAL_PATH: &str =
    "/v1/reports/runtime-attestation-appraisal";
pub(crate) const RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH: &str =
    "/v1/reports/runtime-attestation-appraisal-result";
pub(crate) const RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH: &str =
    "/v1/reports/runtime-attestation-appraisal/import";
pub(crate) const BEHAVIORAL_FEED_PATH: &str = "/v1/reports/behavioral-feed";
pub(crate) const EXPOSURE_LEDGER_PATH: &str = "/v1/reports/exposure-ledger";
pub(crate) const CREDIT_SCORECARD_PATH: &str = "/v1/reports/credit-scorecard";
pub(crate) const CAPITAL_BOOK_PATH: &str = "/v1/reports/capital-book";
pub(crate) const CAPITAL_INSTRUCTION_ISSUE_PATH: &str = "/v1/capital/instructions/issue";
pub(crate) const CAPITAL_ALLOCATION_ISSUE_PATH: &str = "/v1/capital/allocations/issue";
pub(crate) const CREDIT_FACILITY_REPORT_PATH: &str = "/v1/reports/facility-policy";
pub(crate) const CREDIT_FACILITY_ISSUE_PATH: &str = "/v1/facilities/issue";
pub(crate) const CREDIT_FACILITIES_REPORT_PATH: &str = "/v1/reports/facilities";
pub(crate) const CREDIT_BOND_REPORT_PATH: &str = "/v1/reports/bond-policy";
pub(crate) const CREDIT_BOND_ISSUE_PATH: &str = "/v1/bonds/issue";
pub(crate) const CREDIT_BONDS_REPORT_PATH: &str = "/v1/reports/bonds";
pub(crate) const CREDIT_BONDED_EXECUTION_SIMULATION_PATH: &str =
    "/v1/reports/bonded-execution-simulation";
pub(crate) const CREDIT_LOSS_LIFECYCLE_REPORT_PATH: &str = "/v1/reports/bond-loss-policy";
pub(crate) const CREDIT_LOSS_LIFECYCLE_ISSUE_PATH: &str = "/v1/bond-losses/issue";
pub(crate) const CREDIT_LOSS_LIFECYCLE_LIST_PATH: &str = "/v1/reports/bond-losses";
pub(crate) const CREDIT_BACKTEST_PATH: &str = "/v1/reports/credit-backtest";
pub(crate) const CREDIT_PROVIDER_RISK_PACKAGE_PATH: &str = "/v1/reports/provider-risk-package";
pub(crate) const LIABILITY_PROVIDER_ISSUE_PATH: &str = "/v1/liability/providers/issue";
pub(crate) const LIABILITY_PROVIDERS_REPORT_PATH: &str = "/v1/reports/liability-providers";
pub(crate) const LIABILITY_PROVIDER_RESOLVE_PATH: &str = "/v1/liability/providers/resolve";
pub(crate) const LIABILITY_QUOTE_REQUEST_ISSUE_PATH: &str = "/v1/liability/quote-requests/issue";
pub(crate) const LIABILITY_QUOTE_RESPONSE_ISSUE_PATH: &str = "/v1/liability/quote-responses/issue";
pub(crate) const LIABILITY_PRICING_AUTHORITY_ISSUE_PATH: &str =
    "/v1/liability/pricing-authorities/issue";
pub(crate) const LIABILITY_PLACEMENT_ISSUE_PATH: &str = "/v1/liability/placements/issue";
pub(crate) const LIABILITY_BOUND_COVERAGE_ISSUE_PATH: &str = "/v1/liability/bound-coverages/issue";
pub(crate) const LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH: &str = "/v1/liability/auto-bind/issue";
pub(crate) const LIABILITY_MARKET_WORKFLOW_REPORT_PATH: &str = "/v1/reports/liability-market";
pub(crate) const LIABILITY_CLAIM_PACKAGE_ISSUE_PATH: &str = "/v1/liability/claims/issue";
pub(crate) const LIABILITY_CLAIM_RESPONSE_ISSUE_PATH: &str = "/v1/liability/claim-responses/issue";
pub(crate) const LIABILITY_CLAIM_DISPUTE_ISSUE_PATH: &str = "/v1/liability/disputes/issue";
pub(crate) const LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH: &str =
    "/v1/liability/adjudications/issue";
pub(crate) const LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH: &str =
    "/v1/liability/claim-payouts/instructions/issue";
pub(crate) const LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH: &str =
    "/v1/liability/claim-payouts/receipts/issue";
pub(crate) const LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH: &str =
    "/v1/liability/claim-settlements/instructions/issue";
pub(crate) const LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH: &str =
    "/v1/liability/claim-settlements/receipts/issue";
pub(crate) const LIABILITY_CLAIM_WORKFLOW_REPORT_PATH: &str = "/v1/reports/liability-claims";
pub(crate) const SETTLEMENT_REPORT_PATH: &str = "/v1/reports/settlements";
pub(crate) const SETTLEMENT_RECONCILE_PATH: &str = "/v1/settlements/reconcile";
pub(crate) const METERED_BILLING_REPORT_PATH: &str = "/v1/reports/metered-billing";
pub(crate) const METERED_BILLING_RECONCILE_PATH: &str = "/v1/metered-billing/reconcile";
pub(crate) const ECONOMIC_RECEIPT_REPORT_PATH: &str = "/v1/reports/economic-receipts";
pub(crate) const ECONOMIC_COMPLETION_FLOW_REPORT_PATH: &str =
    "/v1/reports/economic-completion-flow";
pub(crate) const AUTHORIZATION_CONTEXT_REPORT_PATH: &str = "/v1/reports/authorization-context";
pub(crate) const AUTHORIZATION_PROFILE_METADATA_PATH: &str =
    "/v1/reports/authorization-profile-metadata";
pub(crate) const AUTHORIZATION_REVIEW_PACK_PATH: &str = "/v1/reports/authorization-review-pack";
pub(crate) const UNDERWRITING_INPUT_PATH: &str = "/v1/reports/underwriting-input";
pub(crate) const UNDERWRITING_DECISION_PATH: &str = "/v1/reports/underwriting-decision";
pub(crate) const UNDERWRITING_SIMULATION_PATH: &str = "/v1/reports/underwriting-simulation";
pub(crate) const UNDERWRITING_DECISIONS_REPORT_PATH: &str = "/v1/reports/underwriting-decisions";
pub(crate) const UNDERWRITING_DECISION_ISSUE_PATH: &str = "/v1/underwriting/decisions/issue";
pub(crate) const UNDERWRITING_APPEALS_PATH: &str = "/v1/underwriting/appeals";
pub(crate) const UNDERWRITING_APPEAL_RESOLVE_PATH: &str = "/v1/underwriting/appeals/resolve";
pub(crate) const LOCAL_REPUTATION_PATH: &str = "/v1/reputation/local/{subject_key}";
pub(crate) const REPUTATION_COMPARE_PATH: &str = "/v1/reputation/compare/{subject_key}";
pub(crate) const PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH: &str =
    "/v1/reputation/portable/summaries/issue";
pub(crate) const PORTABLE_NEGATIVE_EVENT_ISSUE_PATH: &str = "/v1/reputation/portable/events/issue";
pub(crate) const PORTABLE_REPUTATION_EVALUATE_PATH: &str = "/v1/reputation/portable/evaluate";
pub(crate) const LINEAGE_RECORD_PATH: &str = "/v1/lineage";
pub(crate) const LINEAGE_PATH: &str = "/v1/lineage/{capability_id}";
pub(crate) const LINEAGE_CHAIN_PATH: &str = "/v1/lineage/{capability_id}/chain";
pub(crate) const AGENT_RECEIPTS_PATH: &str = "/v1/agents/{subject_key}/receipts";
pub(crate) const DASHBOARD_DIST_DIR: &str = "dashboard/dist";
pub(crate) const DEFAULT_LIST_LIMIT: usize = 50;
pub(crate) const MAX_LIST_LIMIT: usize = 200;
pub(crate) const BUDGET_DELTA_MAX_RECORDS: usize = MAX_LIST_LIMIT * 2;
pub(crate) const AUTHORITY_CACHE_TTL: Duration = Duration::from_secs(2);
pub(crate) const CONTROL_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const CLUSTER_SNAPSHOT_RECORD_THRESHOLD: u64 = 8;

#[derive(Clone)]
pub struct TrustServiceConfig {
    pub listen: SocketAddr,
    pub service_token: String,
    pub tenant_read_tokens: BTreeMap<String, String>,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub federation_policies_file: Option<PathBuf>,
    pub scim_lifecycle_file: Option<PathBuf>,
    pub verifier_policies_file: Option<PathBuf>,
    pub verifier_challenge_db_path: Option<PathBuf>,
    pub passport_statuses_file: Option<PathBuf>,
    pub passport_issuance_offers_file: Option<PathBuf>,
    pub certification_registry_file: Option<PathBuf>,
    pub certification_discovery_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<crate::policy::RuntimeAssuranceIssuancePolicy>,
    pub advertise_url: Option<String>,
    pub allow_local_peer_urls: bool,
    pub certification_public_metadata_ttl_seconds: u64,
    pub peer_urls: Vec<String>,
    pub cluster_sync_interval: Duration,
}

impl TrustServiceConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        validate_control_secret(&self.service_token, "control service token")?;
        for (tenant_id, token) in &self.tenant_read_tokens {
            if tenant_id.trim().is_empty() {
                return Err(CliError::cli_other_error(
                    "tenant read token id must be non-empty".to_string(),
                ));
            }
            if tenant_id.trim() != tenant_id {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain surrounding whitespace".to_string(),
                ));
            }
            if tenant_id.chars().any(char::is_control) {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain control characters".to_string(),
                ));
            }
            let token_label = format!("tenant read token for `{tenant_id}`");
            validate_control_secret(token, &token_label)?;
            if token == &self.service_token {
                return Err(CliError::cli_other_error(
                    "control tenant read token must not equal service token".to_string(),
                ));
            }
        }
        if self.cluster_sync_interval.is_zero() {
            return Err(CliError::cli_other_error(
                "cluster sync interval must be non-zero".to_string(),
            ));
        }
        if self.certification_public_metadata_ttl_seconds == 0 {
            return Err(CliError::cli_other_error(
                "certification public metadata TTL must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_control_secret(secret: &str, label: &str) -> Result<(), CliError> {
    if secret.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be non-empty"
        )));
    }
    if secret.trim() != secret {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain surrounding whitespace"
        )));
    }
    if secret.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod service_config_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        let listen = match "127.0.0.1:0".parse() {
            Ok(addr) => addr,
            Err(error) => panic!("test listen address should parse: {error}"),
        };
        TrustServiceConfig {
            listen,
            service_token: "token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_service_token_at_startup() {
        for token in [" token", "token "] {
            let mut config = base_config();
            config.service_token = token.to_string();

            let error = match config.validate() {
                Ok(()) => panic!("padded service token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("control service token must not contain surrounding whitespace"),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_tokens_at_startup() {
        for token in [" tenant-token", "tenant-token "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert("tenant-a".to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains(
                    "tenant read token for `tenant-a` must not contain surrounding whitespace"
                ),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_token_ids_at_startup() {
        for tenant_id in [" tenant-a", "tenant-a "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), "tenant-token".to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token id should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("tenant read token id must not contain surrounding whitespace"),
                "unexpected error for tenant id `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_control_bearing_tenant_read_tokens_at_startup() {
        for (tenant_id, token) in [
            ("tenant-\na", "tenant-token"),
            ("tenant-a", "tenant\u{7f}token"),
        ] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("control-bearing tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains("control characters"),
                "unexpected error for tenant token mapping `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_zero_public_certification_metadata_ttl() {
        let mut config = base_config();
        config.certification_public_metadata_ttl_seconds = 0;

        let error = config.validate().test_unwrap_err();

        assert!(
            error
                .to_string()
                .contains("certification public metadata TTL must be non-zero"),
            "unexpected zero TTL error: {error}",
        );
    }
}

#[derive(Clone)]
pub(crate) struct TrustServiceState {
    pub(crate) config: TrustServiceConfig,
    pub(crate) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(crate) verifier_policy_registry: Option<Arc<VerifierPolicyRegistry>>,
    pub(crate) federation_admission_rate_limiter: Arc<Mutex<FederationAdmissionRateLimiter>>,
    pub(crate) cluster: Option<Arc<Mutex<ClusterRuntimeState>>>,
}

#[derive(Clone)]
pub struct TrustControlClient {
    pub(crate) endpoints: Arc<Vec<String>>,
    pub(crate) preferred_index: Arc<Mutex<usize>>,
    pub(crate) token: Arc<str>,
    pub(crate) http: Agent,
    pub(crate) cluster_peer_auth: Option<ClusterPeerClientAuth>,
}

#[derive(Clone)]
pub(crate) struct ClusterPeerClientAuth {
    pub(crate) node_id: Arc<str>,
}

pub(crate) struct RemoteCapabilityAuthority {
    pub(crate) client: TrustControlClient,
    pub(crate) cache: Mutex<AuthorityKeyCache>,
}

pub(crate) struct AuthorityKeyCache {
    pub(crate) current: Option<PublicKey>,
    pub(crate) trusted: Vec<PublicKey>,
    pub(crate) refreshed_at: Instant,
}

pub(crate) struct RemoteRevocationStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteReceiptStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteBudgetStore {
    pub(crate) client: TrustControlClient,
    pub(crate) cached_usage: Mutex<HashMap<(String, u32), BudgetUsageRecord>>,
}

impl TrustServiceState {
    // Retained for enterprise-provider validation paths that share this state
    // shape even though current readers do not call the helper directly.
    #[allow(dead_code)]
    pub(crate) fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    // Retained for enterprise-provider validation paths that share this state
    // shape even though current readers do not call the helper directly.
    #[allow(dead_code)]
    pub(crate) fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }

    pub(crate) fn verifier_policy_registry(&self) -> Option<&VerifierPolicyRegistry> {
        self.verifier_policy_registry.as_deref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterRuntimeState {
    pub(crate) self_url: String,
    pub(crate) peers: HashMap<String, PeerSyncState>,
    pub(crate) election_term: u64,
    pub(crate) last_leader_url: Option<String>,
    pub(crate) term_started_at: Option<u64>,
    pub(crate) lease_expires_at: Option<u64>,
    pub(crate) lease_ttl_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerSyncState {
    pub(crate) health: PeerHealth,
    pub(crate) partitioned: bool,
    pub(crate) last_error: Option<String>,
    pub(crate) last_contact_at: Option<u64>,
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    pub(crate) revocation_cursor: Option<RevocationCursor>,
    pub(crate) budget_cursor: Option<BudgetCursor>,
    pub(crate) delta_records_since_snapshot: u64,
    pub(crate) snapshot_applied_count: u64,
    pub(crate) last_snapshot_at: Option<u64>,
    pub(crate) force_snapshot: bool,
}

#[derive(Debug, Default)]
pub(crate) struct FederationAdmissionRateLimiter {
    attempts: HashMap<String, Vec<u64>>,
}

impl FederationAdmissionRateLimiter {
    pub(crate) fn check_and_record(
        &mut self,
        policy_id: &str,
        subject_key: &str,
        limit: &FederationAdmissionRateLimit,
        now: u64,
    ) -> FederationAdmissionRateLimitStatus {
        let key = format!("{policy_id}:{subject_key}");
        let lower_bound = now.saturating_sub(limit.window_seconds);
        let entry = self.attempts.entry(key).or_default();
        entry.retain(|timestamp| *timestamp > lower_bound);
        if entry.len() >= limit.max_requests as usize {
            let retry_after_seconds = entry
                .first()
                .map(|oldest| {
                    oldest
                        .saturating_add(limit.window_seconds)
                        .saturating_sub(now)
                })
                .unwrap_or(limit.window_seconds);
            return FederationAdmissionRateLimitStatus {
                limit: limit.max_requests,
                window_seconds: limit.window_seconds,
                remaining: 0,
                retry_after_seconds: Some(retry_after_seconds.max(1)),
            };
        }
        entry.push(now);
        FederationAdmissionRateLimitStatus {
            limit: limit.max_requests,
            window_seconds: limit.window_seconds,
            remaining: limit.max_requests.saturating_sub(entry.len() as u32),
            retry_after_seconds: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PeerHealth {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub(crate) struct RevocationCursor {
    pub(crate) revoked_at: i64,
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct BudgetCursor {
    pub(crate) seq: u64,
    pub(crate) updated_at: i64,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterConsensusView {
    pub(crate) self_url: String,
    pub(crate) leader_url: Option<String>,
    pub(crate) role: &'static str,
    pub(crate) has_quorum: bool,
    pub(crate) quorum_size: usize,
    pub(crate) reachable_nodes: usize,
    pub(crate) election_term: u64,
}

impl Default for PeerSyncState {
    fn default() -> Self {
        Self {
            health: PeerHealth::Unknown,
            partitioned: false,
            last_error: None,
            last_contact_at: None,
            tool_seq: 0,
            child_seq: 0,
            lineage_seq: 0,
            revocation_cursor: None,
            budget_cursor: None,
            delta_records_since_snapshot: 0,
            snapshot_applied_count: 0,
            last_snapshot_at: None,
            force_snapshot: true,
        }
    }
}

impl PeerHealth {
    pub(crate) fn is_reachable(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAuthorityStatus {
    pub configured: bool,
    pub backend: Option<String>,
    pub public_key: Option<String>,
    pub generation: Option<u64>,
    pub rotated_at: Option<u64>,
    pub applies_to_future_sessions_only: bool,
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueCapabilityRequest {
    pub(crate) subject_public_key: String,
    pub(crate) scope: ChioScope,
    pub(crate) ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_attestation: Option<RuntimeAttestationEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueCapabilityResponse {
    pub(crate) capability: CapabilityToken,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueRequest {
    pub presentation: PassportPresentationResponse,
    pub expected_challenge: PassportPresentationChallenge,
    pub capability: crate::policy::DefaultCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_policy: Option<chio_policy::HushSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity: Option<EnterpriseIdentityContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_policy: Option<FederatedDelegationPolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueResponse {
    pub subject: String,
    pub subject_public_key: String,
    pub verification: PassportPresentationVerification,
    pub capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity_provenance: Option<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_audit: Option<EnterpriseAdmissionAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_anchor_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAdmissionAudit {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: String,
    pub principal: String,
    pub subject_key: String,
    pub subject_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderListResponse {
    pub configured: bool,
    pub count: usize,
    pub providers: Vec<EnterpriseProviderRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderDeleteResponse {
    pub provider_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyListResponse {
    pub configured: bool,
    pub count: usize,
    pub policies: Vec<SignedPassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyDeleteResponse {
    pub policy_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeRequest {
    pub verifier: String,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credentials: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPassportChallengeRequest {
    pub presentation: PassportPresentationResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_challenge: Option<PassportPresentationChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationTransport {
    pub challenge_id: String,
    pub challenge_url: String,
    pub submit_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeResponse {
    pub challenge: PassportPresentationChallenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<PassportPresentationTransport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityAssertionRequest {
    pub subject: String,
    pub continuity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<CreateIdentityAssertionRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequestResponse {
    pub request: Oid4vpRequestObject,
    pub transport: chio_credentials::Oid4vpRequestTransport,
    pub wallet_exchange: WalletExchangeStatusResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeStatusResponse {
    pub descriptor: WalletExchangeDescriptor,
    pub transaction: WalletExchangeTransactionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

#[derive(Debug, Deserialize)]
pub struct Oid4vpDirectPostForm {
    pub response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportIssuanceOfferRequest {
    pub passport: AgentPassport,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyBody {
    pub schema: String,
    pub issuer: String,
    pub partner: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub ttl_seconds: u64,
    pub scope: ChioScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyDocument {
    pub body: FederatedDelegationPolicyBody,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordCapabilitySnapshotRequest {
    pub(crate) capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_capability_id: Option<String>,
}

pub fn verify_federated_delegation_policy(
    policy: &FederatedDelegationPolicyDocument,
) -> Result<(), CliError> {
    if policy.body.schema != FEDERATED_DELEGATION_POLICY_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "unsupported federated delegation policy schema: expected {}, got {}",
            FEDERATED_DELEGATION_POLICY_SCHEMA, policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy created_at must be less than or equal to expires_at"
                .to_string(),
        ));
    }
    if policy.body.ttl_seconds == 0 {
        return Err(CliError::cli_other_error(
            "federated delegation policy ttl_seconds must be greater than zero".to_string(),
        ));
    }
    if !policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)?
    {
        return Err(CliError::cli_other_error(
            "federated delegation policy signature verification failed".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_federated_delegation_policy_active(
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if now < policy.body.created_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy is not yet valid".to_string(),
        ));
    }
    if now > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy has expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_requested_capability_within_delegation_policy(
    capability: &crate::policy::DefaultCapability,
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if !capability.scope.is_subset_of(&policy.body.scope) {
        return Err(CliError::cli_other_error(
            "requested capability scope exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    if capability.ttl > policy.body.ttl_seconds {
        return Err(CliError::cli_other_error(
            "requested capability ttl exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "requested capability expires after the federated delegation policy validity window"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_requested_capability_within_parent_snapshot(
    capability: &crate::policy::DefaultCapability,
    parent_snapshot: &CapabilitySnapshot,
    now: u64,
) -> Result<(), CliError> {
    let parent_scope: ChioScope = serde_json::from_str(&parent_snapshot.grants_json)?;
    if !capability.scope.is_subset_of(&parent_scope) {
        return Err(CliError::cli_other_error(
            "requested capability scope exceeds the imported upstream capability scope".to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > parent_snapshot.expires_at {
        return Err(CliError::cli_other_error(
            "requested capability expires after the imported upstream capability validity window"
                .to_string(),
        ));
    }
    if now >= parent_snapshot.expires_at {
        return Err(CliError::cli_other_error(
            "imported upstream capability has already expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_capability_snapshot(
    token: &CapabilityToken,
    delegation_depth: u64,
    parent_capability_id: Option<String>,
) -> Result<CapabilitySnapshot, CliError> {
    Ok(CapabilitySnapshot {
        capability_id: token.id.clone(),
        subject_key: token.subject.to_hex(),
        issuer_key: token.issuer.to_hex(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        grants_json: serde_json::to_string(&token.scope)?,
        delegation_depth,
        parent_capability_id,
    })
}

pub(crate) fn build_federated_delegation_anchor_snapshot(
    policy: &FederatedDelegationPolicyDocument,
    subject_key: &str,
    challenge: &PassportPresentationChallenge,
    now: u64,
    parent_capability: Option<&CapabilitySnapshot>,
) -> Result<CapabilitySnapshot, CliError> {
    let anchor_descriptor = json!({
        "policySha256": sha256_hex(&canonical_json_bytes(&policy.body)?),
        "subjectKey": subject_key,
        "verifier": challenge.verifier,
        "nonce": challenge.nonce,
        "challengeIssuedAt": challenge.issued_at,
        "challengeExpiresAt": challenge.expires_at,
        "parentCapabilityId": parent_capability.map(|snapshot| snapshot.capability_id.clone()),
    });
    Ok(CapabilitySnapshot {
        capability_id: format!(
            "fed-del-{}",
            sha256_hex(&canonical_json_bytes(&anchor_descriptor)?)
        ),
        subject_key: subject_key.to_string(),
        issuer_key: policy.body.signer_public_key.to_hex(),
        issued_at: now,
        expires_at: parent_capability
            .map(|snapshot| snapshot.expires_at.min(policy.body.expires_at))
            .unwrap_or(policy.body.expires_at),
        grants_json: serde_json::to_string(&policy.body.scope)?,
        delegation_depth: parent_capability
            .map(|snapshot| snapshot.delegation_depth.saturating_add(1))
            .unwrap_or(0),
        parent_capability_id: None,
    })
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ToolReceiptQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// HTTP query parameters for the GET /v1/receipts/query endpoint.
/// Supports receipt filters and cursor pagination.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryHttpQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub min_cost: Option<u64>,
    #[serde(default)]
    pub max_cost: Option<u64>,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub agent_subject: Option<String>,
}

/// Query parameters for GET /v1/agents/:subject_key/receipts.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentReceiptsHttpQuery {
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationQuery {
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCompareRequest {
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_policy: Option<PassportVerifierPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Response body for GET /v1/receipts/query.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryResponse {
    pub total_count: u64,
    pub next_cursor: Option<u64>,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateRequest {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateResponse {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateRequest {
    pub receipt_id: String,
    pub adapter_kind: String,
    pub evidence_id: String,
    pub observed_units: u64,
    pub billed_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub recorded_at: u64,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateResponse {
    pub receipt_id: String,
    pub evidence: MeteredBillingEvidenceRecord,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionIssueRequest {
    pub query: UnderwritingPolicyInputQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_bond_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionRequest {
    pub query: CapitalBookQuery,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_instruction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionRequest {
    pub query: CapitalBookQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleIssueRequest {
    pub query: CreditLossLifecycleQuery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_window: Option<CapitalExecutionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<CapitalExecutionRail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderIssueRequest {
    pub report: LiabilityProviderReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_provider_record_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteRequestIssueRequest {
    pub provider_id: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub requested_coverage_amount: MonetaryAmount,
    pub requested_effective_from: u64,
    pub requested_effective_until: u64,
    pub risk_package: SignedCreditProviderRiskPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteResponseIssueRequest {
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_quote_ref: String,
    pub disposition: LiabilityQuoteDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_quote_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_terms: Option<LiabilityQuoteTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityIssueRequest {
    pub quote_request: SignedLiabilityQuoteRequest,
    pub facility: SignedCreditFacility,
    pub underwriting_decision: SignedUnderwritingDecision,
    pub capital_book: SignedCapitalBookReport,
    pub envelope: LiabilityPricingAuthorityEnvelope,
    pub max_coverage_amount: MonetaryAmount,
    pub max_premium_amount: MonetaryAmount,
    pub expires_at: u64,
    pub auto_bind_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPlacementIssueRequest {
    pub quote_response: SignedLiabilityQuoteResponse,
    pub selected_coverage_amount: MonetaryAmount,
    pub selected_premium_amount: MonetaryAmount,
    pub effective_from: u64,
    pub effective_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityBoundCoverageIssueRequest {
    pub placement: SignedLiabilityPlacement,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<u64>,
    pub effective_from: u64,
    pub effective_until: u64,
    pub coverage_amount: MonetaryAmount,
    pub premium_amount: MonetaryAmount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityAutoBindIssueRequest {
    pub authority: SignedLiabilityPricingAuthority,
    pub quote_response: SignedLiabilityQuoteResponse,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPackageIssueRequest {
    pub bound_coverage: SignedLiabilityBoundCoverage,
    pub exposure: SignedExposureLedgerReport,
    pub bond: SignedCreditBond,
    pub loss_event: SignedCreditLossLifecycle,
    pub claimant: String,
    pub claim_event_at: u64,
    pub claim_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub narrative: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimResponseIssueRequest {
    pub claim: SignedLiabilityClaimPackage,
    pub provider_response_ref: String,
    pub disposition: LiabilityClaimResponseDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimDisputeIssueRequest {
    pub provider_response: SignedLiabilityClaimResponse,
    pub opened_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimAdjudicationIssueRequest {
    pub dispute: SignedLiabilityClaimDispute,
    pub adjudicator: String,
    pub outcome: LiabilityClaimAdjudicationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awarded_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutInstructionIssueRequest {
    pub adjudication: SignedLiabilityClaimAdjudication,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutReceiptIssueRequest {
    pub payout_instruction: SignedLiabilityClaimPayoutInstruction,
    pub payout_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimPayoutReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementInstructionIssueRequest {
    pub payout_receipt: SignedLiabilityClaimPayoutReceipt,
    pub capital_book: SignedCapitalBookReport,
    pub settlement_kind: LiabilityClaimSettlementKind,
    pub settlement_amount: MonetaryAmount,
    pub topology: LiabilityClaimSettlementRoleTopology,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementReceiptIssueRequest {
    pub settlement_instruction: SignedLiabilityClaimSettlementInstruction,
    pub settlement_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimSettlementReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    pub observed_payer_id: String,
    pub observed_payee_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TrustHttpError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl TrustHttpError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub(crate) fn into_response(self) -> Response {
        plain_http_error(self.status, &self.message)
    }
}

impl From<TrustHttpError> for CliError {
    fn from(error: TrustHttpError) -> Self {
        CliError::cli_other_error(error.message)
    }
}

impl From<ReceiptStoreError> for TrustHttpError {
    fn from(error: ReceiptStoreError) -> Self {
        trust_http_error_from_receipt_store(error)
    }
}

impl From<CliError> for TrustHttpError {
    fn from(error: CliError) -> Self {
        TrustHttpError::internal(error.to_string())
    }
}

pub(crate) fn liability_market_http_error(message: &str) -> Response {
    let status = if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("already")
        || message.contains("stale")
        || message.contains("unsupported")
        || message.contains("not active")
        || message.contains("superseded")
        || message.contains("expires")
        || message.contains("mismatch")
        || message.contains("must match")
        || message.contains("cannot be issued")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    plain_http_error(status, message)
}

#[derive(Debug, Clone)]
pub(crate) enum UnderwritingQuotedExposure {
    None,
    Single(MonetaryAmount),
    MixedCurrencies(BTreeSet<String>),
}

impl UnderwritingQuotedExposure {
    pub(crate) fn amount_for_pricing(&self) -> Option<MonetaryAmount> {
        match self {
            Self::Single(amount) => Some(amount.clone()),
            Self::None | Self::MixedCurrencies(_) => None,
        }
    }

    pub(crate) fn apply_to_artifact(
        &self,
        artifact: &mut chio_kernel::UnderwritingDecisionArtifact,
    ) {
        let Self::MixedCurrencies(currencies) = self else {
            return;
        };
        if artifact.premium.state != chio_kernel::UnderwritingPremiumState::Quoted {
            return;
        }

        artifact.premium.state = chio_kernel::UnderwritingPremiumState::Withheld;
        artifact.premium.basis_points = None;
        artifact.premium.quoted_amount = None;
        artifact.premium.rationale = format!(
            "premium is withheld because governed exposure spans multiple currencies: {}",
            currencies.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChildReceiptQuery {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_request_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub terminal_state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecordView {
    pub capability_id: String,
    pub revoked_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    pub count: usize,
    pub revocations: Vec<RevocationRecordView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptListResponse {
    pub configured: bool,
    pub backend: String,
    pub kind: String,
    pub count: usize,
    pub filters: Value,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BudgetQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug)]
pub struct BudgetUsageView {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
    pub updated_at: i64,
    pub seq: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWire<'a> {
    capability_id: &'a str,
    grant_index: u32,
    invocation_count: u32,
    total_exposure_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWireInput {
    capability_id: String,
    grant_index: u32,
    invocation_count: u32,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default)]
    seq: Option<u64>,
}

impl Serialize for BudgetUsageView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BudgetUsageViewWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: Some(self.total_cost_realized_spend),
            updated_at: self.updated_at,
            seq: self.seq,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BudgetUsageView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BudgetUsageViewWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            invocation_count: wire.invocation_count,
            total_cost_exposed: require_budget_amount(
                wire.total_exposure_charged,
                "`totalExposureCharged`",
            )?,
            total_cost_realized_spend: wire.total_realized_spend.unwrap_or(0),
            updated_at: wire.updated_at,
            seq: wire.seq,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    pub count: usize,
    pub usages: Vec<BudgetUsageView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterStatusResponse {
    pub(crate) self_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_url: Option<String>,
    pub(crate) role: String,
    pub(crate) has_quorum: bool,
    pub(crate) quorum_size: usize,
    pub(crate) reachable_nodes: usize,
    pub(crate) election_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
    pub(crate) replication: ClusterReplicationHeadsView,
    pub(crate) peers: Vec<PeerStatusView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PeerStatusView {
    pub(crate) peer_url: String,
    pub(crate) health: String,
    pub(crate) partitioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_contact_at: Option<u64>,
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_cursor: Option<RevocationCursorView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_cursor: Option<BudgetCursorView>,
    pub(crate) snapshot_applied_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_snapshot_at: Option<u64>,
    pub(crate) delta_records_since_snapshot: u64,
    pub(crate) force_snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterReplicationHeadsView {
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    pub(crate) budget_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_cursor: Option<RevocationCursorView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterStateSnapshotResponse {
    pub(crate) generated_at: u64,
    #[serde(default)]
    pub(crate) election_term: u64,
    pub(crate) replication: ClusterReplicationHeadsView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<AuthoritySnapshotView>,
    pub(crate) revocations: Vec<RevocationRecordView>,
    pub(crate) tool_receipts: Vec<StoredReceiptView>,
    pub(crate) child_receipts: Vec<StoredReceiptView>,
    pub(crate) lineage: Vec<StoredLineageView>,
    pub(crate) budgets: Vec<BudgetUsageView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_mutation_events: Vec<BudgetMutationEventView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterPartitionRequest {
    #[serde(default)]
    pub(crate) blocked_peer_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterPartitionResponse {
    pub(crate) self_url: String,
    pub(crate) blocked_peer_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_url: Option<String>,
    pub(crate) role: String,
    pub(crate) has_quorum: bool,
    pub(crate) reachable_nodes: usize,
    pub(crate) quorum_size: usize,
    pub(crate) election_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterAuthorityLeaseView {
    pub(crate) authority_id: String,
    pub(crate) leader_url: String,
    pub(crate) term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) term_started_at: Option<u64>,
    pub(crate) lease_expires_at: u64,
    pub(crate) lease_ttl_ms: u64,
    pub(crate) lease_valid: bool,
}

/// Trust-control heartbeat that refreshes a held authority lease before it
/// expires. Wire shape mirrors
/// `spec/schemas/chio-wire/v1/trust-control/heartbeat.schema.json`: the lease
/// is named by (`leaseId`, `leaseEpoch`), the leader claiming continued
/// ownership by `leaderUrl`, and the observation instant by `observedAt`
/// (unix milliseconds). Deserialization is fail-closed: unknown fields are
/// rejected and the non-negative integer fields decode as unsigned so a
/// negative timestamp or epoch cannot be smuggled in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseHeartbeatRequest {
    pub lease_id: String,
    pub lease_epoch: u64,
    pub leader_url: String,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_expires_at: Option<u64>,
}

/// Typed reason carried by a [`LeaseTerminateRequest`]. Mirrors the `reason`
/// enum in `spec/schemas/chio-wire/v1/trust-control/terminate.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseTerminationReason {
    /// Planned reassignment of the lease to a successor leader.
    LeaderHandoff,
    /// Detected loss of cluster quorum.
    QuorumLost,
    /// Explicit operator-initiated stepdown.
    OperatorStepdown,
    /// A higher election term superseded the lease.
    TermAdvanced,
}

/// Trust-control request that voluntarily releases a held authority lease
/// before its TTL expires. Wire shape mirrors
/// `spec/schemas/chio-wire/v1/trust-control/terminate.schema.json`: the lease
/// is named by (`leaseId`, `leaseEpoch`), the releasing leader by `leaderUrl`,
/// and a typed `reason` distinguishes leader handoff from quorum loss or
/// operator stepdown. Deserialization is fail-closed (unknown fields rejected,
/// non-negative integers decode as unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseTerminateRequest {
    pub lease_id: String,
    pub lease_epoch: u64,
    pub leader_url: String,
    pub reason: LeaseTerminationReason,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_leader_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationCursorView {
    pub(crate) revoked_at: i64,
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetCursorView {
    pub(crate) seq: u64,
    pub(crate) updated_at: i64,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetMutationAuthorityView {
    pub(crate) authority_id: String,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetMutationEventView {
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hold_id: Option<String>,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) allowed: Option<bool>,
    pub(crate) recorded_at: i64,
    pub(crate) event_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage_seq: Option<u64>,
    pub(crate) exposure_units: u64,
    pub(crate) realized_spend_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_invocations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_cost_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) invocation_count_after: u32,
    pub(crate) total_cost_exposed_after: u64,
    pub(crate) total_cost_realized_spend_after: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<BudgetMutationAuthorityView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthoritySnapshotView {
    pub(crate) public_key_hex: String,
    pub(crate) generation: u64,
    pub(crate) rotated_at: u64,
    pub(crate) trusted_keys: Vec<AuthorityTrustedKeyView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorityTrustedKeyView {
    pub(crate) public_key_hex: String,
    pub(crate) generation: u64,
    pub(crate) activated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationDeltaQuery {
    #[serde(default)]
    pub(crate) after_revoked_at: Option<i64>,
    #[serde(default)]
    pub(crate) after_capability_id: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationDeltaResponse {
    pub(crate) records: Vec<RevocationRecordView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptDeltaQuery {
    #[serde(default)]
    pub(crate) after_seq: Option<u64>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredReceiptView {
    pub(crate) seq: u64,
    pub(crate) receipt: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptDeltaResponse {
    pub(crate) records: Vec<StoredReceiptView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredLineageView {
    pub(crate) seq: u64,
    pub(crate) snapshot: CapabilitySnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LineageDeltaResponse {
    pub(crate) records: Vec<StoredLineageView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetDeltaQuery {
    #[serde(default)]
    pub(crate) after_seq: Option<u64>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetDeltaResponse {
    pub(crate) records: Vec<BudgetUsageView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mutation_events: Vec<BudgetMutationEventView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetWriteCommitView {
    pub(crate) budget_seq: u64,
    pub(crate) commit_index: u64,
    pub(crate) quorum_committed: bool,
    pub(crate) quorum_size: usize,
    pub(crate) committed_nodes: usize,
    pub(crate) witness_urls: Vec<String>,
    pub(crate) authority_id: String,
    pub(crate) budget_term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetAuthorityMetadataView {
    pub(crate) authority_id: String,
    pub(crate) leader_url: String,
    pub(crate) budget_term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
    pub(crate) lease_expires_at: u64,
    pub(crate) lease_ttl_ms: u64,
    pub(crate) guarantee_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit_index: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TryIncrementBudgetRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) max_invocations: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TryIncrementBudgetResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
}

#[derive(Debug)]
pub(crate) struct TryChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) max_invocations: Option<u32>,
    pub(crate) cost_units: u64,
    pub(crate) max_cost_per_invocation: Option<u64>,
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct TryChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) allowed: bool,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug)]
pub(crate) struct ReverseChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) cost_units: u64,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ReverseChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug)]
pub(crate) struct ReduceChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) cost_units: u64,
    pub(crate) exposure_units: Option<u64>,
    pub(crate) realized_spend_units: Option<u64>,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ReduceChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) released_exposure_units: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_invocations: Option<u32>,
    exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_exposure_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_total_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    max_invocations: Option<u32>,
    #[serde(default)]
    exposure_units: Option<u64>,
    #[serde(default)]
    max_exposure_per_invocation: Option<u64>,
    #[serde(default)]
    max_total_exposure_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl Serialize for TryChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TryChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            max_invocations: self.max_invocations,
            exposure_units: self.cost_units,
            max_exposure_per_invocation: self.max_cost_per_invocation,
            max_total_exposure_units: self.max_total_cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TryChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TryChargeCostRequestWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            max_invocations: wire.max_invocations,
            cost_units: require_budget_amount(wire.exposure_units, "`exposureUnits`")?,
            max_cost_per_invocation: wire.max_exposure_per_invocation,
            max_total_cost_units: wire.max_total_exposure_units,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    allowed: bool,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
}

impl Serialize for TryChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TryChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            allowed: self.allowed,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TryChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TryChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            allowed: wire.allowed,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    exposure_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl Serialize for ReverseChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReverseChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            exposure_units: self.cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReverseChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReverseChargeCostRequestWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            cost_units: require_budget_amount(wire.exposure_units, "`exposureUnits`")?,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
}

impl Serialize for ReverseChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReverseChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReverseChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReverseChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    realized_spend_units: Option<u64>,
    reduction_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    authorized_exposure_units: Option<u64>,
    #[serde(default)]
    realized_spend_units: Option<u64>,
    #[serde(default)]
    reduction_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl ReduceChargeCostRequest {
    pub(crate) fn release_units(&self) -> u64 {
        self.cost_units
    }
}

impl Serialize for ReduceChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReduceChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            authorized_exposure_units: self.exposure_units,
            realized_spend_units: self.realized_spend_units,
            reduction_units: self.cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReduceChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReduceChargeCostRequestWireInput::deserialize(deserializer)?;
        let exposure_units = wire.authorized_exposure_units;
        let cost_units = match wire.reduction_units {
            Some(cost_units) => cost_units,
            None => {
                let authorized_exposure_units = exposure_units.ok_or_else(|| {
                    serde::de::Error::missing_field(
                        "one of `reductionUnits` or `authorizedExposureUnits`",
                    )
                })?;
                let realized_spend_units = wire
                    .realized_spend_units
                    .ok_or_else(|| serde::de::Error::missing_field("`realizedSpendUnits`"))?;
                authorized_exposure_units
                    .checked_sub(realized_spend_units)
                    .ok_or_else(|| {
                        serde::de::Error::custom(
                            "`realizedSpendUnits` cannot exceed `authorizedExposureUnits`",
                        )
                    })?
            }
        };
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            cost_units,
            exposure_units,
            realized_spend_units: wire.realized_spend_units,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    released_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    released_exposure_units: Option<u64>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
}

impl Serialize for ReduceChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReduceChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            invocation_count: self.invocation_count,
            released_exposure_units: self.released_exposure_units,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReduceChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReduceChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            released_exposure_units: wire.released_exposure_units,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
        })
    }
}

fn require_budget_amount<E>(amount: Option<u64>, missing_field_name: &str) -> Result<u64, E>
where
    E: serde::de::Error,
{
    amount.ok_or_else(|| E::custom(format!("missing required field {missing_field_name}")))
}

#[cfg(test)]
mod cluster_lease_rpc_tests {
    use chio_test_support::prelude::*;

    use super::{LeaseHeartbeatRequest, LeaseTerminateRequest, LeaseTerminationReason};

    #[test]
    fn lease_heartbeat_request_round_trips_camel_case() {
        let request = LeaseHeartbeatRequest {
            lease_id: "lease-7".to_string(),
            lease_epoch: 3,
            leader_url: "https://node-a.example/v1".to_string(),
            observed_at: 1_700_000_000_000,
            proposed_expires_at: Some(1_700_000_030_000),
        };
        let value = serde_json::to_value(&request).test_unwrap();
        assert_eq!(value["leaseId"], "lease-7");
        assert_eq!(value["leaseEpoch"], 3);
        assert_eq!(value["leaderUrl"], "https://node-a.example/v1");
        assert_eq!(value["observedAt"], 1_700_000_000_000u64);
        assert_eq!(value["proposedExpiresAt"], 1_700_000_030_000u64);

        let decoded: LeaseHeartbeatRequest = serde_json::from_value(value).test_unwrap();
        assert_eq!(decoded.lease_id, request.lease_id);
        assert_eq!(decoded.lease_epoch, request.lease_epoch);
        assert_eq!(decoded.proposed_expires_at, request.proposed_expires_at);
    }

    #[test]
    fn lease_heartbeat_request_optional_expiry_is_omitted_when_absent() {
        let json =
            r#"{"leaseId":"lease-1","leaseEpoch":0,"leaderUrl":"https://n/1","observedAt":1}"#;
        let decoded: LeaseHeartbeatRequest = serde_json::from_str(json).test_unwrap();
        assert!(decoded.proposed_expires_at.is_none());
        let reserialized = serde_json::to_value(&decoded).test_unwrap();
        assert!(reserialized.get("proposedExpiresAt").is_none());
    }

    #[test]
    fn lease_heartbeat_request_rejects_unknown_field() {
        let json = r#"{"leaseId":"lease-1","leaseEpoch":0,"leaderUrl":"https://n/1","observedAt":1,"rogue":true}"#;
        assert!(serde_json::from_str::<LeaseHeartbeatRequest>(json).is_err());
    }

    #[test]
    fn lease_heartbeat_request_rejects_negative_epoch() {
        let json =
            r#"{"leaseId":"lease-1","leaseEpoch":-1,"leaderUrl":"https://n/1","observedAt":1}"#;
        assert!(serde_json::from_str::<LeaseHeartbeatRequest>(json).is_err());
    }

    #[test]
    fn lease_terminate_request_round_trips_with_typed_reason() {
        let request = LeaseTerminateRequest {
            lease_id: "lease-9".to_string(),
            lease_epoch: 5,
            leader_url: "https://node-b.example/v1".to_string(),
            reason: LeaseTerminationReason::LeaderHandoff,
            observed_at: 1_700_000_100_000,
            successor_leader_url: Some("https://node-c.example/v1".to_string()),
        };
        let value = serde_json::to_value(&request).test_unwrap();
        assert_eq!(value["reason"], "leader_handoff");
        assert_eq!(value["successorLeaderUrl"], "https://node-c.example/v1");

        let decoded: LeaseTerminateRequest = serde_json::from_value(value).test_unwrap();
        assert_eq!(decoded.reason, LeaseTerminationReason::LeaderHandoff);
        assert_eq!(decoded.successor_leader_url, request.successor_leader_url);
    }

    #[test]
    fn lease_termination_reason_variants_use_snake_case() {
        for (reason, wire) in [
            (LeaseTerminationReason::LeaderHandoff, "leader_handoff"),
            (LeaseTerminationReason::QuorumLost, "quorum_lost"),
            (
                LeaseTerminationReason::OperatorStepdown,
                "operator_stepdown",
            ),
            (LeaseTerminationReason::TermAdvanced, "term_advanced"),
        ] {
            assert_eq!(serde_json::to_value(reason).test_unwrap(), wire);
            let decoded: LeaseTerminationReason =
                serde_json::from_value(serde_json::json!(wire)).test_unwrap();
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn lease_terminate_request_rejects_unknown_reason() {
        let json = r#"{"leaseId":"l","leaseEpoch":0,"leaderUrl":"https://n/1","reason":"mutiny","observedAt":1}"#;
        assert!(serde_json::from_str::<LeaseTerminateRequest>(json).is_err());
    }

    #[test]
    fn lease_terminate_request_rejects_unknown_field() {
        let json = r#"{"leaseId":"l","leaseEpoch":0,"leaderUrl":"https://n/1","reason":"quorum_lost","observedAt":1,"rogue":1}"#;
        assert!(serde_json::from_str::<LeaseTerminateRequest>(json).is_err());
    }
}
