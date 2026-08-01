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
pub(crate) const FINDINGS_PUBLISH_PATH: &str = "/v1/findings/publish";
pub(crate) const FINDING_PATH: &str = "/v1/findings/{finding_id}";
pub(crate) const FINDINGS_SEARCH_PATH: &str = "/v1/findings/search";
pub(crate) const FINDINGS_RECIPES_PATH: &str = "/v1/findings/recipes";
pub(crate) const FINDINGS_PROFILES_PATH: &str = "/v1/findings/profiles";
pub(crate) const FINDINGS_COLLATERAL_PATH: &str = "/v1/findings/collateral";
pub(crate) const FINDING_ACTIVATE_PATH: &str = "/v1/findings/{finding_id}/activate";
pub(crate) const FINDING_PARTICIPATION_PATH: &str = "/v1/findings/{finding_id}/participation";
pub(crate) const FINDING_ADMISSION_PATH: &str = "/v1/findings/{finding_id}/admission";
pub(crate) const FINDING_PURCHASE_PATH: &str = "/v1/findings/{finding_id}/purchase";
/// Authenticated canonical challenge-envelope submission.
pub(crate) const FINDING_CHALLENGES_PATH: &str = "/v1/findings/{finding_id}/challenges";
pub(crate) const FINDING_STATUS_ROOT_PATH: &str = "/v1/findings/status/{feed}/root";
pub(crate) const FINDING_STATUS_PROOF_PATH: &str = "/v1/findings/status/{feed}/proof/{finding_id}";
pub(crate) const FINDING_STATUS_INTENTS_PATH: &str = "/v1/findings/status/{feed}/intents";
pub(crate) const OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH: &str = "/v1/registry/market/fees/issue";
pub(crate) const OPEN_MARKET_PENALTY_ISSUE_PATH: &str = "/v1/registry/market/penalties/issue";
pub(crate) const OPEN_MARKET_PENALTY_EVALUATE_PATH: &str = "/v1/registry/market/penalties/evaluate";
pub(crate) const FISCAL_RUNTIME_STATUS_PATH: &str = "/v1/fiscal/runtime";
pub(crate) const FISCAL_PROPOSALS_PATH: &str = "/v1/fiscal/proposals";
pub(crate) const FISCAL_PROPOSAL_PREVIEW_PATH: &str = "/v1/fiscal/proposals/preview";
pub(crate) const FISCAL_PROPOSAL_ADMIT_PATH: &str = "/v1/fiscal/proposals/admit";
pub(crate) const FISCAL_APPROVALS_PATH: &str = "/v1/fiscal/approvals";
pub(crate) const FISCAL_ACTIVATIONS_PATH: &str = "/v1/fiscal/activations";
pub(crate) const FISCAL_RESOLVE_PATH: &str = "/v1/fiscal/resolve";
pub(crate) const FISCAL_MARKETPLACE_PRICE_PATH: &str = "/v1/fiscal/marketplace/price";
pub(crate) const FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH: &str = "/v1/fiscal/marketplace/credit-limit";
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
pub(crate) const BUDGET_CAPTURE_INVOCATION_PATH: &str = "/v1/budgets/capture-invocation";
pub(crate) const BUDGET_RELEASE_EXPOSURE_PATH: &str = "/v1/budgets/release-exposure";
pub(crate) const BUDGET_RECONCILE_SPEND_PATH: &str = "/v1/budgets/reconcile-spend";
pub(crate) const STRUCTURED_BUDGET_AUTHORIZE_PATH: &str = "/v1/budgets/holds/authorize";
pub(crate) const STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH: &str =
    "/v1/budgets/holds/authorize-cumulative";
pub(crate) const STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH: &str =
    "/v1/budgets/cumulative-approval/lookup";
pub(crate) const STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH: &str = "/v1/budgets/holds/cancel-captured";
pub(crate) const STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH: &str =
    "/v1/budgets/holds/capture-invocation";
pub(crate) const STRUCTURED_BUDGET_FENCED_REVERSE_PATH: &str = "/v1/budgets/holds/reverse";
pub(crate) const STRUCTURED_BUDGET_RELEASE_PATH: &str = "/v1/budgets/holds/release";
pub(crate) const STRUCTURED_BUDGET_RECONCILE_PATH: &str = "/v1/budgets/holds/reconcile";
pub(crate) const STRUCTURED_BUDGET_CAPTURE_SPEND_PATH: &str = "/v1/budgets/holds/capture-spend";
pub(crate) const INTERNAL_CLUSTER_STATUS_PATH: &str = "/v1/internal/cluster/status";
pub(crate) const INTERNAL_CLUSTER_SNAPSHOT_PATH: &str = "/v1/internal/cluster/snapshot";
pub(crate) const INTERNAL_CLUSTER_PARTITION_PATH: &str = "/v1/internal/cluster/partition";
pub(crate) const INTERNAL_AUTHORITY_SNAPSHOT_PATH: &str = "/v1/internal/authority/snapshot";
pub(crate) const INTERNAL_ADMISSION_AUTHORITY_PATH: &str = "/v1/internal/admission-authority";
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
pub(crate) const COMPTROLLER_SURFACE_PATH: &str = "/v1/reports/comptroller-surface";
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
/// Hard cap on a single peer-response body the cluster client will buffer and
/// decode. Matches the HTTP relay body-size posture; an oversized or
/// streaming-forever body is a typed error, not an unbounded allocation.
pub(crate) const MAX_PEER_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const CLUSTER_SNAPSHOT_RECORD_THRESHOLD: u64 = 8;
