// Trust-control service wire types and shared helpers.
//
// This module owns the data types for the trust-control surface. The shared
// import set lives in the parent `trust_control.rs` and is inherited here via
// `use super::*;` so every sibling module composes against the same scope.

use super::*;

#[path = "service_types/admission_authority.rs"]
mod admission_authority;
#[path = "service_types/budget_lifecycle.rs"]
mod budget_lifecycle;
#[path = "service_types/cluster_budget.rs"]
mod cluster_budget;
#[path = "service_types/config.rs"]
mod config;
#[cfg(feature = "cognition-market-experimental")]
#[path = "service_types/finding_market_config.rs"]
mod finding_market_config;
#[path = "service_types/paths.rs"]
mod paths;
#[path = "service_types/requests.rs"]
mod requests;
#[path = "service_types/responses.rs"]
mod responses;
#[path = "service_types/state.rs"]
mod state;
#[path = "service_types/structured_budget.rs"]
mod structured_budget;

pub(crate) use self::admission_authority::*;
pub(crate) use self::budget_lifecycle::BudgetMutationLifecycleView;
pub(crate) use self::cluster_budget::{
    AbandonedSeqRange, AuthoritySnapshotView, AuthorityTrustedKeyView, BudgetAuthorityMetadataView,
    BudgetAuthorizeExposureDecision, BudgetCursorView, BudgetDeltaQuery, BudgetDeltaResponse,
    BudgetMutationAuthorityView, BudgetMutationEventView, BudgetOriginAck, BudgetWriteCommitView,
    CaptureInvocationDecision, CaptureInvocationRequest, CaptureInvocationResponse,
    ClusterAuthorityLeaseView, ClusterPartitionRequest, ClusterPartitionResponse,
    ClusterReplicationHeadsView, ClusterStateSnapshotResponse, ClusterStatusResponse,
    LineageDeltaResponse, PeerStatusView, ReceiptDeltaQuery, ReceiptDeltaResponse,
    ReduceChargeCostRequest, ReduceChargeCostResponse, ReverseChargeCostRequest,
    ReverseChargeCostResponse, RevocationCursorView, RevocationDeltaQuery, RevocationDeltaResponse,
    StoredLineageView, StoredReceiptView, TryChargeCostRequest, TryChargeCostResponse,
    TryIncrementBudgetRequest, TryIncrementBudgetResponse,
};
pub use self::cluster_budget::{
    LeaseHeartbeatRequest, LeaseTerminateRequest, LeaseTerminationReason,
};
pub(crate) use self::config::validate_control_secret;
pub use self::config::{TrustFiscalRuntimeConfig, TrustServiceConfig};
#[cfg(feature = "cognition-market-experimental")]
pub(crate) use self::finding_market_config::{
    require_status_feed_through, FINDING_STATUS_MAX_EPOCH_AGE_SECS,
};
#[cfg(feature = "cognition-market-experimental")]
pub use self::finding_market_config::{
    FindingAuthorityPin, FindingMarketConfig, FindingPoolPin, FindingStatusOperatorPin,
    FindingStatusServiceBond, FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_OPERATOR_ROLE,
};
pub use self::paths::FEDERATED_DELEGATION_POLICY_SCHEMA;
pub(crate) use self::paths::{
    AGENT_RECEIPTS_PATH, AUTHORITY_CACHE_TTL, AUTHORITY_PATH, AUTHORIZATION_CONTEXT_REPORT_PATH,
    AUTHORIZATION_PROFILE_METADATA_PATH, AUTHORIZATION_REVIEW_PACK_PATH, BEHAVIORAL_FEED_PATH,
    BUDGETS_PATH, BUDGET_AUTHORIZE_EXPOSURE_PATH, BUDGET_CAPTURE_INVOCATION_PATH,
    BUDGET_DELTA_MAX_RECORDS, BUDGET_INCREMENT_PATH, BUDGET_RECONCILE_SPEND_PATH,
    BUDGET_RELEASE_EXPOSURE_PATH, CAPITAL_ALLOCATION_ISSUE_PATH, CAPITAL_BOOK_PATH,
    CAPITAL_INSTRUCTION_ISSUE_PATH, CERTIFICATIONS_PATH, CERTIFICATION_DISCOVERY_CONSUME_PATH,
    CERTIFICATION_DISCOVERY_PATH, CERTIFICATION_DISCOVERY_RESOLVE_PATH,
    CERTIFICATION_DISCOVERY_SEARCH_PATH, CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH,
    CERTIFICATION_DISPUTE_PATH, CERTIFICATION_PATH, CERTIFICATION_RESOLVE_PATH,
    CERTIFICATION_REVOKE_PATH, CHILD_RECEIPTS_PATH, CLUSTER_AUTH_FAILURE_BURST,
    CLUSTER_AUTH_FAILURE_WINDOW_SECS, CLUSTER_AUTH_ISSUED_AT_HEADER, CLUSTER_AUTH_MAX_SKEW_SECS,
    CLUSTER_AUTH_SCHEME, CLUSTER_AUTH_SIGNATURE_HEADER, CLUSTER_AUTH_TERM_HEADER,
    CLUSTER_NODE_ID_HEADER, CLUSTER_SNAPSHOT_RECORD_THRESHOLD, COMPTROLLER_SURFACE_PATH,
    CONTROL_HTTP_TIMEOUT, COST_ATTRIBUTION_PATH, CREDIT_BACKTEST_PATH,
    CREDIT_BONDED_EXECUTION_SIMULATION_PATH, CREDIT_BONDS_REPORT_PATH, CREDIT_BOND_ISSUE_PATH,
    CREDIT_BOND_REPORT_PATH, CREDIT_FACILITIES_REPORT_PATH, CREDIT_FACILITY_ISSUE_PATH,
    CREDIT_FACILITY_REPORT_PATH, CREDIT_LOSS_LIFECYCLE_ISSUE_PATH, CREDIT_LOSS_LIFECYCLE_LIST_PATH,
    CREDIT_LOSS_LIFECYCLE_REPORT_PATH, CREDIT_PROVIDER_RISK_PACKAGE_PATH, CREDIT_SCORECARD_PATH,
    CSP_VALUE, DASHBOARD_DIST_DIR, DEFAULT_LIST_LIMIT, ECONOMIC_COMPLETION_FLOW_REPORT_PATH,
    ECONOMIC_RECEIPT_REPORT_PATH, EVIDENCE_EXPORT_PATH, EVIDENCE_IMPORT_PATH, EXPOSURE_LEDGER_PATH,
    FEDERATED_ISSUE_PATH, FEDERATION_EVIDENCE_SHARES_PATH, FEDERATION_POLICIES_PATH,
    FEDERATION_POLICY_EVALUATE_PATH, FEDERATION_POLICY_PATH, FEDERATION_PROVIDERS_PATH,
    FEDERATION_PROVIDER_PATH, FISCAL_ACTIVATIONS_PATH, FISCAL_APPROVALS_PATH,
    FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH, FISCAL_MARKETPLACE_PRICE_PATH, FISCAL_PROPOSALS_PATH,
    FISCAL_PROPOSAL_ADMIT_PATH, FISCAL_PROPOSAL_PREVIEW_PATH, FISCAL_RESOLVE_PATH,
    FISCAL_RUNTIME_STATUS_PATH, GENERIC_GOVERNANCE_CASE_EVALUATE_PATH,
    GENERIC_GOVERNANCE_CASE_ISSUE_PATH, GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH,
    GENERIC_TRUST_ACTIVATION_EVALUATE_PATH, GENERIC_TRUST_ACTIVATION_ISSUE_PATH, HEALTH_PATH,
    INTERNAL_ADMISSION_AUTHORITY_PATH, INTERNAL_AUTHORITY_SNAPSHOT_PATH,
    INTERNAL_BUDGETS_DELTA_PATH, INTERNAL_CHILD_RECEIPTS_DELTA_PATH,
    INTERNAL_CLUSTER_PARTITION_PATH, INTERNAL_CLUSTER_SNAPSHOT_PATH, INTERNAL_CLUSTER_STATUS_PATH,
    INTERNAL_LINEAGE_DELTA_PATH, INTERNAL_REVOCATIONS_DELTA_PATH,
    INTERNAL_TOOL_RECEIPTS_DELTA_PATH, ISSUE_CAPABILITY_PATH,
    LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH, LIABILITY_BOUND_COVERAGE_ISSUE_PATH,
    LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH, LIABILITY_CLAIM_DISPUTE_ISSUE_PATH,
    LIABILITY_CLAIM_PACKAGE_ISSUE_PATH, LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH,
    LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH, LIABILITY_CLAIM_RESPONSE_ISSUE_PATH,
    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH,
    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH, LIABILITY_CLAIM_WORKFLOW_REPORT_PATH,
    LIABILITY_MARKET_WORKFLOW_REPORT_PATH, LIABILITY_PLACEMENT_ISSUE_PATH,
    LIABILITY_PRICING_AUTHORITY_ISSUE_PATH, LIABILITY_PROVIDERS_REPORT_PATH,
    LIABILITY_PROVIDER_ISSUE_PATH, LIABILITY_PROVIDER_RESOLVE_PATH,
    LIABILITY_QUOTE_REQUEST_ISSUE_PATH, LIABILITY_QUOTE_RESPONSE_ISSUE_PATH, LINEAGE_CHAIN_PATH,
    LINEAGE_PATH, LINEAGE_RECORD_PATH, LOCAL_REPUTATION_PATH, MAX_LIST_LIMIT,
    MAX_PEER_RESPONSE_BYTES, METERED_BILLING_RECONCILE_PATH, METERED_BILLING_REPORT_PATH,
    OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH, OPEN_MARKET_PENALTY_EVALUATE_PATH,
    OPEN_MARKET_PENALTY_ISSUE_PATH, OPERATOR_REPORT_PATH, PASSPORT_CHALLENGES_PATH,
    PASSPORT_CHALLENGE_VERIFY_PATH, PASSPORT_ISSUANCE_CREDENTIAL_PATH,
    PASSPORT_ISSUANCE_OFFERS_PATH, PASSPORT_ISSUANCE_TOKEN_PATH, PASSPORT_ISSUER_JWKS_PATH,
    PASSPORT_ISSUER_METADATA_PATH, PASSPORT_OID4VP_REQUESTS_PATH,
    PASSPORT_SD_JWT_TYPE_METADATA_PATH, PASSPORT_STATUSES_PATH, PASSPORT_STATUS_PATH,
    PASSPORT_STATUS_RESOLVE_PATH, PASSPORT_STATUS_REVOKE_PATH, PASSPORT_VERIFIER_POLICIES_PATH,
    PASSPORT_VERIFIER_POLICY_PATH, PORTABLE_NEGATIVE_EVENT_ISSUE_PATH,
    PORTABLE_REPUTATION_EVALUATE_PATH, PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH,
    PUBLIC_CERTIFICATION_METADATA_PATH, PUBLIC_CERTIFICATION_RESOLVE_PATH,
    PUBLIC_CERTIFICATION_SEARCH_PATH, PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
    PUBLIC_DISCOVERY_TTL_SECS, PUBLIC_GENERIC_LISTINGS_PATH, PUBLIC_GENERIC_NAMESPACE_PATH,
    PUBLIC_PASSPORT_CHALLENGE_PATH, PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
    PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH, PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH,
    PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH, PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH,
    PUBLIC_PASSPORT_OID4VP_REQUEST_PATH, PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
    PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH, PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
    RECEIPT_ANALYTICS_PATH, RECEIPT_QUERY_PATH, REPUTATION_COMPARE_PATH, REVOCATIONS_PATH,
    RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH, RUNTIME_ATTESTATION_APPRAISAL_PATH,
    RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH, SCIM_USERS_PATH, SCIM_USER_PATH,
    SETTLEMENT_RECONCILE_PATH, SETTLEMENT_REPORT_PATH, STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH,
    STRUCTURED_BUDGET_AUTHORIZE_PATH, STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH,
    STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH, STRUCTURED_BUDGET_CAPTURE_SPEND_PATH,
    STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH, STRUCTURED_BUDGET_FENCED_REVERSE_PATH,
    STRUCTURED_BUDGET_RECONCILE_PATH, STRUCTURED_BUDGET_RELEASE_PATH, TOOL_RECEIPTS_PATH,
    UNDERWRITING_APPEALS_PATH, UNDERWRITING_APPEAL_RESOLVE_PATH,
    UNDERWRITING_DECISIONS_REPORT_PATH, UNDERWRITING_DECISION_ISSUE_PATH,
    UNDERWRITING_DECISION_PATH, UNDERWRITING_INPUT_PATH, UNDERWRITING_SIMULATION_PATH,
};
#[cfg(feature = "cognition-market-experimental")]
pub(crate) use self::paths::{
    FINDINGS_COLLATERAL_PATH, FINDINGS_PROFILES_PATH, FINDINGS_PUBLISH_PATH, FINDINGS_RECIPES_PATH,
    FINDINGS_SEARCH_PATH, FINDING_ACTIVATE_PATH, FINDING_ADMISSION_PATH, FINDING_CHALLENGES_PATH,
    FINDING_PARTICIPATION_PATH, FINDING_PATH, FINDING_PURCHASE_PATH, FINDING_STATUS_INTENTS_PATH,
    FINDING_STATUS_PROOF_PATH, FINDING_STATUS_ROOT_PATH,
};
pub(crate) use self::requests::{
    build_capability_snapshot, build_federated_delegation_anchor_snapshot,
    ensure_federated_delegation_policy_active,
    ensure_requested_capability_within_delegation_policy,
    ensure_requested_capability_within_parent_snapshot, IssueCapabilityRequest,
    IssueCapabilityResponse, RecordCapabilitySnapshotRequest,
};
pub use self::requests::{
    verify_federated_delegation_policy, AgentReceiptsHttpQuery, CapitalAllocationDecisionRequest,
    CapitalExecutionInstructionRequest, CreateIdentityAssertionRequest, CreateOid4vpRequest,
    CreateOid4vpRequestResponse, CreatePassportChallengeRequest, CreatePassportChallengeResponse,
    CreatePassportIssuanceOfferRequest, CreditBondIssueRequest, CreditFacilityIssueRequest,
    CreditLossLifecycleIssueRequest, EnterpriseAdmissionAudit, EnterpriseProviderDeleteResponse,
    EnterpriseProviderListResponse, FederatedDelegationPolicyBody,
    FederatedDelegationPolicyDocument, FederatedIssueRequest, FederatedIssueResponse,
    LiabilityAutoBindIssueRequest, LiabilityBoundCoverageIssueRequest,
    LiabilityClaimAdjudicationIssueRequest, LiabilityClaimDisputeIssueRequest,
    LiabilityClaimPackageIssueRequest, LiabilityClaimPayoutInstructionIssueRequest,
    LiabilityClaimPayoutReceiptIssueRequest, LiabilityClaimResponseIssueRequest,
    LiabilityClaimSettlementInstructionIssueRequest, LiabilityClaimSettlementReceiptIssueRequest,
    LiabilityPlacementIssueRequest, LiabilityPricingAuthorityIssueRequest,
    LiabilityProviderIssueRequest, LiabilityQuoteRequestIssueRequest,
    LiabilityQuoteResponseIssueRequest, LocalReputationQuery,
    MeteredBillingReconciliationUpdateRequest, MeteredBillingReconciliationUpdateResponse,
    Oid4vpDirectPostForm, PassportPresentationTransport, ReceiptQueryHttpQuery,
    ReceiptQueryResponse, ReputationCompareRequest, SettlementReconciliationUpdateRequest,
    SettlementReconciliationUpdateResponse, ToolReceiptQuery, TrustAuthorityStatus,
    UnderwritingDecisionIssueRequest, VerifierPolicyDeleteResponse, VerifierPolicyListResponse,
    VerifyPassportChallengeRequest, WalletExchangeStatusResponse,
};
pub(crate) use self::responses::{
    liability_market_http_error, project_combined_delegation_chain, TrustHttpError,
    UnderwritingQuotedExposure,
};
pub use self::responses::{
    BudgetListResponse, BudgetQuery, BudgetUsageView, ChildReceiptQuery, ReceiptListResponse,
    RevocationListResponse, RevocationQuery, RevocationRecordView,
};
pub use self::state::TrustControlClient;
pub(crate) use self::state::{
    AuthorityKeyCache, BudgetCursor, CachedBudgetUsage, ClusterConsensusView,
    ClusterPeerClientAuth, ClusterProgress, ClusterRuntimeState, FederationAdmissionRateLimiter,
    PeerHealth, PeerSyncState, RemoteBudgetStore, RemoteCapabilityAuthority, RemoteReceiptStore,
    RemoteRevocationStore, RevocationCursor, TrustServiceState,
};
pub(crate) use self::structured_budget::*;
