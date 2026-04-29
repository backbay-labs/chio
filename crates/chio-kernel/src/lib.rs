//! Chio Runtime Kernel.
//!
//! The kernel is the trusted computing base (TCB) of the Chio protocol.
//! It sits between the untrusted agent and the sandboxed tool servers,
//! mediating every tool invocation.
//!
//! The kernel's responsibilities:
//!
//! 1. **Capability validation** -- verify signatures, time bounds, revocation
//!    status, scope matching, and invocation budgets.
//! 2. **Guard evaluation** -- run policy guards against the tool call before
//!    forwarding it.
//! 3. **Receipt signing** -- produce a signed receipt for every decision
//!    (allow or deny) and append it to the receipt log.
//! 4. **Tool dispatch** -- forward validated requests to the appropriate tool
//!    server over an authenticated channel.
//!
//! The kernel is architecturally invisible to the agent. The agent communicates
//! through an anonymous pipe or Unix domain socket and never learns the kernel's
//! PID, address, or signing key.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod approval;
pub mod approval_channels;
pub mod authority;
pub mod budget_store;
pub mod capability_lineage;
pub mod checkpoint;
pub mod compliance_score;
pub mod cost_attribution;
pub mod dpop;
pub mod evidence_export;
pub mod execution_nonce;
pub mod memory_provenance;
pub mod observability;
pub mod operator_report;
pub mod otel;
pub mod payment;
pub mod post_invocation;
#[allow(deprecated)]
pub mod provider_verdict;
pub mod receipt_analytics;
pub mod receipt_query;
pub mod receipt_store;
mod receipt_support;
mod request_matching;
pub mod revocation_runtime;
pub mod revocation_store;
pub mod runtime;
pub mod session;
pub mod transport;

pub(crate) use std::collections::HashMap;
pub(crate) use std::future::Future;
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) use chio_core::canonical::canonical_json_bytes;
pub(crate) use chio_core::capability::{
    AttestationTrustPolicy, CapabilityToken, ChioScope, Constraint, GovernedApprovalDecision,
    GovernedApprovalToken, GovernedAutonomyTier, Operation, PromptGrant, ResourceGrant,
    RuntimeAssuranceTier, ToolGrant,
};
pub(crate) use chio_core::crypto::{sha256_hex, Keypair};
pub(crate) use chio_core::receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, Decision,
    FinancialReceiptMetadata, GovernedApprovalReceiptMetadata, GovernedAutonomyReceiptMetadata,
    GovernedCommerceReceiptMetadata, GovernedTransactionReceiptMetadata,
    MeteredBillingReceiptMetadata, ReceiptAttributionMetadata, RuntimeAssuranceReceiptMetadata,
    SettlementStatus, ToolCallAction,
};
pub(crate) use chio_core::session::{
    CompleteOperation, CompletionReference, CompletionResult, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, GetPromptOperation,
    NormalizedRoot, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, PromptResult, ReadResourceOperation, RequestId, ResourceContent,
    ResourceDefinition, ResourceTemplateDefinition, ResourceUriClassification, RootDefinition,
    SessionAuthContext, SessionId, SessionOperation, ToolCallOperation,
};
pub(crate) use chio_link::convert::convert_supported_units;
pub(crate) use chio_link::{PriceOracle, PriceOracleError};
pub(crate) use tracing::{debug, info, warn};

pub(crate) use receipt_support::*;
pub(crate) use request_matching::{
    begin_child_request_in_sessions, begin_session_request_in_sessions, check_subject_binding,
    check_time_bounds, complete_session_request_with_terminal_state_in_sessions,
    nested_child_request_id, resolve_matching_grants, session_from_map,
    validate_elicitation_request_in_sessions, validate_sampling_request_in_sessions,
};
pub use request_matching::{
    capability_matches_prompt_request, capability_matches_request,
    capability_matches_request_with_model_metadata, capability_matches_resource_pattern,
    capability_matches_resource_request, capability_matches_resource_subscription,
};

pub use approval::{
    compute_parameter_hash, resume_with_decision, ApprovalChannel, ApprovalContext,
    ApprovalDecision, ApprovalFilter, ApprovalGuard, ApprovalOutcome, ApprovalRequest,
    ApprovalStore, ApprovalStoreError, ApprovalToken, BatchApproval, BatchApprovalStore,
    ChannelError, ChannelHandle, HitlVerdict, InMemoryApprovalStore, InMemoryBatchApprovalStore,
    ResolvedApproval, MAX_APPROVAL_TTL_SECS,
};
pub use approval_channels::{RecordingChannel, WebhookChannel, WebhookPayload};
pub use authority::{
    AuthoritySnapshot, AuthorityStatus, AuthorityStoreError, AuthorityTrustedKeySnapshot,
    CapabilityAuthority, LocalCapabilityAuthority,
};
pub use budget_store::{BudgetStore, BudgetStoreError, BudgetUsageRecord, InMemoryBudgetStore};
pub use capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, StoredCapabilitySnapshot,
};
pub use checkpoint::{
    build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof,
    checkpoint_body_sha256, is_supported_checkpoint_schema, verify_checkpoint_continuity,
    verify_checkpoint_signature, CheckpointError, KernelCheckpoint, KernelCheckpointBody,
    ReceiptInclusionProof, CHECKPOINT_SCHEMA,
};
pub use chio_core::credit::{
    CapitalAllocationDecisionArtifact, CapitalAllocationDecisionFinding,
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode,
    CapitalAllocationDecisionSupportBoundary, CapitalAllocationInstructionDraft, CapitalBookEvent,
    CapitalBookEventKind, CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery,
    CapitalBookReport, CapitalBookRole, CapitalBookSource, CapitalBookSourceKind,
    CapitalBookSummary, CapitalBookSupportBoundary, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionAction, CapitalExecutionInstructionArtifact,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionRailKind,
    CapitalExecutionReconciledState, CapitalExecutionRole, CapitalExecutionWindow,
    CreditBacktestQuery, CreditBacktestReasonCode, CreditBacktestReport, CreditBacktestSummary,
    CreditBacktestWindow, CreditBondArtifact, CreditBondDisposition, CreditBondFinding,
    CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport, CreditBondListSummary,
    CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport, CreditBondRow,
    CreditBondSupportBoundary, CreditBondTerms, CreditBondedExecutionControlPolicy,
    CreditBondedExecutionDecision, CreditBondedExecutionEvaluation, CreditBondedExecutionFinding,
    CreditBondedExecutionFindingCode, CreditBondedExecutionSimulationDelta,
    CreditBondedExecutionSimulationQuery, CreditBondedExecutionSimulationReport,
    CreditBondedExecutionSimulationRequest, CreditBondedExecutionSupportBoundary,
    CreditCertificationState, CreditFacilityArtifact, CreditFacilityCapitalSource,
    CreditFacilityDisposition, CreditFacilityFinding, CreditFacilityLifecycleState,
    CreditFacilityListQuery, CreditFacilityListReport, CreditFacilityListSummary,
    CreditFacilityPrerequisites, CreditFacilityReasonCode, CreditFacilityReport, CreditFacilityRow,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleListSummary, CreditLossLifecycleQuery,
    CreditLossLifecycleReasonCode, CreditLossLifecycleReport, CreditLossLifecycleRow,
    CreditLossLifecycleSummary, CreditLossLifecycleSupportBoundary, CreditProviderFacilitySnapshot,
    CreditProviderRiskPackage, CreditProviderRiskPackageQuery,
    CreditProviderRiskPackageSupportBoundary, CreditRecentLossEntry, CreditRecentLossHistory,
    CreditRecentLossSummary, CreditReserveControlAppealState, CreditReserveControlExecutionState,
    CreditRuntimeAssuranceState, CreditScorecardAnomaly, CreditScorecardAnomalySeverity,
    CreditScorecardBand, CreditScorecardConfidence, CreditScorecardDimension,
    CreditScorecardDimensionKind, CreditScorecardEvidenceKind, CreditScorecardEvidenceReference,
    CreditScorecardProbationStatus, CreditScorecardReasonCode, CreditScorecardReport,
    CreditScorecardReputationContext, CreditScorecardSummary, CreditScorecardSupportBoundary,
    ExposureLedgerCurrencyPosition, ExposureLedgerDecisionEntry, ExposureLedgerEvidenceKind,
    ExposureLedgerEvidenceReference, ExposureLedgerQuery, ExposureLedgerReceiptEntry,
    ExposureLedgerReport, ExposureLedgerSummary, ExposureLedgerSupportBoundary,
    SignedCapitalAllocationDecision, SignedCapitalBookReport, SignedCapitalExecutionInstruction,
    SignedCreditBond, SignedCreditFacility, SignedCreditLossLifecycle,
    SignedCreditProviderRiskPackage, SignedCreditScorecardReport, SignedExposureLedgerReport,
    CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA, CAPITAL_BOOK_REPORT_SCHEMA,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA, CREDIT_BACKTEST_REPORT_SCHEMA,
    CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA, CREDIT_BOND_ARTIFACT_SCHEMA,
    CREDIT_BOND_LIST_REPORT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA, CREDIT_FACILITY_ARTIFACT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA, CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA,
    CREDIT_SCORECARD_SCHEMA, EXPOSURE_LEDGER_SCHEMA, MAX_CREDIT_BACKTEST_WINDOW_LIMIT,
    MAX_CREDIT_BOND_LIST_LIMIT, MAX_CREDIT_FACILITY_LIST_LIMIT,
    MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT, MAX_CREDIT_PROVIDER_LOSS_LIMIT,
    MAX_EXPOSURE_LEDGER_DECISION_LIMIT, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT,
};
pub use chio_core::governance::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    evaluate_generic_governance_case, GenericGovernanceAuthorityScope,
    GenericGovernanceCaseArtifact, GenericGovernanceCaseEvaluation,
    GenericGovernanceCaseEvaluationRequest, GenericGovernanceCaseIssueRequest,
    GenericGovernanceCaseKind, GenericGovernanceCaseState, GenericGovernanceCharterArtifact,
    GenericGovernanceCharterIssueRequest, GenericGovernanceEffectiveState,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference, GenericGovernanceFinding,
    GenericGovernanceFindingCode, SignedGenericGovernanceCase, SignedGenericGovernanceCharter,
    GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA, GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA,
};
pub use chio_core::listing::{
    aggregate_generic_listing_reports, build_generic_trust_activation_artifact,
    ensure_generic_listing_namespace_consistency, evaluate_generic_trust_activation,
    normalize_namespace, GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
    GenericListingCompatibilityReference, GenericListingDivergence, GenericListingFreshnessState,
    GenericListingFreshnessWindow, GenericListingQuery, GenericListingReplicaFreshness,
    GenericListingReport, GenericListingSearchError, GenericListingSearchPolicy,
    GenericListingSearchResponse, GenericListingSearchResult, GenericListingStatus,
    GenericListingSubject, GenericListingSummary, GenericNamespaceArtifact,
    GenericNamespaceLifecycleState, GenericNamespaceOwnership, GenericRegistryPublisher,
    GenericRegistryPublisherRole, GenericTrustActivationArtifact,
    GenericTrustActivationDisposition, GenericTrustActivationEligibility,
    GenericTrustActivationEvaluation, GenericTrustActivationEvaluationRequest,
    GenericTrustActivationFinding, GenericTrustActivationFindingCode,
    GenericTrustActivationIssueRequest, GenericTrustActivationReviewContext,
    GenericTrustAdmissionClass, SignedGenericListing, SignedGenericNamespace,
    SignedGenericTrustActivation, DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS,
    GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_LISTING_NETWORK_SEARCH_SCHEMA,
    GENERIC_LISTING_REPORT_SCHEMA, GENERIC_LISTING_SEARCH_ALGORITHM_V1,
    GENERIC_NAMESPACE_ARTIFACT_SCHEMA, GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA,
    MAX_GENERIC_LISTING_LIMIT,
};
pub use chio_core::market::{
    LiabilityAutoBindDecisionArtifact, LiabilityAutoBindDisposition, LiabilityAutoBindFinding,
    LiabilityAutoBindReasonCode, LiabilityBoundCoverageArtifact,
    LiabilityClaimAdjudicationArtifact, LiabilityClaimAdjudicationOutcome,
    LiabilityClaimDisputeArtifact, LiabilityClaimEvidenceKind, LiabilityClaimEvidenceReference,
    LiabilityClaimPackageArtifact, LiabilityClaimPayoutInstructionArtifact,
    LiabilityClaimPayoutReceiptArtifact, LiabilityClaimPayoutReconciliationState,
    LiabilityClaimResponseArtifact, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementInstructionArtifact, LiabilityClaimSettlementKind,
    LiabilityClaimSettlementReceiptArtifact, LiabilityClaimSettlementReconciliationState,
    LiabilityClaimSettlementRoleBinding, LiabilityClaimSettlementRoleTopology,
    LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow,
    LiabilityClaimWorkflowSummary, LiabilityCoverageClass, LiabilityEvidenceRequirement,
    LiabilityJurisdictionPolicy, LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport,
    LiabilityMarketWorkflowRow, LiabilityMarketWorkflowSummary, LiabilityPlacementArtifact,
    LiabilityPricingAuthorityArtifact, LiabilityPricingAuthorityEnvelope,
    LiabilityPricingAuthorityEnvelopeKind, LiabilityProviderArtifact,
    LiabilityProviderLifecycleState, LiabilityProviderListQuery, LiabilityProviderListReport,
    LiabilityProviderListSummary, LiabilityProviderPolicyReference, LiabilityProviderProvenance,
    LiabilityProviderReport, LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport,
    LiabilityProviderRow, LiabilityProviderSupportBoundary, LiabilityProviderType,
    LiabilityQuoteDisposition, LiabilityQuoteRequestArtifact, LiabilityQuoteResponseArtifact,
    LiabilityQuoteTerms, SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimPayoutInstruction, SignedLiabilityClaimPayoutReceipt,
    SignedLiabilityClaimResponse, SignedLiabilityClaimSettlementInstruction,
    SignedLiabilityClaimSettlementReceipt, SignedLiabilityPlacement,
    SignedLiabilityPricingAuthority, SignedLiabilityProvider, SignedLiabilityQuoteRequest,
    SignedLiabilityQuoteResponse, LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA, LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
    LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA, LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA, LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
    MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT, MAX_LIABILITY_MARKET_WORKFLOW_LIMIT,
    MAX_LIABILITY_PROVIDER_LIST_LIMIT,
};
pub use chio_core::open_market::{
    build_open_market_fee_schedule_artifact, build_open_market_penalty_artifact,
    evaluate_open_market_penalty, OpenMarketAbuseClass, OpenMarketBondClass,
    OpenMarketBondRequirement, OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope,
    OpenMarketEvidenceKind, OpenMarketEvidenceReference, OpenMarketFeeScheduleArtifact,
    OpenMarketFeeScheduleIssueRequest, OpenMarketFinding, OpenMarketFindingCode,
    OpenMarketPenaltyAction, OpenMarketPenaltyArtifact, OpenMarketPenaltyEffectiveState,
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest, OpenMarketPenaltyIssueRequest,
    OpenMarketPenaltyState, SignedOpenMarketFeeSchedule, SignedOpenMarketPenalty,
    OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA, OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
};
pub use chio_core::underwriting::{
    build_underwriting_decision_artifact, evaluate_underwriting_policy_input,
    SignedUnderwritingDecision, SignedUnderwritingPolicyInput, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolution, UnderwritingAppealResolveRequest,
    UnderwritingAppealStatus, UnderwritingBudgetAction, UnderwritingBudgetRecommendation,
    UnderwritingCertificationEvidence, UnderwritingCertificationState,
    UnderwritingComplianceEvidence, UnderwritingDecisionArtifact, UnderwritingDecisionFinding,
    UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
    UnderwritingDecisionOutcome, UnderwritingDecisionPolicy, UnderwritingDecisionQuery,
    UnderwritingDecisionReasonCode, UnderwritingDecisionReport, UnderwritingDecisionRow,
    UnderwritingDecisionSummary, UnderwritingEvidenceKind, UnderwritingEvidenceReference,
    UnderwritingPolicyInput, UnderwritingPolicyInputQuery, UnderwritingPremiumQuote,
    UnderwritingPremiumState, UnderwritingReasonCode, UnderwritingReceiptEvidence,
    UnderwritingRemediation, UnderwritingReputationEvidence, UnderwritingReviewState,
    UnderwritingRiskClass, UnderwritingRiskTaxonomy, UnderwritingRuntimeAssuranceEvidence,
    UnderwritingSignal, UnderwritingSimulationDelta, UnderwritingSimulationReport,
    UnderwritingSimulationRequest, MAX_UNDERWRITING_DECISION_LIMIT, MAX_UNDERWRITING_RECEIPT_LIMIT,
    UNDERWRITING_APPEAL_SCHEMA, UNDERWRITING_COMPLIANCE_EVIDENCE_SCHEMA,
    UNDERWRITING_DECISION_ARTIFACT_SCHEMA, UNDERWRITING_DECISION_POLICY_SCHEMA,
    UNDERWRITING_DECISION_POLICY_VERSION, UNDERWRITING_DECISION_REPORT_SCHEMA,
    UNDERWRITING_POLICY_INPUT_SCHEMA, UNDERWRITING_RISK_TAXONOMY_VERSION,
    UNDERWRITING_SIMULATION_REPORT_SCHEMA,
};
pub use compliance_score::{
    compliance_factor_breakdown, compliance_score, ComplianceFactor, ComplianceFactorBreakdown,
    ComplianceScore, ComplianceScoreConfig, ComplianceScoreInputs, COMPLIANCE_SCORE_MAX,
    DEFAULT_ATTESTATION_STALENESS_SECS, WEIGHT_ATTESTATION_FRESHNESS, WEIGHT_DENY_RATE,
    WEIGHT_POLICY_COVERAGE, WEIGHT_REVOCATION, WEIGHT_VELOCITY_ANOMALY,
};
pub use cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
pub use dpop::{
    is_supported_dpop_schema, verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof,
    DpopProofBody, DPOP_SCHEMA,
};
pub use evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportError, EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt,
};
pub use execution_nonce::{
    is_supported_execution_nonce_schema, mint_execution_nonce, verify_execution_nonce,
    ExecutionNonce, ExecutionNonceConfig, ExecutionNonceError, ExecutionNonceStore,
    InMemoryExecutionNonceStore, NonceBinding, SignedExecutionNonce,
    DEFAULT_EXECUTION_NONCE_STORE_CAPACITY, DEFAULT_EXECUTION_NONCE_TTL_SECS,
    EXECUTION_NONCE_SCHEMA,
};
pub use memory_provenance::{
    classify_memory_action, next_entry_id as next_memory_provenance_entry_id,
    recompute_entry_hash as recompute_memory_provenance_entry_hash, InMemoryMemoryProvenanceStore,
    MemoryActionKind, MemoryProvenanceAppend, MemoryProvenanceEntry, MemoryProvenanceError,
    MemoryProvenanceStore, ProvenanceVerification, UnverifiedReason,
    MEMORY_PROVENANCE_ENTRY_SCHEMA, MEMORY_PROVENANCE_GENESIS_PREV_HASH,
};
pub use observability::metrics::{
    guard_metrics_endpoint, render_guard_metrics_prometheus, GuardMetricFamily,
    MetricsEndpointResponse, PrometheusMetricKind, GUARD_METRICS_PATH, GUARD_METRIC_FAMILIES,
    PROMETHEUS_TEXT_CONTENT_TYPE,
};
pub use operator_report::{behavioral_anomaly_score, BehavioralAnomalyScore, EmaBaselineState};
pub use operator_report::{
    AuthorizationContextReport, AuthorizationContextRow, AuthorizationContextSenderConstraint,
    AuthorizationContextSummary, BehavioralFeedDecisionSummary,
    BehavioralFeedGovernedActionSummary, BehavioralFeedMeteredBillingRow,
    BehavioralFeedMeteredBillingSummary, BehavioralFeedPrivacyBoundary, BehavioralFeedQuery,
    BehavioralFeedReceiptRow, BehavioralFeedReceiptSelection, BehavioralFeedReport,
    BehavioralFeedReputationSummary, BehavioralFeedSettlementSummary, BudgetDimensionProfile,
    BudgetDimensionUsage, BudgetUtilizationReport, BudgetUtilizationRow, BudgetUtilizationSummary,
    ChioOAuthArtifactBoundary, ChioOAuthAuthorizationDiscoveryMetadata,
    ChioOAuthAuthorizationExampleMapping, ChioOAuthAuthorizationMetadataReport,
    ChioOAuthAuthorizationProfile, ChioOAuthAuthorizationReviewPack,
    ChioOAuthAuthorizationReviewPackRecord, ChioOAuthAuthorizationReviewPackSummary,
    ChioOAuthAuthorizationSupportBoundary, ChioOAuthRequestTimeContract, ChioOAuthResourceBinding,
    ChioOAuthSenderConstraintProfile, ComplianceReport, EconomicCompletionFlowReport,
    EconomicCompletionFlowSummary, EconomicReceiptMeteringProjection,
    EconomicReceiptProjectionReport, EconomicReceiptProjectionRow,
    EconomicReceiptProjectionSummary, EconomicReceiptSettlementProjection,
    GovernedAuthorizationCommerceDetail, GovernedAuthorizationDetail,
    GovernedAuthorizationMeteredBillingDetail, GovernedAuthorizationTransactionContext,
    MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationRow, MeteredBillingReconciliationState,
    MeteredBillingReconciliationSummary, OperatorReport, OperatorReportQuery,
    SettlementReconciliationReport, SettlementReconciliationRow, SettlementReconciliationState,
    SettlementReconciliationSummary, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary, SignedBehavioralFeed,
    BEHAVIORAL_FEED_SCHEMA, CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA, CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID,
    CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA, CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE, CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER,
    CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT, CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA,
    CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP, ECONOMIC_COMPLETION_FLOW_SCHEMA,
    MAX_AUTHORIZATION_CONTEXT_LIMIT, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT, MAX_METERED_BILLING_LIMIT,
    MAX_OPERATOR_BUDGET_LIMIT, MAX_SETTLEMENT_BACKLOG_LIMIT, MAX_SHARED_EVIDENCE_LIMIT,
};
pub use payment::{
    AcpPaymentAdapter, CommercePaymentContext, GovernedPaymentContext, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementStatus, ReceiptSettlement, X402PaymentAdapter,
};
pub use post_invocation::{
    PipelineOutcome, PostInvocationContext, PostInvocationHook, PostInvocationPipeline,
    PostInvocationVerdict,
};
pub use provider_verdict::{
    build_tool_call_request, canonical_invocation_bytes, verdict_result_from_response,
    ProviderVerdictError, FABRIC_SHIM_PROVIDER_LANES,
};
pub use receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
pub use receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
pub use receipt_store::{
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, ReceiptStore, ReceiptStoreError,
    RetentionConfig, StoredChildReceipt, StoredToolReceipt,
};
pub use revocation_runtime::{InMemoryRevocationStore, RevocationStore};
pub use revocation_store::{RevocationRecord, RevocationStoreError};
pub use runtime::{
    NestedFlowBridge, NestedFlowClient, ToolCallChunk, ToolCallOutput, ToolCallRequest,
    ToolCallResponse, ToolCallStream, ToolInvocationCost, ToolServerConnection, ToolServerEvent,
    ToolServerOutput, ToolServerStreamResult, Verdict,
};
pub use session::{
    InflightRegistry, InflightRequest, LateSessionEvent, PeerCapabilities, Session, SessionError,
    SessionOperationResponse, SessionPersistError, SessionState, SubscriptionRegistry,
    TerminalRegistry,
};

/// A string-typed agent identifier.
#[path = "kernel/mod.rs"]
mod kernel;

pub(crate) use kernel::{current_unix_timestamp, MatchingGrant, ReceiptContent};

pub use kernel::{
    AgentId, CapabilityId, ChildReceiptLog, ChioKernel, Guard, GuardContext, KernelConfig,
    KernelError, PromptProvider, ReceiptLog, ResourceProvider, ServerId, StructuredErrorReport,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DEFAULT_RETENTION_DAYS, EMERGENCY_STOP_DENY_REASON,
};

pub use kernel::evaluator::ToolEvaluator;

/// Default bounded capacity for the kernel's mpsc-backed signing-task channel.
/// Re-exported so integration tests can assert against the configured value
/// without reaching into crate-private module paths.
pub const SIGNING_CHANNEL_DEFAULT_CAPACITY: usize =
    kernel::signing_task::DEFAULT_SIGNING_CHANNEL_CAPACITY;
