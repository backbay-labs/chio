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
// Under `--cfg loom` only the `session` module below is compiled; every other
// item is gated to `cfg(not(loom))`. The interleaving model in
// tests/loom_concurrency.rs drives the real `Session` terminal-admission state
// machine; its only heavy dependency (chio-core) reaches neither hyper-util nor
// tokio and so builds under loom. Every runtime-bearing module stays gated out
// because the wider dependency graph pulls hyper-util, which cannot compile
// when tokio drops `tokio::net`. Normal builds compile every item unchanged.

#[cfg(not(loom))]
pub mod admission_operation;
#[cfg(not(loom))]
pub mod approval;
#[cfg(not(loom))]
pub mod approval_channels;
#[cfg(not(loom))]
pub mod authority;
#[cfg(not(loom))]
pub mod boot;
#[cfg(not(loom))]
pub mod budget_store;
#[cfg(not(loom))]
pub mod capability_lineage;
#[cfg(not(loom))]
pub mod checkpoint;
#[cfg(not(loom))]
pub mod compliance_certificate;
#[cfg(not(loom))]
pub mod compliance_score;
#[cfg(not(loom))]
pub mod cost_attribution;
#[cfg(not(loom))]
pub mod custody;
#[cfg(not(loom))]
pub mod dispatch_status;
#[cfg(not(loom))]
pub mod dpop;
#[cfg(not(loom))]
pub mod evidence_export;
#[cfg(not(loom))]
pub mod execution_nonce;
#[cfg(not(loom))]
pub mod federation_artifact_store;
#[cfg(not(loom))]
pub mod finding_purchase;
#[cfg(not(loom))]
pub mod finding_recovery;
#[cfg(not(loom))]
pub mod governed_active_response;
#[cfg(not(loom))]
pub mod governed_approval_replay;
pub mod memory_provenance;
#[cfg(not(loom))]
pub mod observability;
#[cfg(not(loom))]
pub mod operator_report;
#[cfg(not(loom))]
pub mod otel;
#[cfg(not(loom))]
pub mod payment;
#[cfg(not(loom))]
pub mod post_invocation;
#[cfg(not(loom))]
#[allow(deprecated)]
pub mod provider_verdict;
#[cfg(not(loom))]
pub mod receipt_analytics;
#[cfg(not(loom))]
pub mod receipt_query;
#[cfg(not(loom))]
pub mod receipt_store;
#[cfg(not(loom))]
mod receipt_support;
#[cfg(not(loom))]
mod replay_retention;
#[cfg(not(loom))]
mod request_matching;
#[cfg(not(loom))]
pub mod revocation_runtime;
#[cfg(not(loom))]
pub mod revocation_store;
#[cfg(not(loom))]
pub mod runtime;
#[cfg(not(loom))]
mod runtime_trace;
pub mod session;
#[cfg(not(loom))]
mod settlement_routing;
#[cfg(not(loom))]
pub mod supplemental_quota;
#[cfg(not(loom))]
pub mod threshold_approval;
#[cfg(not(loom))]
pub mod tool_outcome;
#[cfg(not(loom))]
pub mod transport;
#[cfg(not(loom))]
pub mod weights_binding;

#[cfg(not(loom))]
pub(crate) use std::collections::HashMap;
#[cfg(not(loom))]
pub(crate) use std::future::Future;
#[cfg(not(loom))]
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(not(loom))]
pub(crate) use chio_core::canonical::canonical_json_bytes;
#[cfg(not(loom))]
pub(crate) use chio_core::capability::{
    governance::{GovernedApprovalDecision, GovernedApprovalToken, GovernedAutonomyTier},
    runtime_attestation::RuntimeAssuranceTier,
    scope::{ChioScope, Constraint, Operation, PromptGrant, ResourceGrant, ToolGrant},
    token::CapabilityToken,
    trust_policy::AttestationTrustPolicy,
};
#[cfg(not(loom))]
pub(crate) use chio_core::crypto::{sha256_hex, Keypair};
#[cfg(not(loom))]
pub(crate) use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    economics::FinancialReceiptMetadata, economics::SettlementStatus,
    governance::GovernedApprovalReceiptMetadata, governance::GovernedAutonomyReceiptMetadata,
    governance::GovernedCommerceReceiptMetadata, governance::GovernedTransactionReceiptMetadata,
    governance::MeteredBillingReceiptMetadata, governance::RuntimeAssuranceReceiptMetadata,
    lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
    metadata::ReceiptAttributionMetadata,
};
#[cfg(not(loom))]
pub(crate) use chio_core::session::{
    CompleteOperation, CompletionReference, CompletionResult, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, GetPromptOperation,
    NormalizedRoot, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, PromptResult, ReadResourceOperation, RequestId, ResourceContent,
    ResourceDefinition, ResourceTemplateDefinition, ResourceUriClassification, RootDefinition,
    SessionAuthContext, SessionId, SessionOperation, ToolCallOperation,
};
#[cfg(not(loom))]
pub(crate) use chio_link::convert::convert_supported_units;
#[cfg(not(loom))]
pub(crate) use chio_link::{PriceOracle, PriceOracleError};
#[cfg(not(loom))]
pub(crate) use tracing::{debug, info, warn};

#[cfg(not(loom))]
pub(crate) use receipt_support::*;
// Hybrid receipt signing path. The kernel boot wiring constructs a
// `Box<dyn SigningBackend>` from `KernelCryptoFloor` plus an optional
// ML-DSA-65 seed; consumers (kernel boot, integration tests, custody
// envelope issuance) sign through the resulting backend so the receipt body
// remains byte-identical across classical and hybrid paths under
// `crypto_floor=allow_classical`.
#[cfg(not(loom))]
pub use receipt_support::{
    fixed_runtime_unix_secs_for_current_thread, kernel_signing_backend,
    receipt_body_fields_coupled, scope_fixed_runtime_for_current_thread,
    sign_receipt_body_hybrid_canonical, sign_receipt_body_with_backend, FixedRuntimeScope,
    KernelCryptoFloor, KernelSigningBackendError, ReceiptCouplingExpectation, SignedHybridReceipt,
};
#[cfg(not(loom))]
pub(crate) use request_matching::{
    begin_child_request_in_sessions, begin_session_request_in_sessions, check_subject_binding,
    check_time_bounds, complete_session_request_with_terminal_state_in_sessions,
    nested_child_request_id, resolve_required_matching_grants, session_from_map,
    validate_elicitation_request_in_sessions, validate_sampling_request_in_sessions,
};
#[cfg(not(loom))]
pub use request_matching::{
    capability_matches_prompt_request, capability_matches_request,
    capability_matches_request_with_model_metadata, capability_matches_resource_pattern,
    capability_matches_resource_request, capability_matches_resource_subscription,
    capability_request_requires_dpop, capability_request_requires_dpop_with_model_metadata,
};
#[cfg(not(loom))]
pub use threshold_approval::{
    CollectedThresholdApprovalSet, InMemoryThresholdApprovalCollectorStore,
    ThresholdApprovalCollector, ThresholdApprovalCollectorProposal,
    ThresholdApprovalCollectorState, ThresholdApprovalCollectorStore,
    ThresholdApprovalCollectorStoreError,
};

#[cfg(not(loom))]
pub use approval::{
    compute_parameter_hash, resume_with_decision, ApprovalChannel, ApprovalContext,
    ApprovalDecision, ApprovalFilter, ApprovalGuard, ApprovalOutcome, ApprovalRequest,
    ApprovalStore, ApprovalStoreError, ApprovalToken, BatchApproval, BatchApprovalStore,
    ChannelError, ChannelHandle, HitlVerdict, InMemoryApprovalStore, InMemoryBatchApprovalStore,
    ResolvedApproval, MAX_APPROVAL_TTL_SECS,
};
#[cfg(not(loom))]
pub use approval_channels::{RecordingChannel, WebhookChannel, WebhookPayload};
#[cfg(not(loom))]
pub use authority::{
    ensure_capability_issuance_supported, validate_issued_capability_response,
    validate_issued_capability_response_at, AuthoritySnapshot, AuthorityStatus,
    AuthorityStoreError, AuthorityTrustedKeySnapshot, CapabilityAuthority,
    LocalCapabilityAuthority,
};
#[cfg(not(loom))]
pub use budget_store::{BudgetStore, BudgetStoreError, BudgetUsageRecord, InMemoryBudgetStore};
#[cfg(not(loom))]
pub use capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, CapabilitySnapshotProvenance,
    StoredCapabilitySnapshot,
};
#[cfg(not(loom))]
pub use checkpoint::{
    build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof,
    checkpoint_body_sha256, is_supported_checkpoint_schema, verify_checkpoint_continuity,
    verify_checkpoint_signature, CheckpointError, KernelCheckpoint, KernelCheckpointBody,
    ReceiptInclusionProof, CHECKPOINT_SCHEMA, CHECKPOINT_SCHEMA_V1, CHECKPOINT_SCHEMA_V2,
};
#[cfg(not(loom))]
pub use chio_core::credit::{
    ensure_capital_execution_custodian_authority, ensure_capital_execution_owner_authority,
    validate_capital_execution_envelope, CapitalAllocationDecisionArtifact,
    CapitalAllocationDecisionFinding, CapitalAllocationDecisionOutcome,
    CapitalAllocationDecisionReasonCode, CapitalAllocationDecisionSupportBoundary,
    CapitalAllocationInstructionDraft, CapitalBookEvent, CapitalBookEventKind,
    CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery, CapitalBookReport,
    CapitalBookRole, CapitalBookSource, CapitalBookSourceKind, CapitalBookSummary,
    CapitalBookSupportBoundary, CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction,
    CapitalExecutionInstructionArtifact, CapitalExecutionInstructionSupportBoundary,
    CapitalExecutionIntendedState, CapitalExecutionObservation, CapitalExecutionRail,
    CapitalExecutionRailKind, CapitalExecutionReconciledState, CapitalExecutionRole,
    CapitalExecutionWindow, CreditBacktestQuery, CreditBacktestReasonCode, CreditBacktestReport,
    CreditBacktestSummary, CreditBacktestWindow, CreditBondArtifact, CreditBondDisposition,
    CreditBondFinding, CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport,
    CreditBondListSummary, CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport,
    CreditBondRow, CreditBondSupportBoundary, CreditBondTerms, CreditBondedExecutionControlPolicy,
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
#[cfg(not(loom))]
pub use chio_core::governance::evaluation::evaluate_generic_governance_case;
#[cfg(not(loom))]
pub use chio_core::governance::generic::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    GenericGovernanceAuthorityScope, GenericGovernanceCaseArtifact,
    GenericGovernanceCaseEvaluation, GenericGovernanceCaseEvaluationRequest,
    GenericGovernanceCaseIssueRequest, GenericGovernanceCaseKind, GenericGovernanceCaseState,
    GenericGovernanceCharterArtifact, GenericGovernanceCharterIssueRequest,
    GenericGovernanceEffectiveState, GenericGovernanceEvidenceKind,
    GenericGovernanceEvidenceReference, GenericGovernanceFinding, GenericGovernanceFindingCode,
    SignedGenericGovernanceCase, SignedGenericGovernanceCharter,
    GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA, GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA,
};
#[cfg(not(loom))]
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
#[cfg(not(loom))]
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
#[cfg(not(loom))]
pub use chio_core::open_market::evaluation::{
    evaluate_open_market_penalty, evaluate_open_market_penalty_with_trusted_signers,
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest,
};
#[cfg(not(loom))]
pub use chio_core::open_market::evidence::{
    OpenMarketEvidenceKind, OpenMarketEvidenceReference, OpenMarketFinding, OpenMarketFindingCode,
};
#[cfg(not(loom))]
pub use chio_core::open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleArtifact,
    OpenMarketFeeScheduleIssueRequest, SignedOpenMarketFeeSchedule,
    OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA,
};
#[cfg(not(loom))]
pub use chio_core::open_market::penalty::{
    build_open_market_penalty_artifact, build_open_market_penalty_artifact_with_trusted_signers,
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyArtifact,
    OpenMarketPenaltyEffectiveState, OpenMarketPenaltyIssueRequest, OpenMarketPenaltyState,
    SignedOpenMarketPenalty, OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
};
#[cfg(not(loom))]
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
#[cfg(not(loom))]
pub use chio_credit::obligation::CreditExposureReservationRequest;
#[cfg(not(loom))]
pub use compliance_score::{
    compliance_factor_breakdown, compliance_score, ComplianceFactor, ComplianceFactorBreakdown,
    ComplianceScore, ComplianceScoreConfig, ComplianceScoreInputs, COMPLIANCE_SCORE_MAX,
    DEFAULT_ATTESTATION_STALENESS_SECS, WEIGHT_ATTESTATION_FRESHNESS, WEIGHT_DENY_RATE,
    WEIGHT_POLICY_COVERAGE, WEIGHT_REVOCATION, WEIGHT_VELOCITY_ANOMALY,
};
#[cfg(not(loom))]
pub use cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
#[cfg(not(loom))]
pub use custody::PasskeyCapabilityVerifier;
#[cfg(not(loom))]
pub use dpop::{
    is_supported_dpop_schema, verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof,
    DpopProofBody, DPOP_SCHEMA,
};
#[cfg(not(loom))]
pub use evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportError, EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt,
};
#[cfg(not(loom))]
pub use execution_nonce::{
    is_supported_execution_nonce_schema, mint_execution_nonce, verify_execution_nonce,
    ExecutionNonce, ExecutionNonceConfig, ExecutionNonceError, ExecutionNonceStore,
    InMemoryExecutionNonceStore, NonceBinding, SignedExecutionNonce,
    DEFAULT_EXECUTION_NONCE_STORE_CAPACITY, DEFAULT_EXECUTION_NONCE_TTL_SECS,
    EXECUTION_NONCE_SCHEMA,
};
#[cfg(not(loom))]
pub use governed_approval_replay::{
    GovernedApprovalReplayStore, InMemoryGovernedApprovalReplayStore,
    DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY,
};
#[cfg(not(loom))]
pub use memory_provenance::{
    classify_memory_action, next_entry_id as next_memory_provenance_entry_id,
    recompute_entry_hash as recompute_memory_provenance_entry_hash, InMemoryMemoryProvenanceStore,
    MemoryActionKind, MemoryProvenanceAppend, MemoryProvenanceEntry, MemoryProvenanceError,
    MemoryProvenanceStore, ProvenanceVerification, UnverifiedReason,
    MEMORY_PROVENANCE_ENTRY_SCHEMA, MEMORY_PROVENANCE_GENESIS_PREV_HASH,
};
#[cfg(not(loom))]
pub use observability::metrics::{
    guard_metrics_endpoint, record_receipt_health_gauges, render_guard_metrics_prometheus,
    GuardMetricFamily, MetricsEndpointResponse, PrometheusMetricKind, GUARD_METRICS_PATH,
    GUARD_METRIC_FAMILIES, METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL, METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
    PROMETHEUS_TEXT_CONTENT_TYPE,
};
#[cfg(not(loom))]
pub use operator_report::{behavioral_anomaly_score, BehavioralAnomalyScore, EmaBaselineState};
#[cfg(not(loom))]
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
#[cfg(not(loom))]
pub use payment::{
    AcpPaymentAdapter, CommercePaymentContext, GovernedPaymentContext, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentCredentialDisposition, PaymentError, PaymentJournalError, PaymentJournalRecord,
    PaymentJournalState, PaymentJournalTransition, PaymentRailMode, PaymentReleaseAuthorityBinding,
    PaymentReleaseAuthorityKind, PaymentResult, PaymentSettleAction,
    PreDispatchPaymentUnwindEvidence, PreDispatchPaymentUnwindStatus, RailSettlementState,
    RailSettlementStatus, ReceiptSettlement, X402PaymentAdapter,
};
#[cfg(not(loom))]
pub use post_invocation::{
    PipelineOutcome, PostInvocationContext, PostInvocationHook, PostInvocationHookIdentity,
    PostInvocationPipeline, PostInvocationVerdict,
};
#[cfg(not(loom))]
pub use provider_verdict::{
    build_tool_call_request, canonical_invocation_bytes, verdict_result_from_response,
    ProviderVerdictError, FABRIC_SHIM_PROVIDER_LANES,
};
#[cfg(not(loom))]
pub use receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
#[cfg(not(loom))]
pub use receipt_query::{
    EffectiveReceiptReadScope, ReceiptQuery, ReceiptQueryResult, ReceiptReadBoundary,
    ReceiptReadContext, ReceiptReadContextSource, MAX_QUERY_LIMIT,
};
#[cfg(not(loom))]
pub use receipt_store::{
    AdmissionBudgetAuthorization, AdmissionBudgetAuthorizationError, AdmissionBudgetCapture,
    AdmissionPaymentJournalAdvance, AdmissionPaymentJournalError, AdmissionPaymentSettlement,
    AdmissionPaymentSettlementBegin, AtomicReceiptProjection, AuthorizationReceiptConsumption,
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, PendingSettlementObservation,
    QualifiedAdmissionProjectionStore, ReceiptCheckpointCreateReport, ReceiptCheckpointRange,
    ReceiptCheckpointStatusReport, ReceiptFlushReport, ReceiptStore, ReceiptStoreError,
    ReceiptStoreHealthReport, ReceiptWalCheckpointReport, ReceiptWriterCounters,
    ReceiptWriterLiveness, RetentionConfig, StoredChildReceipt, StoredToolReceipt,
    ThresholdApprovalReplayReservationV1, ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND,
};
#[cfg(not(loom))]
pub use revocation_runtime::{InMemoryRevocationStore, RevocationObservation, RevocationStore};
#[cfg(not(loom))]
pub use revocation_store::{RevocationRecord, RevocationStoreError};
#[cfg(not(loom))]
pub use runtime::{
    NestedFlowBridge, NestedFlowClient, ToolCallChunk, ToolCallOutput, ToolCallRequest,
    ToolCallResponse, ToolCallStream, ToolInvocationCost, ToolServerConnection, ToolServerEvent,
    ToolServerOutput, ToolServerStreamResult, Verdict,
};
#[cfg(not(loom))]
pub use runtime_trace::{RuntimeTraceEvent, RuntimeTraceObserver};
#[cfg(not(loom))]
pub use session::{
    InflightRegistry, InflightRequest, LateSessionEvent, PeerCapabilities, Session, SessionError,
    SessionOperationResponse, SessionPersistError, SessionState, SubscriptionRegistry,
    TerminalRegistry,
};
#[cfg(not(loom))]
pub use supplemental_quota::{
    supplemental_authorization_artifact_digest, supplemental_request_binding_hash,
    CanonicalRevocationSet, SupplementalQuotaError, SupplementalQuotaVerificationContext,
    SupplementalQuotaVerifier, SupplementalQuotaVerifierBinding, SupplementalQuotaVerifierError,
    VerifiedSupplementalQuotaClaim, BROKER_CAPABILITY_EXECUTION_PROFILE,
    MAX_ADMISSION_REVOCATION_IDS, MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES,
    MAX_SUPPLEMENTAL_CLAIM_FIELD_BYTES, MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES,
    MAX_SUPPLEMENTAL_NEGOTIATED_FEATURES, MAX_SUPPLEMENTAL_REVOCATION_IDS,
    MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES,
};
#[cfg(not(loom))]
pub use weights_binding::{evaluate_weights_binding, WeightsBindingError, WeightsBindingRequest};

#[cfg(not(loom))]
/// A string-typed agent identifier.
#[path = "kernel/mod.rs"]
mod kernel;

#[cfg(not(loom))]
pub(crate) use kernel::{current_unix_timestamp, MatchingGrant, ReceiptContent};

#[cfg(not(loom))]
pub use kernel::{
    AgentId, CapabilityId, ChildReceiptLog, ChioKernel, FederationTreatyAdmissionBinding,
    FederationTreatyVerification, Guard, GuardContext, GuardDecision, HotPathDeadlineConfig,
    HotPathStage, HybridSigningConfig, KernelBuildError, KernelConfig, KernelError,
    MemoryBudgetConfig, OverloadResource, PromptProvider, ReceiptLog, ReplayClockDirection,
    ResourceProvider, RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
    RuntimeAdmissionReadinessToken, RuntimeAdmissionRevalidationContext, ServerId,
    SettlementRuntimeConfigError, StructuredErrorReport, VerifiedFederationTreatyMaterial,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DEFAULT_RECEIPT_APPEND_BUDGET_MS,
    DEFAULT_RECEIPT_WRITER_POLL_MS, DEFAULT_RECEIPT_WRITER_STALL_MS, DEFAULT_RETENTION_DAYS,
    EMERGENCY_STOP_DENY_REASON, MIN_RECEIPT_APPEND_BUDGET_MS,
};

#[cfg(not(loom))]
pub use kernel::evaluator::ToolEvaluator;

#[cfg(not(loom))]
/// Settlement observer surface. Re-exported so integration tests and
/// embedders can drive a SettlementHook against finalized receipts
/// without reaching into crate-private module paths.
pub mod settlement_observer {
    pub use crate::kernel::settlement_observer::{
        build_observation, run_observer, SettlementObservationBuild, SettlementObserverStatus,
        SETTLEMENT_OBSERVER_STATUS_SCHEMA,
    };
}

#[cfg(not(loom))]
/// Default bounded capacity for the kernel's mpsc-backed signing-task channel.
/// Re-exported so integration tests can assert against the configured value
/// without reaching into crate-private module paths.
pub const SIGNING_CHANNEL_DEFAULT_CAPACITY: usize =
    kernel::signing_task::DEFAULT_SIGNING_CHANNEL_CAPACITY;

#[cfg(not(loom))]
/// Prometheus counter name emitted when the bounded receipt-signing channel
/// blocks under backpressure.
pub use kernel::signing_task::METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL;
