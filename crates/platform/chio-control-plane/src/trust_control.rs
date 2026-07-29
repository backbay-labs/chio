#![allow(clippy::result_large_err)]

#[path = "trust_control/fiscal_handlers.rs"]
mod fiscal_handlers;
#[path = "trust_control/fiscal_runtime.rs"]
mod fiscal_runtime;
#[path = "trust_control/frost.rs"]
pub mod frost;
#[path = "trust_control/health.rs"]
mod trust_control_health;

// Shared import set for the entire trust-control surface. The sibling modules
// below inherit these via `use super::*;`.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Form;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chio_core::appraisal::{
    derive_runtime_attestation_appraisal, evaluate_imported_runtime_attestation_appraisal,
    RuntimeAttestationAppraisalImportReport, RuntimeAttestationAppraisalImportRequest,
    RuntimeAttestationAppraisalReport, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResult, RuntimeAttestationAppraisalResultExportRequest,
    RuntimeAttestationPolicyOutcome, SignedRuntimeAttestationAppraisalReport,
    SignedRuntimeAttestationAppraisalResult, RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA,
};
use chio_core::capability::{
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, MonetaryAmount},
    token::CapabilityToken,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::listing::GenericTrustAdmissionClass;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    economics::SettlementStatus, lineage::ChildRequestReceipt,
    metadata::ReceiptAttributionMetadata,
};
use chio_core::session::{
    ChioIdentityAssertion, EnterpriseIdentityContext, OperationTerminalState,
};
use chio_core::{canonical_json_bytes, sha256_hex, Signature};
use chio_credentials::{
    build_chio_passport_jwt_vc_json_type_metadata, build_chio_passport_sd_jwt_type_metadata,
    build_oid4vp_request_transport, build_portable_jwks, build_portable_negative_event_artifact,
    build_portable_reputation_summary_artifact, build_wallet_exchange_descriptor_for_oid4vp,
    create_passport_presentation_challenge_with_reference,
    create_signed_public_discovery_transparency, create_signed_public_issuer_discovery,
    create_signed_public_verifier_discovery,
    default_oid4vci_passport_issuer_metadata_with_signing_key,
    ensure_signed_passport_verifier_policy_active, evaluate_portable_reputation,
    inspect_chio_passport_sd_jwt_vc_unverified, inspect_oid4vp_direct_post_response,
    verify_oid4vp_direct_post_response_with_any_issuer_key,
    verify_passport_presentation_response_with_policy,
    verify_signed_oid4vp_request_object_with_any_key, verify_signed_passport_verifier_policy,
    AgentPassport, EnterpriseIdentityProvenance, Oid4vciCredentialIssuerMetadata,
    Oid4vciCredentialRequest, Oid4vciCredentialResponse, Oid4vciTokenRequest, Oid4vciTokenResponse,
    Oid4vpPresentationVerification, Oid4vpRequestObject, Oid4vpRequestedCredential,
    Oid4vpVerifierMetadata, PassportLifecycleRecord, PassportLifecycleResolution,
    PassportLifecycleState, PassportPresentationChallenge, PassportPresentationResponse,
    PassportPresentationVerification, PassportStatusDistribution, PassportVerifierPolicy,
    PassportVerifierPolicyReference, PortableJwkSet, PortableNegativeEventIssueRequest,
    PortableReputationEvaluation, PortableReputationEvaluationRequest,
    PortableReputationSummaryIssueRequest, PublicDiscoveryEntryKind,
    PublicDiscoveryImportGuardrails, PublicDiscoveryTransparencyEntry,
    SignedPassportVerifierPolicy, SignedPortableNegativeEvent, SignedPortableReputationSummary,
    SignedPublicDiscoveryTransparency, SignedPublicIssuerDiscovery, SignedPublicVerifierDiscovery,
    WalletExchangeDescriptor, WalletExchangeTransactionState,
    CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    CHIO_PASSPORT_SD_JWT_VC_TYPE, CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH,
    OID4VCI_ISSUER_METADATA_PATH, OID4VCI_JWKS_PATH, OID4VCI_PASSPORT_CREDENTIAL_PATH,
    OID4VCI_PASSPORT_OFFERS_PATH, OID4VCI_PASSPORT_TOKEN_PATH,
    OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI, OID4VP_OPENID4VP_SCHEME,
    OID4VP_RESPONSE_MODE_DIRECT_POST_JWT, OID4VP_RESPONSE_TYPE_VP_TOKEN,
    OID4VP_VERIFIER_METADATA_PATH,
};
use chio_did::DidChio;
use chio_kernel::budget_store::{
    ApprovalRequiredBudgetHold, AuthorizedBudgetHold, BudgetAdmissionBinding,
    BudgetAuthorizationOutcome, BudgetAuthorizeCumulativeApprovalRequest,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetCapturedBeforeDispatchCancellationDecision,
    BudgetCommitMetadata, BudgetCumulativeApprovalAccountKey,
    BudgetCumulativeApprovalAuthorizationDecision, BudgetCumulativeApprovalRequest,
    BudgetCumulativeApprovalState, BudgetCumulativeApprovalUsage, BudgetEventAuthority,
    BudgetGuaranteeLevel, BudgetHoldMutationDecision, BudgetInvocationCaptureDecision,
    BudgetInvocationQuota, BudgetInvocationQuotaUsage, BudgetInvocationState, BudgetMonetaryState,
    BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldRequest, BudgetReleaseHoldRequest, BudgetReverseHoldRequest,
    DeniedBudgetHold, RevocationCommitMetadata,
};
use chio_kernel::operator_report::ComptrollerSurfaceReport;
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    build_generic_trust_activation_artifact, build_open_market_fee_schedule_artifact,
    build_open_market_penalty_artifact_with_trusted_signers,
    ensure_generic_listing_namespace_consistency, evaluate_generic_governance_case,
    evaluate_generic_trust_activation, evaluate_open_market_penalty_with_trusted_signers,
    normalize_namespace, GenericGovernanceCaseEvaluation, GenericGovernanceCaseEvaluationRequest,
    GenericGovernanceCaseIssueRequest, GenericGovernanceCharterIssueRequest,
    GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
    GenericListingCompatibilityReference, GenericListingFreshnessWindow, GenericListingQuery,
    GenericListingReport, GenericListingSearchPolicy, GenericListingStatus, GenericListingSubject,
    GenericListingSummary, GenericNamespaceArtifact, GenericNamespaceLifecycleState,
    GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole,
    GenericTrustActivationEvaluation, GenericTrustActivationEvaluationRequest,
    GenericTrustActivationIssueRequest, OpenMarketFeeScheduleIssueRequest,
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest, OpenMarketPenaltyIssueRequest,
    SignedGenericGovernanceCase, SignedGenericGovernanceCharter, SignedGenericListing,
    SignedGenericNamespace, SignedGenericTrustActivation, SignedOpenMarketFeeSchedule,
    SignedOpenMarketPenalty, DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS,
    GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_LISTING_REPORT_SCHEMA,
    GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
};
use chio_kernel::{
    AuthoritySnapshot, AuthorityStatus, AuthorizationContextReport, BehavioralFeedDecisionSummary,
    BehavioralFeedPrivacyBoundary, BehavioralFeedQuery, BehavioralFeedReceiptRow,
    BehavioralFeedReport, BudgetDimensionProfile, BudgetDimensionUsage, BudgetStore,
    BudgetStoreError, BudgetUsageRecord, BudgetUtilizationReport, BudgetUtilizationRow,
    BudgetUtilizationSummary, CapabilityAuthority, CapabilitySnapshot,
    CapitalAllocationDecisionArtifact, CapitalAllocationDecisionFinding,
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode,
    CapitalAllocationDecisionSupportBoundary, CapitalAllocationInstructionDraft, CapitalBookEvent,
    CapitalBookEventKind, CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery,
    CapitalBookReport, CapitalBookRole, CapitalBookSource, CapitalBookSourceKind,
    CapitalBookSummary, CapitalBookSupportBoundary, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionAction, CapitalExecutionInstructionArtifact,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionReconciledState,
    CapitalExecutionRole, CapitalExecutionWindow, ChioOAuthAuthorizationMetadataReport,
    ChioOAuthAuthorizationReviewPack, CostAttributionQuery, CostAttributionReport,
    CreditBacktestQuery, CreditBacktestReasonCode, CreditBacktestReport, CreditBacktestSummary,
    CreditBacktestWindow, CreditBondArtifact, CreditBondDisposition, CreditBondFinding,
    CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport, CreditBondPrerequisites,
    CreditBondReasonCode, CreditBondReport, CreditBondSupportBoundary, CreditBondTerms,
    CreditBondedExecutionControlPolicy, CreditBondedExecutionDecision,
    CreditBondedExecutionEvaluation, CreditBondedExecutionFinding,
    CreditBondedExecutionFindingCode, CreditBondedExecutionSimulationDelta,
    CreditBondedExecutionSimulationReport, CreditBondedExecutionSimulationRequest,
    CreditBondedExecutionSupportBoundary, CreditCertificationState, CreditFacilityArtifact,
    CreditFacilityCapitalSource, CreditFacilityDisposition, CreditFacilityFinding,
    CreditFacilityLifecycleState, CreditFacilityListQuery, CreditFacilityListReport,
    CreditFacilityPrerequisites, CreditFacilityReasonCode, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleQuery, CreditLossLifecycleReasonCode,
    CreditLossLifecycleReport, CreditLossLifecycleSupportBoundary, CreditProviderFacilitySnapshot,
    CreditProviderRiskPackage, CreditProviderRiskPackageQuery,
    CreditProviderRiskPackageSupportBoundary, CreditRecentLossEntry, CreditRecentLossHistory,
    CreditRecentLossSummary, CreditReserveControlAppealState, CreditReserveControlExecutionState,
    CreditRuntimeAssuranceState, CreditScorecardAnomaly, CreditScorecardAnomalySeverity,
    CreditScorecardBand, CreditScorecardConfidence, CreditScorecardDimension,
    CreditScorecardDimensionKind, CreditScorecardEvidenceKind, CreditScorecardEvidenceReference,
    CreditScorecardProbationStatus, CreditScorecardReasonCode, CreditScorecardReport,
    CreditScorecardReputationContext, CreditScorecardSummary, CreditScorecardSupportBoundary,
    EconomicCompletionFlowReport, EconomicReceiptProjectionReport, EvidenceExportQuery,
    ExposureLedgerCurrencyPosition, ExposureLedgerDecisionEntry, ExposureLedgerEvidenceKind,
    ExposureLedgerEvidenceReference, ExposureLedgerQuery, ExposureLedgerReceiptEntry,
    ExposureLedgerReport, ExposureLedgerSummary, ExposureLedgerSupportBoundary,
    LiabilityAutoBindDecisionArtifact, LiabilityAutoBindDisposition,
    LiabilityBoundCoverageArtifact, LiabilityClaimAdjudicationArtifact,
    LiabilityClaimAdjudicationOutcome, LiabilityClaimDisputeArtifact, LiabilityClaimEvidenceKind,
    LiabilityClaimEvidenceReference, LiabilityClaimPackageArtifact,
    LiabilityClaimPayoutInstructionArtifact, LiabilityClaimPayoutReceiptArtifact,
    LiabilityClaimPayoutReconciliationState, LiabilityClaimResponseArtifact,
    LiabilityClaimResponseDisposition, LiabilityClaimSettlementInstructionArtifact,
    LiabilityClaimSettlementKind, LiabilityClaimSettlementReceiptArtifact,
    LiabilityClaimSettlementReconciliationState, LiabilityClaimSettlementRoleTopology,
    LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport, LiabilityCoverageClass,
    LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport, LiabilityPlacementArtifact,
    LiabilityPricingAuthorityArtifact, LiabilityPricingAuthorityEnvelope,
    LiabilityProviderArtifact, LiabilityProviderListQuery, LiabilityProviderListReport,
    LiabilityProviderPolicyReference, LiabilityProviderReport, LiabilityProviderResolutionQuery,
    LiabilityProviderResolutionReport, LiabilityQuoteDisposition, LiabilityQuoteRequestArtifact,
    LiabilityQuoteResponseArtifact, LiabilityQuoteTerms, LocalCapabilityAuthority,
    MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationState, OperatorReport, OperatorReportQuery, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, ReceiptQuery, ReceiptReadBoundary, ReceiptReadContext, ReceiptStore,
    ReceiptStoreError, RevocationRecord, RevocationStore, RevocationStoreError,
    SettlementReconciliationReport, SettlementReconciliationState, SharedEvidenceQuery,
    SharedEvidenceReferenceReport, SignedBehavioralFeed, SignedCapitalAllocationDecision,
    SignedCapitalBookReport, SignedCapitalExecutionInstruction, SignedCreditBond,
    SignedCreditFacility, SignedCreditLossLifecycle, SignedCreditProviderRiskPackage,
    SignedCreditScorecardReport, SignedExposureLedgerReport, SignedLiabilityAutoBindDecision,
    SignedLiabilityBoundCoverage, SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute,
    SignedLiabilityClaimPackage, SignedLiabilityClaimPayoutInstruction,
    SignedLiabilityClaimPayoutReceipt, SignedLiabilityClaimResponse,
    SignedLiabilityClaimSettlementInstruction, SignedLiabilityClaimSettlementReceipt,
    SignedLiabilityPlacement, SignedLiabilityPricingAuthority, SignedLiabilityProvider,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, SignedUnderwritingDecision,
    SignedUnderwritingPolicyInput, StoredCapabilitySnapshot, StoredChildReceipt, StoredToolReceipt,
    UnderwritingAppealCreateRequest, UnderwritingAppealRecord, UnderwritingAppealResolveRequest,
    UnderwritingCertificationEvidence, UnderwritingCertificationState,
    UnderwritingDecisionListReport, UnderwritingDecisionPolicy, UnderwritingDecisionQuery,
    UnderwritingDecisionReport, UnderwritingEvidenceKind, UnderwritingEvidenceReference,
    UnderwritingPolicyInput, UnderwritingPolicyInputQuery, UnderwritingReasonCode,
    UnderwritingReceiptEvidence, UnderwritingReputationEvidence, UnderwritingRiskClass,
    UnderwritingRiskTaxonomy, UnderwritingRuntimeAssuranceEvidence, UnderwritingSignal,
    UnderwritingSimulationDelta, UnderwritingSimulationReport, UnderwritingSimulationRequest,
    BEHAVIORAL_FEED_SCHEMA, CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA,
    CAPITAL_BOOK_REPORT_SCHEMA, CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
    CREDIT_BACKTEST_REPORT_SCHEMA, CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA,
    CREDIT_BOND_ARTIFACT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA, CREDIT_FACILITY_ARTIFACT_SCHEMA,
    CREDIT_FACILITY_REPORT_SCHEMA, CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA, CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA,
    CREDIT_SCORECARD_SCHEMA, EXPOSURE_LEDGER_SCHEMA, LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
    LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA, LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA, LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
    MAX_CREDIT_BOND_LIST_LIMIT, MAX_CREDIT_FACILITY_LIST_LIMIT,
    MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT, UNDERWRITING_POLICY_INPUT_SCHEMA,
    UNDERWRITING_SIMULATION_REPORT_SCHEMA,
};
use chio_store_sqlite::budget_store::{
    budget_snapshot_anchor_authenticator, budget_snapshot_anchor_set_digest,
    BudgetSnapshotAnchorProvenance, BudgetStoreSnapshot,
};
use chio_store_sqlite::{
    SqliteAuthorityStore, SqliteBudgetStore, SqliteCapabilityAuthority, SqliteReceiptStore,
    SqliteRevocationStore,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};
use ureq::Agent;
use url::form_urlencoded::Serializer as UrlFormSerializer;
use url::{Host, Url};

use crate::{
    authority_public_key_from_seed_file,
    certify::{
        CertificationConsumptionRequest, CertificationConsumptionResponse,
        CertificationDiscoveryResponse, CertificationDisputeRequest,
        CertificationMarketplaceSearchQuery, CertificationMarketplaceTransparencyQuery,
        CertificationNetworkPublishRequest, CertificationNetworkPublishResponse,
        CertificationPublicMetadata, CertificationPublicSearchQuery,
        CertificationPublicSearchResponse, CertificationRegistry, CertificationRegistryEntry,
        CertificationRegistryListResponse, CertificationRegistryState,
        CertificationResolutionResponse, CertificationResolutionState,
        CertificationRevocationRequest, CertificationTransparencyQuery,
        CertificationTransparencyResponse, SignedCertificationCheck,
    },
    enterprise_federation::{
        CertificationDiscoveryNetwork, EnterpriseProviderKind, EnterpriseProviderRecord,
        EnterpriseProviderRegistry,
    },
    evidence_export,
    federation_policy::{
        verify_admission_proof_of_work, verify_federation_admission_policy_record,
        FederationAdmissionEvaluationRequest, FederationAdmissionEvaluationResponse,
        FederationAdmissionPolicyDeleteResponse, FederationAdmissionPolicyListResponse,
        FederationAdmissionPolicyRecord, FederationAdmissionPolicyRegistry,
        FederationAdmissionRateLimit, FederationAdmissionRateLimitStatus,
    },
    issuance, load_or_create_authority_keypair,
    passport_verifier::{
        Oid4vpVerifierTransactionStore, PassportIssuanceOfferRecord, PassportIssuanceOfferRegistry,
        PassportStatusListResponse, PassportStatusRegistry, PassportStatusRevocationRequest,
        PassportVerifierChallengeStore, PublishPassportStatusRequest, VerifierPolicyRegistry,
    },
    reputation, rotate_authority_keypair,
    scim_lifecycle::{
        build_scim_error, build_scim_user_record, ensure_scim_provider, required_chio_extension,
        ScimLifecycleRegistry, ScimUserResource,
    },
    CliError,
};

#[path = "trust_control/authority_handlers.rs"]
mod authority_handlers;
#[path = "trust_control/budget_handlers.rs"]
mod budget_handlers;
#[path = "trust_control/capital_and_liability.rs"]
mod capital_and_liability;
#[path = "trust_control/certification_handlers.rs"]
mod certification_handlers;
#[path = "trust_control/cluster.rs"]
pub mod cluster;
#[path = "trust_control/cluster_and_reports.rs"]
#[cfg(test)]
mod cluster_and_reports;
#[path = "trust_control/config_and_public.rs"]
mod config_and_public;
#[path = "trust_control/credit_and_loss.rs"]
mod credit_and_loss;
#[cfg(feature = "cognition-market-experimental")]
#[path = "trust_control/finding_handlers.rs"]
mod finding_handlers;
#[cfg(feature = "cognition-market-experimental")]
#[path = "trust_control/finding_purchase_coordinator.rs"]
pub mod finding_purchase_coordinator;
#[cfg(feature = "cognition-market-experimental")]
#[path = "trust_control/finding_purchase_verifier.rs"]
pub mod finding_purchase_verifier;
#[cfg(feature = "cognition-market-experimental")]
#[path = "trust_control/finding_reveal_server.rs"]
pub mod finding_reveal_server;
#[path = "trust_control/passport_handlers.rs"]
mod passport_handlers;
#[path = "trust_control/receipt_handlers.rs"]
mod receipt_handlers;
#[path = "trust_control/report_rendering.rs"]
pub(crate) mod report_rendering;
#[path = "trust_control/report_validation.rs"]
pub(crate) mod report_validation;
#[path = "trust_control/reports.rs"]
pub mod reports;
#[path = "trust_control/risk_finance_handlers.rs"]
mod risk_finance_handlers;
#[path = "trust_control/service_runtime.rs"]
pub mod service_runtime;
#[path = "trust_control/service_types.rs"]
mod service_types;
#[path = "trust_control/underwriting_and_support.rs"]
mod underwriting_and_support;

// Re-export stable high-level trust-control types and configuration helpers.
// Runtime client and remote adapter entrypoints live under named
// `service_runtime` child modules.
pub use self::config_and_public::*;
pub use self::service_types::*;
// The domain handler modules and credit_and_loss expose only crate-internal
// (`pub(crate)`) items, so they are re-exported with crate visibility.
pub(crate) use self::authority_handlers::*;
pub(crate) use self::budget_handlers::*;
pub use self::capital_and_liability::*;
pub(crate) use self::certification_handlers::*;
pub(crate) use self::credit_and_loss::*;
#[cfg(feature = "cognition-market-experimental")]
pub(crate) use self::finding_handlers::*;
pub(crate) use self::fiscal_handlers::*;
pub(crate) use self::fiscal_runtime::*;
pub(crate) use self::passport_handlers::*;
pub(crate) use self::receipt_handlers::*;
pub(crate) use self::risk_finance_handlers::*;
pub use self::underwriting_and_support::*;
