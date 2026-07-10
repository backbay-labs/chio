use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::{evidence_export, CliError};
use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::build_checkpoint;
use chio_mercury_core::proof_package::MercuryInquiryPackageArgs;
use chio_mercury_core::{
    MercuryAssuranceArtifactKind, MercuryAssuranceAudience, MercuryAssuranceDisclosureProfile,
    MercuryAssuranceInvestigationPackage, MercuryAssurancePackage, MercuryAssuranceReviewPackage,
    MercuryAssuranceReviewerPopulation, MercuryAssuranceSuiteArtifact,
    MercuryAssuranceSuitePackage, MercuryBroaderDistributionArtifact,
    MercuryBroaderDistributionArtifactKind, MercuryBroaderDistributionMotion,
    MercuryBroaderDistributionPackage, MercuryBroaderDistributionProfile,
    MercuryBroaderDistributionSurface, MercuryBundleManifest, MercuryControlledAdoptionArtifact,
    MercuryControlledAdoptionArtifactKind, MercuryControlledAdoptionCohort,
    MercuryControlledAdoptionPackage, MercuryControlledAdoptionProfile,
    MercuryControlledAdoptionSurface, MercuryDeliveryContinuityArtifact,
    MercuryDeliveryContinuityArtifactKind, MercuryDeliveryContinuityMotion,
    MercuryDeliveryContinuityPackage, MercuryDeliveryContinuityProfile,
    MercuryDeliveryContinuitySurface, MercuryDownstreamArtifact, MercuryDownstreamArtifactRole,
    MercuryDownstreamConsumerProfile, MercuryDownstreamReviewPackage, MercuryDownstreamTransport,
    MercuryEmbeddedArtifactKind, MercuryEmbeddedOemArtifact, MercuryEmbeddedOemPackage,
    MercuryEmbeddedOemProfile, MercuryEmbeddedPartnerSurface, MercuryEmbeddedSdkSurface,
    MercuryGovernanceChangeClass, MercuryGovernanceControlState, MercuryGovernanceDecisionPackage,
    MercuryGovernanceGateState, MercuryGovernanceReviewAudience, MercuryGovernanceReviewPackage,
    MercuryGovernanceWorkflowPath, MercuryInquiryPackage, MercuryPackageKind, MercuryPilotScenario,
    MercuryPilotStep, MercuryPortfolioProgramArtifact, MercuryPortfolioProgramArtifactKind,
    MercuryPortfolioProgramMotion, MercuryPortfolioProgramPackage, MercuryPortfolioProgramProfile,
    MercuryPortfolioProgramSurface, MercuryPortfolioRevenueBoundaryArtifact,
    MercuryPortfolioRevenueBoundaryArtifactKind, MercuryPortfolioRevenueBoundaryMotion,
    MercuryPortfolioRevenueBoundaryPackage, MercuryPortfolioRevenueBoundaryProfile,
    MercuryPortfolioRevenueBoundarySurface, MercuryProgramFamilyArtifact,
    MercuryProgramFamilyArtifactKind, MercuryProgramFamilyMotion, MercuryProgramFamilyPackage,
    MercuryProgramFamilyProfile, MercuryProgramFamilySurface, MercuryProofPackage,
    MercuryPublicationProfile, MercuryReferenceDistributionArtifact,
    MercuryReferenceDistributionArtifactKind, MercuryReferenceDistributionMotion,
    MercuryReferenceDistributionPackage, MercuryReferenceDistributionProfile,
    MercuryReferenceDistributionSurface, MercuryReleaseReadinessArtifact,
    MercuryReleaseReadinessArtifactKind, MercuryReleaseReadinessAudience,
    MercuryReleaseReadinessDeliverySurface, MercuryReleaseReadinessPackage,
    MercuryReleaseReadinessProfile, MercuryRenewalQualificationArtifact,
    MercuryRenewalQualificationArtifactKind, MercuryRenewalQualificationMotion,
    MercuryRenewalQualificationPackage, MercuryRenewalQualificationProfile,
    MercuryRenewalQualificationSurface, MercurySecondAccountExpansionArtifact,
    MercurySecondAccountExpansionArtifactKind, MercurySecondAccountExpansionMotion,
    MercurySecondAccountExpansionPackage, MercurySecondAccountExpansionProfile,
    MercurySecondAccountExpansionSurface, MercurySecondPortfolioProgramArtifact,
    MercurySecondPortfolioProgramArtifactKind, MercurySecondPortfolioProgramMotion,
    MercurySecondPortfolioProgramPackage, MercurySecondPortfolioProgramProfile,
    MercurySecondPortfolioProgramSurface, MercurySelectiveAccountActivationArtifact,
    MercurySelectiveAccountActivationArtifactKind, MercurySelectiveAccountActivationMotion,
    MercurySelectiveAccountActivationPackage, MercurySelectiveAccountActivationProfile,
    MercurySelectiveAccountActivationSurface, MercurySupervisedLiveCapture,
    MercurySupervisedLiveControlState, MercurySupervisedLiveMode, MercuryThirdProgramArtifact,
    MercuryThirdProgramArtifactKind, MercuryThirdProgramMotion, MercuryThirdProgramPackage,
    MercuryThirdProgramProfile, MercuryThirdProgramSurface, MercuryTrustNetworkArtifact,
    MercuryTrustNetworkArtifactKind, MercuryTrustNetworkInteropSurface, MercuryTrustNetworkPackage,
    MercuryTrustNetworkProfile, MercuryTrustNetworkSponsorBoundary, MercuryTrustNetworkTrustAnchor,
    MercuryTrustNetworkWitnessStep, MercuryVerificationReport,
    MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA, MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA,
    MERCURY_ASSURANCE_PACKAGE_SCHEMA, MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA,
    MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA, MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA,
    MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA, MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA,
    MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA, MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA,
    MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA, MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA,
    MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA, MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA,
    MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA, MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA,
    MERCURY_INQUIRY_PACKAGE_SCHEMA, MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA, MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA,
    MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA, MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA,
    MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA, MERCURY_PROOF_PACKAGE_SCHEMA,
    MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA, MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA,
    MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA, MERCURY_RELEASE_READINESS_PROFILE_SCHEMA,
    MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA, MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA,
    MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA,
    MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA,
    MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA,
    MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA,
    MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA, MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA, MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA,
    MERCURY_TRUST_NETWORK_PROFILE_SCHEMA,
};
use chio_store_sqlite::SqliteReceiptStore;
use chrono::Utc;
use serde::Serialize;

mod account_delivery;
mod portfolio_program_lane;
mod portfolio_revenue_boundary_lane;
mod program_family_lane;
mod renewal_qualification_lane;
mod second_account_expansion_lane;
mod second_portfolio_program_lane;
mod selective_account_activation_support;
mod third_program_lane;

use account_delivery::export_delivery_continuity;
pub use account_delivery::{
    cmd_mercury_delivery_continuity_export, cmd_mercury_delivery_continuity_validate,
    cmd_mercury_selective_account_activation_export,
    cmd_mercury_selective_account_activation_validate,
};
use portfolio_program_lane::export_portfolio_program;
pub use portfolio_program_lane::{
    cmd_mercury_portfolio_program_export, cmd_mercury_portfolio_program_validate,
};
pub use portfolio_revenue_boundary_lane::{
    cmd_mercury_portfolio_revenue_boundary_export, cmd_mercury_portfolio_revenue_boundary_validate,
};
use program_family_lane::export_program_family;
pub use program_family_lane::{
    cmd_mercury_program_family_export, cmd_mercury_program_family_validate,
};
use renewal_qualification_lane::export_renewal_qualification;
pub use renewal_qualification_lane::{
    cmd_mercury_renewal_qualification_export, cmd_mercury_renewal_qualification_validate,
};
use second_account_expansion_lane::export_second_account_expansion;
pub use second_account_expansion_lane::{
    cmd_mercury_second_account_expansion_export, cmd_mercury_second_account_expansion_validate,
};
use second_portfolio_program_lane::export_second_portfolio_program;
pub use second_portfolio_program_lane::{
    cmd_mercury_second_portfolio_program_export, cmd_mercury_second_portfolio_program_validate,
};
use selective_account_activation_support::{
    build_selective_account_activation_profile, MercurySelectiveAccountActivationApprovalRefresh,
    MercurySelectiveAccountActivationClaimContainmentRules,
    MercurySelectiveAccountActivationCustomerHandoffBrief,
    MercurySelectiveAccountActivationDecisionRecord,
    MercurySelectiveAccountActivationExportSummary, MercurySelectiveAccountActivationManifest,
    MercurySelectiveAccountActivationScopeFreeze,
    MercurySelectiveAccountActivationValidationReport,
};
use third_program_lane::export_third_program;
pub use third_program_lane::{
    cmd_mercury_third_program_export, cmd_mercury_third_program_validate,
};

const MERCURY_WORKFLOW_BOUNDARY: &str =
    "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes.";
const MERCURY_SUPERVISED_LIVE_DECISION: &str = "proceed";
const MERCURY_DOWNSTREAM_DECISION: &str = "proceed_case_management_only";
const MERCURY_GOVERNANCE_DECISION: &str = "proceed_governance_workbench_only";
const MERCURY_ASSURANCE_DECISION: &str = "proceed_assurance_suite_only";
const MERCURY_EMBEDDED_OEM_DECISION: &str = "proceed_embedded_oem_only";
const MERCURY_TRUST_NETWORK_DECISION: &str = "proceed_trust_network_only";
const MERCURY_RELEASE_READINESS_DECISION: &str = "launch_release_readiness_only";
const MERCURY_CONTROLLED_ADOPTION_DECISION: &str = "scale_controlled_adoption_only";
const MERCURY_REFERENCE_DISTRIBUTION_DECISION: &str = "proceed_reference_distribution_only";
const MERCURY_BROADER_DISTRIBUTION_DECISION: &str = "proceed_broader_distribution_only";
const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION: &str =
    "proceed_selective_account_activation_only";
const MERCURY_DELIVERY_CONTINUITY_DECISION: &str = "proceed_delivery_continuity_only";
const MERCURY_RENEWAL_QUALIFICATION_DECISION: &str = "proceed_renewal_qualification_only";
const MERCURY_SECOND_ACCOUNT_EXPANSION_DECISION: &str = "proceed_second_account_expansion_only";
const MERCURY_PORTFOLIO_PROGRAM_DECISION: &str = "proceed_portfolio_program_only";
const MERCURY_SECOND_PORTFOLIO_PROGRAM_DECISION: &str = "proceed_second_portfolio_program_only";
const MERCURY_THIRD_PROGRAM_DECISION: &str = "proceed_third_program_only";
const MERCURY_PROGRAM_FAMILY_DECISION: &str = "proceed_program_family_only";
const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_DECISION: &str = "proceed_portfolio_revenue_boundary_only";
const MERCURY_DOWNSTREAM_DESTINATION_LABEL: &str = "case-management-review-drop";
const MERCURY_DOWNSTREAM_DESTINATION_OWNER: &str = "partner-case-management-owner";
const MERCURY_DOWNSTREAM_SUPPORT_OWNER: &str = "mercury-review-ops";
const MERCURY_GOVERNANCE_WORKFLOW_OWNER: &str = "mercury-workflow-owner";
const MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER: &str = "mercury-control-review";
const MERCURY_ASSURANCE_REVIEWER_OWNER: &str = "mercury-assurance-review";
const MERCURY_ASSURANCE_SUPPORT_OWNER: &str = "mercury-assurance-ops";
const MERCURY_EMBEDDED_PARTNER_OWNER: &str = "partner-review-platform-owner";
const MERCURY_EMBEDDED_SUPPORT_OWNER: &str = "mercury-embedded-ops";
const MERCURY_TRUST_NETWORK_SPONSOR_OWNER: &str = "counterparty-review-network-sponsor";
const MERCURY_TRUST_NETWORK_SUPPORT_OWNER: &str = "mercury-trust-network-ops";
const MERCURY_RELEASE_OWNER: &str = "mercury-release-manager";
const MERCURY_RELEASE_PARTNER_OWNER: &str = "mercury-partner-delivery";
const MERCURY_RELEASE_SUPPORT_OWNER: &str = "mercury-release-ops";
const MERCURY_CUSTOMER_SUCCESS_OWNER: &str = "mercury-customer-success";
const MERCURY_REFERENCE_OWNER: &str = "mercury-reference-program";
const MERCURY_ADOPTION_SUPPORT_OWNER: &str = "mercury-adoption-ops";
const MERCURY_BUYER_APPROVAL_OWNER: &str = "mercury-buyer-reference-approval";
const MERCURY_LANDED_ACCOUNT_SALES_OWNER: &str = "mercury-landed-account-sales";
const MERCURY_QUALIFICATION_OWNER: &str = "mercury-account-qualification";
const MERCURY_DISTRIBUTION_APPROVAL_OWNER: &str = "mercury-broader-distribution-approval";
const MERCURY_BROADER_DISTRIBUTION_OWNER: &str = "mercury-broader-distribution";
const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER: &str = "mercury-selective-account-activation";
const MERCURY_ACTIVATION_APPROVAL_OWNER: &str = "mercury-activation-approval";
const MERCURY_CONTROLLED_DELIVERY_OWNER: &str = "mercury-controlled-delivery";
const MERCURY_DELIVERY_CONTINUITY_OWNER: &str = "mercury-delivery-continuity";
const MERCURY_RENEWAL_GATE_OWNER: &str = "mercury-renewal-gate";
const MERCURY_CUSTOMER_EVIDENCE_OWNER: &str = "mercury-customer-evidence";
const MERCURY_RENEWAL_QUALIFICATION_OWNER: &str = "mercury-renewal-qualification";
const MERCURY_OUTCOME_REVIEW_OWNER: &str = "mercury-outcome-review";
const MERCURY_EXPANSION_BOUNDARY_OWNER: &str = "mercury-expansion-boundary";
const MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER: &str = "mercury-second-account-expansion";
const MERCURY_PORTFOLIO_REVIEW_OWNER: &str = "mercury-portfolio-review";
const MERCURY_REUSE_GOVERNANCE_OWNER: &str = "mercury-reuse-governance";
const MERCURY_PORTFOLIO_PROGRAM_OWNER: &str = "mercury-portfolio-program";
const MERCURY_PROGRAM_REVIEW_OWNER: &str = "mercury-program-review";
const MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER: &str = "mercury-revenue-ops-guardrails";
const MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER: &str = "mercury-second-portfolio-program";
const MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER: &str = "mercury-portfolio-reuse-review";
const MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER: &str = "mercury-revenue-boundary-guardrails";
const MERCURY_THIRD_PROGRAM_OWNER: &str = "mercury-third-program";
const MERCURY_MULTI_PROGRAM_REVIEW_OWNER: &str = "mercury-multi-program-review";
const MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER: &str = "mercury-multi-program-guardrails";
const MERCURY_PROGRAM_FAMILY_OWNER: &str = "mercury-program-family";
const MERCURY_SHARED_REVIEW_OWNER: &str = "mercury-shared-review";
const MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER: &str = "mercury-portfolio-claim-discipline";
const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER: &str = "mercury-portfolio-revenue-boundary";
const MERCURY_COMMERCIAL_REVIEW_OWNER: &str = "mercury-commercial-review";
const MERCURY_CHANNEL_BOUNDARY_OWNER: &str = "mercury-channel-boundary";

mod assurance_release;
mod core_cli;
mod shared;
use assurance_release::{
    export_assurance_suite, export_broader_distribution, export_controlled_adoption,
    export_embedded_oem, export_reference_distribution, export_release_readiness,
    export_trust_network,
};
use core_cli::export_governance_workbench;
pub use core_cli::{
    cmd_mercury_assurance_suite_export, cmd_mercury_assurance_suite_validate,
    cmd_mercury_broader_distribution_export, cmd_mercury_broader_distribution_validate,
    cmd_mercury_controlled_adoption_export, cmd_mercury_controlled_adoption_validate,
    cmd_mercury_downstream_review_export, cmd_mercury_downstream_review_validate,
    cmd_mercury_embedded_oem_export, cmd_mercury_embedded_oem_validate,
    cmd_mercury_governance_workbench_export, cmd_mercury_governance_workbench_validate,
    cmd_mercury_inquiry_export, cmd_mercury_pilot_export, cmd_mercury_proof_export,
    cmd_mercury_reference_distribution_export, cmd_mercury_reference_distribution_validate,
    cmd_mercury_release_readiness_export, cmd_mercury_release_readiness_validate,
    cmd_mercury_supervised_live_export, cmd_mercury_supervised_live_qualify,
    cmd_mercury_trust_network_export, cmd_mercury_trust_network_validate, cmd_mercury_verify,
};
use shared::*;
