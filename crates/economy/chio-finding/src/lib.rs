//! Cognition-market finding artifacts for the Chio protocol.
//!
//! The signed information-good artifact (`chio.finding.v1`) with fail-closed
//! pure validation and inline signing, plus every supporting market artifact
//! family. No storage, no I/O, no kernel wiring. Status-feed artifacts have
//! no resolver in this crate: callers resolve the feeds a profile pins and
//! supply what they find. Design:
//! docs/market/ARCHITECTURE.md sections 4-5 and ADR-0017.
//!
//! # Artifact families
//!
//! - Finding core: [`Finding`], [`FindingDescriptor`], the classification
//!   enums, and the sign/verify entry points ([`sign_finding`],
//!   [`verify_finding`]).
//! - Publication and admission: seller [`FindingMarketTerms`],
//!   [`FindingSellerAuthorization`], [`FindingBondBacking`], the reusable
//!   [`FindingChallengeVerifierProfile`], the unsigned
//!   [`FindingReplayRecipeInput`], and the venue [`FindingAdmission`]
//!   bundle.
//! - Purchase and delivery terminals: the unsigned
//!   [`FindingPurchaseContext`], the settled [`FindingPurchaseRecord`], the
//!   [`FindingFailedDelivery`] terminal, and the reveal-envelope helpers.
//! - Challenge and audit lane: the class-gated [`FindingChallenge`], its
//!   [`FindingChallengeOutcome`] and [`FindingChallengeEnforcement`], the
//!   [`FindingFinalizedBondSnapshot`], the [`FindingVerifierReport`], and
//!   the audit epoch, report, and round-authorization artifacts.
//! - Status feed: the signed sparse [`FindingStatusEpoch`], the portable
//!   [`FindingStatusProofInput`], the operator authorization, and the
//!   freshness policy.
//! - Recovery: the unsigned [`FindingRecoveryContext`] carrier and its
//!   deterministic identity.
//! - Governance: [`FindingKeyRevocation`] and [`FindingAuthorityStatus`].
//! - Hosted terminals: claim allocation, purchase result, verified-fix
//!   submission, voluntary retraction, and the liability lifecycle.
//! - Replay observation: the unsigned [`FindingReplayObservation`]
//!   preimage.
//!
//! Every family follows one grammar: a `FINDING_*_SCHEMA_V1` identifier, a
//! content-addressed `compute_*_id`, a `Signed*` envelope alias, and a
//! fail-closed `verify_signed_*` entry point that checks exact canonical
//! bytes before trusting any field.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical_json_bytes, crypto};

mod admission;
mod audit_epoch;
mod audit_report;
mod audit_round_authorization;
mod authorization;
mod backing;
mod challenge;
mod challenge_enforcement;
mod challenge_outcome;
mod envelope;
mod failed_delivery;
mod finalized_bond_snapshot;
mod hosted;
mod key_revocation;
mod profile;
mod purchase_context;
mod purchase_record;
mod recipe;
mod recovery_context;
mod replay_observation;
mod report;
mod reveal;
mod status;
mod terms;
mod types;
mod validate;

pub use admission::{
    compute_admission_id, verify_signed_admission, FindingAdmission, FindingFeeEvent,
    FindingFeeTerminalBinding, FindingPoolBinding, SignedFindingAdmission,
    FINDING_ADMISSION_SCHEMA_V1,
};
pub use audit_epoch::{
    audit_seed_witness_signing_bytes, compute_audit_epoch_id, derive_audit_seed_commitment,
    verify_signed_audit_epoch, FindingAuditEpoch, SignedFindingAuditEpoch,
    FINDING_AUDIT_EPOCH_SCHEMA_V1, MAX_PUBLISHED_RATE_BPS,
};
pub use audit_report::{
    compute_audit_report_id, verify_audit_report_epoch_binding, verify_signed_audit_report,
    FindingAuditReport, FindingMissedAudit, SignedFindingAuditReport,
    FINDING_AUDIT_REPORT_SCHEMA_V1, MAX_AUDIT_SELECTION,
};
pub use audit_round_authorization::{
    audit_epoch_precommitment_sha256, verify_signed_audit_round_authorization,
    FindingAuditRoundAuthorization, SignedFindingAuditRoundAuthorization,
    FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1,
};
pub use authorization::{
    compute_authorization_id, verify_signed_seller_authorization, FindingPayee,
    FindingSellerAuthorization, SignedFindingSellerAuthorization,
    FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1, FINDING_SELLER_AUTHORIZATION_SCHEMA_V1,
};
pub use backing::{
    compute_allocation_id, verify_signed_bond_backing, FindingBondBacking, FindingBondClass,
    FindingCollateralVault, SignedFindingBondBacking, FINDING_BOND_BACKING_SCHEMA_V1,
};
pub use challenge::{
    compute_challenge_id, ensure_challenge_class_compatibility, verify_signed_challenge,
    FindingAffectedDelivery, FindingBuyerSubmission, FindingChallenge,
    FindingChallengeAuthorization, FindingChallengeAuthorizationKind, FindingChallengeEvidence,
    FindingChallengeEvidenceKind, FindingChallengeStanding, FindingCheckpointRef,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingReceiptRef, FindingReplayReproduction,
    FindingVenueAuditAuthorization, SignedFindingChallenge, FINDING_CHALLENGE_SCHEMA_V1,
    MAX_CHALLENGE_AFFECTED_DELIVERIES, MAX_CHALLENGE_CHALLENGED_EVIDENCE_REFS,
    MAX_CHALLENGE_RECIPE_PREIMAGE_BYTES, MAX_CHALLENGE_REPRODUCTIONS,
};
pub use challenge_enforcement::{
    compute_enforcement_id, derive_seller_impair_intent_id, verify_signed_challenge_enforcement,
    FindingChallengeEnforcement, FindingEffectIntentBinding, FindingEffectIntentKind,
    FindingEnforcementDestination, SignedFindingChallengeEnforcement,
    FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1, MAX_ENFORCEMENT_DESTINATIONS,
};
pub use challenge_outcome::{
    derive_outcome_id, verdict_for_replay_predicate, verify_outcome_challenge_binding,
    verify_signed_challenge_outcome, FindingChallengeFacet, FindingChallengeOutcome,
    FindingChallengeVerdict, FindingDigestMismatchFacet, FindingEvidenceInvalidFacet,
    FindingEvidenceInvalidity, FindingPenaltyCalculation, FindingReplayContradictionFacet,
    FindingReplayPredicateResult, SignedFindingChallengeOutcome,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1, MAX_OUTCOME_CHALLENGED_RECEIPTS,
    MAX_OUTCOME_OBSERVATION_DIGESTS,
};
pub use envelope::{signed_envelope_sha256, verify_pinned_envelope};
pub use failed_delivery::{
    compute_failed_delivery_id, verify_signed_failed_delivery, FindingFailedDelivery,
    FindingHoldReleaseTerminal, SignedFindingFailedDelivery, FINDING_FAILED_DELIVERY_SCHEMA_V1,
};
pub use finalized_bond_snapshot::{
    compute_snapshot_id, verify_signed_finalized_bond_snapshot, FindingFinalizedBondSnapshot,
    FindingObservedFinality, FindingVaultReference, SignedFindingFinalizedBondSnapshot,
    FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
};
pub use hosted::{
    FindingClaimAllocation, FindingClaimAllocationEntry, FindingClaimBeneficiaryKind,
    FindingHostedPurchaseVerdict, FindingHostedSettlementTerminal, FindingLiability,
    FindingLiabilityLifecycleState, FindingPurchaseResult, FindingVerifiedFixSubmission,
    FindingVoluntaryRetraction, FindingVoluntaryRetractionReason, SignedFindingClaimAllocation,
    SignedFindingLiability, SignedFindingPurchaseResult, SignedFindingVerifiedFixSubmission,
    SignedFindingVoluntaryRetraction, FINDING_CLAIM_ALLOCATION_SCHEMA_V1,
    FINDING_LIABILITY_SCHEMA_V1, FINDING_PURCHASE_RESULT_SCHEMA_V1,
    FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA_V1, FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1,
};
pub use key_revocation::{
    verify_signed_authority_status, verify_signed_key_revocation, FindingAuthorityStatus,
    FindingKeyRevocation, SignedFindingAuthorityStatus, SignedFindingKeyRevocation,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1, FINDING_KEY_REVOCATION_SCHEMA_V1,
};
pub use profile::{
    compute_profile_id, finding_checkpoint_log_id, verify_signed_profile,
    FindingAuthorityKeyPolicy, FindingBbsIssuerPolicy, FindingChallengeVerifierProfile,
    FindingCheckpointLogPolicy, FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole,
    FindingResourceCaps, SignedFindingChallengeVerifierProfile,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1,
};
pub use purchase_context::{
    decode_purchase_context_b64, parse_purchase_context, FindingPurchaseContext,
    PURCHASE_CONTEXT_MAX_CANONICAL_BYTES, PURCHASE_CONTEXT_MAX_ENCODED_BYTES,
    PURCHASE_CONTEXT_SCHEMA,
};
pub use purchase_record::{
    canonical_evm_payout_destination, derive_purchase_key, validate_evm_payout_destination,
    verify_signed_purchase_record, FindingPurchaseRecord, SignedFindingPurchaseRecord,
    FINDING_PURCHASE_RECORD_SCHEMA_V1,
};
pub use recipe::{
    FindingClaimedVerdict, FindingPreRunTemplate, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayRecipeInput, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
};
pub use recovery_context::{
    derive_finding_recovery_id, parse_finding_recovery_context, FindingRecoveryContext,
    FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES, FINDING_RECOVERY_CONTEXT_SCHEMA_V1,
};
pub use replay_observation::{
    FindingReplayObservation, FindingReplayTerminalResult, FINDING_REPLAY_OBSERVATION_SCHEMA_V1,
    MAX_REPLAY_OBSERVATION_BYTES,
};
pub use report::{
    compute_report_id, required_finding_facets, verify_signed_verifier_report, FindingFacetKind,
    FindingFacetOutcome, FindingFacetResult, FindingVerifierReport, SignedFindingVerifierReport,
    FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
pub use reveal::{finding_payload_sha256, finding_reveal_envelope, FindingRevealEnvelope};
pub use status::{
    build_status_inclusion_proof_input, build_status_non_inclusion_proof_input,
    compute_status_epoch_id, decode_signed_status_epoch_b64, decode_status_proof_input_b64,
    parse_signed_status_epoch, parse_status_proof_input, status_epoch_envelope_sha256,
    verify_signed_status_epoch, verify_status_proof_input, FindingStatusEpoch,
    FindingStatusFreshnessPolicy, FindingStatusInclusionProofInput,
    FindingStatusNonInclusionProofInput, FindingStatusOperatorAuthorization,
    FindingStatusOperatorRole, FindingStatusProofInput, FindingStatusValue,
    SignedFindingStatusEpoch, FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
    FINDING_STATUS_SIGNATURE_DOMAIN, MAX_FINDING_STATUS_ANCHOR_REFS,
    MAX_FINDING_STATUS_ENCODED_BYTES, MAX_FINDING_STATUS_EPOCH_BYTES,
    MAX_FINDING_STATUS_PROOF_BYTES,
};
pub use terms::{
    compute_terms_id, verify_signed_market_terms, FindingBackingRequirement,
    FindingChallengeBondLimit, FindingMarketTerms, SignedFindingMarketTerms,
    FINDING_COLLATERAL_POLICY_VENUE_LEDGER_EXCLUSIVE_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_PAYOUT_POLICY_PRO_RATA_CAPPED_V1,
};
pub use types::{
    Finding, FindingDescriptor, FindingEvidenceClass, FindingGuaranteeClass, FindingOutcomeClass,
    FINDING_SCHEMA_V1,
};
pub use validate::{
    compute_finding_id, sign_finding, sign_finding_with_backend, verify_finding,
    verify_finding_signature, FindingError, MAX_FINDING_ARTIFACT_ITEMS,
    MAX_FINDING_EVIDENCE_RECEIPTS, MAX_FINDING_IDENTIFIER_BYTES, MAX_FINDING_TEXT_BYTES,
};
