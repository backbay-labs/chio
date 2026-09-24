//! End-to-end coverage for the finding challenge and audit lane: a buyer
//! files a challenge and pays for it, a venue audit files one and pays
//! nothing, a verdict disposes the bond it earned, an upheld verdict
//! blocks the listing and freezes the purchase cutoff, the sealed
//! accounting sums exactly, the three penalty branches hold, reverse, and
//! slash, an unresolved appeal quarantines instead of impairing, and an
//! ambiguous impairment leaves the liability parked with purchases still
//! denied.
//! All three evidence classes are driven from real artifacts rather than
//! from a stubbed verdict: the findings are signed, the receipts are
//! kernel signed and Merkle committed to real checkpoints, the profile is
//! governance signed, and every digest travels derived rather than
//! asserted, because the evaluator's whole job is to refuse anything that
//! only claims to bind. Each class reaches an enforced sanction, and the
//! denials that merely resemble fraud reach none.
//!
//! One sqlite authority store backs the market, purchase, and challenge
//! stores, so the upheld transaction runs against the same connection and
//! the same serving-owner fence the sale path uses.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use axum::body::{to_bytes, Body, Bytes};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request as HttpRequest, StatusCode};
use chio_core::canonical_json_bytes;
use chio_core::canonical_json_string;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::merkle::{leaf_hash, MerkleTree};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::TrustLevel;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::receipt::metadata::{
    DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
    FindingMediaTypeCheck, FindingTransformProfile, DELIVERY_CONTRACT_METADATA_KEY,
    DELIVERY_CONTRACT_SCHEMA, FINDING_DELIVERY_METADATA_KEY, FINDING_DELIVERY_SCHEMA,
};
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    audit_epoch_precommitment_sha256, audit_seed_witness_signing_bytes, compute_admission_id,
    compute_allocation_id, compute_audit_epoch_id, compute_challenge_id, compute_enforcement_id,
    compute_failed_delivery_id, compute_finding_id, compute_profile_id, compute_snapshot_id,
    compute_terms_id, derive_audit_seed_commitment, derive_purchase_key, sign_finding,
    signed_envelope_sha256, Finding, FindingAdmission, FindingAffectedDelivery, FindingAuditEpoch,
    FindingAuditRoundAuthorization, FindingAuthorityKeyPolicy, FindingBackingRequirement,
    FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass, FindingBuyerSubmission,
    FindingChallenge, FindingChallengeAuthorization, FindingChallengeBondLimit,
    FindingChallengeEnforcement, FindingChallengeEvidence, FindingChallengeFacet,
    FindingChallengeStanding, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingCheckpointRef, FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingEffectIntentBinding, FindingEnforcementDestination,
    FindingEvidenceClass, FindingEvidenceInvalidity, FindingFacetKind, FindingFailedDelivery,
    FindingFeeEvent, FindingFeeTerminalBinding, FindingFinalizedBondSnapshot,
    FindingGuaranteeClass, FindingHoldReleaseTerminal, FindingMarketTerms, FindingObservedFinality,
    FindingOutcomeClass, FindingPoolBinding, FindingPredicate, FindingPurchaseRecord,
    FindingReceiptRef, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingReplayObservation,
    FindingReplayPredicateResult, FindingReplayRecipeInput, FindingReplayReproduction,
    FindingResourceCaps, FindingVaultReference, FindingVenueAuditAuthorization,
    SignedFindingAdmission, SignedFindingAuthorityStatus, SignedFindingChallenge,
    SignedFindingChallengeEnforcement, SignedFindingChallengeOutcome,
    SignedFindingChallengeVerifierProfile, SignedFindingFailedDelivery,
    SignedFindingFinalizedBondSnapshot, SignedFindingMarketTerms, SignedFindingPurchaseRecord,
    FINDING_ADMISSION_SCHEMA_V1, FINDING_AUDIT_EPOCH_SCHEMA_V1,
    FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1, FINDING_CHALLENGE_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_FAILED_DELIVERY_SCHEMA_V1,
    FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_PURCHASE_RECORD_SCHEMA_V1, FINDING_REPLAY_OBSERVATION_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1, MAX_PUBLISHED_RATE_BPS,
};
use chio_finding_challenge::{
    FindingChallengeClassEvidence, FindingDigestMismatchEvidence, FindingEvidenceInvalidEvidence,
    FindingPurchaseStandingEvidence, FindingReplayContradictionEvidence,
    FindingResolvedReproduction,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_body_sha256,
    checkpoint_log_id, CheckpointTransparencySummary, KernelCheckpoint,
};
use chio_open_market::bidding::{
    AcceptedBid, BidRequest, RequestedScope, ReservationReceipt, SignedAcceptedBid,
    SignedBidRequest, SignedReservationReceipt, ACCEPTED_BID_SCHEMA, BID_REQUEST_SCHEMA,
    RESERVATION_RECEIPT_SCHEMA,
};
use chio_open_market::evaluation::OpenMarketPenaltyEvaluation;
use chio_open_market::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference};
use chio_open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
    SignedOpenMarketFeeSchedule,
};
use chio_open_market::finding_audit::{
    derive_audit_draw, derive_eligible_snapshot_digest, EligibleListing,
    AUDIT_SELECTION_ALGORITHM_V1,
};
use chio_open_market::governance::generic::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    GenericGovernanceAuthorityScope, GenericGovernanceCaseIssueRequest, GenericGovernanceCaseKind,
    GenericGovernanceCaseState, GenericGovernanceCharterIssueRequest,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference, SignedGenericGovernanceCase,
    SignedGenericGovernanceCharter,
};
use chio_open_market::listing::{
    build_generic_trust_activation_artifact, GenericListingActorKind, GenericListingArtifact,
    GenericListingBoundary, GenericListingCompatibilityReference, GenericListingFreshnessState,
    GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
    GenericNamespaceArtifact, GenericNamespaceLifecycleState, GenericNamespaceOwnership,
    GenericRegistryPublisher, GenericRegistryPublisherRole, GenericTrustActivationDisposition,
    GenericTrustActivationEligibility, GenericTrustActivationIssueRequest,
    GenericTrustActivationReviewContext, GenericTrustAdmissionClass, SignedGenericListing,
    SignedGenericTrustActivation, GENERIC_LISTING_ARTIFACT_SCHEMA,
    GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
};
use chio_open_market::penalty::{
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyArtifact,
    OpenMarketPenaltyEffectiveState, OpenMarketPenaltyState, SignedOpenMarketPenalty,
    OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use chio_settle::{
    finding_anchor_checkpoint_statement_sha256, prepare_bond_impair,
    settlement_devnet_rpc_egress_contract, EvmBondSnapshot, EvmTransactionReceipt,
    FindingAnchorCheckpointPublication, FindingBondObservationRecheck, FindingImpairmentAttempt,
    FindingImpairmentOutcome, FindingImpairmentPublishError, FindingImpairmentPublisher,
    FindingImpairmentQuarantine, FindingVaultRejection, PreparedEvmCall, SettlementChainConfig,
    SettlementEvidenceConfig, SettlementFinalityStatus, SettlementOracleConfig,
    SettlementPolicyConfig, SignedFindingAnchorCheckpointPublication, StoredImpairmentTransaction,
    FINDING_ANCHOR_CHECKPOINT_PUBLICATION_SCHEMA_V1,
};
use chio_store_sqlite::finding_market_store::{FindingRecordInput, SqliteFindingMarketStore};
use chio_store_sqlite::{
    derive_dispute_bond_funding_intent_key, dispute_bond_funding_intent_digest,
    FindingChallengeState, FindingChallengeVerdict, FindingChallengeWriteOutcome,
    FindingDisputeLockDisposition, FindingDisputeLockInput, FindingDisputeLockState,
    FindingEffectIntentKind, FindingEffectIntentState, FindingLiabilityState,
    FindingPurchaseDeliveryInput, FindingPurchaseDenyInput, FindingPurchaseReservationInput,
    FindingRetractionIntentCommitLiveness, SqliteAuthorityStore, SqliteFindingChallengeStore,
    SqliteFindingPurchaseStore,
};
use futures_util::stream;

use crate::trust_control::finding_challenge_coordinator::{
    anchor_evidence_intent_commitment, derive_anchor_evidence_intent_key, derive_defect_key,
    derive_liability_key, require_admitted_replay_decision_rule, root_intent_commitment,
    AppealDisposition, AppealResolution, AuthorizedImpairment, ChallengeCoordinatorError,
    ChallengeEvaluationRequest, ChallengeSubmissionOutcome, EvaluationAdmission, FindingAuditRound,
    FindingAuthorityStatus, FindingAuthorityStatusResolver, FindingChallengeCoordinator,
    FindingCollateralFacts, FindingFilingResolver, FindingFinalization, FindingLiabilityIdentity,
    FindingPenaltyGovernance, FindingPenaltyOutcome, UpheldLiability,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use crate::trust_control::{
    FederationAdmissionRateLimiter, FindingAuthorityPin, FindingChallengeSubmissionExecutor,
    FindingChallengeSubmissionRequest, FindingChallengeSubmissionResponse,
    FindingChallengeSubmissionRuntime, FindingChallengeSubmissionWrite, FindingMarketConfig,
    FindingPoolPin, FindingStatusOperatorPin, FindingStatusServiceBond, TrustServiceConfig,
    TrustServiceState, FINDING_STATUS_OPERATOR_ROLE,
};
use crate::trust_control::{FindingRailInstruction, FindingRailObservation, FindingRailObserver};
use chio_test_support::plain::TestResultOk;
use tower::ServiceExt;

#[path = "finding_challenge_enforcement_e2e_tests/appeal_finality_tests.rs"]
mod appeal_finality_tests;
#[path = "finding_challenge_enforcement_e2e_tests/audit_and_configuration_tests.rs"]
mod audit_and_configuration_tests;
#[path = "finding_challenge_enforcement_e2e_tests/enforcement_anchor_proof.rs"]
mod enforcement_anchor_proof_fixture;
#[path = "finding_challenge_enforcement_e2e_tests/evidence_bundle_tests.rs"]
mod evidence_bundle_tests;
#[path = "finding_challenge_enforcement_e2e_tests/purchase_standing_fixture.rs"]
mod purchase_standing_fixture;
#[path = "finding_challenge_enforcement_e2e_tests/replay_fixture.rs"]
mod replay_fixture;
#[path = "finding_challenge_enforcement_e2e_tests/status_impairment_tests.rs"]
mod status_impairment_tests;

use enforcement_anchor_proof_fixture::{
    anchor_evidence_hash, enforcement_anchor_proof, sample_anchor_evidence_hash,
};
use purchase_standing_fixture::{clone_resolved, settled_delivery_evidence, SettledPurchase};
use replay_fixture::{PhaseShape, ReplayActionFactory};

use super::build_router;

type AnyError = Box<dyn std::error::Error>;
type TestResult = Result<(), AnyError>;

struct FixtureStatusCommitClock;

impl crate::trust_control::finding_challenge_coordinator::FindingStatusCommitClock
    for FixtureStatusCommitClock
{
    fn now_unix_secs(&self, venue_now: u64) -> u64 {
        venue_now
    }
}

const VENUE_ID: &str = "venue-challenge";
const LISTING_ID: &str = "listing-42";
const NAMESPACE: &str = "https://registry.chio.example";
const OPERATOR_ID: &str = "https://registry.chio.example";
const AUDIT_POOL_PRINCIPAL: &str = "pool:audit";
const AUDIT_POOL_DESTINATION: &str = "rail:venue-ledger:audit-pool";
const CHALLENGE_POOL_PRINCIPAL: &str = "pool:challenge-admin";
const CHALLENGE_POOL_DESTINATION: &str = "rail:venue-ledger:challenge-admin";
const COMMUNITY_FUND_DESTINATION: &str = "0xcccccccccccccccccccccccccccccccccccccccc";
const BUYER_ONE_DESTINATION: &str = "rail:venue-ledger:buyer-one";
const BUYER_TWO_DESTINATION: &str = "rail:venue-ledger:buyer-two";
const CHALLENGER_BOUNTY_DESTINATION: &str = "rail:venue-ledger:challenger-bounty";
const NOW: u64 = 1_750_000_000;
fn buyer_destination(seed: u8) -> String {
    format!("0x{seed:040x}")
}
/// Seller-signed claim window. Two distinct second-granular instants keep
/// the window-opening and sealing calls one tick apart.
const CLAIM_WINDOW_SECS: u64 = 1;
// The shorter signed dispute lock is this fixture's retry cap.
const RETRY_POLICY_DEADLINE: u64 = NOW + 86_400;
const REGISTERED_EXPOSURE_CAP: u64 = 450;
// Every pinned role and revocation status uses this epoch.
const PINNED_KEY_EPOCH: u64 = 1;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const REVOCATION_STATUS_REF: &str = "revocations/finding-market";
// The published challenge fee and stake. Other values are not priced by
// the schedule.
const DISPUTE_FEE_UNITS: u64 = 25;
const DISPUTE_BOND_UNITS: u64 = 40;

// Appeal finality is reachable only after the seller-signed window.
const APPEAL_FINAL_AT: u64 = NOW + 400_000;
/// The sanction case `finalizing_liability` records as the live head.
const FIXTURE_SANCTION_CASE_ID: &str = "case-sanction-fixture-01";
const FIXTURE_HELD_PENALTY_ID: &str = "market-penalty-hold-fixture";

// Shared key-role validity window and revocation publication instant.
const KEY_VALID_FROM: u64 = 1_600_000_000;
const KEY_VALID_UNTIL: u64 = 1_900_000_000;
const PUBLISHED_AT: u64 = 1_700_000_000;

// Kernel log coordinates must match each signed checkpoint's batch range.
const PRODUCTION_FIRST_AT: u64 = 1_690_000_000;
const EVIDENCE_CHECKPOINT_SEQ: u64 = 1;
const EVIDENCE_FIRST_SEQ: u64 = 1;
const EVIDENCE_LAST_SEQ: u64 = 2;
const DENY_AT: u64 = 1_745_000_000;
const DENY_CHECKPOINT_SEQ: u64 = 1;
const DENY_RECEIPT_SEQ: u64 = 1;
const REPLAY_AT: u64 = 1_746_000_000;
const REPLAY_CHECKPOINT_SEQ: u64 = 1;
const REPLAY_FIRST_SEQ: u64 = 1;
const REPLAY_RUN_ID: &str = "replay-run-01";

// The denied reveal the digest-mismatch class rests on. It never became a
// purchase record, so these identifiers live only on the failed-delivery
// terminal and the delivery overlay that must agree with it.
const DENY_RESERVATION_ID: &str = "reservation-denied-01";
const DENY_INTENT_ID: &str = "intent-denied-01";
const DENY_PAYMENT_ID: &str = "payment-denied-01";

// Settlement fixtures. The bond vault takes EVM addresses, so the
// impairment leg is denominated in them rather than the rail-tagged
// destinations the purchase index admits.
const BOND_VAULT_CONTRACT: &str = "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125";
const OPERATOR_KEY_HASH: &str =
    "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975";
const EVM_BUYER_DESTINATION: &str = "0x1000000000000000000000000000000000000006";
const EVM_COMMUNITY_FUND: &str = "0x1000000000000000000000000000000000000007";
const OBSERVED_AT: u64 = 1_750_090_000;
const SETTLEMENT_NOW: u64 = OBSERVED_AT + 500;
const MAX_SNAPSHOT_AGE_SECS: u64 = 3_600;

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn hex64(character: char) -> String {
    character.to_string().repeat(64)
}

fn byte_hex64(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn chain_hash(byte: u8) -> String {
    format!("0x{}", byte_hex64(byte))
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn digest(tag: &str) -> String {
    sha256_hex(tag.as_bytes())
}

fn secure_directory(path: &std::path::Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn authority_pin(seed: u8, id: &str) -> FindingAuthorityPin {
    FindingAuthorityPin {
        authority_id: id.to_string(),
        key_hex: keypair(seed).public_key().to_hex(),
        key_epoch: PINNED_KEY_EPOCH,
        valid_from: 1,
        valid_until: I_JSON_MAX_SAFE_INTEGER,
        revocation_status_ref: REVOCATION_STATUS_REF.to_string(),
    }
}

#[derive(Debug, Clone)]
struct TestAuthorityStatusResolver {
    signer_seed: u8,
    status_ref_override: Option<String>,
    revoked_authority: Option<String>,
    revoked_from_override: Option<u64>,
    observed_at_override: Option<u64>,
}

impl TestAuthorityStatusResolver {
    fn live() -> Self {
        Self {
            signer_seed: 37,
            status_ref_override: None,
            revoked_authority: None,
            revoked_from_override: None,
            observed_at_override: None,
        }
    }
}

impl FindingAuthorityStatusResolver for TestAuthorityStatusResolver {
    fn resolve(
        &self,
        pin: &FindingAuthorityPin,
        now: u64,
    ) -> Result<chio_core::receipt::lineage::SignedExportEnvelope<FindingAuthorityStatus>, String>
    {
        let body = FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: self
                .status_ref_override
                .clone()
                .unwrap_or_else(|| pin.revocation_status_ref.clone()),
            authority_id: pin.authority_id.clone(),
            key: pin.key().map_err(|error| error.to_string())?,
            key_epoch: pin.key_epoch,
            revoked_from: self
                .revoked_authority
                .as_ref()
                .filter(|authority| *authority == &pin.authority_id)
                .map(|_| self.revoked_from_override.unwrap_or(1)),
            observed_at: self.observed_at_override.unwrap_or(now),
        };
        SignedExportEnvelope::sign(body, &keypair(self.signer_seed))
            .map_err(|error| error.to_string())
    }

    fn checkpoint_publication(
        &self,
        proof: &AnchorInclusionProof,
        now: u64,
    ) -> Result<SignedFindingAnchorCheckpointPublication, String> {
        SignedExportEnvelope::sign(
            FindingAnchorCheckpointPublication {
                schema: FINDING_ANCHOR_CHECKPOINT_PUBLICATION_SCHEMA_V1.to_string(),
                checkpoint_statement_sha256: finding_anchor_checkpoint_statement_sha256(proof)
                    .map_err(|error| error.to_string())?,
                checkpoint_seq: proof.checkpoint_statement.checkpoint_seq,
                published_at: proof.checkpoint_statement.issued_at,
                observed_at: self.observed_at_override.unwrap_or(now),
            },
            &keypair(self.signer_seed),
        )
        .map_err(|error| error.to_string())
    }
}

fn market_config() -> FindingMarketConfig {
    FindingMarketConfig {
        venue_id: VENUE_ID.to_string(),
        venue: authority_pin(6, "venue"),
        listing: authority_pin(24, "listing"),
        governance_root: authority_pin(1, "governance"),
        authority_status: authority_pin(37, "authority-status"),
        verifier_report: authority_pin(15, "verifier-report"),
        collateral: authority_pin(4, "collateral"),
        purchase: authority_pin(16, "purchase"),
        failed_delivery: authority_pin(17, "failed-delivery"),
        challenge_evaluator: authority_pin(31, "challenge-evaluator"),
        venue_finalization: authority_pin(32, "venue-finalization"),
        market_penalty: authority_pin(33, "market-penalty"),
        settlement_observer: authority_pin(34, "settlement-observer"),
        anchor_publisher: authority_pin(7, "anchor-publisher"),
        max_snapshot_age_secs: MAX_SNAPSHOT_AGE_SECS,
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 64,
        },
        audit_authority: authority_pin(35, "audit-authority"),
        audit_randomness_witness: authority_pin(38, "audit-randomness-witness"),
        audit_pool: FindingPoolPin {
            principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
            rail_destination: AUDIT_POOL_DESTINATION.to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolPin {
            principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
            rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: COMMUNITY_FUND_DESTINATION.to_string(),
        status_feed_operator_ref: "status-feed/venue-challenge".to_string(),
        status_feed_operator: FindingStatusOperatorPin {
            feed_id: "status-feed/venue-challenge".to_string(),
            role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
            authority: authority_pin(36, "status-operator"),
            rotation_policy_ref: "rotation-policy/status-feed-v1".to_string(),
            authorization_sha256: digest("status-operator-authorization"),
            revoked_from: None,
        },
        status_feed_service_bond: FindingStatusServiceBond {
            bond_id: "status-bond-venue-challenge".to_string(),
            feed_id: "status-feed/venue-challenge".to_string(),
            operator_id: "status-operator".to_string(),
            locked_units: 1_000,
            currency: "USD".to_string(),
            valid_from: 1,
            valid_until: u64::MAX,
            inclusion_sla_secs: 3_600,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: digest("status-bond-venue-challenge"),
        },
        status_max_epoch_age_secs: 300,
        fee_schedule_operator_keys: vec![fee_schedule_keypair().public_key().to_hex()],
    }
}

/// Rail that acknowledges every instruction and keeps what it was asked
/// to move, so a test can prove which pool a charge actually reached, and
/// that can be told to refuse, as a rail that cannot settle would.
#[derive(Default)]
struct RecordingRail {
    instructions: Mutex<Vec<FindingRailInstruction>>,
    refusing: AtomicBool,
    misreporting: AtomicBool,
    dispatch_attempts: AtomicUsize,
    fail_after_record_on_attempt: AtomicUsize,
}

impl RecordingRail {
    fn charges(&self) -> Vec<FindingRailInstruction> {
        self.instructions
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn refuse(&self) {
        self.refusing.store(true, Ordering::SeqCst);
    }

    fn accept(&self) {
        self.refusing.store(false, Ordering::SeqCst);
    }

    fn fail_after_record_on_attempt(&self, attempt: usize) {
        self.fail_after_record_on_attempt
            .store(attempt, Ordering::SeqCst);
    }

    fn misreport(&self) {
        self.misreporting.store(true, Ordering::SeqCst);
    }
}

impl FindingRailObserver for RecordingRail {
    fn dispatch(
        &self,
        instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String> {
        let attempt = self.dispatch_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if self.refusing.load(Ordering::SeqCst) {
            return Err("rail refused the instruction".to_string());
        }
        if let Ok(mut guard) = self.instructions.lock() {
            if let Some(recorded) = guard
                .iter()
                .find(|recorded| recorded.idempotency_key == instruction.idempotency_key)
            {
                if recorded.payer != instruction.payer
                    || recorded.amount_units != instruction.amount_units
                    || recorded.currency != instruction.currency
                    || recorded.pool_principal_id != instruction.pool_principal_id
                    || recorded.rail_destination != instruction.rail_destination
                {
                    return Err("idempotency key was reused for another instruction".to_string());
                }
            } else {
                guard.push(instruction.clone());
            }
        }
        if self.fail_after_record_on_attempt.load(Ordering::SeqCst) == attempt {
            return Err("rail response was lost after recording the instruction".to_string());
        }
        Ok(FindingRailObservation {
            instruction_sha256: if self.misreporting.load(Ordering::SeqCst) {
                digest("another instruction")
            } else {
                sha256_hex(&canonical_json_bytes(instruction).map_err(|error| error.to_string())?)
            },
            amount_units: instruction.amount_units,
            currency: instruction.currency.clone(),
            rail_destination: instruction.rail_destination.clone(),
            rail: "venue-ledger".to_string(),
        })
    }
}

/// The venue's published record of the signed artifacts a filing may bind
/// by digest. A filing resolves against this and nothing else, so a digest
/// that names an artifact the venue never published resolves to nothing.
#[derive(Default)]
struct PublishedArtifacts {
    fee_schedules: BTreeMap<String, SignedOpenMarketFeeSchedule>,
    audit_rounds: BTreeMap<String, FindingAuditRound>,
    admissions: BTreeMap<(String, String, String), SignedFindingAdmission>,
    admissions_by_digest: BTreeMap<String, SignedFindingAdmission>,
    venue_policies: BTreeMap<String, FindingAuthorityPin>,
    profile_governance_policies: BTreeMap<String, FindingAuthorityPin>,
    case_governance_policies: RwLock<BTreeMap<String, FindingAuthorityPin>>,
    penalty_policies: RwLock<BTreeMap<String, FindingAuthorityPin>>,
    evaluator_policies: RwLock<BTreeMap<String, FindingAuthorityPin>>,
    audit_policies: BTreeMap<String, FindingAuthorityPin>,
    audit_witness_policies: BTreeMap<String, FindingAuthorityPin>,
    audit_governance_policies: BTreeMap<String, FindingAuthorityPin>,
    market_terms: BTreeMap<String, SignedFindingMarketTerms>,
}

fn clone_policy_lock(
    source: &RwLock<BTreeMap<String, FindingAuthorityPin>>,
) -> RwLock<BTreeMap<String, FindingAuthorityPin>> {
    let values = match source.read() {
        Ok(values) => values.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    RwLock::new(values)
}

impl Clone for PublishedArtifacts {
    fn clone(&self) -> Self {
        Self {
            fee_schedules: self.fee_schedules.clone(),
            audit_rounds: self.audit_rounds.clone(),
            admissions: self.admissions.clone(),
            admissions_by_digest: self.admissions_by_digest.clone(),
            venue_policies: self.venue_policies.clone(),
            profile_governance_policies: self.profile_governance_policies.clone(),
            case_governance_policies: clone_policy_lock(&self.case_governance_policies),
            penalty_policies: clone_policy_lock(&self.penalty_policies),
            evaluator_policies: clone_policy_lock(&self.evaluator_policies),
            audit_policies: self.audit_policies.clone(),
            audit_witness_policies: self.audit_witness_policies.clone(),
            audit_governance_policies: self.audit_governance_policies.clone(),
            market_terms: self.market_terms.clone(),
        }
    }
}

impl PublishedArtifacts {
    fn publish_schedule(
        mut self,
        schedule: &SignedOpenMarketFeeSchedule,
    ) -> Result<Self, AnyError> {
        self.fee_schedules
            .insert(signed_envelope_sha256(schedule)?, schedule.clone());
        Ok(self)
    }

    fn publish_round(
        mut self,
        round: &FindingAuditRound,
        audit_policy: FindingAuthorityPin,
        witness_policy: FindingAuthorityPin,
        governance_policy: FindingAuthorityPin,
    ) -> Result<Self, AnyError> {
        let epoch_digest = signed_envelope_sha256(&round.epoch)?;
        let authorization_digest = signed_envelope_sha256(&round.authorization)?;
        self.audit_policies
            .insert(epoch_digest.clone(), audit_policy);
        self.audit_witness_policies
            .insert(epoch_digest.clone(), witness_policy);
        self.audit_governance_policies
            .insert(authorization_digest, governance_policy);
        self.audit_rounds.insert(epoch_digest, round.clone());
        Ok(self)
    }

    fn publish_admission(
        mut self,
        admission: &SignedFindingAdmission,
        venue_policy: FindingAuthorityPin,
    ) -> Result<Self, AnyError> {
        let digest = signed_envelope_sha256(admission)?;
        self.admissions_by_digest
            .insert(digest.clone(), admission.clone());
        self.venue_policies.insert(digest, venue_policy);
        self.admissions.insert(
            (
                admission.body.finding_id.clone(),
                admission.body.listing_id.clone(),
                admission.body.backing_envelope_sha256.clone(),
            ),
            admission.clone(),
        );
        Ok(self)
    }

    fn publish_terms(mut self, terms: &SignedFindingMarketTerms) -> Result<Self, AnyError> {
        self.market_terms
            .insert(signed_envelope_sha256(terms)?, terms.clone());
        Ok(self)
    }

    fn publish_profile_policy(
        mut self,
        profile: &SignedFindingChallengeVerifierProfile,
        governance_policy: FindingAuthorityPin,
    ) -> Result<Self, AnyError> {
        self.profile_governance_policies
            .insert(signed_envelope_sha256(profile)?, governance_policy);
        Ok(self)
    }

    fn publish_governance_policy<T: serde::Serialize>(
        mut self,
        artifact: &SignedExportEnvelope<T>,
        governance_policy: FindingAuthorityPin,
    ) -> Result<Self, AnyError> {
        self.case_governance_policies
            .get_mut()
            .map_err(|_| "governance-policy index lock is poisoned")?
            .insert(signed_envelope_sha256(artifact)?, governance_policy);
        Ok(self)
    }

    fn retain_governance_policy<T: serde::Serialize>(
        &self,
        artifact: &SignedExportEnvelope<T>,
        governance_policy: FindingAuthorityPin,
    ) -> Result<(), AnyError> {
        self.case_governance_policies
            .write()
            .map_err(|_| "governance-policy index lock is poisoned")?
            .insert(signed_envelope_sha256(artifact)?, governance_policy);
        Ok(())
    }
}

impl FindingFilingResolver for PublishedArtifacts {
    fn fee_schedule(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedOpenMarketFeeSchedule>, String> {
        Ok(self.fee_schedules.get(envelope_sha256).cloned())
    }

    fn audit_round(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuditRound>, String> {
        Ok(self.audit_rounds.get(epoch_envelope_sha256).cloned())
    }

    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String> {
        Ok(self
            .admissions
            .get(&(
                finding_id.to_owned(),
                listing_id.to_owned(),
                backing_envelope_sha256.to_owned(),
            ))
            .cloned())
    }

    fn admission_by_envelope_sha256(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingAdmission>, String> {
        Ok(self.admissions_by_digest.get(envelope_sha256).cloned())
    }

    fn venue_policy_for_admission(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self.venue_policies.get(envelope_sha256).cloned())
    }

    fn governance_policy_for_profile(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .profile_governance_policies
            .get(envelope_sha256)
            .cloned())
    }

    fn governance_policy_for_case(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .case_governance_policies
            .read()
            .map_err(|_| "case-governance-policy index lock is poisoned".to_owned())?
            .get(envelope_sha256)
            .cloned())
    }

    fn governance_policy_for_activation(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .case_governance_policies
            .read()
            .map_err(|_| "case-governance-policy index lock is poisoned".to_owned())?
            .get(envelope_sha256)
            .cloned())
    }

    fn penalty_policy_for_penalty(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .penalty_policies
            .read()
            .map_err(|_| "penalty-policy index lock is poisoned".to_owned())?
            .get(envelope_sha256)
            .cloned())
    }

    fn retain_penalty_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        let mut policies = self
            .penalty_policies
            .write()
            .map_err(|_| "penalty-policy index lock is poisoned".to_owned())?;
        match policies.get(envelope_sha256) {
            Some(existing) if existing != policy => {
                Err("penalty envelope is already bound to another policy".to_owned())
            }
            Some(_) => Ok(()),
            None => {
                policies.insert(envelope_sha256.to_owned(), policy.clone());
                Ok(())
            }
        }
    }

    fn evaluator_policy_for_outcome(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .evaluator_policies
            .read()
            .map_err(|_| "evaluator-policy index lock is poisoned".to_owned())?
            .get(envelope_sha256)
            .cloned())
    }

    fn retain_evaluator_policy(
        &self,
        envelope_sha256: &str,
        policy: &FindingAuthorityPin,
    ) -> Result<(), String> {
        let mut policies = self
            .evaluator_policies
            .write()
            .map_err(|_| "evaluator-policy index lock is poisoned".to_owned())?;
        match policies.get(envelope_sha256) {
            Some(existing) if existing != policy => {
                Err("outcome envelope is already bound to another evaluator policy".to_owned())
            }
            Some(_) => Ok(()),
            None => {
                policies.insert(envelope_sha256.to_owned(), policy.clone());
                Ok(())
            }
        }
    }

    fn audit_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self.audit_policies.get(epoch_envelope_sha256).cloned())
    }

    fn randomness_witness_policy_for_epoch(
        &self,
        epoch_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .audit_witness_policies
            .get(epoch_envelope_sha256)
            .cloned())
    }

    fn governance_policy_for_audit_authorization(
        &self,
        authorization_envelope_sha256: &str,
    ) -> Result<Option<FindingAuthorityPin>, String> {
        Ok(self
            .audit_governance_policies
            .get(authorization_envelope_sha256)
            .cloned())
    }

    fn market_terms(
        &self,
        envelope_sha256: &str,
    ) -> Result<Option<SignedFindingMarketTerms>, String> {
        Ok(self.market_terms.get(envelope_sha256).cloned())
    }
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

struct Deployment {
    _temp: tempfile::TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    _authority: Arc<SqliteAuthorityStore>,
    market: SqliteFindingMarketStore,
    purchases: SqliteFindingPurchaseStore,
    challenges: SqliteFindingChallengeStore,
    status: chio_store_sqlite::SqliteFindingStatusStore,
    allocation_id: String,
    admission_envelope_sha256: String,
    fee_schedule_envelope_sha256: String,
    rail: Arc<RecordingRail>,
    filings: Arc<PublishedArtifacts>,
}

fn deployment() -> Result<Deployment, AnyError> {
    deployment_publishing_terms(&[])
}

/// Build the reference deployment with any caller-selected terms added to
/// the venue's published digest index.
fn deployment_publishing_terms(
    extra_terms: &[SignedFindingMarketTerms],
) -> Result<Deployment, AnyError> {
    deployment_publishing_terms_and_rounds(extra_terms, &[])
}

fn deployment_publishing_terms_and_rounds(
    extra_terms: &[SignedFindingMarketTerms],
    extra_rounds: &[FindingAuditRound],
) -> Result<Deployment, AnyError> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database: PathBuf = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    secure_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let market = authority.finding_market_store();
    let purchases = authority.finding_purchase_store();
    let challenges = authority.finding_challenge_store();
    let status = authority.finding_status_store();
    let challenged = challenged_finding()?;
    market.put_finding(
        &FindingRecordInput {
            finding_id: &challenged.finding.finding_id,
            artifact_json: &challenged.raw_finding,
            topic: &challenged.finding.descriptor.topic,
            context_sha256: &challenged.finding.descriptor.context_sha256,
            issued_at: challenged.finding.issued_at,
            expires_at: challenged.finding.expires_at,
        },
        NOW,
    )?;
    let allocation_id = consume_allocation(&market, LISTING_ID, &hex64('1'))?;
    purchases.register_community_fund_destination(
        &allocation_id,
        COMMUNITY_FUND_DESTINATION,
        NOW,
    )?;
    let terms = match extra_terms.first() {
        Some(terms) => terms.clone(),
        None => market_terms(CLAIM_WINDOW_SECS)?,
    };
    let admission = signed_admission(&allocation_id, &terms)?;
    let admission_envelope_sha256 = signed_envelope_sha256(&admission)?;
    let fee_schedule_envelope_sha256 = admission.body.fee_schedule_envelope_sha256.clone();
    purchases.install_active_admission_for_tests(
        &admission.body.finding_id,
        &allocation_id,
        LISTING_ID,
        &admission.body.admission_id,
        &admission_envelope_sha256,
        &fee_schedule_envelope_sha256,
        NOW,
    )?;
    let config = market_config();
    let retained_governance = governance()?;
    let mut filings = PublishedArtifacts::default()
        .publish_schedule(&published_fee_schedule()?)?
        .publish_round(
            &published_audit_round()?,
            config.audit_authority.clone(),
            config.audit_randomness_witness.clone(),
            config.governance_root.clone(),
        )?
        .publish_round(
            &unrelated_audit_round()?,
            config.audit_authority.clone(),
            config.audit_randomness_witness.clone(),
            config.governance_root.clone(),
        )?
        .publish_terms(&terms)?
        .publish_terms(&lapsed_window_terms()?)?
        .publish_terms(&audit_disabled_terms()?)?
        .publish_terms(&narrow_bond_terms()?)?
        .publish_admission(&admission, config.venue.clone())?
        .publish_profile_policy(&verifier_profile()?, config.governance_root.clone())?
        .publish_governance_policy(&retained_governance.charter, config.governance_root.clone())?
        .publish_governance_policy(
            &retained_governance.activation,
            config.governance_root.clone(),
        )?
        .publish_governance_policy(
            &retained_governance.sanction_case,
            config.governance_root.clone(),
        )?
        .publish_governance_policy(
            &retained_governance.appeal_case,
            config.governance_root.clone(),
        )?;
    for terms in extra_terms {
        filings = filings.publish_terms(terms)?;
    }
    for round in extra_rounds {
        filings = filings.publish_round(
            round,
            config.audit_authority.clone(),
            config.audit_randomness_witness.clone(),
            config.governance_root.clone(),
        )?;
    }
    Ok(Deployment {
        _temp: temp,
        database,
        lock_root,
        _authority: authority,
        market,
        purchases,
        challenges,
        status,
        allocation_id,
        admission_envelope_sha256,
        fee_schedule_envelope_sha256,
        rail: Arc::new(RecordingRail::default()),
        filings: Arc::new(filings),
    })
}

impl Deployment {
    fn coordinator(
        &self,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        self.coordinator_under(&market_config(), failed_challenge_disposition)
    }

    /// The same coordinator under a caller-chosen deployment pin roster,
    /// so a test can drive a role whose configured lifecycle has moved.
    fn coordinator_under(
        &self,
        config: &FindingMarketConfig,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        self.coordinator_under_with_status(
            config,
            Arc::new(TestAuthorityStatusResolver::live()),
            failed_challenge_disposition,
        )
    }

    fn coordinator_under_with_status(
        &self,
        config: &FindingMarketConfig,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        self.coordinator_under_with_evaluator_and_status(
            config,
            keypair(31),
            authority_status,
            failed_challenge_disposition,
        )
    }

    fn coordinator_under_with_evaluator_and_status(
        &self,
        config: &FindingMarketConfig,
        evaluator: Keypair,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        Ok(FindingChallengeCoordinator::new_with_status_commit_clock(
            self.challenges.clone(),
            self.purchases.clone(),
            self.status.clone(),
            config,
            evaluator,
            keypair(32),
            keypair(33),
            authority_status,
            self.rail.clone(),
            self.filings.clone(),
            failed_challenge_disposition,
            Arc::new(FixtureStatusCommitClock),
        )?)
    }

    fn coordinator_with_revoked_role(
        &self,
        authority_id: &str,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        self.coordinator_under_with_status(
            &market_config(),
            Arc::new(TestAuthorityStatusResolver {
                revoked_authority: Some(authority_id.to_string()),
                ..TestAuthorityStatusResolver::live()
            }),
            failed_challenge_disposition,
        )
    }

    /// Close every handle on the authority database and open it again, as
    /// a restarted operator would. The caller drops its coordinator first,
    /// because a live store handle still owns the serving lock.
    fn restart(self) -> Result<Self, AnyError> {
        let Self {
            _temp,
            database,
            lock_root,
            _authority,
            market,
            purchases,
            challenges,
            status,
            allocation_id,
            admission_envelope_sha256,
            fee_schedule_envelope_sha256,
            rail,
            filings,
        } = self;
        // The serving lock lives on the open handles, so every one of them
        // closes before the database can be served again.
        drop(challenges);
        drop(status);
        drop(purchases);
        drop(market);
        drop(_authority);
        let authority = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
        let market = authority.finding_market_store();
        let purchases = authority.finding_purchase_store();
        let challenges = authority.finding_challenge_store();
        let status = authority.finding_status_store();
        Ok(Self {
            _temp,
            database,
            lock_root,
            _authority: authority,
            market,
            purchases,
            challenges,
            status,
            allocation_id,
            admission_envelope_sha256,
            fee_schedule_envelope_sha256,
            rail,
            filings,
        })
    }
}

/// Route adapter that records the exact ingress views and delegates every
/// submission to the real durable coordinator. The fixed coordinator clock
/// keeps this historical fixture's signed fee schedule live; the handler's
/// independently observed clock is still recorded and asserted by the test.
struct RouteChallengeExecutor {
    coordinator: FindingChallengeCoordinator,
    raw_challenge_envelopes: Mutex<Vec<String>>,
    raw_findings: Mutex<Vec<String>>,
    handler_times: Mutex<Vec<u64>>,
}

impl FindingChallengeSubmissionExecutor for RouteChallengeExecutor {
    fn submit(
        &self,
        request: &FindingChallengeSubmissionRequest,
        raw_challenge_envelope: &str,
        raw_finding: &str,
        now: u64,
    ) -> Result<ChallengeSubmissionOutcome, ChallengeCoordinatorError> {
        self.raw_challenge_envelopes
            .lock()
            .map_err(|_| ChallengeCoordinatorError::Canonical)?
            .push(raw_challenge_envelope.to_string());
        self.raw_findings
            .lock()
            .map_err(|_| ChallengeCoordinatorError::Canonical)?
            .push(raw_finding.to_string());
        self.handler_times
            .lock()
            .map_err(|_| ChallengeCoordinatorError::Canonical)?
            .push(now);
        self.coordinator
            .submit(&request.challenge, raw_finding, NOW)
    }
}

fn challenge_route_state(
    deployment: &Deployment,
    executor: Arc<dyn FindingChallengeSubmissionExecutor>,
) -> TrustServiceState {
    let config = TrustServiceConfig {
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        service_token: "challenge-service-secret".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
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
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: std::time::Duration::from_millis(25),
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: Some(market_config()),
    };
    TrustServiceState {
        config,
        joint_authority_store: Some(Arc::clone(&deployment._authority)),
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        enterprise_provider_registry: None,
        verifier_policy_registry: None,
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster: None,
        cluster_progress: None,
        finding_rail: Some(deployment.rail.clone()),
        finding_purchase_executor: None,
        finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_seller_submission_executor: None,
        finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_authority_status_resolver: Some(Arc::new(TestAuthorityStatusResolver::live())),
        finding_challenge_executor: Some(executor),
    }
}

async fn submit_challenge_route(
    state: &TrustServiceState,
    finding_id: &str,
    raw_envelope: &str,
    authenticated: bool,
) -> Result<(StatusCode, Vec<u8>), AnyError> {
    let mut builder = HttpRequest::builder()
        .method("POST")
        .uri(format!("/v1/findings/{finding_id}/challenges"))
        .header("content-type", "application/json");
    if authenticated {
        builder = builder.header(AUTHORIZATION, "Bearer challenge-service-secret");
    }
    let response = build_router(state.clone())
        .oneshot(builder.body(Body::from(raw_envelope.to_string()))?)
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, body.to_vec()))
}

/// Register and consume one collateral allocation for a listing. The
/// allocation id is content-addressed over the backing, so a distinct
/// seller authorization is what makes a second allocation for the same
/// listing a different vault rather than a replay of the first.
fn consume_allocation(
    market: &SqliteFindingMarketStore,
    listing_id: &str,
    authorization_envelope_sha256: &str,
) -> Result<String, AnyError> {
    let backing = allocation_body(listing_id, authorization_envelope_sha256)?;
    let signed = SignedExportEnvelope::sign(backing.clone(), &keypair(4))?;
    let envelope = String::from_utf8(canonical_json_bytes(&signed)?)?;
    market.register_allocation(&envelope, &backing, NOW)?;
    market.consume_allocation(&backing.allocation_id)?;
    Ok(backing.allocation_id)
}

fn allocation_body(
    listing_id: &str,
    authorization_envelope_sha256: &str,
) -> Result<FindingBondBacking, AnyError> {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: keypair(4).public_key(),
        seller: keypair(22).public_key(),
        authorization_envelope_sha256: authorization_envelope_sha256.to_string(),
        finding_id: finding_artifact()?.0.finding_id,
        listing_id: listing_id.to_string(),
        terms_envelope_sha256: admitted_terms_digest()?,
        profile_envelope_sha256: hex64('3'),
        fee_requirement_sha256: hex64('4'),
        fee_schedule_envelope_sha256: hex64('5'),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(500),
        maximum_sale_exposure: usd(REGISTERED_EXPOSURE_CAP),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = compute_allocation_id(&backing)?;
    Ok(backing)
}

fn admitted_admission_digest() -> Result<String, AnyError> {
    admission_digest_for_terms(&market_terms(CLAIM_WINDOW_SECS)?)
}

fn admission_digest_for_terms(terms: &SignedFindingMarketTerms) -> Result<String, AnyError> {
    let allocation = allocation_body(LISTING_ID, &hex64('1'))?;
    let admission = signed_admission(&allocation.allocation_id, terms)?;
    Ok(signed_envelope_sha256(&admission)?)
}

// ---------------------------------------------------------------------------
// The challenged finding and the challenges against it
// ---------------------------------------------------------------------------

/// The kernel keys the governance profile pins, one per receipt role.
fn production_kernel() -> Keypair {
    keypair(21)
}

fn delivery_kernel() -> Keypair {
    keypair(12)
}

fn replay_kernel() -> Keypair {
    keypair(13)
}

/// Checkpoint signing stays in a separate trust domain from receipt signing.
fn production_log_signer() -> Keypair {
    keypair(23)
}

fn delivery_log_signer() -> Keypair {
    keypair(24)
}

fn replay_log_signer() -> Keypair {
    keypair(25)
}

fn key_policy(key: &PublicKey, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: key.clone(),
        key_epoch: 1,
        valid_from: KEY_VALID_FROM,
        valid_until: KEY_VALID_UNTIL,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

/// Retained venue admission that bound the challenged backing to the
/// allocation the purchase lane consumed.
fn signed_admission(
    allocation_id: &str,
    terms: &SignedFindingMarketTerms,
) -> Result<SignedFindingAdmission, AnyError> {
    signed_admission_with_backing(allocation_id, terms, &hex64('6'))
}

fn signed_admission_with_backing(
    allocation_id: &str,
    terms: &SignedFindingMarketTerms,
    backing_envelope_sha256: &str,
) -> Result<SignedFindingAdmission, AnyError> {
    let schedule_digest = signed_envelope_sha256(&published_fee_schedule()?)?;
    signed_admission_with_backing_and_schedule(
        allocation_id,
        terms,
        backing_envelope_sha256,
        &schedule_digest,
    )
}

fn signed_admission_with_backing_and_schedule(
    allocation_id: &str,
    terms: &SignedFindingMarketTerms,
    backing_envelope_sha256: &str,
    schedule_digest: &str,
) -> Result<SignedFindingAdmission, AnyError> {
    let challenged = challenged_finding()?;
    let venue = keypair(6);
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: venue.public_key(),
        venue_id: VENUE_ID.to_string(),
        finding_id: challenged.finding.finding_id.clone(),
        finding_artifact_sha256: challenged.finding_artifact_sha256,
        seller_authorization_envelope_sha256: hex64('1'),
        listing_id: LISTING_ID.to_string(),
        listing_envelope_sha256: hex64('2'),
        server_id: "finding-server".to_string(),
        metadata_url: "https://venue.example/findings/listing-42".to_string(),
        pricing_hint_envelope_sha256: hex64('4'),
        capability_scope: format!("finding:{}", challenged.finding.finding_id),
        publisher_operator_id: OPERATOR_ID.to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: schedule_digest.to_string(),
        verifier_report_id: hex64('5'),
        verifier_report_envelope_sha256: hex64('7'),
        terms_envelope_sha256: signed_envelope_sha256(terms)?,
        profile_envelope_sha256: challenged.profile_envelope_sha256,
        fee_terminals: vec![
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: schedule_digest.to_string(),
                event: FindingFeeEvent::Publication,
                payer: "seller-42".to_string(),
                amount: usd(100),
                pool_principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
                rail_destination: AUDIT_POOL_DESTINATION.to_string(),
                instruction_sha256: hex64('8'),
                observation_sha256: hex64('9'),
            },
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: schedule_digest.to_string(),
                event: FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                payer: "seller-42".to_string(),
                amount: usd(500),
                pool_principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
                rail_destination: AUDIT_POOL_DESTINATION.to_string(),
                instruction_sha256: hex64('a'),
                observation_sha256: hex64('b'),
            },
        ],
        backing_allocation_id: allocation_id.to_string(),
        backing_envelope_sha256: backing_envelope_sha256.to_string(),
        audit_pool: FindingPoolBinding {
            principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
            rail_destination: AUDIT_POOL_DESTINATION.to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolBinding {
            principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
            rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: COMMUNITY_FUND_DESTINATION.to_string(),
        status_feed_operator_ref: "status-feed/venue-challenge".to_string(),
        purchase_authority: key_policy(&keypair(16).public_key(), "purchase"),
        failed_delivery_authority: key_policy(&keypair(17).public_key(), "failed-delivery"),
        issued_at: NOW - 7_200,
        expires_at: KEY_VALID_UNTIL,
    };
    admission.admission_id = compute_admission_id(&admission)?;
    admission.validate()?;
    Ok(SignedExportEnvelope::sign(admission, &venue)?)
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 262_144,
        max_evidence_receipts: 64,
        max_runtime_secs: 900,
        max_memory_bytes: 2_147_483_648,
    }
}

/// A kernel-signed receipt whose action commitment agrees with the
/// parameters it carries.
fn signed_receipt(
    kernel: &Keypair,
    timestamp: u64,
    tool_name: &str,
    action: ToolCallAction,
    decision: Decision,
    content_hash: &str,
    metadata: Option<serde_json::Value>,
) -> Result<ChioReceipt, AnyError> {
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp,
        capability_id: format!("cap-{timestamp}"),
        tool_server: "finding-server".to_string(),
        tool_name: tool_name.to_string(),
        action,
        decision: Some(decision),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: content_hash.to_string(),
        policy_hash: "policy-finding-market".to_string(),
        evidence: Vec::new(),
        metadata,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(ChioReceipt::sign(body, kernel)?)
}

/// Bind one receipt to the Merkle tree its checkpoint committed.
fn resolve(
    receipt: ChioReceipt,
    leaves: &[Vec<u8>],
    leaf_index: usize,
    checkpoint_seq: u64,
    receipt_seq: u64,
) -> Result<ResolvedReceiptEvidence, AnyError> {
    let tree = MerkleTree::from_leaves(leaves)?;
    let canonical_receipt_bytes = canonical_json_bytes(&receipt)?;
    Ok(ResolvedReceiptEvidence {
        receipt,
        canonical_receipt_bytes,
        inclusion_proof: build_inclusion_proof(&tree, leaf_index, checkpoint_seq, receipt_seq)?,
    })
}

/// The local log identity a kernel key publishes under, derived through
/// the same helper the checkpoint verifier uses.
fn log_id_for(kernel: &Keypair) -> Result<String, AnyError> {
    let probe = build_checkpoint(1, 1, 1, &[b"probe".to_vec()], kernel)?;
    Ok(checkpoint_log_id(&probe))
}

fn checkpoint_reference(checkpoint: &KernelCheckpoint) -> Result<FindingCheckpointRef, AnyError> {
    Ok(FindingCheckpointRef {
        checkpoint_ref: format!(
            "{}#{}",
            checkpoint_log_id(checkpoint),
            checkpoint.body.checkpoint_seq
        ),
        checkpoint_sha256: checkpoint_body_sha256(&checkpoint.body)?,
    })
}

fn receipt_reference(evidence: &ResolvedReceiptEvidence) -> FindingReceiptRef {
    FindingReceiptRef {
        receipt_id: evidence.receipt.id.clone(),
        receipt_sha256: sha256_hex(&evidence.canonical_receipt_bytes),
    }
}

/// The governance-signed profile that pins every role key, every
/// checkpoint log, and the predicate the recipe is allowed to commit.
fn verifier_profile() -> Result<SignedFindingChallengeVerifierProfile, AnyError> {
    let mut body = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: governing_keypair().public_key(),
        operator: VENUE_ID.to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(&production_kernel().public_key(), "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(&delivery_kernel().public_key(), "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(&replay_kernel().public_key(), "replay"),
            },
        ],
        checkpoint_logs: vec![
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&production_log_signer())?,
                signer: key_policy(&production_log_signer().public_key(), "production-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&delivery_log_signer())?,
                signer: key_policy(&delivery_log_signer().public_key(), "delivery-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&replay_log_signer())?,
                signer: key_policy(&replay_log_signer().public_key(), "replay-log"),
            },
        ],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: hex64('1'),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: KEY_VALID_FROM,
            valid_until: KEY_VALID_UNTIL,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![hex64('3')],
        required_receipt_semantics: "chio.mediated_spend.v1".to_string(),
        resolver_policy_ref: "resolver-policy-v1".to_string(),
        retention_policy_ref: "retention-forever-v1".to_string(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_string(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
        ],
        verifier_report_signer: key_policy(&keypair(15).public_key(), "verifier-report"),
        purchase_authority: key_policy(&keypair(16).public_key(), "purchase"),
        failed_delivery_authority: key_policy(&keypair(17).public_key(), "failed-delivery"),
        issued_at: KEY_VALID_FROM,
        expires_at: KEY_VALID_UNTIL,
    };
    body.profile_id = compute_profile_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &governing_keypair())?)
}

/// The execution environment the recipe commits to. Every reproduction
/// has to report its digest, so the two are derived from one value.
fn replay_environment() -> FindingRecipeEnvironment {
    FindingRecipeEnvironment {
        runtime_image_sha256: hex64('5'),
        platform: "linux/amd64".to_string(),
        network_policy: "deny_all".to_string(),
        clock_policy: "fixed:1700000000".to_string(),
        randomness_policy: "seed:42".to_string(),
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
    }
}

fn replay_environment_digest() -> Result<String, AnyError> {
    Ok(sha256_hex(&canonical_json_bytes(&replay_environment())?))
}

/// The seller's replay recipe. It commits the admitted profile, so it can
/// only be built once that profile's envelope digest exists.
fn replay_recipe(profile_envelope_sha256: &str) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: hex64('7'),
        payload_sha256: hex64('8'),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: hex64('3'),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: hex64('1'),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: hex64('2'),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: hex64('4'),
        environment: replay_environment(),
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: hex64('6'),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

/// How the finding's two production evidence receipts are built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionShape {
    Sound,
    /// The first receipt carries a signature that belongs to another body,
    /// which is affirmative invalidity rather than an unresolved input.
    ForeignSignature,
}

/// The finding's own evidence receipts. Their identifiers are derived from
/// their bodies, so a broken signature leaves the finding that names them
/// byte for byte identical.
fn production_receipts(shape: ProductionShape) -> Result<Vec<ChioReceipt>, AnyError> {
    let kernel = production_kernel();
    let payload_sha256 = hex64('8');
    let mut delivery_metadata = serde_json::Map::new();
    delivery_metadata.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_string(),
        serde_json::to_value(DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
            expected_digest: payload_sha256.clone(),
            observed_digest: payload_sha256.clone(),
            result: DeliveryResult::Matched,
        })?,
    );
    let mut first = signed_receipt(
        &kernel,
        PRODUCTION_FIRST_AT,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 0 }))?,
        Decision::Allow,
        &payload_sha256,
        Some(serde_json::Value::Object(delivery_metadata.clone())),
    )?;
    let second = signed_receipt(
        &kernel,
        PRODUCTION_FIRST_AT + 1,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 1 }))?,
        Decision::Allow,
        &payload_sha256,
        Some(serde_json::Value::Object(delivery_metadata)),
    )?;
    if shape == ProductionShape::ForeignSignature {
        first.signature.clone_from(&second.signature);
    }
    Ok(vec![first, second])
}

/// The production evidence as the resolver hands it to an adjudication:
/// the receipts, the checkpoint that committed them, and the reference
/// that names it.
struct ProductionEvidence {
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    reference: FindingCheckpointRef,
}

fn production_evidence(shape: ProductionShape) -> Result<ProductionEvidence, AnyError> {
    let receipts = production_receipts(shape)?;
    let mut leaves = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        leaves.push(canonical_json_bytes(receipt)?);
    }
    let checkpoint = build_checkpoint(
        EVIDENCE_CHECKPOINT_SEQ,
        EVIDENCE_FIRST_SEQ,
        EVIDENCE_LAST_SEQ,
        &leaves,
        &production_log_signer(),
    )?;
    let reference = checkpoint_reference(&checkpoint)?;
    let mut resolved = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        resolved.push(resolve(
            receipt,
            &leaves,
            index,
            EVIDENCE_CHECKPOINT_SEQ,
            EVIDENCE_FIRST_SEQ + index as u64,
        )?);
    }
    Ok(ProductionEvidence {
        receipts: resolved,
        checkpoint,
        reference,
    })
}

/// The published finding, the governance profile it was published under,
/// and the recipe it committed. Every digest here is derived rather than
/// asserted, because the evaluator rejects anything that only claims to
/// bind.
struct ChallengedFinding {
    profile: SignedFindingChallengeVerifierProfile,
    profile_envelope_sha256: String,
    recipe_preimage: String,
    recipe_sha256: String,
    finding: Finding,
    raw_finding: String,
    finding_artifact_sha256: String,
}

fn challenged_finding() -> Result<ChallengedFinding, AnyError> {
    let issuer = keypair(9);
    let profile = verifier_profile()?;
    let profile_envelope_sha256 = signed_envelope_sha256(&profile)?;
    let recipe = replay_recipe(&profile_envelope_sha256);
    let recipe_preimage = canonical_json_string(&recipe)?;
    let recipe_sha256 = sha256_hex(recipe_preimage.as_bytes());
    let evidence_receipt_ids: Vec<String> = production_receipts(ProductionShape::Sound)?
        .iter()
        .map(|receipt| receipt.id.clone())
        .collect();
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#challenge-lane".to_string(),
            context_sha256: hex64('7'),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('8'),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids,
        evidence_checkpoint_ref: format!(
            "{}#{EVIDENCE_CHECKPOINT_SEQ}",
            log_id_for(&production_log_signer())?
        ),
        evidence_cost: usd(10),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(recipe_sha256.clone()),
        intent_commitment_receipt_id: None,
        bond_ref: "bond:pending-allocation".to_string(),
        status_feed_ref: "status-feed/venue-challenge".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: PUBLISHED_AT,
        expires_at: KEY_VALID_UNTIL,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &issuer)?;
    let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;
    let finding_artifact_sha256 = sha256_hex(raw_finding.as_bytes());
    Ok(ChallengedFinding {
        profile,
        profile_envelope_sha256,
        recipe_preimage,
        recipe_sha256,
        finding,
        raw_finding,
        finding_artifact_sha256,
    })
}

/// The seller's signed finding plus its exact canonical bytes. The
/// challenge binds the digest of those bytes, so the pair travels
/// together. The derivation is deterministic, so every caller that
/// rebuilds it gets the same artifact.
fn finding_artifact() -> Result<(Finding, String), AnyError> {
    let challenged = challenged_finding()?;
    Ok((challenged.finding, challenged.raw_finding))
}

/// Which authorization branch a challenge is filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filing {
    Buyer,
    VenueAudit,
}

impl ChallengedFinding {
    fn affected_delivery(
        receipt_ref: &FindingReceiptRef,
        checkpoint_ref: &FindingCheckpointRef,
    ) -> FindingAffectedDelivery {
        FindingAffectedDelivery {
            receipt_id: receipt_ref.receipt_id.clone(),
            receipt_sha256: receipt_ref.receipt_sha256.clone(),
            checkpoint_ref: checkpoint_ref.checkpoint_ref.clone(),
            checkpoint_sha256: checkpoint_ref.checkpoint_sha256.clone(),
        }
    }

    /// A buyer's authorization: the challenger, the dispute fee it paid to
    /// the admission-pinned challenge-administration pool, the exclusive
    /// lock its collateral sits in, and the standing that lets it file.
    fn buyer_authorization(
        &self,
        lock_tag: &str,
        standing: FindingChallengeStanding,
    ) -> Result<FindingChallengeAuthorization, AnyError> {
        let buyer = keypair(41);
        let schedule_envelope_sha256 = signed_envelope_sha256(&published_fee_schedule()?)?;
        Ok(FindingChallengeAuthorization::BuyerSubmission(Box::new(
            FindingBuyerSubmission {
                challenger: buyer.public_key(),
                dispute_fee_terminal: FindingDisputeFeeTerminal {
                    fee_schedule_envelope_sha256: schedule_envelope_sha256.clone(),
                    event: FindingDisputeFeeEvent::ChallengeFiling,
                    payer: buyer.public_key(),
                    amount: usd(DISPUTE_FEE_UNITS),
                    beneficiary_pool_principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
                    rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
                },
                dispute_lock_ref: FindingDisputeLockRef {
                    lock_id: format!("dispute-lock-{lock_tag}"),
                    class: FindingDisputeBondClass::Dispute,
                    fee_schedule_envelope_sha256: schedule_envelope_sha256,
                    amount: usd(DISPUTE_BOND_UNITS),
                    expiry: NOW + 86_400,
                },
                standing,
            },
        )))
    }

    fn venue_authorization(&self) -> Result<FindingChallengeAuthorization, AnyError> {
        venue_audit_authorization(&published_audit_round()?, &self.finding.finding_id)
    }

    fn sign_challenge(
        &self,
        authorization: FindingChallengeAuthorization,
        evidence: FindingChallengeEvidence,
        affected_deliveries: Vec<FindingAffectedDelivery>,
    ) -> Result<SignedFindingChallenge, AnyError> {
        let signer = match &authorization {
            FindingChallengeAuthorization::BuyerSubmission(_) => keypair(41),
            FindingChallengeAuthorization::VenueAudit(_) => keypair(35),
        };
        let mut body = FindingChallenge {
            schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
            challenge_id: String::new(),
            finding_id: self.finding.finding_id.clone(),
            finding_artifact_sha256: self.finding_artifact_sha256.clone(),
            listing_id: LISTING_ID.to_string(),
            terms_envelope_sha256: admitted_terms_digest()?,
            profile_envelope_sha256: self.profile_envelope_sha256.clone(),
            venue_admission_envelope_sha256: admitted_admission_digest()?,
            backing_envelope_sha256: hex64('6'),
            filed_at: NOW,
            affected_deliveries,
            authorization,
            evidence,
        };
        body.challenge_id = compute_challenge_id(&body)?;
        Ok(SignedExportEnvelope::sign(body, &signer)?)
    }
}

// ---------------------------------------------------------------------------
// digest_mismatch evidence
// ---------------------------------------------------------------------------

/// The exact denial terminal a case presents, so a test builds the denial
/// it means rather than mutating a signed one.
struct DenyShape {
    include_overlay: bool,
    contract_result: DeliveryResult,
    overlay_digest_check: DeliveryResult,
    media_type_check: FindingMediaTypeCheck,
    /// `None` uses the finding's own committed payload digest.
    expected_digest: Option<String>,
    observed_digest: String,
    decision: Decision,
}

impl DenyShape {
    /// The authenticated seller-origin mismatch: the only shape that
    /// reaches a sanction.
    fn seller_origin() -> Self {
        Self {
            include_overlay: true,
            contract_result: DeliveryResult::Mismatched,
            overlay_digest_check: DeliveryResult::Mismatched,
            media_type_check: FindingMediaTypeCheck::NotEvaluated,
            expected_digest: None,
            observed_digest: hex64('e'),
            decision: Decision::Deny {
                reason: "delivered output does not match the committed output digest".to_string(),
                guard: "delivery_contract".to_string(),
            },
        }
    }
}

struct DigestMismatchCase {
    challenge: SignedFindingChallenge,
    failed_delivery: SignedFindingFailedDelivery,
    failed_delivery_authority_status: SignedFindingAuthorityStatus,
    delivery_authority_status: SignedFindingAuthorityStatus,
    deny_receipt: ResolvedReceiptEvidence,
    deny_checkpoint: KernelCheckpoint,
    deny_checkpoint_transparency: CheckpointTransparencySummary,
}

impl DigestMismatchCase {
    fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        FindingChallengeClassEvidence::DigestMismatch(FindingDigestMismatchEvidence {
            failed_delivery: &self.failed_delivery,
            failed_delivery_authority_status: &self.failed_delivery_authority_status,
            delivery_authority_status: &self.delivery_authority_status,
            deny_receipt: &self.deny_receipt,
            deny_checkpoint: &self.deny_checkpoint,
            checkpoint_transparency: &self.deny_checkpoint_transparency,
        })
    }
}

fn digest_mismatch_case(
    deployment: &Deployment,
    challenged: &ChallengedFinding,
    shape: &DenyShape,
    filing: Filing,
) -> Result<DigestMismatchCase, AnyError> {
    let expected_digest = shape
        .expected_digest
        .clone()
        .unwrap_or_else(|| challenged.finding.payload_sha256.clone());
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_string(),
        serde_json::to_value(&DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
            expected_digest,
            observed_digest: shape.observed_digest.clone(),
            result: shape.contract_result,
        })?,
    );
    if shape.include_overlay {
        metadata.insert(
            FINDING_DELIVERY_METADATA_KEY.to_string(),
            serde_json::to_value(&FindingDelivery {
                schema: FINDING_DELIVERY_SCHEMA.to_string(),
                finding_id: challenged.finding.finding_id.clone(),
                listing_id: LISTING_ID.to_string(),
                transform_profile: FindingTransformProfile::Identity,
                digest_check: shape.overlay_digest_check,
                media_type_check: shape.media_type_check,
                settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
                accepted_bid_envelope_sha256: hex64('c'),
                venue_admission_envelope_sha256: deployment.admission_envelope_sha256.clone(),
                reservation_id: DENY_RESERVATION_ID.to_string(),
                purchase_intent_id: DENY_INTENT_ID.to_string(),
                authoritative_payment_operation_id: DENY_PAYMENT_ID.to_string(),
                status_proof: None,
            })?,
        );
    }
    let kernel = delivery_kernel();
    let receipt = signed_receipt(
        &kernel,
        DENY_AT,
        "finding.reveal",
        ToolCallAction::from_parameters(serde_json::json!({ "finding": "reveal" }))?,
        shape.decision.clone(),
        &shape.observed_digest,
        Some(serde_json::Value::Object(metadata)),
    )?;
    let leaves = vec![canonical_json_bytes(&receipt)?];
    let deny_checkpoint = build_checkpoint(
        DENY_CHECKPOINT_SEQ,
        DENY_RECEIPT_SEQ,
        DENY_RECEIPT_SEQ,
        &leaves,
        &delivery_log_signer(),
    )?;
    let deny_checkpoint_ref = checkpoint_reference(&deny_checkpoint)?;
    let deny_receipt = resolve(receipt, &leaves, 0, DENY_CHECKPOINT_SEQ, DENY_RECEIPT_SEQ)?;
    let deny_receipt_ref = receipt_reference(&deny_receipt);

    let mut terminal = FindingFailedDelivery {
        schema: FINDING_FAILED_DELIVERY_SCHEMA_V1.to_string(),
        failed_delivery_id: String::new(),
        buyer: keypair(41).public_key(),
        finding_id: challenged.finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        accepted_bid_envelope_sha256: hex64('c'),
        venue_admission_envelope_sha256: admitted_admission_digest()?,
        seller_backing_envelope_sha256: hex64('6'),
        reservation_id: DENY_RESERVATION_ID.to_string(),
        purchase_intent_id: DENY_INTENT_ID.to_string(),
        authoritative_payment_operation_id: DENY_PAYMENT_ID.to_string(),
        hold_attempt_reference: "hold-attempt-01".to_string(),
        release_terminal: FindingHoldReleaseTerminal::Released,
        deny_receipt_id: deny_receipt_ref.receipt_id.clone(),
        deny_receipt_sha256: deny_receipt_ref.receipt_sha256.clone(),
        deny_checkpoint_ref: deny_checkpoint_ref.checkpoint_ref.clone(),
        deny_checkpoint_sha256: deny_checkpoint_ref.checkpoint_sha256.clone(),
        realized_spend_units: 0,
        currency: "USD".to_string(),
        payout_eligible: false,
        recorded_at: DENY_AT + 500,
    };
    terminal.failed_delivery_id = compute_failed_delivery_id(&terminal)?;
    let failed_delivery = SignedExportEnvelope::sign(terminal, &keypair(17))?;
    let failed_delivery_envelope_sha256 = signed_envelope_sha256(&failed_delivery)?;
    let failed_delivery_policy = &challenged.profile.body.failed_delivery_authority;
    let failed_delivery_authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: failed_delivery_policy.revocation_status_ref.clone(),
            authority_id: failed_delivery_policy.authority_id.clone(),
            key: failed_delivery_policy.key.clone(),
            key_epoch: failed_delivery_policy.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(37),
    )?;
    let delivery_policy = challenged
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Delivery)
        .ok_or("missing delivery role policy")?;
    let delivery_authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: delivery_policy.policy.revocation_status_ref.clone(),
            authority_id: delivery_policy.policy.authority_id.clone(),
            key: delivery_policy.policy.key.clone(),
            key_epoch: delivery_policy.policy.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(37),
    )?;

    // Retain the exact reservation and backing that produced the denial.
    // The evaluator must resolve this durable sale identity rather than
    // trusting a terminal presented beside whichever admission is current.
    deployment
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: DENY_RESERVATION_ID,
            purchase_intent_id: DENY_INTENT_ID,
            authoritative_payment_operation_id: DENY_PAYMENT_ID,
            payer_hex: &keypair(41).public_key().to_hex(),
            agent_id: "agent-buyer-01",
            payout_destination: EVM_BUYER_DESTINATION,
            finding_id: &challenged.finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &hex64('c'),
            ask_digest: &digest("deny-ask"),
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
            fee_schedule_envelope_sha256: &deployment.fee_schedule_envelope_sha256,
            participation_epoch: 0,
            amount_units: 100,
            currency: "USD",
            expires_at: NOW + 3_600,
            encumbrance_id: "encumbrance-denied-01",
            allocation_id: &deployment.allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW,
        })?;
    deployment
        .purchases
        .reserve_slot(DENY_RESERVATION_ID, NOW)?;
    let failed_delivery_json = canonical_json_bytes(&failed_delivery)?;
    deployment
        .purchases
        .close_slot_with_deny(&FindingPurchaseDenyInput {
            reservation_id: DENY_RESERVATION_ID,
            failed_delivery_id: &failed_delivery.body.failed_delivery_id,
            record_json: &failed_delivery_json,
            record_sha256: &sha256_hex(&failed_delivery_json),
            deny_receipt_id: &failed_delivery.body.deny_receipt_id,
            now: NOW,
        })?;

    let evidence = FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: failed_delivery_envelope_sha256.clone(),
        deny_receipt_ref: deny_receipt_ref.clone(),
        deny_checkpoint_ref: deny_checkpoint_ref.clone(),
    };
    let (authorization, affected) = match filing {
        Filing::Buyer => (
            challenged.buyer_authorization(
                "digest",
                FindingChallengeStanding::FailedDelivery {
                    failed_delivery_id: failed_delivery.body.failed_delivery_id.clone(),
                    failed_delivery_envelope_sha256,
                },
            )?,
            vec![ChallengedFinding::affected_delivery(
                &deny_receipt_ref,
                &deny_checkpoint_ref,
            )],
        ),
        Filing::VenueAudit => (challenged.venue_authorization()?, Vec::new()),
    };
    let deny_checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&deny_checkpoint))?;
    Ok(DigestMismatchCase {
        challenge: challenged.sign_challenge(authorization, evidence, affected)?,
        failed_delivery,
        failed_delivery_authority_status,
        delivery_authority_status,
        deny_receipt,
        deny_checkpoint,
        deny_checkpoint_transparency,
    })
}

// ---------------------------------------------------------------------------
// evidence_invalid evidence
// ---------------------------------------------------------------------------

struct EvidenceInvalidCase {
    challenge: SignedFindingChallenge,
    purchase_record: SignedFindingPurchaseRecord,
    purchase_bid_request: SignedBidRequest,
    purchase_accepted_bid: SignedAcceptedBid,
    purchase_reservation_receipt: SignedReservationReceipt,
    purchase_delivery_receipt: ResolvedReceiptEvidence,
    purchase_delivery_checkpoint: KernelCheckpoint,
    purchase_delivery_checkpoint_transparency: CheckpointTransparencySummary,
    purchase_delivery_authority_status: SignedFindingAuthorityStatus,
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    checkpoint_transparency: CheckpointTransparencySummary,
    checkpoint_authority_status: SignedFindingAuthorityStatus,
    production_authority_status: SignedFindingAuthorityStatus,
    unestablished_production_authority_status: SignedFindingAuthorityStatus,
    /// A checkpoint carrying the named identity but not the artifact the
    /// reference names, which is an unresolved input rather than a
    /// contradiction.
    unresolved_checkpoint: KernelCheckpoint,
    unresolved_checkpoint_transparency: CheckpointTransparencySummary,
}

impl EvidenceInvalidCase {
    fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        self.evidence_against(&self.checkpoint, &self.checkpoint_transparency)
    }

    fn unresolved_evidence(&self) -> FindingChallengeClassEvidence<'_> {
        self.evidence_against(
            &self.unresolved_checkpoint,
            &self.unresolved_checkpoint_transparency,
        )
    }

    fn evidence_without_production_status(&self) -> FindingChallengeClassEvidence<'_> {
        FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
            purchase_standing: FindingPurchaseStandingEvidence {
                purchase_record: &self.purchase_record,
                bid_request: &self.purchase_bid_request,
                accepted_bid: &self.purchase_accepted_bid,
                reservation_receipt: &self.purchase_reservation_receipt,
                delivery_receipt: &self.purchase_delivery_receipt,
                delivery_checkpoint: &self.purchase_delivery_checkpoint,
                delivery_checkpoint_transparency: &self.purchase_delivery_checkpoint_transparency,
                delivery_authority_status: &self.purchase_delivery_authority_status,
            },
            challenged_receipts: &self.receipts,
            challenged_checkpoint: &self.checkpoint,
            checkpoint_transparency: &self.checkpoint_transparency,
            checkpoint_authority_status: &self.checkpoint_authority_status,
            production_authority_status: &self.unestablished_production_authority_status,
            revoked_keys: &[],
        })
    }

    fn evidence_against<'a>(
        &'a self,
        checkpoint: &'a KernelCheckpoint,
        checkpoint_transparency: &'a CheckpointTransparencySummary,
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
            purchase_standing: FindingPurchaseStandingEvidence {
                purchase_record: &self.purchase_record,
                bid_request: &self.purchase_bid_request,
                accepted_bid: &self.purchase_accepted_bid,
                reservation_receipt: &self.purchase_reservation_receipt,
                delivery_receipt: &self.purchase_delivery_receipt,
                delivery_checkpoint: &self.purchase_delivery_checkpoint,
                delivery_checkpoint_transparency: &self.purchase_delivery_checkpoint_transparency,
                delivery_authority_status: &self.purchase_delivery_authority_status,
            },
            challenged_receipts: &self.receipts,
            challenged_checkpoint: checkpoint,
            checkpoint_transparency,
            checkpoint_authority_status: &self.checkpoint_authority_status,
            production_authority_status: &self.production_authority_status,
            revoked_keys: &[],
        })
    }
}

fn evidence_invalid_case(
    challenged: &ChallengedFinding,
    shape: ProductionShape,
    standing: &SettledPurchase,
    filing: Filing,
) -> Result<EvidenceInvalidCase, AnyError> {
    let evidence = production_evidence(shape)?;
    let challenged_refs: Vec<FindingReceiptRef> =
        evidence.receipts.iter().map(receipt_reference).collect();
    let first_ref = challenged_refs
        .first()
        .ok_or("the finding names its production evidence")?
        .clone();
    let unresolved_checkpoint = build_checkpoint(
        EVIDENCE_CHECKPOINT_SEQ,
        EVIDENCE_FIRST_SEQ,
        EVIDENCE_LAST_SEQ,
        &[b"unresolved-leaf-a".to_vec(), b"unresolved-leaf-b".to_vec()],
        &production_log_signer(),
    )?;
    let branch = FindingChallengeEvidence::EvidenceInvalid {
        challenged_evidence_receipt_refs: challenged_refs,
        challenged_checkpoint_ref: evidence.reference.clone(),
        purchase_record_envelope_sha256: standing.record_envelope_sha256.clone(),
    };
    let (authorization, affected) = match filing {
        Filing::Buyer => (
            challenged.buyer_authorization(
                "evidence",
                FindingChallengeStanding::FinalizedPurchase {
                    purchase_key: standing.purchase_key.clone(),
                    purchase_record_envelope_sha256: standing.record_envelope_sha256.clone(),
                },
            )?,
            vec![ChallengedFinding::affected_delivery(
                &first_ref,
                &evidence.reference,
            )],
        ),
        Filing::VenueAudit => (challenged.venue_authorization()?, Vec::new()),
    };
    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&evidence.checkpoint))?;
    let unresolved_checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&unresolved_checkpoint))?;
    let production_log_id = log_id_for(&production_log_signer())?;
    let checkpoint_policy = challenged
        .profile
        .body
        .checkpoint_logs
        .iter()
        .find(|policy| policy.log_id == production_log_id)
        .ok_or("missing production checkpoint policy")?;
    let checkpoint_authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: checkpoint_policy.signer.revocation_status_ref.clone(),
            authority_id: checkpoint_policy.signer.authority_id.clone(),
            key: checkpoint_policy.signer.key.clone(),
            key_epoch: checkpoint_policy.signer.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(37),
    )?;
    let production_policy = challenged
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Production)
        .ok_or("missing production role policy")?;
    let production_authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: production_policy.policy.revocation_status_ref.clone(),
            authority_id: production_policy.policy.authority_id.clone(),
            key: production_policy.policy.key.clone(),
            key_epoch: production_policy.policy.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(37),
    )?;
    let unestablished_production_authority_status =
        SignedExportEnvelope::sign(production_authority_status.body.clone(), &keypair(36))?;
    Ok(EvidenceInvalidCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
        purchase_bid_request: standing.bid_request.clone(),
        purchase_accepted_bid: standing.accepted_bid.clone(),
        purchase_reservation_receipt: standing.reservation_receipt.clone(),
        purchase_delivery_receipt: clone_resolved(&standing.delivery_receipt)?,
        purchase_delivery_checkpoint: standing.delivery_checkpoint.clone(),
        purchase_delivery_checkpoint_transparency: standing
            .delivery_checkpoint_transparency
            .clone(),
        purchase_delivery_authority_status: standing.delivery_authority_status.clone(),
        receipts: evidence.receipts,
        checkpoint: evidence.checkpoint,
        checkpoint_transparency,
        checkpoint_authority_status,
        production_authority_status,
        unestablished_production_authority_status,
        unresolved_checkpoint,
        unresolved_checkpoint_transparency,
    })
}

// ---------------------------------------------------------------------------
// replay_contradiction evidence
// ---------------------------------------------------------------------------

struct ReplayCase {
    challenge: SignedFindingChallenge,
    purchase_record: SignedFindingPurchaseRecord,
    purchase_bid_request: SignedBidRequest,
    purchase_accepted_bid: SignedAcceptedBid,
    purchase_reservation_receipt: SignedReservationReceipt,
    purchase_delivery_receipt: ResolvedReceiptEvidence,
    purchase_delivery_checkpoint: KernelCheckpoint,
    purchase_delivery_checkpoint_transparency: CheckpointTransparencySummary,
    purchase_delivery_authority_status: SignedFindingAuthorityStatus,
    replay_authority_status: SignedFindingAuthorityStatus,
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    checkpoint_transparency: CheckpointTransparencySummary,
}

impl ReplayCase {
    fn reproductions(&self) -> Vec<FindingResolvedReproduction<'_>> {
        self.receipts
            .iter()
            .map(|receipt| FindingResolvedReproduction {
                receipt,
                checkpoint: &self.checkpoint,
                checkpoint_transparency: &self.checkpoint_transparency,
            })
            .collect()
    }

    fn evidence<'a>(
        &'a self,
        reproductions: &'a [FindingResolvedReproduction<'a>],
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::ReplayContradiction(FindingReplayContradictionEvidence {
            purchase_standing: FindingPurchaseStandingEvidence {
                purchase_record: &self.purchase_record,
                bid_request: &self.purchase_bid_request,
                accepted_bid: &self.purchase_accepted_bid,
                reservation_receipt: &self.purchase_reservation_receipt,
                delivery_receipt: &self.purchase_delivery_receipt,
                delivery_checkpoint: &self.purchase_delivery_checkpoint,
                delivery_checkpoint_transparency: &self.purchase_delivery_checkpoint_transparency,
                delivery_authority_status: &self.purchase_delivery_authority_status,
            },
            replay_authority_status: &self.replay_authority_status,
            reproductions,
        })
    }
}

fn replay_case(
    challenged: &ChallengedFinding,
    lock_tag: &str,
    phases: &[PhaseShape],
    recipe_preimage: Option<&str>,
    standing: &SettledPurchase,
) -> Result<ReplayCase, AnyError> {
    let recipe_preimage =
        recipe_preimage.map_or_else(|| challenged.recipe_preimage.clone(), str::to_owned);
    let replay_action = ReplayActionFactory::from_preimage(&recipe_preimage)?;
    let recipe_digest = replay_action.recipe_sha256().to_owned();
    let kernel = replay_kernel();

    let mut observation_texts = Vec::with_capacity(phases.len());
    let mut receipts = Vec::with_capacity(phases.len());
    let mut leaves = Vec::with_capacity(phases.len());
    for (index, phase) in phases.iter().enumerate() {
        let observation = FindingReplayObservation {
            schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
            recipe_digest: recipe_digest.clone(),
            verifier_profile_digest: challenged.profile_envelope_sha256.clone(),
            phase_id: phase.phase,
            runner_manifest_digest: hex64('3'),
            resolved_input_bundle_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => hex64('1'),
                FindingRecipePhaseKind::Candidate => hex64('2'),
            },
            environment_digest: replay_environment_digest()?,
            terminal_result: phase.terminal,
            exit_code: phase.exit_code,
            report_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => hex64('a'),
                FindingRecipePhaseKind::Candidate => hex64('b'),
            },
            replay_run_id: REPLAY_RUN_ID.to_string(),
        };
        let text = canonical_json_string(&observation)?;
        let receipt = signed_receipt(
            &kernel,
            REPLAY_AT + index as u64,
            "finding.replay",
            replay_action.for_phase(phase.phase)?,
            Decision::Allow,
            &sha256_hex(text.as_bytes()),
            None,
        )?;
        leaves.push(canonical_json_bytes(&receipt)?);
        receipts.push(receipt);
        observation_texts.push(text);
    }
    let checkpoint = build_checkpoint(
        REPLAY_CHECKPOINT_SEQ,
        REPLAY_FIRST_SEQ,
        REPLAY_FIRST_SEQ + receipts.len() as u64 - 1,
        &leaves,
        &replay_log_signer(),
    )?;
    let checkpoint_ref = checkpoint_reference(&checkpoint)?;
    let mut resolved = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        resolved.push(resolve(
            receipt,
            &leaves,
            index,
            REPLAY_CHECKPOINT_SEQ,
            REPLAY_FIRST_SEQ + index as u64,
        )?);
    }
    let reproduction: Vec<FindingReplayReproduction> = resolved
        .iter()
        .zip(&observation_texts)
        .map(|(receipt, text)| FindingReplayReproduction {
            receipt_ref: receipt_reference(receipt),
            checkpoint_ref: checkpoint_ref.clone(),
            observation_bytes: text.clone(),
        })
        .collect();
    let branch = FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage,
        purchase_record_envelope_sha256: standing.record_envelope_sha256.clone(),
    };
    let authorization = challenged.buyer_authorization(
        lock_tag,
        FindingChallengeStanding::FinalizedPurchase {
            purchase_key: standing.purchase_key.clone(),
            purchase_record_envelope_sha256: standing.record_envelope_sha256.clone(),
        },
    )?;
    let affected = vec![ChallengedFinding::affected_delivery(
        &receipt_reference(
            resolved
                .first()
                .ok_or("a reproduction set is never empty")?,
        ),
        &checkpoint_ref,
    )];
    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&checkpoint))?;
    let replay_policy = challenged
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Replay)
        .ok_or("missing replay role policy")?;
    let replay_authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: replay_policy.policy.revocation_status_ref.clone(),
            authority_id: replay_policy.policy.authority_id.clone(),
            key: replay_policy.policy.key.clone(),
            key_epoch: replay_policy.policy.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(37),
    )?;
    Ok(ReplayCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
        purchase_bid_request: standing.bid_request.clone(),
        purchase_accepted_bid: standing.accepted_bid.clone(),
        purchase_reservation_receipt: standing.reservation_receipt.clone(),
        purchase_delivery_receipt: clone_resolved(&standing.delivery_receipt)?,
        purchase_delivery_checkpoint: standing.delivery_checkpoint.clone(),
        purchase_delivery_checkpoint_transparency: standing
            .delivery_checkpoint_transparency
            .clone(),
        purchase_delivery_authority_status: standing.delivery_authority_status.clone(),
        replay_authority_status,
        receipts: resolved,
        checkpoint,
        checkpoint_transparency,
    })
}

fn buyer_challenge(buyer: &Keypair) -> Result<SignedFindingChallenge, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let schedule_envelope_sha256 = signed_envelope_sha256(&published_fee_schedule()?)?;
    let profile_envelope_sha256 = signed_envelope_sha256(&verifier_profile()?)?;
    let mut body = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw.as_bytes()),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: admitted_terms_digest()?,
        profile_envelope_sha256,
        venue_admission_envelope_sha256: admitted_admission_digest()?,
        backing_envelope_sha256: hex64('6'),
        filed_at: NOW,
        affected_deliveries: vec![chio_finding::FindingAffectedDelivery {
            receipt_id: "receipt-delivery-01".to_string(),
            receipt_sha256: hex64('a'),
            checkpoint_ref: "checkpoint-delivery-01".to_string(),
            checkpoint_sha256: hex64('b'),
        }],
        authorization: FindingChallengeAuthorization::BuyerSubmission(Box::new(
            FindingBuyerSubmission {
                challenger: buyer.public_key(),
                dispute_fee_terminal: FindingDisputeFeeTerminal {
                    fee_schedule_envelope_sha256: schedule_envelope_sha256.clone(),
                    event: FindingDisputeFeeEvent::ChallengeFiling,
                    payer: buyer.public_key(),
                    amount: usd(DISPUTE_FEE_UNITS),
                    beneficiary_pool_principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
                    rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
                },
                dispute_lock_ref: FindingDisputeLockRef {
                    lock_id: "dispute-lock-01".to_string(),
                    class: FindingDisputeBondClass::Dispute,
                    fee_schedule_envelope_sha256: schedule_envelope_sha256,
                    amount: usd(DISPUTE_BOND_UNITS),
                    expiry: NOW + 86_400,
                },
                standing: FindingChallengeStanding::FinalizedPurchase {
                    purchase_key: hex64('c'),
                    purchase_record_envelope_sha256: hex64('d'),
                },
            },
        )),
        evidence: FindingChallengeEvidence::EvidenceInvalid {
            challenged_evidence_receipt_refs: vec![FindingReceiptRef {
                receipt_id: "receipt-evidence-01".to_string(),
                receipt_sha256: hex64('e'),
            }],
            challenged_checkpoint_ref: FindingCheckpointRef {
                checkpoint_ref: "checkpoint-evidence-01".to_string(),
                checkpoint_sha256: hex64('f'),
            },
            purchase_record_envelope_sha256: hex64('d'),
        },
    };
    body.challenge_id = chio_finding::compute_challenge_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, buyer)?)
}

/// The seed this venue committed to before its round sampled and revealed
/// once the round was over.
fn audit_seed() -> String {
    byte_hex64(0x7c)
}

/// The round that drew the challenged listing: an epoch committing the
/// eligible snapshot and the seed commitment, the snapshot itself, and the
/// seed the venue later revealed.
fn published_audit_round() -> Result<FindingAuditRound, AnyError> {
    let challenged = challenged_finding()?;
    let finding = &challenged.finding;
    audit_round_over(vec![EligibleListing {
        finding_id: finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        weight_or_none: None,
    }])
}

/// A published round whose eligible universe never contained the
/// challenged listing, so no seed can draw it.
fn unrelated_audit_round() -> Result<FindingAuditRound, AnyError> {
    audit_round_over(vec![EligibleListing {
        finding_id: byte_hex64(0x5a),
        listing_id: "listing-99".to_string(),
        weight_or_none: None,
    }])
}

/// One published round over a caller-chosen eligible snapshot, audited at
/// the full published rate so every eligible listing is drawn.
fn audit_round_over(eligible: Vec<EligibleListing>) -> Result<FindingAuditRound, AnyError> {
    let revealed_seed = audit_seed();
    let audit_authority = keypair(35);
    let randomness_witness = keypair(38);
    let eligible_snapshot_at = NOW - 2_000;
    let seed_witnessed_at = NOW - 1_500;
    let eligible_snapshot_digest = derive_eligible_snapshot_digest(&eligible)?;
    let seed_commitment = derive_audit_seed_commitment(&revealed_seed);
    let mut epoch = FindingAuditEpoch {
        schema: FINDING_AUDIT_EPOCH_SCHEMA_V1.to_string(),
        audit_epoch_id: String::new(),
        epoch_index: 1,
        audit_authority: audit_authority.public_key(),
        seed_witnessed_at,
        eligible_snapshot_at,
        seed_witness: randomness_witness.public_key(),
        seed_witness_signature: randomness_witness.sign(&audit_seed_witness_signing_bytes(
            &audit_authority.public_key(),
            1,
            &eligible_snapshot_digest,
            &seed_commitment,
            eligible_snapshot_at,
            seed_witnessed_at,
        )),
        eligible_snapshot_digest,
        eligible_listing_count: u64::try_from(eligible.len())?,
        fee_schedule_envelope_sha256: signed_envelope_sha256(&published_fee_schedule()?)?,
        seed_commitment,
        selection_algorithm_id: AUDIT_SELECTION_ALGORITHM_V1.to_string(),
        published_rate_bps: MAX_PUBLISHED_RATE_BPS,
        available_budget: usd(10_000),
        authorization_digest: String::new(),
        committed_at: NOW - 1_000,
    };
    let authorization = SignedExportEnvelope::sign(
        FindingAuditRoundAuthorization {
            schema: FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1.to_string(),
            epoch_precommitment_sha256: audit_epoch_precommitment_sha256(&epoch)?,
            authorized_at: NOW - 1_250,
            expires_at: NOW + 900_000,
        },
        &keypair(1),
    )?;
    epoch.authorization_digest = signed_envelope_sha256(&authorization)?;
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch)?;
    epoch.validate()?;
    Ok(FindingAuditRound {
        epoch: SignedExportEnvelope::sign(epoch, &audit_authority)?,
        authorization,
        revealed_seed,
        eligible,
    })
}

fn reseal_audit_round(
    round: &FindingAuditRound,
    rewrite_epoch: impl FnOnce(&mut FindingAuditEpoch),
    authorization_signer: &Keypair,
) -> Result<FindingAuditRound, AnyError> {
    let mut epoch = round.epoch.body.clone();
    rewrite_epoch(&mut epoch);
    epoch.audit_epoch_id.clear();
    epoch.authorization_digest.clear();
    let authorization = SignedExportEnvelope::sign(
        FindingAuditRoundAuthorization {
            schema: FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1.to_string(),
            epoch_precommitment_sha256: audit_epoch_precommitment_sha256(&epoch)?,
            authorized_at: NOW - 1_250,
            expires_at: NOW + 900_000,
        },
        authorization_signer,
    )?;
    epoch.authorization_digest = signed_envelope_sha256(&authorization)?;
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch)?;
    epoch.validate()?;
    Ok(FindingAuditRound {
        epoch: SignedExportEnvelope::sign(epoch, &keypair(35))?,
        authorization,
        revealed_seed: round.revealed_seed.clone(),
        eligible: round.eligible.clone(),
    })
}

/// The authorization a bondless audit carries: the round it was filed
/// under, the draw that round produced for this listing, and the
/// governance authorization the round runs on.
fn venue_audit_authorization(
    round: &FindingAuditRound,
    finding_id: &str,
) -> Result<FindingChallengeAuthorization, AnyError> {
    Ok(FindingChallengeAuthorization::VenueAudit(
        FindingVenueAuditAuthorization {
            audit_epoch_envelope_sha256: signed_envelope_sha256(&round.epoch)?,
            selection_digest: derive_audit_draw(&round.revealed_seed, finding_id, LISTING_ID),
            authorization_digest: round.epoch.body.authorization_digest.clone(),
        },
    ))
}

fn venue_audit_challenge() -> Result<SignedFindingChallenge, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let profile_envelope_sha256 = signed_envelope_sha256(&verifier_profile()?)?;
    let mut body = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw.as_bytes()),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: admitted_terms_digest()?,
        profile_envelope_sha256,
        venue_admission_envelope_sha256: admitted_admission_digest()?,
        backing_envelope_sha256: hex64('6'),
        filed_at: NOW,
        affected_deliveries: Vec::new(),
        authorization: venue_audit_authorization(&published_audit_round()?, &finding.finding_id)?,
        evidence: FindingChallengeEvidence::EvidenceInvalid {
            challenged_evidence_receipt_refs: vec![FindingReceiptRef {
                receipt_id: "receipt-evidence-01".to_string(),
                receipt_sha256: hex64('e'),
            }],
            challenged_checkpoint_ref: FindingCheckpointRef {
                checkpoint_ref: "checkpoint-evidence-01".to_string(),
                checkpoint_sha256: hex64('f'),
            },
            purchase_record_envelope_sha256: hex64('d'),
        },
    };
    body.challenge_id = chio_finding::compute_challenge_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &keypair(35))?)
}

fn venue_audit_challenge_for_round(
    round: &FindingAuditRound,
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = venue_audit_challenge()?.body;
    challenge.authorization = venue_audit_authorization(round, &challenge.finding_id)?;
    challenge.challenge_id = compute_challenge_id(&challenge)?;
    Ok(SignedExportEnvelope::sign(challenge, &keypair(35))?)
}

/// Whether the test preserves the sale path's payout standing or removes
/// it afterward to model a corrupted retained purchase index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayoutStanding {
    Intact,
    RemovedAfterSettlement,
}

/// Open one reservation, take its slot, and close it against a real
/// purchase-authority-signed record, so the claim snapshot reads exactly
/// what the sale path would have written.
fn settle_purchase(
    deployment: &Deployment,
    tag: &str,
    destination: &str,
    realized_spend_units: u64,
    now: u64,
) -> Result<SettledPurchase, AnyError> {
    settle_purchase_with(
        deployment,
        &deployment.allocation_id,
        tag,
        destination,
        realized_spend_units,
        "USD",
        now,
        PayoutStanding::Intact,
    )
}

/// The same settlement against a caller-chosen allocation, so a test can
/// sell from the backing a listing carried before it was rebacked.
#[allow(clippy::too_many_arguments)]
fn settle_purchase_with(
    deployment: &Deployment,
    allocation_id: &str,
    tag: &str,
    destination: &str,
    realized_spend_units: u64,
    record_currency: &str,
    now: u64,
    standing: PayoutStanding,
) -> Result<SettledPurchase, AnyError> {
    let (finding, _) = finding_artifact()?;
    let reservation_id = format!("reservation-{tag}");
    let buyer = if destination == BUYER_TWO_DESTINATION {
        keypair(42)
    } else {
        keypair(41)
    };
    let refund_destination = buyer_destination(if destination == BUYER_TWO_DESTINATION {
        42
    } else {
        41
    });
    let settlement_destination = &refund_destination;
    let buyer_hex = buyer.public_key().to_hex();
    let ask_digest = digest(&format!("ask-{tag}"));
    let bid_request = SignedExportEnvelope::sign(
        BidRequest {
            schema: BID_REQUEST_SCHEMA.to_string(),
            agent_id: buyer_hex.clone(),
            payout_destination: Some(refund_destination.clone()),
            listing_id: LISTING_ID.to_string(),
            max_price_per_call: usd(100),
            window_seconds: 300,
            requested_scope: RequestedScope {
                server_id: "finding-provider".to_string(),
                tool_name: "finding.reveal".to_string(),
                max_invocations: Some(1),
                capability_scope_prefix: "finding://".to_string(),
            },
            issued_at: now.saturating_sub(10),
        },
        &buyer,
    )?;
    let bid_body_digest = sha256_hex(&canonical_json_bytes(&bid_request.body)?);
    let accepted_bid = SignedExportEnvelope::sign(
        AcceptedBid {
            schema: ACCEPTED_BID_SCHEMA.to_string(),
            listing_id: LISTING_ID.to_string(),
            agent_id: buyer_hex.clone(),
            bid_digest: bid_body_digest,
            ask_digest: ask_digest.clone(),
            bid_receipt_id: reservation_id.clone(),
            quoted_price: usd(100),
            accepted_at: now.saturating_sub(5),
            token_id: format!("finding-token-{tag}"),
            token_subject: buyer.public_key(),
            token_expires_at: now + 3_600,
        },
        &buyer,
    )?;
    let bid = signed_envelope_sha256(&accepted_bid)?;
    let reservation_receipt = SignedExportEnvelope::sign(
        ReservationReceipt {
            schema: RESERVATION_RECEIPT_SCHEMA.to_string(),
            receipt_id: reservation_id.clone(),
            agent_id: buyer_hex.clone(),
            listing_id: LISTING_ID.to_string(),
            ask_digest: ask_digest.clone(),
            reserved_amount: usd(100),
        },
        &keypair(16),
    )?;
    let purchase_intent_id = derive_purchase_intent_id(&reservation_id);
    let payment_operation_id = derive_payment_operation_id(&reservation_id);
    let encumbrance_id =
        sha256_hex(format!("chio.finding.encumbrance.v1\0{reservation_id}").as_bytes());
    deployment
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: &reservation_id,
            purchase_intent_id: &purchase_intent_id,
            authoritative_payment_operation_id: &payment_operation_id,
            payer_hex: &buyer_hex,
            agent_id: &buyer_hex,
            payout_destination: settlement_destination,
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &bid,
            ask_digest: &ask_digest,
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
            fee_schedule_envelope_sha256: &deployment.fee_schedule_envelope_sha256,
            participation_epoch: 0,
            amount_units: 100,
            currency: "USD",
            expires_at: now + 3_600,
            encumbrance_id: &encumbrance_id,
            allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: now,
        })?;
    let ordinal = deployment.purchases.reserve_slot(&reservation_id, now)?;
    let mut record = FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_string(),
        purchase_key: derive_purchase_key(&bid, &payment_operation_id),
        purchase_intent_id,
        authoritative_payment_operation_id: payment_operation_id.clone(),
        buyer: buyer.public_key(),
        payer: buyer.public_key(),
        finding_id: finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        accepted_bid_envelope_sha256: bid.clone(),
        venue_admission_envelope_sha256: deployment.admission_envelope_sha256.clone(),
        accepted_price: MonetaryAmount {
            units: 100,
            currency: record_currency.to_owned(),
        },
        realized_spend: MonetaryAmount {
            units: realized_spend_units,
            currency: record_currency.to_owned(),
        },
        seller_backing_envelope_sha256: hex64('6'),
        encumbrance_id,
        delivery_receipt_id: String::new(),
        payment_reference: payment_operation_id.clone(),
        payout_destination: settlement_destination.clone(),
        recorded_at: now,
    };
    let delivery =
        settled_delivery_evidence(&record, &reservation_id, &finding.payload_sha256, now)?;
    record.delivery_receipt_id = delivery.receipt.receipt.id.clone();
    record.validate()?;
    let purchase_key = record.purchase_key.clone();
    let signed = SignedFindingPurchaseRecord::sign(record, &keypair(16))?;
    let record_json = canonical_json_bytes(&signed)?;
    let record_sha256 = sha256_hex(&record_json);
    if standing == PayoutStanding::Intact {
        deployment
            .purchases
            .admit_payout_destination(allocation_id, &refund_destination, now)?;
    }
    deployment
        .purchases
        .mark_capture_pending(&reservation_id, &payment_operation_id, now)?;
    deployment
        .purchases
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &reservation_id,
            purchase_key: &purchase_key,
            record_json: &record_json,
            record_sha256: &record_sha256,
            delivery_receipt_id: &delivery.receipt.receipt.id,
            payout_destination: settlement_destination,
            retention_expires_at: now + 100_000,
            now,
        })?;
    assert!(ordinal >= 1, "slot ordinals start at one");
    Ok(SettledPurchase {
        record_envelope_sha256: signed_envelope_sha256(&signed)?,
        purchase_key,
        record: signed,
        bid_request,
        accepted_bid,
        reservation_receipt,
        delivery_receipt: delivery.receipt,
        delivery_checkpoint: delivery.checkpoint,
        delivery_checkpoint_transparency: delivery.checkpoint_transparency,
        delivery_authority_status: delivery.authority_status,
    })
}

/// Corrupt the retained payout index after all legitimate preconditions have
/// been established. Production code cannot delete this immutable row; the
/// fixture proves the serving-owner integrity fence denies the later payout.
fn remove_payout_standing_for_test(
    deployment: &Deployment,
    allocation_id: &str,
    destination: &str,
) -> TestResult {
    let mut connection = rusqlite::Connection::open(&deployment.database)?;
    let transaction = connection.transaction()?;
    transaction.execute_batch("DROP TRIGGER payout_destinations_no_delete;")?;
    let removed = transaction.execute(
        "DELETE FROM payout_destinations WHERE allocation_id = ?1 AND destination = ?2",
        rusqlite::params![allocation_id, destination],
    )?;
    if removed != 1 {
        return Err("adversarial payout standing fixture removed no row".into());
    }
    transaction.execute_batch(
        r#"
        CREATE TRIGGER payout_destinations_no_delete
        BEFORE DELETE ON payout_destinations
        BEGIN
            SELECT RAISE(ABORT, 'admitted payout destination must be retained');
        END;
        "#,
    )?;
    transaction.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Governance fixtures for the penalty branches
// ---------------------------------------------------------------------------

struct Governance {
    fee_schedule: SignedOpenMarketFeeSchedule,
    admission: SignedFindingAdmission,
    charter: SignedGenericGovernanceCharter,
    listing: SignedGenericListing,
    activation: SignedGenericTrustActivation,
    publisher: GenericRegistryPublisher,
    sanction_case: SignedGenericGovernanceCase,
    appeal_case: SignedGenericGovernanceCase,
}

fn governing_keypair() -> Keypair {
    keypair(1)
}

/// The pinned fee-schedule operator. It is deliberately not the
/// governance root: a schedule authenticates against its own roster.
fn fee_schedule_keypair() -> Keypair {
    keypair(39)
}

fn governance() -> Result<Governance, AnyError> {
    governance_signed_by(&governing_keypair(), &fee_schedule_keypair())
}

/// The same governance bundle under caller-chosen keys, so a test can
/// present artifacts no pinned authority ever signed.
fn governance_signed_by(
    signer: &Keypair,
    fee_schedule_signer: &Keypair,
) -> Result<Governance, AnyError> {
    let signer = signer.clone();
    let fee_schedule = sample_fee_schedule(fee_schedule_signer)?;
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let allocation = allocation_body(LISTING_ID, &hex64('1'))?;
    let admission = signed_admission_with_backing_and_schedule(
        &allocation.allocation_id,
        &terms,
        &hex64('6'),
        &signed_envelope_sha256(&fee_schedule)?,
    )?;
    let listing = sample_listing(&signer)?;
    let activation = sample_activation(&signer, &listing)?;
    let charter = sample_charter(&signer)?;
    let sanction_case = sample_case(
        &signer,
        &listing,
        &activation,
        &charter,
        GenericGovernanceCaseKind::Sanction,
        None,
        None,
    )?;
    let appeal_case = sample_case(
        &signer,
        &listing,
        &activation,
        &charter,
        GenericGovernanceCaseKind::Appeal,
        Some(sanction_case.body.case_id.clone()),
        Some(sanction_case.body.case_id.clone()),
    )?;
    Ok(Governance {
        fee_schedule,
        admission,
        charter,
        listing,
        activation,
        publisher: sample_publisher(),
        sanction_case,
        appeal_case,
    })
}

impl Governance {
    fn context(&self) -> FindingPenaltyGovernance<'_> {
        FindingPenaltyGovernance {
            local_operator_id: OPERATOR_ID,
            subject_operator_id: OPERATOR_ID,
            issued_by: "market@chio.example",
            fee_schedule: &self.fee_schedule,
            admission: &self.admission,
            charter: &self.charter,
            listing: &self.listing,
            activation: Some(&self.activation),
            current_publisher: &self.publisher,
            penalty_expires_at: Some(NOW + 900_000),
        }
    }
}

fn sample_publisher() -> GenericRegistryPublisher {
    GenericRegistryPublisher {
        role: GenericRegistryPublisherRole::Origin,
        operator_id: OPERATOR_ID.to_string(),
        operator_name: Some("Registry Operator".to_string()),
        registry_url: NAMESPACE.to_string(),
        upstream_registry_urls: Vec::new(),
    }
}

fn sample_listing(signer: &Keypair) -> Result<SignedGenericListing, AnyError> {
    let namespace = GenericNamespaceArtifact {
        schema: GENERIC_NAMESPACE_ARTIFACT_SCHEMA.to_string(),
        namespace_id: "namespace-registry-chio-example".to_string(),
        lifecycle_state: GenericNamespaceLifecycleState::Active,
        ownership: GenericNamespaceOwnership {
            namespace: NAMESPACE.to_string(),
            owner_id: OPERATOR_ID.to_string(),
            owner_name: Some("Registry Operator".to_string()),
            registry_url: NAMESPACE.to_string(),
            signer_public_key: signer.public_key(),
            registered_at: 100,
            transferred_from_owner_id: None,
        },
        boundary: GenericListingBoundary::default(),
    };
    let listing = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: LISTING_ID.to_string(),
        namespace: namespace.ownership.namespace.clone(),
        published_at: NOW - 1_000,
        expires_at: Some(NOW + 1_000_000),
        status: GenericListingStatus::Active,
        namespace_ownership: namespace.ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: "finding-server".to_string(),
            display_name: Some("Finding Server".to_string()),
            metadata_url: Some("https://registry.chio.example/servers/finding".to_string()),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: "cert-check-finding".to_string(),
            source_artifact_sha256: "sha256-finding".to_string(),
        },
        boundary: GenericListingBoundary::default(),
    };
    Ok(SignedGenericListing::sign(listing, signer)?)
}

fn sample_activation(
    signer: &Keypair,
    listing: &SignedGenericListing,
) -> Result<SignedGenericTrustActivation, AnyError> {
    let artifact = build_generic_trust_activation_artifact(
        OPERATOR_ID,
        Some("Registry Operator".to_string()),
        &GenericTrustActivationIssueRequest {
            listing: listing.clone(),
            admission_class: GenericTrustAdmissionClass::BondBacked,
            disposition: GenericTrustActivationDisposition::Approved,
            eligibility: GenericTrustActivationEligibility {
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                allowed_statuses: vec![GenericListingStatus::Active],
                require_fresh_listing: true,
                require_bond_backing: true,
                required_listing_operator_ids: vec![OPERATOR_ID.to_string()],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            review_context: GenericTrustActivationReviewContext {
                publisher: sample_publisher(),
                freshness: GenericListingReplicaFreshness {
                    state: GenericListingFreshnessState::Fresh,
                    age_secs: 0,
                    max_age_secs: 300,
                    valid_until: NOW + 1_000_000,
                    generated_at: NOW - 1_000,
                },
            },
            requested_by: "ops@chio.example".to_string(),
            reviewed_by: Some("reviewer@chio.example".to_string()),
            requested_at: Some(NOW - 900),
            reviewed_at: Some(NOW - 800),
            expires_at: Some(NOW + 900_000),
            note: None,
        },
        NOW - 900,
    )?;
    Ok(SignedGenericTrustActivation::sign(artifact, signer)?)
}

fn sample_charter(signer: &Keypair) -> Result<SignedGenericGovernanceCharter, AnyError> {
    let artifact = build_generic_governance_charter_artifact(
        OPERATOR_ID,
        Some("Registry Operator".to_string()),
        &GenericGovernanceCharterIssueRequest {
            authority_scope: GenericGovernanceAuthorityScope {
                namespace: NAMESPACE.to_string(),
                allowed_listing_operator_ids: vec![OPERATOR_ID.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                policy_reference: Some("policy/governance/default".to_string()),
            },
            allowed_case_kinds: vec![
                GenericGovernanceCaseKind::Sanction,
                GenericGovernanceCaseKind::Appeal,
            ],
            escalation_operator_ids: Vec::new(),
            issued_by: "governance@chio.example".to_string(),
            issued_at: Some(NOW - 700),
            expires_at: Some(NOW + 900_000),
            note: None,
        },
        NOW - 700,
    )?;
    Ok(SignedGenericGovernanceCharter::sign(artifact, signer)?)
}

fn sample_case(
    signer: &Keypair,
    listing: &SignedGenericListing,
    activation: &SignedGenericTrustActivation,
    charter: &SignedGenericGovernanceCharter,
    kind: GenericGovernanceCaseKind,
    appeal_of_case_id: Option<String>,
    supersedes_case_id: Option<String>,
) -> Result<SignedGenericGovernanceCase, AnyError> {
    let opened_at = match kind {
        GenericGovernanceCaseKind::Appeal => NOW + 5,
        _ => NOW - 600,
    };
    sample_case_at(
        signer,
        listing,
        activation,
        charter,
        kind,
        appeal_of_case_id,
        supersedes_case_id,
        opened_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn sample_case_at(
    signer: &Keypair,
    listing: &SignedGenericListing,
    activation: &SignedGenericTrustActivation,
    charter: &SignedGenericGovernanceCharter,
    kind: GenericGovernanceCaseKind,
    appeal_of_case_id: Option<String>,
    supersedes_case_id: Option<String>,
    opened_at: u64,
) -> Result<SignedGenericGovernanceCase, AnyError> {
    let artifact = build_generic_governance_case_artifact(
        OPERATOR_ID,
        &GenericGovernanceCaseIssueRequest {
            charter: charter.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            kind,
            state: GenericGovernanceCaseState::Enforced,
            subject_operator_id: Some(OPERATOR_ID.to_string()),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::TrustActivation,
                reference_id: activation.body.activation_id.clone(),
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id,
            supersedes_case_id,
            issued_by: "governance@chio.example".to_string(),
            opened_at: Some(opened_at),
            updated_at: Some(opened_at),
            expires_at: Some(NOW + 900_000),
            note: None,
        },
        opened_at,
    )?;
    Ok(SignedGenericGovernanceCase::sign(artifact, signer)?)
}

/// The one schedule this venue published, signed by the pinned
/// fee-schedule operator. Every filing prices against it.
fn published_fee_schedule() -> Result<SignedOpenMarketFeeSchedule, AnyError> {
    sample_fee_schedule(&fee_schedule_keypair())
}

fn sample_fee_schedule(signer: &Keypair) -> Result<SignedOpenMarketFeeSchedule, AnyError> {
    let artifact = build_open_market_fee_schedule_artifact(
        OPERATOR_ID,
        Some("Registry Operator".to_string()),
        &OpenMarketFeeScheduleIssueRequest {
            scope: OpenMarketEconomicsScope {
                namespace: NAMESPACE.to_string(),
                allowed_listing_operator_ids: vec![OPERATOR_ID.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            publication_fee: usd(100),
            dispute_fee: usd(DISPUTE_FEE_UNITS),
            market_participation_fee: usd(500),
            bond_requirements: vec![
                OpenMarketBondRequirement {
                    bond_class: OpenMarketBondClass::Listing,
                    required_amount: usd(5_000),
                    collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                    slashable: true,
                },
                OpenMarketBondRequirement {
                    bond_class: OpenMarketBondClass::Dispute,
                    required_amount: usd(DISPUTE_BOND_UNITS),
                    collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
                    slashable: true,
                },
            ],
            issued_by: "market@chio.example".to_string(),
            issued_at: Some(NOW - 700),
            expires_at: Some(NOW + 900_000),
            note: None,
        },
        NOW - 700,
    )?;
    Ok(SignedOpenMarketFeeSchedule::sign(artifact, signer)?)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The seller-signed terms this listing sells under: the claim window the
/// upheld transaction freezes, and the filing window, audit toggle, and
/// bond limits every filing is admitted against. Issued shortly before
/// the fixture clock so a filing at `NOW` sits inside the signed filing
/// window.
fn market_terms(claim_window_secs: u64) -> Result<SignedFindingMarketTerms, AnyError> {
    let (finding, raw_finding) = finding_artifact()?;
    let seller = keypair(22);
    let profile_envelope_sha256 = signed_envelope_sha256(&verifier_profile()?)?;
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw_finding.as_bytes()),
        listing_id: LISTING_ID.to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(300),
            maximum_sale_exposure: usd(REGISTERED_EXPOSURE_CAP),
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 1_000_000,
        claim_window_secs,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 2_592_000,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: profile_envelope_sha256,
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(10),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: NOW - 3_600,
        expires_at: KEY_VALID_UNTIL,
    };
    terms.terms_id = compute_terms_id(&terms)?;
    Ok(SignedExportEnvelope::sign(terms, &seller)?)
}

#[test]
fn finding_challenge_terms_reject_an_unlisted_replay_rule() -> TestResult {
    let profile_envelope_sha256 = signed_envelope_sha256(&verifier_profile()?)?;
    let allowed = replay_recipe(&profile_envelope_sha256);
    let allowed_evidence = FindingChallengeEvidence::ReplayContradiction {
        reproduction: Vec::new(),
        recipe_preimage: canonical_json_string(&allowed)?,
        purchase_record_envelope_sha256: hex64('1'),
    };
    require_admitted_replay_decision_rule(&market_terms(CLAIM_WINDOW_SECS)?, &allowed_evidence)?;

    let mut disallowed = allowed;
    disallowed.decision_rule_ref = "decision/replay-v2".to_string();
    let disallowed_evidence = FindingChallengeEvidence::ReplayContradiction {
        reproduction: Vec::new(),
        recipe_preimage: canonical_json_string(&disallowed)?,
        purchase_record_envelope_sha256: hex64('1'),
    };
    assert!(matches!(
        require_admitted_replay_decision_rule(
            &market_terms(CLAIM_WINDOW_SECS)?,
            &disallowed_evidence,
        ),
        Err(ChallengeCoordinatorError::ReplayDecisionRule(
            "decision_rule_ref"
        ))
    ));
    Ok(())
}

/// The standard admitted terms with one field bent, re-addressed and
/// re-signed, so the variant is a distinct admitted envelope.
fn market_terms_shaped(
    shape: impl FnOnce(&mut FindingMarketTerms),
) -> Result<SignedFindingMarketTerms, AnyError> {
    let signed = market_terms(CLAIM_WINDOW_SECS)?;
    let mut terms = signed.body;
    shape(&mut terms);
    terms.terms_id = compute_terms_id(&terms)?;
    Ok(SignedExportEnvelope::sign(terms, &keypair(22))?)
}

/// Admitted terms whose filing window lapsed before the fixture clock.
fn lapsed_window_terms() -> Result<SignedFindingMarketTerms, AnyError> {
    market_terms_shaped(|terms| terms.filing_window_secs = 600)
}

/// Admitted terms whose artifact expiry closes before their longer filing
/// duration would otherwise end.
fn early_expiry_terms() -> Result<SignedFindingMarketTerms, AnyError> {
    market_terms_shaped(|terms| terms.expires_at = NOW)
}

/// Admitted terms that keep the listing out of the audit rotation.
fn audit_disabled_terms() -> Result<SignedFindingMarketTerms, AnyError> {
    market_terms_shaped(|terms| terms.audit_eligible = false)
}

/// Admitted terms whose bond ceiling sits below the schedule's dispute
/// requirement.
fn narrow_bond_terms() -> Result<SignedFindingMarketTerms, AnyError> {
    market_terms_shaped(|terms| {
        if let Some(limit) = terms.challenge_bond_limits.first_mut() {
            limit.max_bond = usd(DISPUTE_BOND_UNITS - 10);
        }
    })
}

/// Envelope digest of the admitted terms every reference filing binds.
fn admitted_terms_digest() -> Result<String, AnyError> {
    Ok(signed_envelope_sha256(&market_terms(CLAIM_WINDOW_SECS)?)?)
}

/// Uphold across the seller-signed claim window, ending at `now`.
///
/// The call that opens the window freezes the deadline and can never
/// seal, so a payout only closes on a later call past that deadline. Both
/// calls carry identical arguments; the second is the one the caller's
/// assertion is about, and it carries whatever the sealing path decided.
#[allow(clippy::too_many_arguments)]
fn uphold_across_claim_window(
    coordinator: &FindingChallengeCoordinator,
    terms: &SignedFindingMarketTerms,
    challenge: &SignedFindingChallenge,
    outcome: &SignedFindingChallengeOutcome,
    identity: &FindingLiabilityIdentity<'_>,
    cutoff_slot: u64,
    claim_candidates: &[String],
    collateral: &FindingCollateralFacts<'_>,
    governance: &FindingPenaltyGovernance<'_>,
    sanction_case: &SignedGenericGovernanceCase,
    now: u64,
) -> Result<UpheldLiability, ChallengeCoordinatorError> {
    let opened = coordinator.uphold(
        &challenge.body.challenge_id,
        challenge,
        outcome,
        identity,
        terms,
        cutoff_slot,
        claim_candidates,
        collateral,
        governance,
        sanction_case,
        now - CLAIM_WINDOW_SECS,
    );
    assert!(
        matches!(opened, Err(ChallengeCoordinatorError::ClaimWindowOpen)),
        "the claim window can never close in the call that opens it: {opened:?}"
    );
    coordinator.uphold(
        &challenge.body.challenge_id,
        challenge,
        outcome,
        identity,
        terms,
        cutoff_slot,
        claim_candidates,
        collateral,
        governance,
        sanction_case,
        now,
    )
}

fn liability_identity<'a>(
    finding_id: &'a str,
    allocation_id: &'a str,
) -> FindingLiabilityIdentity<'a> {
    FindingLiabilityIdentity {
        finding_id,
        listing_id: LISTING_ID,
        allocation_id,
        chain_id: "chio-devnet",
        vault_contract: "vault:finding-collateral",
        vault_id: "vault-01",
    }
}

fn collateral_facts<'a>(
    stake: &'a MonetaryAmount,
    required: &'a MonetaryAmount,
    allocation_id: &'a str,
    live: u64,
) -> FindingCollateralFacts<'a> {
    collateral_facts_at(stake, required, allocation_id, live, NOW)
}

fn collateral_facts_at<'a>(
    stake: &'a MonetaryAmount,
    required: &'a MonetaryAmount,
    allocation_id: &'a str,
    live: u64,
    observed_at: u64,
) -> FindingCollateralFacts<'a> {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: "chio-devnet".to_string(),
        vault_contract: "vault:finding-collateral".to_string(),
        vault_id: "vault-01".to_string(),
        seller: keypair(22).public_key(),
        allocation_id: allocation_id.to_string(),
        locked_amount: required.units,
        held_amount: required
            .units
            .checked_sub(live)
            .test_expect("fixture live collateral does not exceed locked collateral"),
        slashed_amount: 0,
        currency: stake.currency.clone(),
        block_number: 21_000_000,
        block_hash: chain_hash(0xbb),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        observed_at,
    };
    snapshot.snapshot_id =
        compute_snapshot_id(&snapshot).test_expect("fixture collateral snapshot id computes");
    FindingCollateralFacts {
        base_finding_stake: stake,
        bond_snapshot: SignedExportEnvelope::sign(snapshot, &keypair(34))
            .test_expect("fixture collateral snapshot signs"),
    }
}

/// One adjudication request over real evidence, at the venue clock.
fn evaluation_request<'a>(
    challenge: &'a SignedFindingChallenge,
    challenged: &'a ChallengedFinding,
    evidence: &'a FindingChallengeClassEvidence<'a>,
    collateral: &'a FindingCollateralFacts<'a>,
    now: u64,
) -> ChallengeEvaluationRequest<'a> {
    ChallengeEvaluationRequest {
        challenge,
        raw_finding: &challenged.raw_finding,
        profile: &challenged.profile,
        evidence,
        collateral,
        evaluator_key_epoch: PINNED_KEY_EPOCH,
        now,
    }
}

#[test]
fn liability_key_length_prefixes_identity_components() {
    let left = FindingLiabilityIdentity {
        finding_id: "finding",
        listing_id: "listing\0allocation",
        allocation_id: "backing",
        chain_id: "chain",
        vault_contract: "contract",
        vault_id: "vault",
    };
    let right = FindingLiabilityIdentity {
        finding_id: "finding",
        listing_id: "listing",
        allocation_id: "allocation\0backing",
        chain_id: "chain",
        vault_contract: "contract",
        vault_id: "vault",
    };

    assert_ne!(
        derive_liability_key(&derive_defect_key("finding"), VENUE_ID, &left),
        derive_liability_key(&derive_defect_key("finding"), VENUE_ID, &right)
    );
}

/// Close the appeal window with no reversal and take the signed
/// instruction the venue authorized.
fn impair_after_appeal(
    coordinator: &FindingChallengeCoordinator,
    governance: &Governance,
    upheld: &UpheldLiability,
    outcome: &SignedFindingChallengeOutcome,
    identity: &FindingLiabilityIdentity<'_>,
    now: u64,
) -> Result<Box<AuthorizedImpairment>, AnyError> {
    let resolution = coordinator.resolve_appeal(
        &upheld.liability_key,
        outcome,
        identity,
        Some(&upheld.sealed),
        &governance.context(),
        &AppealDisposition::Final {
            sanction_case: &governance.sanction_case,
        },
        &upheld.sanction_case_id,
        &upheld.hold,
        &hex64('7'),
        now,
    )?;
    match resolution {
        AppealResolution::Finalizing(authorized) => Ok(authorized),
        _ => Err("appeal finality with no reversal authorizes the impairment".into()),
    }
}

/// The distribution keyed by destination, for exact-sum assertions.
fn allocation_by_destination(
    distribution: &chio_open_market::finding_slash_amount::SlashDistribution,
) -> std::collections::BTreeMap<String, u64> {
    distribution
        .entries
        .iter()
        .map(|entry| (entry.destination.clone(), entry.amount_units))
        .collect()
}

/// Every liability head one defect could ever carry, so a test can prove
/// a second challenge opened none.
fn liability_heads(deployment: &Deployment, finding_id: &str) -> Result<usize, AnyError> {
    Ok(deployment
        .challenges
        .list_liabilities_for_defect(&derive_defect_key(finding_id))?
        .len())
}

/// Drive one challenge through the store to a terminal verdict, exactly
/// as the evaluator's own recorded verdict would, recording the digest of
/// the outcome envelope the verdict was carried by.
fn close_challenge(
    deployment: &Deployment,
    challenge_id: &str,
    verdict: FindingChallengeVerdict,
    outcome_envelope_sha256: &str,
    outcome_envelope_json: &[u8],
    now: u64,
) -> Result<FindingChallengeState, AnyError> {
    deployment.filings.retain_evaluator_policy(
        outcome_envelope_sha256,
        &market_config().challenge_evaluator,
    )?;
    deployment.challenges.begin_evaluation(challenge_id, now)?;
    if verdict == FindingChallengeVerdict::Upheld {
        let outcome: SignedFindingChallengeOutcome = serde_json::from_slice(outcome_envelope_json)?;
        let calculation = outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or("an upheld fixture outcome carries its exposure calculation")?;
        Ok(deployment
            .challenges
            .record_test_upheld_verdict_with_exposure_fence(
                challenge_id,
                outcome_envelope_sha256,
                outcome_envelope_json,
                &outcome.body.backing_allocation_id,
                calculation.open_per_sale_encumbrance_units,
                now,
            )?)
    } else {
        Ok(deployment.challenges.record_test_verdict(
            challenge_id,
            verdict,
            outcome_envelope_sha256,
            outcome_envelope_json,
            now,
        )?)
    }
}

fn close_upheld_challenge(
    deployment: &Deployment,
    challenge: &SignedFindingChallenge,
    now: u64,
) -> TestResult {
    let exposure = deployment
        .purchases
        .list_outstanding_exposure_total(&deployment.allocation_id, now)?;
    let outcome = upheld_outcome(challenge, &deployment.allocation_id, exposure, "USD")?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    close_challenge(
        deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        now,
    )?;
    Ok(())
}

/// The evaluator-signed upheld outcome the uphold transaction consumes.
fn upheld_outcome(
    challenge: &SignedFindingChallenge,
    allocation_id: &str,
    open_per_sale_encumbrance_units: u64,
    currency: &str,
) -> Result<chio_finding::SignedFindingChallengeOutcome, AnyError> {
    let computed_exposure_units = 300 + open_per_sale_encumbrance_units;
    let mut outcome = chio_finding::FindingChallengeOutcome {
        schema: chio_finding::FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_string(),
        outcome_id: String::new(),
        challenge_envelope_sha256: signed_envelope_sha256(challenge)?,
        finding_id: challenge.body.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        backing_allocation_id: allocation_id.to_string(),
        authorization: challenge.body.authorization.kind(),
        evidence_kind: challenge.body.evidence.kind(),
        verifier_profile_envelope_sha256: challenge.body.profile_envelope_sha256.clone(),
        evidence_bundle_digest: hex64('e'),
        verdict: chio_finding::FindingChallengeVerdict::Upheld,
        facet: chio_finding::FindingChallengeFacet::EvidenceInvalid(
            chio_finding::FindingEvidenceInvalidFacet {
                challenged_receipt_ids: vec!["receipt-evidence-01".to_string()],
                invalidity: chio_finding::FindingEvidenceInvalidity::SignatureInvalid,
            },
        ),
        reason: "evidence_signature_invalid".to_string(),
        trigger_digest: hex64('9'),
        audit_epoch_envelope_sha256: match &challenge.body.authorization {
            FindingChallengeAuthorization::VenueAudit(audit) => {
                Some(audit.audit_epoch_envelope_sha256.clone())
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => None,
        },
        penalty_calculation: Some(chio_finding::FindingPenaltyCalculation {
            base_finding_stake_units: 300,
            open_per_sale_encumbrance_units,
            computed_exposure_units,
            listing_required_amount_units: 5_000,
            live_allocated_collateral_units: 5_000,
            penalty_amount: MonetaryAmount {
                units: computed_exposure_units,
                currency: currency.to_string(),
            },
        }),
        retry_deadline: None,
        evaluator_authority_id: "challenge-evaluator".to_string(),
        evaluator_key: keypair(31).public_key(),
        evaluator_key_epoch: PINNED_KEY_EPOCH,
        evaluator_valid_from: 1,
        evaluator_valid_until: I_JSON_MAX_SAFE_INTEGER,
        evaluator_revocation_status_ref: REVOCATION_STATUS_REF.to_string(),
        evaluated_at: NOW,
    };
    outcome.outcome_id = chio_finding::derive_outcome_id(&outcome)?;
    outcome.validate()?;
    Ok(chio_finding::SignedFindingChallengeOutcome::sign(
        outcome,
        &keypair(31),
    )?)
}

// ---------------------------------------------------------------------------
// Submission and the dispute-fee lane
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finding_challenge_live_route_submits_to_the_durable_coordinator_exactly_once() -> TestResult
{
    let other_deployment = deployment()?;
    let deployment = deployment()?;
    let mismatched_runtime = FindingChallengeSubmissionRuntime::new(
        deployment._authority.clone(),
        Arc::new(other_deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?),
    );
    assert!(matches!(
        mismatched_runtime,
        Err(ChallengeCoordinatorError::Configuration(_))
    ));
    let (finding, raw_finding) = finding_artifact()?;
    deployment.market.put_finding(
        &FindingRecordInput {
            finding_id: &finding.finding_id,
            artifact_json: &raw_finding,
            topic: &finding.descriptor.topic,
            context_sha256: &finding.descriptor.context_sha256,
            issued_at: finding.issued_at,
            expires_at: finding.expires_at,
        },
        NOW,
    )?;
    let challenge = buyer_challenge(&keypair(41))?;
    let raw_challenge = canonical_json_string(&challenge)?;
    let executor = Arc::new(RouteChallengeExecutor {
        coordinator: deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?,
        raw_challenge_envelopes: Mutex::new(Vec::new()),
        raw_findings: Mutex::new(Vec::new()),
        handler_times: Mutex::new(Vec::new()),
    });
    let state = challenge_route_state(&deployment, executor.clone());

    // Load shedding precedes both untrusted envelope parsing and the
    // mutex-backed market lookup. The malformed canonical object would return
    // 400, and the unknown Finding would return 404, if either path ran before
    // the non-queued challenge lane was acquired.
    let busy_finding_id = hex64('9');
    let mut busy_challenge = challenge.body.clone();
    busy_challenge.finding_id = busy_finding_id.clone();
    busy_challenge.finding_artifact_sha256 = hex64('8');
    busy_challenge.challenge_id = compute_challenge_id(&busy_challenge)?;
    let busy_challenge = SignedExportEnvelope::sign(busy_challenge, &keypair(41))?;
    let busy_raw = canonical_json_string(&busy_challenge)?;
    let active_challenge = state
        .finding_challenge_submission_lane
        .clone()
        .try_acquire_owned()?;
    let body_polled = Arc::new(AtomicBool::new(false));
    let body_poll_observation = Arc::clone(&body_polled);
    let unpolled_body = Body::from_stream(stream::once(async move {
        body_poll_observation.store(true, Ordering::SeqCst);
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{}"))
    }));
    let response = build_router(state.clone())
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!("/v1/findings/{busy_finding_id}/challenges"))
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer challenge-service-secret")
                .body(unpolled_body)?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body_polled.load(Ordering::SeqCst));
    let (status, _) = submit_challenge_route(&state, &busy_finding_id, "{}", true).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = submit_challenge_route(&state, &busy_finding_id, &busy_raw, true).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    drop(active_challenge);
    assert!(executor
        .raw_findings
        .lock()
        .map_err(|_| "route finding observation lock poisoned")?
        .is_empty());

    let oversized = " ".repeat(1024 * 1024 + 1);
    let (status, _) = submit_challenge_route(&state, &finding.finding_id, &oversized, true).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let mut unconfigured = state.clone();
    unconfigured.finding_challenge_executor = None;
    let (status, _) =
        submit_challenge_route(&unconfigured, &finding.finding_id, &raw_challenge, true).await?;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = submit_challenge_route(&state, &hex64('9'), &raw_challenge, true).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) =
        submit_challenge_route(&state, &finding.finding_id, &raw_challenge, false).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(deployment.rail.charges().is_empty());
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());

    let (first_status, first_body) =
        submit_challenge_route(&state, &finding.finding_id, &raw_challenge, true).await?;
    let first: FindingChallengeSubmissionResponse = serde_json::from_slice(&first_body)?;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first.write, FindingChallengeSubmissionWrite::Inserted);

    let (second_status, second_body) =
        submit_challenge_route(&state, &finding.finding_id, &raw_challenge, true).await?;
    let second: FindingChallengeSubmissionResponse = serde_json::from_slice(&second_body)?;
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second.write, FindingChallengeSubmissionWrite::ExistingSame);
    assert_eq!(second.challenge_id, first.challenge_id);
    assert_eq!(second.dispute_fee_intent_key, first.dispute_fee_intent_key);
    assert_eq!(second.dispute_bond_lock_id, first.dispute_bond_lock_id);

    let observed_challenges = executor
        .raw_challenge_envelopes
        .lock()
        .map_err(|_| "route challenge observation lock poisoned")?;
    assert_eq!(observed_challenges.len(), 2);
    assert!(observed_challenges
        .iter()
        .all(|observed| observed == &raw_challenge));
    let observed_findings = executor
        .raw_findings
        .lock()
        .map_err(|_| "route finding observation lock poisoned")?;
    assert_eq!(observed_findings.len(), 2);
    assert!(observed_findings
        .iter()
        .all(|observed| observed == &raw_finding));
    let handler_times = executor
        .handler_times
        .lock()
        .map_err(|_| "route time observation lock poisoned")?;
    assert_eq!(handler_times.len(), 2);
    assert!(handler_times.iter().all(|observed| *observed > 0));
    drop(handler_times);
    drop(observed_findings);
    drop(observed_challenges);

    assert_eq!(deployment.rail.charges().len(), 2);
    let challenge_record = deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .ok_or("challenge route did not persist the challenge")?;
    assert_eq!(challenge_record.state, FindingChallengeState::Submitted);
    let fee_key = first
        .dispute_fee_intent_key
        .as_deref()
        .ok_or("challenge route did not return the dispute-fee intent")?;
    let fee_intent = deployment
        .challenges
        .get_effect_intent(fee_key)?
        .ok_or("challenge route did not persist the dispute-fee intent")?;
    assert_eq!(fee_intent.state, FindingEffectIntentState::Confirmed);
    assert_eq!(fee_intent.attempt_count, 1);
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .ok_or("challenge route did not persist the dispute lock")?;
    assert_eq!(lock.state, FindingDisputeLockState::Locked);
    assert_eq!(Some(lock.lock_id), first.dispute_bond_lock_id);
    Ok(())
}

#[tokio::test]
async fn finding_challenge_live_route_defers_historical_audit_authority_resolution() -> TestResult {
    let deployment = deployment()?;
    let (finding, raw_finding) = finding_artifact()?;
    deployment.market.put_finding(
        &FindingRecordInput {
            finding_id: &finding.finding_id,
            artifact_json: &raw_finding,
            topic: &finding.descriptor.topic,
            context_sha256: &finding.descriptor.context_sha256,
            issued_at: finding.issued_at,
            expires_at: finding.expires_at,
        },
        NOW,
    )?;
    let challenge = venue_audit_challenge()?;
    let raw_challenge = canonical_json_string(&challenge)?;
    let mut rotated_config = market_config();
    rotated_config.audit_authority = authority_pin(50, "audit-authority-rotated");
    rotated_config.audit_authority.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_config.audit_authority.valid_from = NOW + 1;
    let executor = Arc::new(RouteChallengeExecutor {
        coordinator: deployment
            .coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?,
        raw_challenge_envelopes: Mutex::new(Vec::new()),
        raw_findings: Mutex::new(Vec::new()),
        handler_times: Mutex::new(Vec::new()),
    });
    let mut state = challenge_route_state(&deployment, executor);
    state.config.finding_market = Some(rotated_config);

    let (status, body) =
        submit_challenge_route(&state, &finding.finding_id, &raw_challenge, true).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_some());
    Ok(())
}

#[test]
fn finding_challenge_buyer_submission_charges_the_challenge_administration_pool() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let challenge = buyer_challenge(&buyer)?;
    let (_, raw) = finding_artifact()?;

    let submitted = coordinator.submit(&challenge, &raw, NOW)?;
    assert_eq!(submitted.challenge_id, challenge.body.challenge_id);

    let charges = deployment.rail.charges();
    assert_eq!(
        charges.len(),
        2,
        "one filing charges one fee and independently funds one dispute bond"
    );
    let charge = &charges[0];
    assert_eq!(charge.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(charge.rail_destination, CHALLENGE_POOL_DESTINATION);
    assert_ne!(
        charge.rail_destination, AUDIT_POOL_DESTINATION,
        "the dispute fee must never reach the audit pool"
    );
    assert_eq!(charge.amount_units, 25);
    assert_eq!(charge.payer, buyer.public_key().to_hex());

    let fee_key = submitted
        .dispute_fee_intent_key
        .ok_or("buyer submission fences a dispute-fee intent")?;
    let fee_intent = deployment
        .challenges
        .get_effect_intent(&fee_key)?
        .ok_or("dispute-fee intent is durable")?;
    assert_eq!(fee_intent.state, FindingEffectIntentState::Confirmed);

    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .ok_or("buyer submission locks its dispute bond")?;
    assert_eq!(lock.state, FindingDisputeLockState::Locked);
    assert_eq!(lock.amount_units, 40);
    assert_eq!(lock.bond_class, "dispute");
    Ok(())
}

#[test]
fn finding_challenge_reused_lock_id_is_refused_before_any_second_charge() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let first = buyer_challenge(&buyer)?;
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&first, &raw, NOW)?;
    assert_eq!(deployment.rail.charges().len(), 2);

    let mut second_body = first.body.clone();
    second_body.filed_at = NOW + 1;
    second_body.challenge_id = compute_challenge_id(&second_body)?;
    let second = SignedExportEnvelope::sign(second_body, &buyer)?;
    assert!(matches!(
        coordinator
            .submit(&second, &raw, NOW + 1)
            .expect_err("a second challenge cannot reuse the funded lock id"),
        ChallengeCoordinatorError::ChallengeStore(ref detail)
            if detail.contains("dispute lock id")
    ));
    assert_eq!(
        deployment.rail.charges().len(),
        2,
        "lock-id uniqueness is durable before either fee or bond dispatch"
    );
    assert!(deployment
        .challenges
        .get_dispute_lock(&second.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_pool_rotation_preserves_the_admission_pinned_rail() -> TestResult {
    let deployment = deployment()?;
    let mut rotated = market_config();
    rotated.challenge_administration_pool = FindingPoolPin {
        principal_id: "pool:challenge-admin-rotated".to_string(),
        rail_destination: "rail:venue-ledger:challenge-admin-rotated".to_string(),
        currency: "USD".to_string(),
        authority_epoch: 2,
    };
    let coordinator =
        deployment.coordinator_under(&rotated, FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;

    coordinator.submit(&challenge, &raw, NOW)?;
    let instructions = deployment.rail.charges();
    assert_eq!(instructions.len(), 2);
    assert!(instructions.iter().all(|instruction| {
        instruction.pool_principal_id == CHALLENGE_POOL_PRINCIPAL
            && instruction.rail_destination == CHALLENGE_POOL_DESTINATION
    }));
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .ok_or("the admission-pinned lock is durable")?;
    assert_eq!(lock.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(lock.pool_rail_destination, CHALLENGE_POOL_DESTINATION);
    assert_eq!(lock.pool_authority_epoch, 1);
    close_upheld_challenge(&deployment, &challenge, NOW + 1)?;
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 2)?,
        Some(FindingDisputeLockDisposition::Returned)
    );
    let returned = deployment
        .rail
        .charges()
        .pop()
        .ok_or("the retained pool returns the dispute bond")?;
    assert_eq!(returned.payer, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(returned.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    Ok(())
}

#[test]
fn finding_challenge_unknown_admission_moves_no_filing_funds() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let mut challenge = buyer_challenge(&buyer)?;
    challenge.body.venue_admission_envelope_sha256 = hex64('9');
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &buyer)?;
    let (_, raw) = finding_artifact()?;

    let refused = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("an unknown admission must be refused before funding");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AdmissionBinding("venue_admission_envelope_sha256")
    ));
    assert!(deployment.rail.charges().is_empty());
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_recovers_and_returns_a_funded_expired_lock() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let challenge_id = challenge.body.challenge_id.clone();
    let (_, raw) = finding_artifact()?;
    deployment.rail.refuse();
    assert!(matches!(
        coordinator
            .submit(&challenge, &raw, NOW)
            .expect_err("the injected first attempt stops before bond reconstruction"),
        ChallengeCoordinatorError::FeeRail(_)
    ));
    deployment.rail.accept();
    let FindingChallengeAuthorization::BuyerSubmission(submission) = &challenge.body.authorization
    else {
        return Err("the recovery fixture is a buyer submission".into());
    };
    let lock = &submission.dispute_lock_ref;
    let owner_hex = submission.challenger.to_hex();
    let input = FindingDisputeLockInput {
        lock_id: &lock.lock_id,
        challenge_id: &challenge_id,
        owner_hex: &owner_hex,
        schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
        amount_units: lock.amount.units,
        currency: &lock.amount.currency,
        pool_principal_id: CHALLENGE_POOL_PRINCIPAL,
        pool_rail_destination: CHALLENGE_POOL_DESTINATION,
        pool_authority_epoch: 1,
        expires_at: lock.expiry,
        locked_at: NOW,
    };
    let funding_key = derive_dispute_bond_funding_intent_key(&challenge_id, &lock.lock_id);
    deployment.challenges.record_effect_intent(
        &funding_key,
        FindingEffectIntentKind::ChallengeBond,
        &dispute_bond_funding_intent_digest(&input),
        None,
        false,
        NOW,
    )?;
    deployment.challenges.advance_effect_intent(
        &funding_key,
        FindingEffectIntentState::Dispatched,
        NOW,
    )?;
    deployment.challenges.advance_effect_intent(
        &funding_key,
        FindingEffectIntentState::Confirmed,
        NOW,
    )?;

    coordinator.submit(&challenge, &raw, lock.expiry)?;
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .ok_or("recovery reconstructed the funded lock")?;
    assert_eq!(lock.state, FindingDisputeLockState::Returned);
    assert_eq!(lock.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("the recovered filing remains durable")?
            .state,
        FindingChallengeState::IndeterminateClosed
    );
    let instructions = deployment.rail.charges();
    assert_eq!(instructions.len(), 2);
    assert_eq!(
        instructions
            .last()
            .ok_or("the recovery refunds the bond")?
            .payer,
        CHALLENGE_POOL_PRINCIPAL
    );
    Ok(())
}

#[test]
fn finding_challenge_reconciles_a_debited_bond_before_expired_recovery() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let challenge_id = challenge.body.challenge_id.clone();
    let (_, raw) = finding_artifact()?;
    let FindingChallengeAuthorization::BuyerSubmission(submission) = &challenge.body.authorization
    else {
        return Err("the compensation fixture is a buyer submission".into());
    };

    deployment.rail.fail_after_record_on_attempt(2);
    assert!(matches!(
        coordinator
            .submit(&challenge, &raw, NOW)
            .expect_err("the bond rail response is lost after the debit"),
        ChallengeCoordinatorError::DisputeBondRail(_)
    ));
    assert_eq!(
        deployment.rail.charges().len(),
        2,
        "the filing fee and bond debit both reached the rail"
    );
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .is_none());

    deployment.rail.accept();
    coordinator.submit(&challenge, &raw, submission.dispute_lock_ref.expiry)?;
    let instructions = deployment.rail.charges();
    assert_eq!(instructions.len(), 3);
    let funding_key =
        derive_dispute_bond_funding_intent_key(&challenge_id, &submission.dispute_lock_ref.lock_id);
    assert_eq!(instructions[1].idempotency_key, funding_key);
    assert_eq!(instructions[1].payer, keypair(41).public_key().to_hex());
    let returned = instructions
        .last()
        .ok_or("the expired funded bond return reached the rail")?;
    assert_eq!(returned.payer, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(returned.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(returned.rail_destination, keypair(41).public_key().to_hex());
    assert_eq!(returned.amount_units, 40);
    assert_eq!(
        deployment
            .challenges
            .get_effect_intent(&funding_key)?
            .ok_or("the reconciled funding intent remains durable")?
            .state,
        FindingEffectIntentState::Confirmed
    );
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("recovery reconstructs the debited bond")?
            .state,
        FindingDisputeLockState::Returned
    );
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("the compensated filing remains durable")?
            .state,
        FindingChallengeState::IndeterminateClosed
    );

    coordinator.submit(&challenge, &raw, submission.dispute_lock_ref.expiry + 1)?;
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "funding reconciliation and bond return are idempotent"
    );
    Ok(())
}

#[test]
fn finding_challenge_reconciles_a_debited_fee_before_expired_recovery() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let challenge_id = challenge.body.challenge_id.clone();
    let (_, raw) = finding_artifact()?;
    let FindingChallengeAuthorization::BuyerSubmission(submission) = &challenge.body.authorization
    else {
        return Err("the compensation fixture is a buyer submission".into());
    };

    deployment.rail.fail_after_record_on_attempt(1);
    assert!(matches!(
        coordinator
            .submit(&challenge, &raw, NOW)
            .expect_err("the fee rail response is lost after the debit"),
        ChallengeCoordinatorError::FeeRail(_)
    ));
    assert_eq!(
        deployment.rail.charges().len(),
        1,
        "the filing fee reached the rail before its response was lost"
    );

    deployment.rail.accept();
    assert!(matches!(
        coordinator
            .submit(&challenge, &raw, submission.dispute_lock_ref.expiry)
            .expect_err("an expired fee-only filing closes after compensation"),
        ChallengeCoordinatorError::DisputeBondWindow
    ));
    let instructions = deployment.rail.charges();
    assert_eq!(
        instructions.len(),
        2,
        "the idempotent fee replay adds only its compensation"
    );
    let fee_intent_key = instructions[0].idempotency_key.clone();
    assert_eq!(instructions[1].payer, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(
        instructions[1].rail_destination,
        keypair(41).public_key().to_hex()
    );
    assert_eq!(
        deployment
            .challenges
            .get_effect_intent(&fee_intent_key)?
            .ok_or("the reconciled fee intent remains durable")?
            .state,
        FindingEffectIntentState::Confirmed
    );
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("the compensated filing remains durable")?
            .state,
        FindingChallengeState::IndeterminateClosed
    );

    assert!(coordinator
        .submit(&challenge, &raw, submission.dispute_lock_ref.expiry + 1)
        .is_err());
    assert_eq!(
        deployment.rail.charges().len(),
        2,
        "fee reconciliation and compensation are idempotent"
    );
    Ok(())
}

#[test]
fn finding_challenge_submission_rejects_noncanonical_finding_before_money_moves() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let (finding, _) = finding_artifact()?;
    let raw = serde_json::to_string_pretty(&finding)?;
    let mut challenge = buyer_challenge(&buyer)?;
    challenge.body.finding_artifact_sha256 = sha256_hex(raw.as_bytes());
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &buyer)?;

    let refused = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("noncanonical finding bytes must be refused before filing effects");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::FindingArtifact(_)
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_submission_rejects_a_finding_from_another_status_feed() -> TestResult {
    let deployment = deployment()?;
    let mut config = market_config();
    config.status_feed_operator_ref = "status-feed/other-venue".to_owned();
    config
        .status_feed_operator
        .feed_id
        .clone_from(&config.status_feed_operator_ref);
    config
        .status_feed_service_bond
        .feed_id
        .clone_from(&config.status_feed_operator_ref);
    let coordinator =
        deployment.coordinator_under(&config, FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;

    let refused = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a different configured status feed must reject the filing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::FindingBinding("status_feed_ref")
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_venue_audit_charges_nothing_and_locks_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = venue_audit_challenge()?;
    let (_, raw) = finding_artifact()?;

    let submitted = coordinator.submit(&challenge, &raw, NOW)?;
    assert!(submitted.dispute_fee_intent_key.is_none());
    assert!(submitted.dispute_bond_lock_id.is_none());
    assert!(
        deployment.rail.charges().is_empty(),
        "a venue audit charges no fee at all"
    );
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_submission_charges_the_dispute_fee_exactly_once() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;

    coordinator.submit(&challenge, &raw, NOW)?;
    coordinator.submit(&challenge, &raw, NOW + 5)?;
    assert_eq!(
        deployment.rail.charges().len(),
        2,
        "a replayed filing reconciles both settled funding instructions"
    );
    Ok(())
}

#[test]
fn finding_challenge_submission_rejects_a_mismatched_rail_observation() -> TestResult {
    let deployment = deployment()?;
    deployment.rail.misreport();
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a different rail observation cannot confirm the fee");
    assert!(matches!(error, ChallengeCoordinatorError::FeeRail(_)));
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .is_none());
    assert_eq!(deployment.rail.charges().len(), 1);
    Ok(())
}

#[test]
fn finding_challenge_submission_refuses_a_fee_aimed_at_the_audit_pool() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let mut challenge = buyer_challenge(&buyer)?;
    if let FindingChallengeAuthorization::BuyerSubmission(submission) =
        &mut challenge.body.authorization
    {
        submission
            .dispute_fee_terminal
            .beneficiary_pool_principal_id = AUDIT_POOL_PRINCIPAL.to_string();
        submission.dispute_fee_terminal.rail_destination = AUDIT_POOL_DESTINATION.to_string();
    }
    challenge.body.challenge_id = chio_finding::compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &buyer)?;
    let (_, raw) = finding_artifact()?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a dispute fee aimed at the audit pool must not settle");
    assert!(matches!(error, ChallengeCoordinatorError::DisputeFeePool));
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_filing_refused_on_its_fee_leaves_no_evaluable_challenge_row() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let mut challenge = buyer_challenge(&buyer)?;
    if let FindingChallengeAuthorization::BuyerSubmission(submission) =
        &mut challenge.body.authorization
    {
        // A bond window that already closed cannot be forfeited, so the
        // filing carries no collectable stake at all.
        submission.dispute_lock_ref.expiry = NOW - 1;
    }
    challenge.body.challenge_id = chio_finding::compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &buyer)?;
    let (_, raw) = finding_artifact()?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a filing whose bond window has closed must not be recorded");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeBondWindow
    ));
    assert!(
        deployment
            .challenges
            .get_challenge(&challenge.body.challenge_id)?
            .is_none(),
        "the evaluation pipeline is fenced on the row alone, so the row must not exist"
    );
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_filing_whose_fee_never_settled_is_not_evaluable() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let challenge_id = challenge.body.challenge_id.clone();
    let (_, raw) = finding_artifact()?;

    // The challenge and lock identity are recorded before the charge. A
    // rail that cannot move the fee leaves both durable, but no funded lock.
    deployment.rail.refuse();
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a filing whose dispute fee cannot be charged must fail");
    assert!(matches!(error, ChallengeCoordinatorError::FeeRail(_)));
    assert!(deployment
        .challenges
        .get_challenge(&challenge_id)?
        .is_some());
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .is_none());
    let reservation_exists = rusqlite::Connection::open(&deployment.database)?.query_row(
        "SELECT EXISTS(SELECT 1 FROM dispute_lock_reservations WHERE challenge_id = ?1)",
        [&challenge_id],
        |row| row.get::<_, bool>(0),
    )?;
    assert!(
        reservation_exists,
        "the dispute lock identity must be fenced before fee dispatch"
    );

    let error = coordinator
        .admit_evaluation(&challenge_id, NOW + 1)
        .expect_err("an unfunded filing must never be adjudicated");
    assert!(matches!(error, ChallengeCoordinatorError::FilingUnfunded));
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("challenge is durable")?
            .state,
        FindingChallengeState::Submitted,
        "a refused admission leaves the challenge exactly where it was"
    );

    // Replaying the filing against a rail that settles collects the fee
    // and locks the bond, and only then is the challenge evaluable.
    deployment.rail.accept();
    coordinator.submit(&challenge, &raw, NOW + 2)?;
    assert_eq!(deployment.rail.charges().len(), 2);
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 3)?,
        EvaluationAdmission::Admitted
    );
    Ok(())
}

#[test]
fn finding_challenge_an_expired_dispute_lock_is_not_evaluable() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let challenge_id = challenge.body.challenge_id.clone();
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&challenge, &raw, NOW)?;
    let expires_at = deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .ok_or("the submitted filing has a lock")?
        .expires_at;

    let refused = coordinator
        .admit_evaluation(&challenge_id, expires_at)
        .expect_err("an expired lock funds no evaluation");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::DisputeBondWindow
    ));
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("challenge remains durable")?
            .state,
        FindingChallengeState::Submitted
    );
    assert_eq!(deployment.rail.charges().len(), 2);
    Ok(())
}

#[test]
fn finding_challenge_evaluation_refuses_collateral_from_an_unadmitted_allocation() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;

    let unadmitted_allocation = consume_allocation(&deployment.market, LISTING_ID, &hex64('2'))?;
    assert_ne!(unadmitted_allocation, deployment.allocation_id);
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &unadmitted_allocation, 5_000);
    let evidence = case.evidence();
    let refused = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 1,
        ))
        .expect_err("collateral cannot choose the allocation the evaluator signs");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::CollateralAllocation
    ));
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&case.challenge.body.challenge_id)?
            .ok_or("challenge remains durable")?
            .state,
        FindingChallengeState::Submitted,
        "a mismatched allocation consumes no evaluation attempt"
    );
    Ok(())
}

#[test]
fn finding_challenge_evaluation_derives_live_collateral_from_the_signed_snapshot() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;

    let stake = usd(300);
    let required = usd(5_000);
    let mut collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    collateral.bond_snapshot.body.held_amount = 4_900;
    collateral.bond_snapshot.body.snapshot_id = String::new();
    collateral.bond_snapshot.body.snapshot_id =
        compute_snapshot_id(&collateral.bond_snapshot.body)?;
    let evidence = case.evidence();
    let refused = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 1,
        ))
        .expect_err("a caller cannot lower the live balance inside a signed snapshot");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::CollateralSnapshot(_)
    ));
    Ok(())
}

#[test]
fn finding_challenge_evaluation_refuses_exhausted_collateral_before_admission() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 0);
    let evidence = case.evidence();
    assert!(matches!(
        coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                NOW + 1,
            ))
            .expect_err("exhausted collateral cannot enter evaluation"),
        ChallengeCoordinatorError::NothingToImpair
    ));
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&case.challenge.body.challenge_id)?
            .ok_or("challenge remains durable")?
            .state,
        FindingChallengeState::Submitted
    );
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_failed_delivery_cannot_move_to_a_rebacked_admission() -> TestResult {
    let mut deployment = deployment()?;
    let challenged = challenged_finding()?;
    let mut case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    let rebacked = consume_allocation(&deployment.market, LISTING_ID, &hex64('e'))?;
    let backing_envelope_sha256 = hex64('f');
    let admission = signed_admission_with_backing(
        &rebacked,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &backing_envelope_sha256,
    )?;
    let admission_envelope_sha256 = signed_envelope_sha256(&admission)?;
    let filings = Arc::get_mut(&mut deployment.filings)
        .ok_or("the test has not shared its filing resolver yet")?;
    filings
        .admissions_by_digest
        .insert(admission_envelope_sha256.clone(), admission.clone());
    filings
        .venue_policies
        .insert(admission_envelope_sha256.clone(), market_config().venue);
    filings.admissions.insert(
        (
            admission.body.finding_id.clone(),
            admission.body.listing_id.clone(),
            backing_envelope_sha256.clone(),
        ),
        admission,
    );
    case.challenge.body.backing_envelope_sha256 = backing_envelope_sha256;
    case.challenge.body.venue_admission_envelope_sha256 = admission_envelope_sha256;
    case.challenge.body.challenge_id = compute_challenge_id(&case.challenge.body)?;
    case.challenge = SignedExportEnvelope::sign(case.challenge.body, &keypair(41))?;

    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;
    coordinator.admit_evaluation(&case.challenge.body.challenge_id, NOW + 1)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &rebacked, 5_000);
    let evidence = case.evidence();
    let refused = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))
        .expect_err("an old failed delivery cannot slash the listing's new backing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AdmissionBinding("failed_delivery_reservation")
    ));
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&case.challenge.body.challenge_id)?
            .ok_or("the challenge remains durable")?
            .state,
        FindingChallengeState::Evaluating
    );
    Ok(())
}

/// Refile the reference venue audit with one of its round bindings
/// rewritten, so a test can prove which binding the round has to answer.
fn venue_audit_challenge_with(
    rewrite: impl FnOnce(&mut FindingVenueAuditAuthorization),
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = venue_audit_challenge()?;
    if let FindingChallengeAuthorization::VenueAudit(audit) = &mut challenge.body.authorization {
        rewrite(audit);
    }
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, &keypair(35))?)
}

#[test]
fn finding_challenge_a_venue_audit_must_prove_the_round_drew_the_listing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;
    let unrelated_round = unrelated_audit_round()?;
    let unrelated_epoch = signed_envelope_sha256(&unrelated_round.epoch)?;
    let unrelated_authorization = unrelated_round.epoch.body.authorization_digest.clone();

    // The audit authority signs every one of these, so the signature is
    // never what is in question: what is in question is the draw.
    let cases: Vec<(SignedFindingChallenge, &'static str)> = vec![
        (
            venue_audit_challenge_with(|audit| audit.selection_digest = hex64('2'))?,
            "selection_digest",
        ),
        (
            venue_audit_challenge_with(|audit| audit.authorization_digest = hex64('3'))?,
            "authorization_digest",
        ),
        (
            // A round the venue published, but one whose eligible universe
            // never contained this listing.
            venue_audit_challenge_with(|audit| {
                audit.audit_epoch_envelope_sha256 = unrelated_epoch;
                audit.authorization_digest = unrelated_authorization;
            })?,
            "selection",
        ),
    ];
    for (challenge, binding) in &cases {
        let error = coordinator
            .submit(challenge, &raw, NOW)
            .expect_err("a bondless audit the round did not draw must not be admitted");
        match error {
            ChallengeCoordinatorError::AuditRoundBinding(refused) => {
                assert_eq!(refused, *binding);
            }
            other => return Err(format!("unexpected rejection for {binding}: {other}").into()),
        }
        assert!(deployment
            .challenges
            .get_challenge(&challenge.body.challenge_id)?
            .is_none());
    }

    // An epoch digest the venue never published resolves to no round at
    // all, which is a denial rather than an unchecked filing.
    let unpublished = venue_audit_challenge_with(|audit| {
        audit.audit_epoch_envelope_sha256 = hex64('1');
    })?;
    let error = coordinator
        .submit(&unpublished, &raw, NOW)
        .expect_err("an unresolvable round must not be admitted");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::UnknownAuditRound
    ));

    // The filing the published round did draw is admitted, and still
    // stakes nothing.
    let drawn = venue_audit_challenge()?;
    coordinator.submit(&drawn, &raw, NOW)?;
    assert!(deployment
        .challenges
        .get_challenge(&drawn.body.challenge_id)?
        .is_some());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_venue_audit_follows_its_authenticated_epoch() -> TestResult {
    let reference = published_audit_round()?;
    let wrong_schedule = reseal_audit_round(
        &reference,
        |epoch| epoch.fee_schedule_envelope_sha256 = digest("another fee schedule"),
        &keypair(1),
    )?;
    let unauthorized = reseal_audit_round(&reference, |_| {}, &keypair(2))?;
    let deployment = deployment_publishing_terms_and_rounds(
        &[],
        &[wrong_schedule.clone(), unauthorized.clone()],
    )?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    let wrong_schedule_challenge = venue_audit_challenge_for_round(&wrong_schedule)?;
    assert!(matches!(
        coordinator
            .submit(&wrong_schedule_challenge, &raw, NOW)
            .expect_err("an admission cannot be audited under another fee schedule"),
        ChallengeCoordinatorError::AuditRoundBinding("fee_schedule_envelope_sha256")
    ));

    let unauthorized_challenge = venue_audit_challenge_for_round(&unauthorized)?;
    assert!(matches!(
        coordinator
            .submit(&unauthorized_challenge, &raw, NOW)
            .expect_err("the audit authority cannot self-authorize a bondless round"),
        ChallengeCoordinatorError::AuditRoundBinding("authorization_signature")
    ));

    let mut predating = venue_audit_challenge()?.body;
    predating.filed_at = reference.epoch.body.committed_at;
    predating.challenge_id = compute_challenge_id(&predating)?;
    let predating = SignedExportEnvelope::sign(predating, &keypair(35))?;
    assert!(matches!(
        coordinator
            .submit(&predating, &raw, NOW)
            .expect_err("an audit filing cannot predate its round"),
        ChallengeCoordinatorError::AuditRoundBinding("filing_after_epoch")
    ));
    Ok(())
}

/// Refile the reference buyer challenge with one filing term rewritten, so
/// a test can prove which term the signed fee schedule fixes.
fn buyer_challenge_with(
    buyer: &Keypair,
    rewrite: impl FnOnce(&mut FindingBuyerSubmission),
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = buyer_challenge(buyer)?;
    if let FindingChallengeAuthorization::BuyerSubmission(submission) =
        &mut challenge.body.authorization
    {
        rewrite(submission);
    }
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, buyer)?)
}

/// The reference buyer filing, filed at a caller-chosen venue instant.
fn buyer_challenge_filed_at(
    buyer: &Keypair,
    filed_at: u64,
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = buyer_challenge(buyer)?;
    challenge.body.filed_at = filed_at;
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, buyer)?)
}

/// The reference buyer filing, bound to a caller-chosen terms envelope.
fn buyer_challenge_bound_to_terms(
    buyer: &Keypair,
    terms_envelope_sha256: &str,
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = buyer_challenge(buyer)?;
    challenge.body.terms_envelope_sha256 = terms_envelope_sha256.to_string();
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, buyer)?)
}

fn buyer_challenge_bound_to_admission_terms(
    buyer: &Keypair,
    terms: &SignedFindingMarketTerms,
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = buyer_challenge(buyer)?;
    challenge.body.terms_envelope_sha256 = signed_envelope_sha256(terms)?;
    challenge.body.venue_admission_envelope_sha256 = admission_digest_for_terms(terms)?;
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, buyer)?)
}

/// The reference venue audit, bound to a caller-chosen terms envelope.
fn venue_audit_challenge_bound_to_terms(
    terms_envelope_sha256: &str,
) -> Result<SignedFindingChallenge, AnyError> {
    let mut challenge = venue_audit_challenge()?;
    challenge.body.terms_envelope_sha256 = terms_envelope_sha256.to_string();
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    Ok(SignedExportEnvelope::sign(challenge.body, &keypair(35))?)
}

#[test]
fn finding_challenge_a_filing_binding_unadmitted_terms_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    let unadmitted = buyer_challenge_bound_to_terms(&keypair(41), &hex64('9'))?;
    let error = coordinator
        .submit(&unadmitted, &raw, NOW)
        .expect_err("terms the venue never admitted authorize no filing");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::UnknownMarketTerms
    ));
    assert!(deployment
        .challenges
        .get_challenge(&unadmitted.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_terms_cannot_admit_a_noncanonical_encoding() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (finding, canonical_raw) = finding_artifact()?;
    let reformatted_raw = serde_json::to_string_pretty(&finding)?;
    assert_ne!(
        sha256_hex(reformatted_raw.as_bytes()),
        sha256_hex(canonical_raw.as_bytes())
    );

    let mut challenge = buyer_challenge(&keypair(41))?;
    challenge.body.finding_artifact_sha256 = sha256_hex(reformatted_raw.as_bytes());
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &keypair(41))?;
    let error = coordinator
        .submit(&challenge, &reformatted_raw, NOW)
        .expect_err("signed terms cannot make a noncanonical finding admissible");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::FindingArtifact(_)
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_filing_past_the_signed_filing_window_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    // The bound terms are admitted and verify cleanly; what has lapsed is
    // the exposure horizon the seller signed for. The schedule window is
    // still open, so only the terms window can refuse this filing.
    let lapsed = signed_envelope_sha256(&lapsed_window_terms()?)?;
    let challenge = buyer_challenge_bound_to_terms(&keypair(41), &lapsed)?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a filing past the seller-signed window reaches no adjudication");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::FilingWindowClosed
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_terms_expiry_closes_initial_filing_admission() -> TestResult {
    let terms = early_expiry_terms()?;
    let deployment = deployment_publishing_terms(std::slice::from_ref(&terms))?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;
    let terms_digest = signed_envelope_sha256(&terms)?;
    let challenge = buyer_challenge_bound_to_terms(&keypair(41), &terms_digest)?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("terms expiry must close the same instant recovery considers expired");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::FilingWindowClosed
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_late_venue_audit_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    let lapsed = signed_envelope_sha256(&lapsed_window_terms()?)?;
    let challenge = venue_audit_challenge_bound_to_terms(&lapsed)?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("the filing window applies to venue audits too");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::FilingWindowClosed
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_an_accepted_audit_filing_replays_after_the_window() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;
    let challenge = venue_audit_challenge()?;

    let first = coordinator.submit(&challenge, &raw, NOW)?;
    assert_eq!(
        first.write,
        chio_store_sqlite::FindingChallengeWriteOutcome::Inserted
    );
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let after_deadline = terms.body.issued_at + terms.body.filing_window_secs + 1;
    let replay = coordinator.submit(&challenge, &raw, after_deadline)?;
    assert_eq!(
        replay.write,
        chio_store_sqlite::FindingChallengeWriteOutcome::ExistingSame,
        "a lost response can recover the exact durable audit filing"
    );
    Ok(())
}

#[test]
fn finding_challenge_a_backdated_filing_cannot_reopen_a_lapsed_window() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    let terms = lapsed_window_terms()?;
    let terms_digest = signed_envelope_sha256(&terms)?;
    let mut challenge = buyer_challenge_bound_to_terms(&keypair(41), &terms_digest)?;
    challenge.body.filed_at = terms.body.issued_at + terms.body.filing_window_secs;
    challenge.body.challenge_id = compute_challenge_id(&challenge.body)?;
    let challenge = SignedExportEnvelope::sign(challenge.body, &keypair(41))?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a caller-signed timestamp cannot override the venue clock");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::FilingWindowClosed
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_a_venue_audit_the_terms_disabled_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    // The published round did draw this listing, so the draw is not what
    // refuses the filing: the admitted terms keep the listing out of the
    // audit rotation entirely.
    let disabled = signed_envelope_sha256(&audit_disabled_terms()?)?;
    let challenge = venue_audit_challenge_bound_to_terms(&disabled)?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("an audit against audit-disabled terms is never admitted");
    assert!(matches!(error, ChallengeCoordinatorError::AuditIneligible));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_a_bond_outside_the_signed_limits_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (_, raw) = finding_artifact()?;

    // The bond equals the schedule's dispute requirement exactly, so the
    // schedule check passes; what refuses the filing is the seller-signed
    // ceiling sitting below that requirement. The two signed artifacts
    // disagree, and a filing admitted under either alone would ignore the
    // other's commitment.
    let narrow = signed_envelope_sha256(&narrow_bond_terms()?)?;
    let challenge = buyer_challenge_bound_to_terms(&keypair(41), &narrow)?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a bond outside the seller-signed limits stakes no filing");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeBondOutsideTermsLimits
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_filing_terms_must_be_the_ones_the_signed_schedule_prices() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let (_, raw) = finding_artifact()?;

    // A bond below the schedule's dispute requirement underprices the
    // filing; a bond above it would let a forfeiture take more than the
    // schedule authorizes. Neither is the stake the schedule set.
    for units in [DISPUTE_BOND_UNITS - 1, DISPUTE_BOND_UNITS + 1] {
        let challenge = buyer_challenge_with(&buyer, |submission| {
            submission.dispute_lock_ref.amount = usd(units);
        })?;
        let error = coordinator
            .submit(&challenge, &raw, NOW)
            .expect_err("a bond the schedule does not set must not be admitted");
        assert!(
            matches!(
                error,
                ChallengeCoordinatorError::DisputeTerms("dispute bond")
            ),
            "unexpected rejection for a {units} unit bond: {error}"
        );
    }

    // The fee is the schedule's dispute fee, not whatever the filing paid.
    let challenge = buyer_challenge_with(&buyer, |submission| {
        submission.dispute_fee_terminal.amount = usd(DISPUTE_FEE_UNITS - 1);
    })?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a fee the schedule does not set must not be admitted");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeTerms("dispute fee")
    ));

    // One filing is priced by one schedule, so the fee and the bond may
    // not name two.
    let challenge = buyer_challenge_with(&buyer, |submission| {
        submission.dispute_lock_ref.fee_schedule_envelope_sha256 = hex64('5');
    })?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("a filing priced by two schedules must not be admitted");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeTerms("fee_schedule_envelope_sha256")
    ));

    // Even when both monetary artifacts agree on a substitute schedule,
    // the admission-pinned schedule remains authoritative.
    let challenge = buyer_challenge_with(&buyer, |submission| {
        submission.dispute_fee_terminal.fee_schedule_envelope_sha256 = hex64('5');
        submission.dispute_lock_ref.fee_schedule_envelope_sha256 = hex64('5');
    })?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("an unresolvable schedule digest must not be admitted");
    assert!(
        matches!(
            &error,
            ChallengeCoordinatorError::DisputeTerms("fee_schedule_envelope_sha256")
        ),
        "{error:?}"
    );

    assert!(
        deployment.rail.charges().is_empty(),
        "no filing priced outside its schedule ever reached the rail"
    );
    Ok(())
}

#[test]
fn finding_challenge_a_filing_outside_the_schedule_window_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let buyer = keypair(41);
    let (_, raw) = finding_artifact()?;
    let schedule = published_fee_schedule()?.body;
    let expires_at = schedule
        .expires_at
        .ok_or("the published schedule carries an expiry")?;

    // The schedule prices filings only while it is live, so its own window
    // is the filing window, at both ends.
    let early = buyer_challenge_filed_at(&buyer, schedule.issued_at - 1)?;
    let error = coordinator
        .submit(&early, &raw, schedule.issued_at - 1)
        .expect_err("a filing ahead of its schedule prices nothing");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeTerms("filing window")
    ));

    let late = buyer_challenge_with(&buyer, |submission| {
        submission.dispute_lock_ref.expiry = expires_at + 1;
    })?;
    let error = coordinator
        .submit(&late, &raw, expires_at)
        .expect_err("a filing at or past the schedule expiry prices nothing");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeTerms("filing window")
    ));

    for challenge in [&early, &late] {
        assert!(deployment
            .challenges
            .get_challenge(&challenge.body.challenge_id)?
            .is_none());
    }
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

#[test]
fn finding_challenge_rejects_an_undersized_appeal_window_before_filing() -> TestResult {
    let terms = market_terms_shaped(|terms| terms.appeal_window_secs = 24 * 60 * 60 - 1)?;
    let deployment = deployment_publishing_terms(std::slice::from_ref(&terms))?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge_bound_to_admission_terms(&keypair(41), &terms)?;
    let (_, raw) = finding_artifact()?;

    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("an appeal window below the venue minimum admits no filing");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::DisputeTerms("appeal window")
    ));
    assert!(deployment
        .challenges
        .get_challenge(&challenge.body.challenge_id)?
        .is_none());
    assert!(deployment.rail.charges().is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// The three bond dispositions
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_upheld_verdict_returns_the_dispute_bond() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&challenge, &raw, NOW)?;

    close_upheld_challenge(&deployment, &challenge, NOW + 10)?;
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 11)?,
        Some(FindingDisputeLockDisposition::Returned)
    );
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .ok_or("lock is durable")?;
    assert_eq!(lock.state, FindingDisputeLockState::Returned);
    let instructions = deployment.rail.charges();
    assert_eq!(instructions.len(), 3);
    let returned = instructions
        .last()
        .ok_or("return instruction is recorded")?;
    assert_eq!(returned.payer, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(returned.pool_principal_id, CHALLENGE_POOL_PRINCIPAL);
    assert_eq!(returned.rail_destination, keypair(41).public_key().to_hex());
    assert_eq!(returned.amount_units, lock.amount_units);
    Ok(())
}

#[test]
fn finding_challenge_a_failed_refund_never_reports_the_bond_returned() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&challenge, &raw, NOW)?;
    close_upheld_challenge(&deployment, &challenge, NOW + 10)?;

    deployment.rail.refuse();
    assert!(matches!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 11),
        Err(ChallengeCoordinatorError::DisputeBondRail(_))
    ));
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge.body.challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Locked
    );

    deployment.rail.accept();
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 12)?,
        Some(FindingDisputeLockDisposition::Returned)
    );
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge.body.challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Returned
    );
    Ok(())
}

#[test]
fn finding_challenge_terminal_evaluation_recovers_its_signed_outcome() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(
        &deployment,
        "outcome-recovery",
        BUYER_ONE_DESTINATION,
        50,
        NOW,
    )?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();

    deployment.rail.refuse();
    assert!(matches!(
        coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                NOW + 2,
            ))
            .expect_err("the refused bond return interrupts the response"),
        ChallengeCoordinatorError::DisputeBondRail(_)
    ));
    let terminal = deployment
        .challenges
        .get_challenge(&case.challenge.body.challenge_id)?
        .ok_or("the verdict committed before the interrupted return")?;
    assert_eq!(terminal.state, FindingChallengeState::Upheld);
    let retained_digest = terminal
        .outcome_envelope_sha256
        .as_deref()
        .ok_or("the terminal verdict retains its outcome digest")?;
    let retained = deployment
        .challenges
        .get_outcome_envelope(retained_digest)?
        .ok_or("the signed outcome bytes commit atomically with the verdict")?;

    deployment.rail.accept();
    let retained_policy = deployment
        .filings
        .evaluator_policies
        .write()
        .map_err(|_| "evaluator-policy index lock is poisoned")?
        .remove(retained_digest)
        .ok_or("the signed outcome retained its evaluator policy")?;
    assert!(matches!(
        coordinator.evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        )),
        Err(ChallengeCoordinatorError::UnknownEvaluatorPolicy)
    ));
    deployment
        .filings
        .retain_evaluator_policy(retained_digest, &retained_policy)?;
    let recovered = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the terminal retry returns the retained signed outcome")?;
    assert_eq!(recovered.state, FindingChallengeState::Upheld);
    assert_eq!(recovered.outcome_envelope_sha256, retained_digest);
    assert_eq!(
        canonical_json_bytes(&recovered.outcome)?,
        retained.outcome_envelope_json
    );
    assert_eq!(
        recovered.bond_disposition,
        Some(FindingDisputeLockDisposition::Returned)
    );
    Ok(())
}

#[test]
fn finding_challenge_rejected_verdict_applies_the_predeclared_forfeit() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&challenge, &raw, NOW)?;

    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Rejected,
        &digest("rejected-outcome"),
        b"rejected-outcome",
        NOW + 10,
    )?;
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 11)?,
        Some(FindingDisputeLockDisposition::Forfeited)
    );
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge.body.challenge_id)?
        .ok_or("lock is durable")?;
    assert_eq!(lock.state, FindingDisputeLockState::Forfeited);
    Ok(())
}

#[test]
fn finding_challenge_indeterminate_never_forfeits_and_closes_by_returning_the_lock_once(
) -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenge = buyer_challenge(&keypair(41))?;
    let (_, raw) = finding_artifact()?;
    coordinator.submit(&challenge, &raw, NOW)?;
    let challenge_id = challenge.body.challenge_id.clone();
    let lock_expiry = deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .ok_or("lock is durable")?
        .expires_at;

    // An indeterminate verdict inside a signed retry window retains the
    // same lock: no forfeiture, no return, no second charge.
    let state = close_challenge(
        &deployment,
        &challenge_id,
        FindingChallengeVerdict::Indeterminate {
            retry_deadline: Some(lock_expiry),
        },
        &digest("indeterminate-outcome"),
        b"indeterminate-outcome",
        NOW + 10,
    )?;
    assert_eq!(state, FindingChallengeState::IndeterminateRetryable);
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge_id, NOW + 11)?,
        None
    );
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Locked,
        "an indeterminate result never forfeits an infrastructure failure"
    );

    // Past the window the store closes the challenge and the lock comes
    // back exactly once.
    let admission = coordinator.admit_evaluation(&challenge_id, lock_expiry)?;
    assert_eq!(
        admission,
        EvaluationAdmission::RetryWindowClosed {
            disposition: Some(FindingDisputeLockDisposition::Returned)
        }
    );
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("challenge is durable")?
            .state,
        FindingChallengeState::IndeterminateClosed
    );
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Returned
    );
    // Replaying the disposition returns the same terminal rather than
    // moving the bond a second time, and nothing further is charged.
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge_id, lock_expiry + 1)?,
        Some(FindingDisputeLockDisposition::Returned)
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "a retry reuses the fee, bond funding, and return identities"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The upheld transaction, the sealed snapshot, and the penalty branches
// ---------------------------------------------------------------------------

struct Upheld {
    deployment: Deployment,
    coordinator: FindingChallengeCoordinator,
    governance: Governance,
    outcome: chio_finding::SignedFindingChallengeOutcome,
    upheld: crate::trust_control::finding_challenge_coordinator::UpheldLiability,
    finding_id: String,
}

/// Sell twice, uphold one challenge against the listing, and seal the
/// claim accounting. Every later stage starts from here.
fn upheld_liability() -> Result<Upheld, AnyError> {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, raw) = finding_artifact()?;
    let first = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;
    let second = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 40, NOW + 1)?;

    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW + 2)?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id, 200, "USD")?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        NOW + 3,
    )?;
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge.body.challenge_id, NOW + 3)?,
        Some(FindingDisputeLockDisposition::Returned)
    );

    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &challenge,
        &outcome,
        &identity,
        2,
        &[first.purchase_key, second.purchase_key],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    Ok(Upheld {
        finding_id: finding.finding_id.clone(),
        deployment,
        coordinator,
        governance,
        outcome,
        upheld,
    })
}

#[test]
fn finding_challenge_uphold_blocks_sales_and_freezes_the_cutoff() -> TestResult {
    let case = upheld_liability()?;
    assert!(
        case.deployment.purchases.sales_blocked(LISTING_ID)?,
        "the upheld transaction blocks every new purchase slot"
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.purchase_cutoff_slot, Some(2));
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert_eq!(liability.appeal_window_opened_at, Some(NOW + 4));
    assert_eq!(liability.appeal_deadline, Some(NOW + 259_204));
    assert_eq!(
        liability.appeal_terms_envelope_sha256,
        Some(admitted_terms_digest()?)
    );
    assert_eq!(
        liability.liability_key,
        derive_liability_key(
            &derive_defect_key(&case.finding_id),
            VENUE_ID,
            &liability_identity(&case.finding_id, &case.deployment.allocation_id)
        )
    );
    Ok(())
}

/// One filed challenge closed upheld, with the evaluator-signed outcome
/// whose envelope the store recorded for it.
struct ReadyToUphold {
    finding: Finding,
    challenge_id: String,
    challenge: SignedFindingChallenge,
    outcome: SignedFindingChallengeOutcome,
}

fn ready_to_uphold(
    deployment: &Deployment,
    coordinator: &FindingChallengeCoordinator,
) -> Result<ReadyToUphold, AnyError> {
    ready_to_uphold_with_terms(deployment, coordinator, &market_terms(CLAIM_WINDOW_SECS)?)
}

fn ready_to_uphold_with_open_exposure(
    deployment: &Deployment,
    coordinator: &FindingChallengeCoordinator,
    open_per_sale_encumbrance_units: u64,
) -> Result<ReadyToUphold, AnyError> {
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let currency = terms
        .body
        .backing_requirement
        .base_finding_stake
        .currency
        .clone();
    ready_to_uphold_with_terms_and_penalty(
        deployment,
        coordinator,
        &terms,
        open_per_sale_encumbrance_units,
        &currency,
    )
}

/// One upheld challenge whose signed filing commits to caller-selected
/// admitted terms. Tests that bend a term must bend the filing that names
/// it as well, or they are exercising terms substitution rather than the
/// downstream invariant they set out to isolate.
fn ready_to_uphold_with_terms(
    deployment: &Deployment,
    coordinator: &FindingChallengeCoordinator,
    terms: &SignedFindingMarketTerms,
) -> Result<ReadyToUphold, AnyError> {
    let currency = &terms.body.backing_requirement.base_finding_stake.currency;
    ready_to_uphold_with_terms_and_penalty(deployment, coordinator, terms, 0, currency)
}

fn ready_to_uphold_with_terms_and_penalty(
    deployment: &Deployment,
    coordinator: &FindingChallengeCoordinator,
    terms: &SignedFindingMarketTerms,
    open_per_sale_encumbrance_units: u64,
    currency: &str,
) -> Result<ReadyToUphold, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge_bound_to_admission_terms(&keypair(41), terms)?;
    coordinator.submit(&challenge, &raw, NOW)?;
    let outcome = upheld_outcome(
        &challenge,
        &deployment.allocation_id,
        open_per_sale_encumbrance_units,
        currency,
    )?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    close_challenge(
        deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        NOW + 1,
    )?;
    Ok(ReadyToUphold {
        finding,
        challenge_id: challenge.body.challenge_id.clone(),
        challenge,
        outcome,
    })
}

#[test]
fn finding_challenge_uphold_rejects_a_different_authoritative_penalty_calculation() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW)?;
    let signed = upheld_outcome(&challenge, &deployment.allocation_id, 0, "USD")?;
    let mut body = signed.body;
    body.penalty_calculation = Some(chio_finding::FindingPenaltyCalculation {
        base_finding_stake_units: 301,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 301,
        listing_required_amount_units: 5_000,
        live_allocated_collateral_units: 5_000,
        penalty_amount: usd(301),
    });
    body.outcome_id = chio_finding::derive_outcome_id(&body)?;
    let outcome = SignedFindingChallengeOutcome::sign(body, &keypair(31))?;
    let outcome_json = canonical_json_bytes(&outcome)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        &outcome_json,
        NOW + 1,
    )?;

    let stake = usd(300);
    let required = usd(5_000);
    let refused = coordinator
        .uphold(
            &challenge.body.challenge_id,
            &challenge,
            &outcome,
            &liability_identity(&finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("a fresh collateral reading cannot replace the signed calculation");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::PenaltyCalculationMismatch
    ));
    assert_eq!(liability_heads(&deployment, &finding.finding_id)?, 0);
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_a_sanction_for_another_listing_opens_no_liability() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;
    let mut foreign_body = governance.sanction_case.body.clone();
    foreign_body.listing_id = "listing-elsewhere".to_string();
    let foreign_case = SignedExportEnvelope::sign(foreign_body, &governing_keypair())?;
    let stake = usd(300);
    let required = usd(5_000);

    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &foreign_case,
            NOW + 2,
        )
        .expect_err("a sanction for another listing cannot block this listing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::GovernanceBinding("listing_id")
    ));
    assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_a_governance_bundle_no_pinned_root_signed_mints_no_penalty() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;
    // A charter, case, listing, activation, and fee schedule all self
    // signed under one fresh key, which is what an attacker holds.
    let forged = keypair(99);
    let governance = governance_signed_by(&forged, &forged)?;

    let stake = usd(300);
    let required = usd(5_000);
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("a self-signed governance bundle authorizes no sanction");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::UnknownGovernanceCasePolicy
    ));
    assert_eq!(
        liability_heads(&deployment, &ready.finding.finding_id)?,
        0,
        "an unpinned governance bundle opens no liability"
    );
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_a_bad_signature_under_the_pinned_case_key_opens_no_liability() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;

    // Advertising the pinned key does not make a signature produced by
    // another key authentic. This opens no liability, while the earlier
    // upheld-verdict fence keeps the listing quarantined.
    let mut forged_case =
        SignedExportEnvelope::sign(governance.sanction_case.body.clone(), &keypair(99))?;
    forged_case.signer_key = governing_keypair().public_key();
    let stake = usd(300);
    let required = usd(5_000);
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &forged_case,
            NOW + 2,
        )
        .expect_err("a forged governance case opens no liability");
    assert!(
        matches!(
            &refused,
            ChallengeCoordinatorError::UnknownGovernanceCasePolicy
        ),
        "{refused:?}"
    );
    assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_exhausted_collateral_keeps_the_verdict_quarantine() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;

    let stake = usd(300);
    let required = usd(5_000);
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 0),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("a defect with nothing left to impair opens no liability");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::NothingToImpair
    ));
    assert_eq!(
        liability_heads(&deployment, &ready.finding.finding_id)?,
        0,
        "the penalty artifacts refuse a zero amount, so the head is never opened"
    );
    assert!(
        deployment.purchases.sales_blocked(LISTING_ID)?,
        "a trusted upheld verdict remains quarantined without minting a hold"
    );
    Ok(())
}

#[test]
fn finding_challenge_collateral_facts_for_another_allocation_uphold_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;

    // Every exposure figure behind the slash is read against the
    // allocation the facts name, so facts pointing at another allocation
    // would charge this vault for encumbrances it never opened.
    let stake = usd(300);
    let required = usd(5_000);
    let elsewhere = hex64('b');
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &elsewhere, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("collateral for another allocation upholds nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::CollateralAllocation
    ));
    assert_eq!(
        liability_heads(&deployment, &ready.finding.finding_id)?,
        0,
        "a mismatched allocation opens no liability"
    );
    assert!(
        deployment.purchases.sales_blocked(LISTING_ID)?,
        "the upheld-verdict quarantine survives rejected allocation facts"
    );
    Ok(())
}

#[test]
fn finding_challenge_collateral_facts_must_carry_the_signed_stake() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;

    // The slash math starts from the seller's signed precommitment. Facts
    // carrying any other stake would size the penalty from a number
    // nothing was signed over, in either direction.
    let inflated = usd(301);
    let required = usd(5_000);
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&inflated, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("a stake the terms never signed sizes no penalty");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::TermsBinding("base_finding_stake")
    ));
    assert_eq!(
        liability_heads(&deployment, &ready.finding.finding_id)?,
        0,
        "an unsigned stake opens no liability"
    );
    assert!(
        deployment.purchases.sales_blocked(LISTING_ID)?,
        "the upheld-verdict quarantine survives rejected stake facts"
    );

    // Matching the facts to a different, valid seller-signed stake is not
    // enough. The upheld challenge commits to one exact terms envelope,
    // so a caller cannot substitute another envelope after adjudication.
    let alternate_terms = market_terms_shaped(|terms| {
        terms.backing_requirement.base_finding_stake = inflated.clone();
    })?;
    let substituted = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            &alternate_terms,
            0,
            &[],
            &collateral_facts(&inflated, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("alternate signed terms cannot replace the challenged envelope");
    assert!(matches!(
        substituted,
        ChallengeCoordinatorError::TermsBinding("terms_envelope_sha256")
    ));
    assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_a_sale_from_the_previous_backing_claims_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;

    // One sale under the allocation the liability is charged to, then the
    // listing is rebacked and a second sale is charged to the new vault.
    let liable = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;
    let rebacked = consume_allocation(&deployment.market, LISTING_ID, &hex64('d'))?;
    let elsewhere = settle_purchase_with(
        &deployment,
        &rebacked,
        "beta",
        BUYER_TWO_DESTINATION,
        40,
        "USD",
        NOW + 1,
        PayoutStanding::Intact,
    )?;
    // The second buyer's destination is admitted under the liable
    // allocation as well, as it would be for a buyer this seller had
    // already paid, so the destination roster cannot be what refuses it.
    deployment.purchases.admit_payout_destination(
        &deployment.allocation_id,
        &buyer_destination(42),
        NOW + 1,
    )?;
    let ready = ready_to_uphold_with_open_exposure(&deployment, &coordinator, 100)?;

    let stake = usd(300);
    let required = usd(5_000);
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let identity = liability_identity(&ready.finding.finding_id, &deployment.allocation_id);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    assert!(matches!(
        coordinator.uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &identity,
            &terms,
            2,
            std::slice::from_ref(&liable.purchase_key),
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 1,
        ),
        Err(ChallengeCoordinatorError::ClaimWindowOpen)
    ));
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &identity,
            &terms,
            2,
            &[liable.purchase_key, elsewhere.purchase_key],
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("a sale charged to another vault is not this liability's harm");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ClaimSetMismatch
    ));
    assert!(
        coordinator
            .sealed_claim(&derive_liability_key(
                &derive_defect_key(&ready.finding.finding_id),
                VENUE_ID,
                &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            ))?
            .is_none(),
        "no accounting is sealed against collateral that never backed the sale"
    );
    Ok(())
}

#[test]
fn finding_challenge_purchase_and_venue_rotation_preserve_historical_standing() -> TestResult {
    let deployment = deployment()?;
    let sale = settle_purchase(
        &deployment,
        "before-rotation",
        BUYER_ONE_DESTINATION,
        60,
        NOW,
    )?;
    let mut rotated = market_config();
    rotated.purchase = authority_pin(48, "purchase-rotated");
    rotated.venue = authority_pin(49, "venue-rotated");
    let coordinator =
        deployment.coordinator_under(&rotated, FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold_with_open_exposure(&deployment, &coordinator, 100)?;
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let stake = usd(300);
    let required = usd(5_000);

    let upheld = uphold_across_claim_window(
        &coordinator,
        &terms,
        &ready.challenge,
        &ready.outcome,
        &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
        1,
        &[sale.purchase_key],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 2,
    )?;
    assert_eq!(upheld.sealed.total_realized_spend_units, 60);
    Ok(())
}

#[test]
fn finding_challenge_evaluation_uses_the_admission_historical_venue_policy() -> TestResult {
    let deployment = deployment()?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    let mut rotated = market_config();
    rotated.venue = authority_pin(49, "venue-rotated");
    let coordinator =
        deployment.coordinator_under(&rotated, FindingDisputeLockDisposition::Forfeited)?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 1,
        ))?
        .ok_or("the retained admission remains evaluable after venue rotation")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    Ok(())
}

#[test]
fn finding_challenge_harm_in_another_currency_seals_nothing() -> TestResult {
    // A verified harm carries bare units, so a bond denominated in
    // anything but the currency the sale realized would pay those units
    // out one for one against collateral that never priced them. The
    // terms sign the same denomination the collateral facts carry, so
    // what stands between this sale and the payout is the harm
    // verification alone.
    let stake = usd(300);
    let required = usd(5_000);
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let sale = settle_purchase_with(
        &deployment,
        &deployment.allocation_id,
        "alpha",
        BUYER_ONE_DESTINATION,
        60,
        "EUR",
        NOW,
        PayoutStanding::Intact,
    )?;
    let ready =
        ready_to_uphold_with_terms_and_penalty(&deployment, &coordinator, &terms, 100, "USD")?;
    let refused = uphold_across_claim_window(
        &coordinator,
        &terms,
        &ready.challenge,
        &ready.outcome,
        &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
        1,
        &[sale.purchase_key],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 2,
    )
    .expect_err("a spend attested in another currency is not a bond-currency harm");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::PurchaseCurrencyMismatch(_)
    ));
    assert!(
        coordinator
            .sealed_claim(&derive_liability_key(
                &derive_defect_key(&ready.finding.finding_id),
                VENUE_ID,
                &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
            ))?
            .is_none(),
        "no accounting is sealed from spends the bond never priced"
    );
    Ok(())
}

#[test]
fn finding_challenge_the_payout_never_seals_inside_the_claim_window() -> TestResult {
    /// A claim window of realistic length, so the refusals below are
    /// measured against a window an operator would want to skip rather
    /// than against a single tick. It stays inside the validity the
    /// governance fixture signs its sanction under.
    const CLAIM_WINDOW: u64 = 86_400;

    let signed = market_terms(CLAIM_WINDOW)?;
    let deployment = deployment_publishing_terms(std::slice::from_ref(&signed))?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let mut governance = governance()?;
    governance.admission = signed_admission(&deployment.allocation_id, &signed)?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let ready =
        ready_to_uphold_with_terms_and_penalty(&deployment, &coordinator, &signed, 100, "USD")?;

    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&ready.finding.finding_id, &deployment.allocation_id);
    let uphold_at = |terms: &SignedFindingMarketTerms, now: u64| {
        coordinator.uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &identity,
            terms,
            1,
            std::slice::from_ref(&sale.purchase_key),
            &collateral_facts_at(&stake, &required, &deployment.allocation_id, 5_000, now),
            &governance.context(),
            &governance.sanction_case,
            now,
        )
    };

    // Adjudication lands and the liability blocks the listing, but the
    // call that opens the window cannot also close it.
    let opened_at = NOW + 2;
    let opened = uphold_at(&signed, opened_at);
    assert!(
        matches!(&opened, Err(ChallengeCoordinatorError::ClaimWindowOpen)),
        "{opened:?}"
    );
    let head = deployment
        .challenges
        .get_liability(&derive_liability_key(
            &derive_defect_key(&ready.finding.finding_id),
            VENUE_ID,
            &identity,
        ))?
        .ok_or("the liability head is durable")?;
    assert_eq!(head.state, FindingLiabilityState::UpheldPendingClaims);
    assert_eq!(head.claim_deadline, Some(opened_at + CLAIM_WINDOW));
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);

    // Every instant short of the frozen deadline is still inside the
    // window a harmed buyer was promised.
    assert!(matches!(
        uphold_at(&signed, opened_at + CLAIM_WINDOW - 1),
        Err(ChallengeCoordinatorError::ClaimWindowOpen)
    ));
    // Nor can a shorter window signed after the fact bring the deadline
    // forward: the challenge admits only its exact terms envelope.
    assert!(matches!(
        uphold_at(&market_terms(1)?, opened_at + CLAIM_WINDOW - 1),
        Err(ChallengeCoordinatorError::TermsBinding(
            "terms_envelope_sha256"
        ))
    ));
    assert!(
        coordinator.sealed_claim(&head.liability_key)?.is_none(),
        "no accounting is sealed while the claim window is still open"
    );

    // Past the deadline the same call seals, and the frozen window is
    // what the sealed snapshot was waited on.
    let upheld = uphold_at(&signed, opened_at + CLAIM_WINDOW)?;
    assert_eq!(upheld.sealed.total_realized_spend_units, 50);
    assert!(coordinator.sealed_claim(&head.liability_key)?.is_some());
    Ok(())
}

#[test]
fn finding_challenge_sealed_snapshot_distribution_sums_exactly() -> TestResult {
    let case = upheld_liability()?;
    let sealed = &case.upheld.sealed;
    assert_eq!(sealed.total_realized_spend_units, 100);
    // Two retained sales keep 100 units of exposure encumbered each, so
    // the checked candidate is the 300-unit base stake plus 200 units of
    // open encumbrance, well inside the 5000-unit signed requirement.
    assert_eq!(sealed.distribution.slash, usd(500));
    // The buyer pool is capped by verified realized spend, never by the
    // slash, and every remaining unit goes to the community fund.
    assert_eq!(sealed.distribution.buyer_pool_units, 100);
    assert_eq!(sealed.distribution.community_fund_units, 400);
    let summed: u64 = sealed
        .distribution
        .entries
        .iter()
        .map(|entry| entry.amount_units)
        .sum();
    assert_eq!(summed, sealed.distribution.slash.units);
    assert!(
        sealed
            .distribution
            .entries
            .iter()
            .any(|entry| entry.destination == COMMUNITY_FUND_DESTINATION),
        "the remainder goes only to the admission-pinned community fund"
    );

    let stored = case
        .coordinator
        .sealed_claim(&case.upheld.liability_key)?
        .ok_or("the snapshot is sealed durably")?;
    assert_eq!(stored.0, sealed.snapshot_digest);
    assert_eq!(stored.1, sealed.allocation_digest);
    Ok(())
}

#[test]
fn finding_challenge_claim_snapshot_refuses_an_omitted_settled_purchase() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let first = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;
    let second = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 40, NOW + 1)?;
    let ready = ready_to_uphold_with_open_exposure(&deployment, &coordinator, 200)?;
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let identity = liability_identity(&ready.finding.finding_id, &deployment.allocation_id);
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let complete = vec![first.purchase_key.clone(), second.purchase_key];

    assert!(matches!(
        coordinator.uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &identity,
            &terms,
            2,
            &complete,
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        ),
        Err(ChallengeCoordinatorError::ClaimWindowOpen)
    ));
    let refused = coordinator
        .uphold(
            &ready.challenge_id,
            &ready.challenge,
            &ready.outcome,
            &identity,
            &terms,
            2,
            std::slice::from_ref(&first.purchase_key),
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 2 + CLAIM_WINDOW_SECS,
        )
        .expect_err("an omitted settled buyer must prevent sealing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ClaimSetMismatch
    ));
    assert!(coordinator
        .sealed_claim(&derive_liability_key(
            &derive_defect_key(&ready.finding.finding_id),
            VENUE_ID,
            &identity,
        ))?
        .is_none());
    Ok(())
}

#[test]
fn finding_challenge_pending_appeal_branch_holds_the_bond() -> TestResult {
    let case = upheld_liability()?;
    assert_eq!(
        case.upheld.hold.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondHeld
    );
    assert!(case.upheld.hold.evaluation.findings.is_empty());
    Ok(())
}

#[test]
fn finding_challenge_successful_appeal_reverses_before_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &case.governance.appeal_case,
            appeal_case_id: &case.governance.appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 20,
    )?;
    let AppealResolution::ReversedBeforeImpairment { reversal } = resolution else {
        return Err("a timely successful appeal reverses the hold".into());
    };
    assert_eq!(
        reversal.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::Reversed
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(
        liability.state,
        FindingLiabilityState::ReversedBeforeImpairment
    );
    assert!(!liability.publication_pending);
    Ok(())
}

#[test]
fn finding_challenge_appeal_accepts_a_retained_activation_across_governance_rotation() -> TestResult
{
    let case = upheld_liability()?;
    let rotated_key = keypair(52);
    let appeal_case = sample_case(
        &rotated_key,
        &case.governance.listing,
        &case.governance.activation,
        &case.governance.charter,
        GenericGovernanceCaseKind::Appeal,
        Some(case.upheld.sanction_case_id.clone()),
        Some(case.upheld.sanction_case_id.clone()),
    )?;
    let mut rotated_policy = authority_pin(52, "governance-rotated");
    rotated_policy.key_epoch = PINNED_KEY_EPOCH + 1;
    rotated_policy.valid_from = NOW;
    case.deployment
        .filings
        .retain_governance_policy(&appeal_case, rotated_policy.clone())?;
    let mut rotated_config = market_config();
    rotated_config.governance_root = rotated_policy;
    let coordinator = case
        .deployment
        .coordinator_under(&rotated_config, FindingDisputeLockDisposition::Forfeited)?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);

    let resolution = coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &appeal_case,
            appeal_case_id: &appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 20,
    )?;
    assert!(matches!(
        resolution,
        AppealResolution::ReversedBeforeImpairment { .. }
    ));
    Ok(())
}

#[test]
fn finding_challenge_appeal_accepts_a_prior_hold_across_penalty_rotation() -> TestResult {
    let case = upheld_liability()?;
    let mut rotated_config = market_config();
    rotated_config.market_penalty = authority_pin(50, "market-penalty-rotated");
    let coordinator = FindingChallengeCoordinator::new_with_status_commit_clock(
        case.deployment.challenges.clone(),
        case.deployment.purchases.clone(),
        case.deployment.status.clone(),
        &rotated_config,
        keypair(31),
        keypair(32),
        keypair(50),
        Arc::new(TestAuthorityStatusResolver::live()),
        case.deployment.rail.clone(),
        case.deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
        Arc::new(FixtureStatusCommitClock),
    )?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);

    let resolution = coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &case.governance.appeal_case,
            appeal_case_id: &case.governance.appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 20,
    )?;
    assert!(matches!(
        resolution,
        AppealResolution::ReversedBeforeImpairment { .. }
    ));
    Ok(())
}

#[test]
fn finding_challenge_an_appeal_opened_after_the_durable_deadline_reverses_nothing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let deadline = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability is durable")?
        .appeal_deadline
        .ok_or("appeal deadline is frozen")?;
    let late = sample_case_at(
        &governing_keypair(),
        &case.governance.listing,
        &case.governance.activation,
        &case.governance.charter,
        GenericGovernanceCaseKind::Appeal,
        Some(case.upheld.sanction_case_id.clone()),
        Some(case.upheld.sanction_case_id.clone()),
        deadline + 1,
    )?;

    let refused = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            Some(&case.upheld.sealed),
            &case.governance.context(),
            &AppealDisposition::Successful {
                appeal_case: &late,
                appeal_case_id: &late.body.case_id,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            deadline + 2,
        )
        .expect_err("a late signed filing cannot reverse the sanction");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));
    let head = case
        .deployment
        .challenges
        .resolve_case_head(&case.upheld.liability_key)?
        .ok_or("sanction remains the case head")?;
    assert_eq!(head.case_id, case.upheld.sanction_case_id);
    assert_eq!(
        case.deployment
            .challenges
            .get_liability(&case.upheld.liability_key)?
            .ok_or("liability remains durable")?
            .state,
        FindingLiabilityState::PendingAppeal
    );
    Ok(())
}

/// Close the appeal window with no reversal, at the given clock.
fn resolve_final(
    case: &Upheld,
    identity: &FindingLiabilityIdentity<'_>,
    outcome: &SignedFindingChallengeOutcome,
    now: u64,
) -> Result<AppealResolution, ChallengeCoordinatorError> {
    case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        outcome,
        identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Final {
            sanction_case: &case.governance.sanction_case,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        now,
    )
}

// ---------------------------------------------------------------------------
// Finalization against the settlement choke point
// ---------------------------------------------------------------------------

fn anchor_proof() -> Result<AnchorInclusionProof, AnyError> {
    Ok(serde_json::from_str(include_str!(
        "../../../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))?)
}

fn settlement_config() -> Result<SettlementChainConfig, AnyError> {
    let proof = anchor_proof()?;
    let anchor = proof
        .chain_anchor
        .as_ref()
        .ok_or("anchor inclusion proof example carries a chain anchor")?;
    let rpc_url = "http://127.0.0.1:8545".to_string();
    let policy = SettlementPolicyConfig::default();
    Ok(SettlementChainConfig {
        chain_id: anchor.chain_id.clone(),
        network_name: "Devnet".to_string(),
        egress_contract: settlement_devnet_rpc_egress_contract(&rpc_url)?,
        rpc_url,
        escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
        bond_vault_contract: BOND_VAULT_CONTRACT.to_string(),
        identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
        root_registry_contract: anchor.contract_address.clone(),
        operator_address: anchor.operator_address.clone(),
        settlement_token_symbol: "mUSDC".to_string(),
        settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
        oracle: SettlementOracleConfig::default(),
        evidence_substrate: SettlementEvidenceConfig::default(),
        policy,
    })
}

fn evm_vault_snapshot() -> EvmBondSnapshot {
    evm_vault_snapshot_for(&chain_hash(0x44))
}

/// The live contract read for one vault, as the operator would take it
/// for whatever vault the instruction in hand names.
fn evm_vault_snapshot_for(vault_id: &str) -> EvmBondSnapshot {
    EvmBondSnapshot {
        vault_id: vault_id.to_string(),
        principal_address: "0x1000000000000000000000000000000000000005".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        expires_at: 1_800_000_000,
        observed_at: 1_799_999_000,
        locked_minor_units: 5_000_000,
        reserve_requirement_minor_units: 1_000_000,
        reserve_requirement_ratio_bps: 2_000,
        slashed_minor_units: 0,
        released: false,
        expired: false,
    }
}

/// The chain and identity state the signed snapshot named, as an operator
/// would re-read it when nothing has moved.
fn qualified_observation() -> FindingBondObservationRecheck {
    FindingBondObservationRecheck {
        block_hash: Some(chain_hash(0xbb)),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        operator_active: true,
    }
}

/// An observation source that replays a fixed script, one entry per read.
/// Two reads happen on a settling finalization, so a script can put the
/// chain in one state before the call is prepared and another after its
/// receipt finalized.
struct ScriptedObservations {
    reads: Mutex<std::collections::VecDeque<FindingBondObservationRecheck>>,
    trailing: FindingBondObservationRecheck,
}

impl ScriptedObservations {
    /// Every read reports the state the snapshot named.
    fn qualified() -> Self {
        Self {
            reads: Mutex::new(std::collections::VecDeque::new()),
            trailing: qualified_observation(),
        }
    }

    /// The named reads happen first; every read after them reports the
    /// state the snapshot named.
    fn then_qualified(reads: Vec<FindingBondObservationRecheck>) -> Self {
        Self {
            reads: Mutex::new(reads.into()),
            trailing: qualified_observation(),
        }
    }
}

impl chio_settle::FindingBondObservationSource for ScriptedObservations {
    fn observe(
        &self,
        _verified: &chio_settle::VerifiedFindingEnforcement,
    ) -> Result<FindingBondObservationRecheck, chio_settle::SettlementError> {
        let scripted = match self.reads.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(_) => {
                return Err(chio_settle::SettlementError::InvalidInput(
                    "observation script is poisoned".to_string(),
                ))
            }
        };
        Ok(scripted.unwrap_or_else(|| self.trailing.clone()))
    }
}

/// A publisher that reports the vault burned this evidence hash without
/// producing the transaction that did it. That is exactly the ambiguity
/// the choke point must refuse to read as a slash.
struct AmbiguousPublisher;

impl FindingImpairmentPublisher for AmbiguousPublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        })
    }

    fn observe(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        })
    }
}

/// A publisher that broadcasts, stores the raw transaction, and only
/// observes a receipt for it on a later attempt. That is the ordinary
/// shape of a real one: the transaction is not mined when publish
/// returns.
struct MiningPublisher {
    tx_hash: String,
    attempts: Mutex<u32>,
}

impl MiningPublisher {
    fn new() -> Self {
        Self {
            tx_hash: chain_hash(0x77),
            attempts: Mutex::new(0),
        }
    }

    fn attempts(&self) -> u32 {
        self.attempts.lock().map(|guard| *guard).unwrap_or_default()
    }

    fn observation(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
        mined: bool,
    ) -> FindingImpairmentAttempt {
        FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: self.tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: mined.then(|| EvmTransactionReceipt {
                    tx_hash: self.tx_hash.clone(),
                    block_number: 21_000_100,
                    block_hash: chain_hash(0xbc),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: mined.then_some(SettlementFinalityStatus::Finalized),
            },
        }
    }
}

impl FindingImpairmentPublisher for MiningPublisher {
    fn publish(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let attempt = match self.attempts.lock() {
            Ok(mut guard) => {
                *guard = guard.saturating_add(1);
                *guard
            }
            Err(_) => return Err(FindingImpairmentPublishError::Transient("poisoned".into())),
        };
        let mined = attempt > 1;
        Ok(self.observation(intent, call, mined))
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(self.observation(intent, call, self.attempts() > 1))
    }
}

/// A publisher that cannot reach the chain and says so. It reports no
/// attempt at all, which is the one shape that leaves the coordinator
/// unable to tell whether anything was broadcast.
struct UnreachableChainPublisher;

impl FindingImpairmentPublisher for UnreachableChainPublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Transient(
            "no route to the chain".to_string(),
        ))
    }

    fn observe(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Transient(
            "no route to the chain".to_string(),
        ))
    }
}

/// A publisher that must never be asked to move anything. A resumed
/// finalization has already impaired the vault, so any dispatch on that
/// path would be a second one.
struct UnreachablePublisher;

impl FindingImpairmentPublisher for UnreachablePublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
        _call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Err(FindingImpairmentPublishError::Permanent(
            "a confirmed impairment must never be dispatched again".to_string(),
        ))
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let tx_hash = chain_hash(0x77);
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: Some(EvmTransactionReceipt {
                    tx_hash,
                    block_number: 21_000_100,
                    block_hash: chain_hash(0xbc),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: Some(SettlementFinalityStatus::Finalized),
            },
        })
    }
}

/// A publisher whose first receipt is finalized but whose immediate
/// re-observation no longer finds that receipt on the canonical chain.
struct ReorgedReceiptPublisher;

impl FindingImpairmentPublisher for ReorgedReceiptPublisher {
    fn publish(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let tx_hash = chain_hash(0x78);
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: tx_hash.clone(),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: Some(EvmTransactionReceipt {
                    tx_hash,
                    block_number: 21_000_101,
                    block_hash: chain_hash(0xbd),
                    status: true,
                    from_address: call.from_address.clone(),
                    to_address: call.to_address.clone(),
                    gas_used: 210_000,
                    observed_at: OBSERVED_AT,
                    logs: Vec::new(),
                }),
                finality: Some(SettlementFinalityStatus::Finalized),
            },
        })
    }

    fn observe(
        &self,
        intent: &chio_settle::FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
                chain_id: intent.chain_id.clone(),
                tx_hash: chain_hash(0x78),
                to_address: call.to_address.clone(),
                input_data: Some(call.data.clone()),
                receipt: None,
                finality: None,
            },
        })
    }
}

include!("finding_challenge_enforcement_e2e_tests/finalizing_liability_support.rs");

pub(super) fn run_enforced_challenge_status_retraction() -> TestResult {
    let case = finalizing_liability()?;
    let publisher = MiningPublisher::new();

    // The first attempt reports exactly what a durable publisher holds
    // before its transaction is mined.
    let first = case.finalize(&publisher, SETTLEMENT_NOW)?;
    assert_eq!(
        first,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::ReceiptMissing
        })
    );
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Failed,
        "a receipt that has not arrived leaves the impairment dispatchable"
    );
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(!parked.quarantined);

    // The same transaction then mines and finalizes. This only makes the
    // retraction outbox eligible: the liability remains publication-pending
    // until a signed status epoch includes the exact intent.
    let second = case.finalize(&publisher, SETTLEMENT_NOW + 60)?;
    let FindingFinalization::Reconciled(FindingImpairmentOutcome::Confirmed { reconciliation }) =
        second
    else {
        return Err("finalized retry did not reconcile the impairment".into());
    };
    assert_eq!(reconciliation.tx_hash(), chain_hash(0x77));
    let retained = case
        .deployment
        .challenges
        .get_seller_impairment_reconciliation(&case.intent_key)?
        .ok_or("confirmed impairment retains its reconciliation")?;
    assert_eq!(retained.tx_hash, chain_hash(0x77));
    assert_eq!(
        retained.reconciliation_sha256,
        reconciliation.reconciliation_sha256()
    );
    assert_eq!(publisher.attempts(), 2);
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Confirmed);
    let pending = case.head()?;
    assert_eq!(pending.state, FindingLiabilityState::Finalizing);
    assert!(pending.publication_pending);

    case.publish_status(SETTLEMENT_NOW + 61)?;
    let resumed = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 62)?;
    assert_eq!(resumed, FindingFinalization::AlreadyConfirmed);
    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    Ok(())
}

// ---------------------------------------------------------------------------
// The three class branches, each from real evidence to an enforced sanction
// ---------------------------------------------------------------------------

pub(super) fn run_finding_challenge_digest_mismatch() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();

    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 1)?,
        EvaluationAdmission::Admitted
    );

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("an authenticated seller-origin mismatch is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(
        evaluated.outcome.body.verdict,
        chio_finding::FindingChallengeVerdict::Upheld
    );
    assert_eq!(
        evaluated.outcome.body.backing_allocation_id, deployment.allocation_id,
        "the evaluator signs the allocation retained in the venue admission"
    );
    assert_eq!(
        evaluated.outcome.body.reason,
        "seller_origin_digest_mismatch"
    );
    assert_eq!(
        evaluated.bond_disposition,
        Some(FindingDisputeLockDisposition::Returned),
        "an upheld challenge gets its dispute bond back"
    );
    let FindingChallengeFacet::DigestMismatch(facet) = &evaluated.outcome.body.facet else {
        return Err("a digest-mismatch challenge carries a digest-mismatch facet".into());
    };
    assert_eq!(facet.realized_spend_units, 0);
    assert_ne!(
        facet.committed_payload_sha256,
        facet.delivered_output_sha256
    );
    let calculation = evaluated
        .outcome
        .body
        .penalty_calculation
        .as_ref()
        .ok_or("an upheld outcome carries its checked calculation")?;
    assert_eq!(calculation.penalty_amount, usd(300));

    // The denied reveal closed its reserved slot without a purchase record,
    // so the cutoff includes that denial but the authoritative claim set is
    // empty.
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        1,
        &[],
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    let liability = deployment
        .challenges
        .get_liability(&upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.purchase_cutoff_slot, Some(1));
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert_eq!(
        upheld.hold.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondHeld
    );

    // A qualified digest mismatch has zero realized spend, so it cannot
    // manufacture a buyer payout at all.
    assert_eq!(upheld.sealed.total_realized_spend_units, 0);
    assert_eq!(upheld.sealed.distribution.buyer_pool_units, 0);
    assert_eq!(upheld.sealed.distribution.slash, usd(300));
    assert_eq!(upheld.sealed.distribution.community_fund_units, 300);
    assert_eq!(
        allocation_by_destination(&upheld.sealed.distribution),
        std::collections::BTreeMap::from([(COMMUNITY_FUND_DESTINATION.to_string(), 300)])
    );

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    assert_eq!(authorized.enforcement.body.amount, usd(300));
    assert_eq!(authorized.slash.penalty.body.penalty_amount, usd(300));
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    assert_eq!(
        authorized.enforcement.body.outcome_id,
        evaluated.outcome.body.outcome_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The evaluator key's own lifecycle
// ---------------------------------------------------------------------------

#[path = "finding_challenge_lifecycle_tests.rs"]
mod finding_challenge_lifecycle_tests;

// ---------------------------------------------------------------------------
// Denials that look like fraud and are not
// ---------------------------------------------------------------------------

/// Adjudicate one digest-mismatch denial and prove it reached the seller
/// sanction gate nowhere: no liability, no penalty, no block.
fn assert_denial_cannot_sanction(shape: &DenyShape, expected_reason: &str) -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(&deployment, &challenged, shape, Filing::Buyer)?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 1,
        ))?
        .ok_or("a resolvable denial is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Rejected);
    assert_eq!(
        evaluated.outcome.body.verdict,
        chio_finding::FindingChallengeVerdict::Rejected
    );
    assert_eq!(evaluated.outcome.body.reason, expected_reason);
    assert!(
        evaluated.outcome.body.penalty_calculation.is_none(),
        "nothing but an upheld verdict carries a checked penalty amount"
    );

    // The penalty lane refuses the outcome outright, so no liability opens
    // and no penalty is minted against the seller's bond.
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let refused = coordinator
        .uphold(
            &case.challenge.body.challenge_id,
            &case.challenge,
            &evaluated.outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 2,
        )
        .expect_err("only an upheld outcome may enter the penalty lane");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::VerdictNotUpheld
    ));
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        0
    );
    // Nothing was fenced for dispatch against the seller's vault either,
    // so the bond is where the sale path left it.
    let liability_key = derive_liability_key(
        &derive_defect_key(&challenged.finding.finding_id),
        VENUE_ID,
        &identity,
    );
    assert!(deployment
        .challenges
        .list_effect_intents(&liability_key)?
        .is_empty());
    assert!(
        !deployment.purchases.sales_blocked(LISTING_ID)?,
        "a rejected challenge blocks no sale"
    );
    assert_eq!(
        evaluated.bond_disposition,
        Some(FindingDisputeLockDisposition::Forfeited),
        "a rejected challenge follows the predeclared failed-challenge rule"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-class pairings and the carried recipe preimage
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Payout derivation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A clean venue audit
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Indeterminate results, the bounded retry, and the bond
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The nested replay mapping through the coordinator
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// One defect, one slash, across a duplicate filing and a restart
// ---------------------------------------------------------------------------
