//! End-to-end coverage for the finding challenge and audit lane: a buyer
//! files a challenge and pays for it, a venue audit files one and pays
//! nothing, a verdict disposes the bond it earned, an upheld verdict
//! blocks the listing and freezes the purchase cutoff, the sealed
//! accounting sums exactly, the three penalty branches hold, reverse, and
//! slash, an unresolved appeal quarantines instead of impairing, and an
//! ambiguous impairment leaves the liability parked with purchases still
//! denied.
//!
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
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
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
    audit_seed_witness_signing_bytes, buyer_refund_destination, compute_admission_id,
    compute_allocation_id, compute_audit_epoch_id, compute_challenge_id, compute_enforcement_id,
    compute_failed_delivery_id, compute_finding_id, compute_profile_id, compute_snapshot_id,
    compute_terms_id, derive_audit_seed_commitment, derive_purchase_key, sign_finding,
    signed_envelope_sha256, Finding, FindingAdmission, FindingAffectedDelivery, FindingAuditEpoch,
    FindingAuthorityKeyPolicy, FindingBackingRequirement, FindingBbsIssuerPolicy,
    FindingBondBacking, FindingBondClass, FindingBuyerSubmission, FindingChallenge,
    FindingChallengeAuthorization, FindingChallengeBondLimit, FindingChallengeEnforcement,
    FindingChallengeEvidence, FindingChallengeFacet, FindingChallengeStanding,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingCheckpointRef,
    FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor, FindingDisputeBondClass,
    FindingDisputeFeeEvent, FindingDisputeFeeTerminal, FindingDisputeLockRef,
    FindingEffectIntentBinding, FindingEnforcementDestination, FindingEvidenceClass,
    FindingEvidenceInvalidity, FindingFacetKind, FindingFailedDelivery, FindingFeeEvent,
    FindingFeeTerminalBinding, FindingFinalizedBondSnapshot, FindingGuaranteeClass,
    FindingHoldReleaseTerminal, FindingMarketTerms, FindingObservedFinality, FindingOutcomeClass,
    FindingPoolBinding, FindingPredicate, FindingPurchaseRecord, FindingReceiptRef,
    FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayObservation, FindingReplayPredicateResult,
    FindingReplayRecipeInput, FindingReplayReproduction, FindingReplayTerminalResult,
    FindingResourceCaps, FindingVaultReference, FindingVenueAuditAuthorization,
    SignedFindingAdmission, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingChallengeOutcome, SignedFindingChallengeVerifierProfile,
    SignedFindingFailedDelivery, SignedFindingFinalizedBondSnapshot, SignedFindingMarketTerms,
    SignedFindingPurchaseRecord, FINDING_ADMISSION_SCHEMA_V1, FINDING_AUDIT_EPOCH_SCHEMA_V1,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_SCHEMA_V1, FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1,
    FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
    FINDING_MARKET_TERMS_SCHEMA_V1, FINDING_PURCHASE_RECORD_SCHEMA_V1,
    FINDING_REPLAY_OBSERVATION_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
    MAX_PUBLISHED_RATE_BPS,
};
use chio_finding_challenge::{
    FindingChallengeClassEvidence, FindingDigestMismatchEvidence, FindingEvidenceInvalidEvidence,
    FindingReplayContradictionEvidence, FindingResolvedReproduction,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_body_sha256,
    checkpoint_log_id, CheckpointTransparencySummary, KernelCheckpoint,
};
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
use chio_settle::{
    settlement_devnet_rpc_egress_contract, EvmBondSnapshot, EvmTransactionReceipt,
    FindingBondObservationRecheck, FindingImpairmentAttempt, FindingImpairmentOutcome,
    FindingImpairmentPublishError, FindingImpairmentPublisher, FindingImpairmentQuarantine,
    FindingVaultRejection, PreparedEvmCall, SettlementChainConfig, SettlementEvidenceConfig,
    SettlementFinalityStatus, SettlementOracleConfig, SettlementPolicyConfig,
    StoredImpairmentTransaction,
};
use chio_store_sqlite::finding_market_store::{FindingRecordInput, SqliteFindingMarketStore};
use chio_store_sqlite::{
    derive_dispute_bond_funding_intent_key, dispute_bond_funding_intent_digest,
    FindingChallengeState, FindingChallengeVerdict, FindingDisputeLockDisposition,
    FindingDisputeLockInput, FindingDisputeLockState, FindingEffectIntentKind,
    FindingEffectIntentState, FindingLiabilityState, FindingPurchaseDeliveryInput,
    FindingPurchaseDenyInput, FindingPurchaseReservationInput, SqliteAuthorityStore,
    SqliteFindingChallengeStore, SqliteFindingPurchaseStore,
};

use crate::trust_control::finding_challenge_coordinator::{
    derive_anchor_evidence_intent_key, derive_defect_key, derive_liability_key,
    root_intent_commitment, AppealDisposition, AppealResolution, AuthorizedImpairment,
    ChallengeCoordinatorError, ChallengeEvaluationRequest, ChallengeSubmissionOutcome,
    EvaluationAdmission, FindingAuditRound, FindingAuthorityStatus, FindingAuthorityStatusResolver,
    FindingChallengeCoordinator, FindingCollateralFacts, FindingFilingResolver,
    FindingFinalization, FindingLiabilityIdentity, FindingPenaltyGovernance, UpheldLiability,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use crate::trust_control::{
    FederationAdmissionRateLimiter, FindingAuthorityPin, FindingChallengeSubmissionExecutor,
    FindingChallengeSubmissionRequest, FindingChallengeSubmissionResponse,
    FindingChallengeSubmissionRuntime, FindingChallengeSubmissionWrite, FindingMarketConfig,
    FindingPoolPin, TrustServiceConfig, TrustServiceState,
};
use crate::trust_control::{FindingRailInstruction, FindingRailObservation, FindingRailObserver};
use chio_test_support::plain::TestResultOk;
use tower::ServiceExt;

use super::build_router;

type AnyError = Box<dyn std::error::Error>;
type TestResult = Result<(), AnyError>;

const VENUE_ID: &str = "venue-challenge";
const LISTING_ID: &str = "listing-42";
const NAMESPACE: &str = "https://registry.chio.example";
const OPERATOR_ID: &str = "https://registry.chio.example";
const AUDIT_POOL_PRINCIPAL: &str = "pool:audit";
const AUDIT_POOL_DESTINATION: &str = "rail:venue-ledger:audit-pool";
const CHALLENGE_POOL_PRINCIPAL: &str = "pool:challenge-admin";
const CHALLENGE_POOL_DESTINATION: &str = "rail:venue-ledger:challenge-admin";
const COMMUNITY_FUND_RAIL: &str = "rail:venue-ledger:community-fund";
const BUYER_ONE_DESTINATION: &str = "rail:venue-ledger:buyer-one";
const BUYER_TWO_DESTINATION: &str = "rail:venue-ledger:buyer-two";
const CHALLENGER_BOUNTY_DESTINATION: &str = "rail:venue-ledger:challenger-bounty";
const NOW: u64 = 1_750_000_000;

fn buyer_destination(seed: u8) -> String {
    buyer_refund_destination(&keypair(seed).public_key())
}

/// Seller-signed claim window the shared terms carry. The lane's clock in
/// these tests is second-granular, so the shortest window that still has
/// two distinct instants keeps the window-opening call and the sealing
/// call one tick apart.
const CLAIM_WINDOW_SECS: u64 = 1;
// The seller filing horizon is longer than the buyer's signed dispute
// lock, so the lock expiry is the policy-derived retry cap in this fixture.
const RETRY_POLICY_DEADLINE: u64 = NOW + 86_400;
const REGISTERED_EXPOSURE_CAP: u64 = 450;

// The epoch every pinned role is issued under and where its revocation
// status is published. An adjudication has to hold against both.
const PINNED_KEY_EPOCH: u64 = 1;
const REVOCATION_STATUS_REF: &str = "revocations/finding-market";

// What the published fee schedule charges to file a challenge and what it
// requires the filer to stake. A filing that names anything else is not
// priced by the schedule it binds.
const DISPUTE_FEE_UNITS: u64 = 25;
const DISPUTE_BOND_UNITS: u64 = 40;

// The shared uphold fixture opens its seller-signed three-day appeal
// window at NOW + 4. Finality is reachable only after that frozen value.
const APPEAL_FINAL_AT: u64 = NOW + 400_000;
/// The sanction case `finalizing_liability` records as the live head.
const FIXTURE_SANCTION_CASE_ID: &str = "case-sanction-fixture-01";

// Key-role validity window every pinned authority in the governance
// profile is issued under, and the publication instant the revocation
// comparisons are made against.
const KEY_VALID_FROM: u64 = 1_600_000_000;
const KEY_VALID_UNTIL: u64 = 1_900_000_000;
const PUBLISHED_AT: u64 = 1_700_000_000;

// Kernel log coordinates. Every checkpoint below is a real signed
// checkpoint over real canonical receipt bytes, so the sequence numbers
// have to line up with the batch ranges the membership verifier rechecks.
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
        valid_until: u64::MAX,
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
            signer_seed: 36,
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
}

fn market_config() -> FindingMarketConfig {
    FindingMarketConfig {
        venue_id: VENUE_ID.to_string(),
        venue: authority_pin(6, "venue"),
        listing: authority_pin(24, "listing"),
        governance_root: authority_pin(1, "governance"),
        authority_status: authority_pin(36, "authority-status"),
        verifier_report: authority_pin(15, "verifier-report"),
        collateral: authority_pin(4, "collateral"),
        purchase: authority_pin(16, "purchase"),
        failed_delivery: authority_pin(17, "failed-delivery"),
        challenge_evaluator: authority_pin(31, "challenge-evaluator"),
        venue_finalization: authority_pin(32, "venue-finalization"),
        market_penalty: authority_pin(33, "market-penalty"),
        settlement_observer: authority_pin(34, "settlement-observer"),
        max_snapshot_age_secs: MAX_SNAPSHOT_AGE_SECS,
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 64,
        },
        audit_authority: authority_pin(35, "audit-authority"),
        audit_randomness_witness: authority_pin(37, "audit-randomness-witness"),
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
        community_fund_destination: COMMUNITY_FUND_RAIL.to_string(),
        status_feed_operator_ref: "status-feed/venue-challenge".to_string(),
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
    market_terms: BTreeMap<String, SignedFindingMarketTerms>,
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

    fn publish_round(mut self, round: &FindingAuditRound) -> Result<Self, AnyError> {
        self.audit_rounds
            .insert(signed_envelope_sha256(&round.epoch)?, round.clone());
        Ok(self)
    }

    fn publish_admission(mut self, admission: &SignedFindingAdmission) -> Self {
        self.admissions.insert(
            (
                admission.body.finding_id.clone(),
                admission.body.listing_id.clone(),
                admission.body.backing_envelope_sha256.clone(),
            ),
            admission.clone(),
        );
        self
    }

    fn publish_terms(mut self, terms: &SignedFindingMarketTerms) -> Result<Self, AnyError> {
        self.market_terms
            .insert(signed_envelope_sha256(terms)?, terms.clone());
        Ok(self)
    }
}

impl FindingFilingResolver for PublishedArtifacts {
    fn fee_schedule(&self, envelope_sha256: &str) -> Option<SignedOpenMarketFeeSchedule> {
        self.fee_schedules.get(envelope_sha256).cloned()
    }

    fn audit_round(&self, epoch_envelope_sha256: &str) -> Option<FindingAuditRound> {
        self.audit_rounds.get(epoch_envelope_sha256).cloned()
    }

    fn admission_for_backing(
        &self,
        finding_id: &str,
        listing_id: &str,
        backing_envelope_sha256: &str,
    ) -> Option<SignedFindingAdmission> {
        self.admissions
            .get(&(
                finding_id.to_owned(),
                listing_id.to_owned(),
                backing_envelope_sha256.to_owned(),
            ))
            .cloned()
    }

    fn market_terms(&self, envelope_sha256: &str) -> Option<SignedFindingMarketTerms> {
        self.market_terms.get(envelope_sha256).cloned()
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
    allocation_id: String,
    admission_envelope_sha256: String,
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
    purchases.register_community_fund_destination(&allocation_id, COMMUNITY_FUND_RAIL, NOW)?;
    let terms = match extra_terms.first() {
        Some(terms) => terms.clone(),
        None => market_terms(CLAIM_WINDOW_SECS)?,
    };
    let admission = signed_admission(&allocation_id, &terms)?;
    let admission_envelope_sha256 = signed_envelope_sha256(&admission)?;
    purchases.install_active_admission_for_tests(
        &admission.body.finding_id,
        &allocation_id,
        LISTING_ID,
        &admission.body.admission_id,
        &admission_envelope_sha256,
        NOW,
    )?;
    let mut filings = PublishedArtifacts::default()
        .publish_schedule(&published_fee_schedule()?)?
        .publish_round(&published_audit_round()?)?
        .publish_round(&unrelated_audit_round()?)?
        .publish_terms(&terms)?
        .publish_terms(&lapsed_window_terms()?)?
        .publish_terms(&audit_disabled_terms()?)?
        .publish_terms(&narrow_bond_terms()?)?
        .publish_admission(&admission);
    for terms in extra_terms {
        filings = filings.publish_terms(terms)?;
    }
    Ok(Deployment {
        _temp: temp,
        database,
        lock_root,
        _authority: authority,
        market,
        purchases,
        challenges,
        allocation_id,
        admission_envelope_sha256,
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
        Ok(FindingChallengeCoordinator::new(
            self.challenges.clone(),
            self.purchases.clone(),
            config,
            keypair(31),
            keypair(32),
            keypair(33),
            authority_status,
            self.rail.clone(),
            self.filings.clone(),
            failed_challenge_disposition,
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
            allocation_id,
            admission_envelope_sha256,
            rail,
            filings,
        } = self;
        // The serving lock lives on the open handles, so every one of them
        // closes before the database can be served again.
        drop(challenges);
        drop(purchases);
        drop(market);
        drop(_authority);
        let authority = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
        let market = authority.finding_market_store();
        let purchases = authority.finding_purchase_store();
        let challenges = authority.finding_challenge_store();
        Ok(Self {
            _temp,
            database,
            lock_root,
            _authority: authority,
            market,
            purchases,
            challenges,
            allocation_id,
            admission_envelope_sha256,
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
    let challenged = challenged_finding()?;
    let venue = keypair(6);
    let schedule_digest = signed_envelope_sha256(&published_fee_schedule()?)?;
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
        fee_schedule_envelope_sha256: schedule_digest.clone(),
        verifier_report_id: hex64('5'),
        verifier_report_envelope_sha256: hex64('7'),
        terms_envelope_sha256: signed_envelope_sha256(terms)?,
        profile_envelope_sha256: challenged.profile_envelope_sha256,
        fee_terminals: vec![
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: schedule_digest.clone(),
                event: FindingFeeEvent::Publication,
                payer: "seller-42".to_string(),
                amount: usd(100),
                pool_principal_id: AUDIT_POOL_PRINCIPAL.to_string(),
                rail_destination: AUDIT_POOL_DESTINATION.to_string(),
                instruction_sha256: hex64('8'),
                observation_sha256: hex64('9'),
            },
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: schedule_digest.clone(),
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
        community_fund_destination: COMMUNITY_FUND_RAIL.to_string(),
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
                log_id: log_id_for(&production_kernel())?,
                signer: key_policy(&production_kernel().public_key(), "production-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&delivery_kernel())?,
                signer: key_policy(&delivery_kernel().public_key(), "delivery-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&replay_kernel())?,
                signer: key_policy(&replay_kernel().public_key(), "replay-log"),
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
    let mut first = signed_receipt(
        &kernel,
        PRODUCTION_FIRST_AT,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 0 }))?,
        Decision::Allow,
        &hex64('a'),
        None,
    )?;
    let second = signed_receipt(
        &kernel,
        PRODUCTION_FIRST_AT + 1,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 1 }))?,
        Decision::Allow,
        &hex64('b'),
        None,
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
        &production_kernel(),
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
            log_id_for(&production_kernel())?
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
    deny_receipt: ResolvedReceiptEvidence,
    deny_checkpoint: KernelCheckpoint,
    deny_checkpoint_transparency: CheckpointTransparencySummary,
}

impl DigestMismatchCase {
    fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        FindingChallengeClassEvidence::DigestMismatch(FindingDigestMismatchEvidence {
            failed_delivery: &self.failed_delivery,
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
                venue_admission_envelope_sha256: hex64('d'),
                reservation_id: DENY_RESERVATION_ID.to_string(),
                purchase_intent_id: DENY_INTENT_ID.to_string(),
                authoritative_payment_operation_id: DENY_PAYMENT_ID.to_string(),
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
        &kernel,
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
            finding_id: &challenged.finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &hex64('c'),
            ask_digest: &digest("deny-ask"),
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
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
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    checkpoint_transparency: CheckpointTransparencySummary,
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

    fn evidence_against<'a>(
        &'a self,
        checkpoint: &'a KernelCheckpoint,
        checkpoint_transparency: &'a CheckpointTransparencySummary,
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
            purchase_record: &self.purchase_record,
            challenged_receipts: &self.receipts,
            challenged_checkpoint: checkpoint,
            checkpoint_transparency,
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
        &production_kernel(),
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
    Ok(EvidenceInvalidCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
        receipts: evidence.receipts,
        checkpoint: evidence.checkpoint,
        checkpoint_transparency,
        unresolved_checkpoint,
        unresolved_checkpoint_transparency,
    })
}

// ---------------------------------------------------------------------------
// replay_contradiction evidence
// ---------------------------------------------------------------------------

/// One reproduction phase as the runner reported it.
#[derive(Debug, Clone, Copy)]
struct PhaseShape {
    phase: FindingRecipePhaseKind,
    terminal: FindingReplayTerminalResult,
    exit_code: i64,
}

impl PhaseShape {
    const fn baseline_fails() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Baseline,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 1,
        }
    }

    const fn candidate_passes() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Candidate,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 0,
        }
    }

    const fn candidate_fails() -> Self {
        Self {
            exit_code: 1,
            ..Self::candidate_passes()
        }
    }
}

struct ReplayCase {
    challenge: SignedFindingChallenge,
    purchase_record: SignedFindingPurchaseRecord,
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
            purchase_record: &self.purchase_record,
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
    let recipe_digest = sha256_hex(recipe_preimage.as_bytes());
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
            ToolCallAction::from_parameters(serde_json::json!({
                "replay_run_id": REPLAY_RUN_ID,
                "phase": index,
            }))?,
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
        &kernel,
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
    Ok(ReplayCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
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
    let (finding, _) = finding_artifact()?;
    audit_round_over(vec![EligibleListing {
        finding_id: finding.finding_id,
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
    let randomness_witness = keypair(37);
    let seed_witnessed_at = NOW - 2_000;
    let eligible_snapshot_at = NOW - 1_500;
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
            &seed_commitment,
            seed_witnessed_at,
            eligible_snapshot_at,
        )),
        eligible_snapshot_digest: derive_eligible_snapshot_digest(&eligible)?,
        eligible_listing_count: u64::try_from(eligible.len())?,
        fee_schedule_envelope_sha256: signed_envelope_sha256(&published_fee_schedule()?)?,
        seed_commitment,
        selection_algorithm_id: AUDIT_SELECTION_ALGORITHM_V1.to_string(),
        published_rate_bps: MAX_PUBLISHED_RATE_BPS,
        available_budget: usd(10_000),
        authorization_digest: digest("audit-authorization"),
        committed_at: NOW - 1_000,
    };
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch)?;
    epoch.validate()?;
    Ok(FindingAuditRound {
        epoch: SignedExportEnvelope::sign(epoch, &audit_authority)?,
        revealed_seed,
        eligible,
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

// ---------------------------------------------------------------------------
// Settled purchases the claim snapshot derives from
// ---------------------------------------------------------------------------

/// One settled sale as the claim snapshot and the two standing-bearing
/// evidence classes read it.
#[derive(Clone)]
struct SettledPurchase {
    purchase_key: String,
    record: SignedFindingPurchaseRecord,
    record_envelope_sha256: String,
}

/// Whether the sale path admitted the record's payout destination. A
/// destination that was never admitted must never reach a distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayoutAdmission {
    Admitted,
    Withheld,
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
        PayoutAdmission::Admitted,
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
    admission: PayoutAdmission,
) -> Result<SettledPurchase, AnyError> {
    let (finding, _) = finding_artifact()?;
    let reservation_id = format!("reservation-{tag}");
    let payment_operation_id = format!("payment-{tag}");
    let bid = digest(&format!("bid-{tag}"));
    let buyer = if destination == BUYER_TWO_DESTINATION {
        keypair(42)
    } else {
        keypair(41)
    };
    let refund_destination = buyer_refund_destination(&buyer.public_key());
    deployment
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: &reservation_id,
            purchase_intent_id: &format!("intent-{tag}"),
            authoritative_payment_operation_id: &payment_operation_id,
            payer_hex: &buyer.public_key().to_hex(),
            agent_id: "agent-buyer-01",
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &bid,
            ask_digest: &digest(&format!("ask-{tag}")),
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
            amount_units: 100,
            currency: "USD",
            expires_at: now + 3_600,
            encumbrance_id: &format!("encumbrance-{tag}"),
            allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: now,
        })?;
    let ordinal = deployment.purchases.reserve_slot(&reservation_id, now)?;
    let record = FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_string(),
        purchase_key: derive_purchase_key(&bid, &payment_operation_id),
        purchase_intent_id: format!("intent-{tag}"),
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
        encumbrance_id: format!("encumbrance-{tag}"),
        delivery_receipt_id: format!("receipt-delivery-{tag}"),
        payment_reference: payment_operation_id,
        payout_destination: refund_destination.clone(),
        recorded_at: now,
    };
    record.validate()?;
    let purchase_key = record.purchase_key.clone();
    let signed = SignedFindingPurchaseRecord::sign(record, &keypair(16))?;
    let record_json = canonical_json_bytes(&signed)?;
    let record_sha256 = sha256_hex(&record_json);
    if admission == PayoutAdmission::Admitted {
        deployment
            .purchases
            .admit_payout_destination(allocation_id, &refund_destination, now)?;
    }
    deployment
        .purchases
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &reservation_id,
            purchase_key: &purchase_key,
            record_json: &record_json,
            record_sha256: &record_sha256,
            delivery_receipt_id: &format!("receipt-delivery-{tag}"),
            payout_destination: match admission {
                PayoutAdmission::Admitted => &refund_destination,
                PayoutAdmission::Withheld => "rail:venue-ledger:withheld-test-placeholder",
            },
            retention_expires_at: now + 100_000,
            now,
        })?;
    assert!(ordinal >= 1, "slot ordinals start at one");
    Ok(SettledPurchase {
        record_envelope_sha256: signed_envelope_sha256(&signed)?,
        purchase_key,
        record: signed,
    })
}

// ---------------------------------------------------------------------------
// Governance fixtures for the penalty branches
// ---------------------------------------------------------------------------

struct Governance {
    fee_schedule: SignedOpenMarketFeeSchedule,
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
    keypair(24)
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
        fee_schedule: sample_fee_schedule(fee_schedule_signer)?,
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
        &upheld.sealed,
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
    now: u64,
) -> Result<FindingChallengeState, AnyError> {
    deployment.challenges.begin_evaluation(challenge_id, now)?;
    Ok(deployment
        .challenges
        .record_verdict(challenge_id, verdict, outcome_envelope_sha256, now)?)
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
        audit_epoch_envelope_sha256: match &challenge.body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(_) => None,
            FindingChallengeAuthorization::VenueAudit(audit) => {
                Some(audit.audit_epoch_envelope_sha256.clone())
            }
        },
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
        evaluator_key_epoch: PINNED_KEY_EPOCH,
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
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &digest("rotated-pool-upheld"),
        NOW + 1,
    )?;
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

    // The row is recorded before the charge, so a rail that cannot move
    // the fee leaves the challenge durable with nothing collected and
    // nothing locked.
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
    let unrelated_epoch = signed_envelope_sha256(&unrelated_audit_round()?.epoch)?;

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

    // A schedule this venue never published resolves to nothing at all.
    let challenge = buyer_challenge_with(&buyer, |submission| {
        submission.dispute_fee_terminal.fee_schedule_envelope_sha256 = hex64('5');
        submission.dispute_lock_ref.fee_schedule_envelope_sha256 = hex64('5');
    })?;
    let error = coordinator
        .submit(&challenge, &raw, NOW)
        .expect_err("an unresolvable schedule digest must not be admitted");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::UnknownFeeSchedule
    ));

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

    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &digest("upheld-outcome"),
        NOW + 10,
    )?;
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
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &digest("upheld-refund-retry"),
        NOW + 10,
    )?;

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
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
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
    close_challenge(
        deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
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
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
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
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
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
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
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
        ChallengeCoordinatorError::AuthorityPinMismatch(_)
    ));
    assert_eq!(
        liability_heads(&deployment, &ready.finding.finding_id)?,
        0,
        "an unpinned governance bundle opens no liability"
    );
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_a_bad_signature_under_the_pinned_case_key_blocks_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let ready = ready_to_uphold(&deployment, &coordinator)?;

    // Advertising the pinned key does not make a signature produced by
    // another key authentic. This must fail before the upheld transaction
    // raises the durable sales block.
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
    assert!(matches!(refused, ChallengeCoordinatorError::PenaltyMint(_)));
    assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_exhausted_collateral_never_blocks_the_listing() -> TestResult {
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
        !deployment.purchases.sales_blocked(LISTING_ID)?,
        "a listing is never blocked behind a hold that can never be minted"
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
        !deployment.purchases.sales_blocked(LISTING_ID)?,
        "nothing durable happens before the allocation binding is proven"
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
        !deployment.purchases.sales_blocked(LISTING_ID)?,
        "nothing durable happens before the stake binding is proven"
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
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
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
        PayoutAdmission::Admitted,
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
        PayoutAdmission::Admitted,
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
    let governance = governance()?;
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
    assert!(matches!(
        uphold_at(&signed, opened_at),
        Err(ChallengeCoordinatorError::ClaimWindowOpen)
    ));
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
            .any(|entry| entry.destination == COMMUNITY_FUND_RAIL),
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
        &case.upheld.sealed,
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
            &case.upheld.sealed,
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

#[test]
fn finding_challenge_an_appeal_case_id_cannot_be_substituted() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let refused = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            &case.upheld.sealed,
            &case.governance.context(),
            &AppealDisposition::Successful {
                appeal_case: &case.governance.appeal_case,
                appeal_case_id: "case-appeal-substituted-01",
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            NOW + 20,
        )
        .expect_err("an unsigned appeal case id can supersede nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head remains durable")?;
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert_eq!(
        case.deployment
            .challenges
            .resolve_case_head(&case.upheld.liability_key)?
            .ok_or("sanction remains live")?
            .case_id,
        case.upheld.sanction_case_id
    );
    Ok(())
}

#[test]
fn finding_challenge_an_unauthenticated_appeal_supersedes_nothing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // An appeal filed under a key the governance root never delegated to,
    // naming the real sanction. It is exactly the filing an attacker can
    // produce, and the index must be left able to accept the real one.
    let forged = sample_case(
        &keypair(99),
        &case.governance.listing,
        &case.governance.activation,
        &case.governance.charter,
        GenericGovernanceCaseKind::Appeal,
        Some(case.upheld.sanction_case_id.clone()),
        Some(case.upheld.sanction_case_id.clone()),
    )?;

    let refused = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            &case.upheld.sealed,
            &case.governance.context(),
            &AppealDisposition::Successful {
                appeal_case: &forged,
                appeal_case_id: &forged.body.case_id,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            NOW + 20,
        )
        .expect_err("an appeal no pinned authority signed reverses nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AuthorityPinMismatch(_)
    ));

    let cases = case
        .deployment
        .challenges
        .list_governance_cases(&case.upheld.liability_key)?;
    assert_eq!(
        cases.len(),
        1,
        "a refused appeal leaves no case head behind it"
    );
    let sanction = cases.first().ok_or("the sanction is indexed")?;
    assert_eq!(sanction.case_id, case.upheld.sanction_case_id);
    assert_eq!(
        sanction.superseded_by_case_id, None,
        "the sanction still governs the liability"
    );

    // The legitimate appeal that follows must still be able to supersede.
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        &case.upheld.sealed,
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &case.governance.appeal_case,
            appeal_case_id: &case.governance.appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 40,
    )?;
    assert!(matches!(
        resolution,
        AppealResolution::ReversedBeforeImpairment { .. }
    ));
    let head = case
        .deployment
        .challenges
        .resolve_case_head(&case.upheld.liability_key)?
        .ok_or("the appeal is the live case head")?;
    assert_eq!(head.case_id, case.governance.appeal_case.body.case_id);
    Ok(())
}

#[test]
fn finding_challenge_appeal_finality_impairs_and_fences_every_effect_intent() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        &case.upheld.sealed,
        &case.governance.context(),
        &AppealDisposition::Final {
            sanction_case: &case.governance.sanction_case,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        APPEAL_FINAL_AT,
    )?;
    let AppealResolution::Finalizing(authorized) = resolution else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("the finalizing liability remains durable")?;
    let stable_penalty_issued_at = liability
        .appeal_deadline
        .and_then(|deadline| deadline.checked_add(1))
        .ok_or("the appeal deadline has a representable successor")?;
    assert_eq!(
        authorized.slash.penalty.body.opened_at, stable_penalty_issued_at,
        "the final penalty is issued from the durable appeal boundary"
    );
    assert_eq!(
        authorized.slash.penalty.body.updated_at, stable_penalty_issued_at,
        "a retry clock cannot change the signed penalty bytes"
    );
    assert_eq!(
        authorized.enforcement.body.amount,
        case.upheld.sealed.distribution.slash
    );
    assert_eq!(
        authorized.enforcement.body.purchase_snapshot_digest,
        case.upheld.sealed.snapshot_digest
    );

    // Every domain-keyed intent is durable and pending before anything is
    // dispatched, and the retraction stays dispatch-ineligible until a
    // confirmed impairment releases it.
    let intents = case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?;
    assert_eq!(
        intents.len(),
        5,
        "seller impairment, root anchor, retraction, collected fee, and bond disposition"
    );
    for intent in &intents {
        assert!(intent.settlement_required);
        let expected = if matches!(
            intent.kind,
            chio_store_sqlite::FindingEffectIntentKind::ChallengeBond
                | chio_store_sqlite::FindingEffectIntentKind::Fee
        ) {
            FindingEffectIntentState::Confirmed
        } else {
            FindingEffectIntentState::Pending
        };
        assert_eq!(intent.state, expected);
    }
    let has = |kind: chio_store_sqlite::FindingEffectIntentKind| {
        intents.iter().any(|intent| intent.kind == kind)
    };
    assert!(has(
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair
    ));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::RootIntent));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::Retraction));
    assert!(has(
        chio_store_sqlite::FindingEffectIntentKind::ChallengeBond
    ));
    assert!(has(chio_store_sqlite::FindingEffectIntentKind::Fee));
    assert_eq!(authorized.effect_intent_keys.len(), 5);

    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.state, FindingLiabilityState::Finalizing);
    assert!(liability.publication_pending);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_refreshes_a_snapshot_only_before_impairment_dispatch() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let authorized = impair_after_appeal(
        &case.coordinator,
        &case.governance,
        &case.upheld,
        &case.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    let seller = keypair(22).public_key();
    let observed_at = APPEAL_FINAL_AT + 10;
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: authorized.enforcement.body.vault.chain_id.clone(),
        vault_contract: authorized.enforcement.body.vault.vault_contract.clone(),
        vault_id: authorized.enforcement.body.vault.vault_id.clone(),
        seller: seller.clone(),
        allocation_id: authorized.enforcement.body.seller_allocation_id.clone(),
        locked_amount: 5_000,
        held_amount: authorized.enforcement.body.amount.units,
        slashed_amount: 0,
        currency: authorized.enforcement.body.amount.currency.clone(),
        block_number: 21_000_200,
        block_hash: chain_hash(0xbd),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        observed_at,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    let snapshot = SignedExportEnvelope::sign(snapshot, &keypair(34))?;
    let refreshed = case.coordinator.refresh_finalizing_enforcement(
        &authorized,
        &snapshot,
        &seller,
        observed_at + 1,
    )?;
    assert_eq!(
        refreshed.enforcement.body.bond_snapshot_envelope_sha256,
        signed_envelope_sha256(&snapshot)?
    );
    assert_ne!(
        refreshed.enforcement_envelope_sha256,
        authorized.enforcement_envelope_sha256
    );
    assert_eq!(refreshed.slash.penalty, authorized.slash.penalty);
    assert_eq!(refreshed.effect_intent_keys, authorized.effect_intent_keys);

    let seller_intent = authorized
        .effect_intent_keys
        .iter()
        .find(|(kind, _)| *kind == FindingEffectIntentKind::SellerImpair)
        .map(|(_, key)| key)
        .ok_or("the impairment authorization fences its seller intent")?;
    case.deployment.challenges.advance_effect_intent(
        seller_intent,
        FindingEffectIntentState::Dispatched,
        observed_at + 2,
    )?;
    let refused = case
        .coordinator
        .refresh_finalizing_enforcement(&refreshed, &snapshot, &seller, observed_at + 3)
        .expect_err("a dispatched impairment can no longer refresh its snapshot");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::Settlement(detail)
            if detail.contains("only before impairment dispatch")
    ));
    Ok(())
}

#[test]
fn finding_challenge_appeal_finality_refuses_a_window_that_has_not_closed() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let deadline = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability is durable")?
        .appeal_deadline
        .ok_or("appeal deadline is frozen")?;
    let close_at = |now: u64| {
        case.coordinator.resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            &case.upheld.sealed,
            &case.governance.context(),
            &AppealDisposition::Final {
                sanction_case: &case.governance.sanction_case,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            now,
        )
    };

    // The seller-signed deadline governs through its exact final instant.
    let early =
        close_at(deadline).expect_err("finality is only reached once the deadline has passed");
    assert!(matches!(
        early,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));

    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an open appeal window fences no impairment effect"
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.state, FindingLiabilityState::PendingAppeal);
    assert!(!liability.publication_pending);

    // The same call once the window has genuinely closed authorizes it.
    assert!(matches!(
        close_at(deadline + 1)?,
        AppealResolution::Finalizing(_)
    ));
    Ok(())
}

#[test]
fn finding_challenge_a_live_appeal_case_blocks_appeal_finality() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // An appeal filed against the sanction and still open. It supersedes
    // nothing yet, so the liability now carries two live cases and no
    // single case can be said to govern it.
    case.deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: "case-appeal-open-01",
            finding_id: &case.finding_id,
            listing_id: LISTING_ID,
            liability_key: &case.upheld.liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Appeal,
            case_state: "open",
            appeal_of_case_id: Some(&case.upheld.sanction_case_id),
            supersedes_case_id: None,
            recorded_at: NOW + 10,
        },
    )?;

    let refused = resolve_final(&case, &identity, &case.outcome, APPEAL_FINAL_AT)
        .expect_err("a live appeal is not a denial and authorizes no impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an unresolved case head fences no impairment effect"
    );
    assert_eq!(
        case.deployment
            .challenges
            .get_liability(&case.upheld.liability_key)?
            .ok_or("liability head is durable")?
            .state,
        FindingLiabilityState::PendingAppeal
    );
    Ok(())
}

#[test]
fn finding_challenge_unresolved_appeal_quarantines_rather_than_impairing() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        &case.upheld.sealed,
        &case.governance.context(),
        &AppealDisposition::Unresolved {
            reason: "appeal is open",
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        NOW + 20,
    )?;
    assert!(matches!(resolution, AppealResolution::Quarantined { .. }));
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(
        liability.state,
        FindingLiabilityState::PendingAppeal,
        "an open appeal is not a denial and impairs nothing"
    );
    assert!(liability.quarantined);
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "an unresolved appeal fences no impairment effect"
    );
    Ok(())
}

#[test]
fn finding_challenge_sealed_accounting_cannot_be_substituted_at_appeal_finality() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let mut tampered = case.upheld.sealed.clone();
    tampered.distribution.entries[0].amount_units = tampered.distribution.entries[0]
        .amount_units
        .saturating_add(1);
    let error = case
        .coordinator
        .resolve_appeal(
            &case.upheld.liability_key,
            &case.outcome,
            &identity,
            &tampered,
            &case.governance.context(),
            &AppealDisposition::Final {
                sanction_case: &case.governance.sanction_case,
            },
            &case.upheld.sanction_case_id,
            &case.upheld.hold,
            &hex64('7'),
            APPEAL_FINAL_AT,
        )
        .expect_err("a substituted distribution must not authorize an impairment");
    assert!(matches!(
        error,
        ChallengeCoordinatorError::SealedClaimMismatch
    ));
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
        &case.upheld.sealed,
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

#[test]
fn finding_challenge_appeal_finality_refuses_an_identity_the_head_does_not_carry() -> TestResult {
    let case = upheld_liability()?;
    let mut elsewhere = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    elsewhere.vault_id = "vault-99";

    let refused = resolve_final(&case, &elsewhere, &case.outcome, APPEAL_FINAL_AT)
        .expect_err("a liability may only be impaired at the vault it was opened against");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityIdentity("vault_id")
    ));
    assert!(
        case.deployment
            .challenges
            .list_effect_intents(&case.upheld.liability_key)?
            .is_empty(),
        "a substituted target fences no effect"
    );
    assert_eq!(
        case.deployment
            .challenges
            .get_liability(&case.upheld.liability_key)?
            .ok_or("liability head is durable")?
            .state,
        FindingLiabilityState::PendingAppeal
    );
    Ok(())
}

#[test]
fn finding_challenge_a_rejected_outcome_never_authorizes_an_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let mut body = case.outcome.body.clone();
    body.verdict = chio_finding::FindingChallengeVerdict::Rejected;
    body.facet =
        FindingChallengeFacet::EvidenceInvalid(chio_finding::FindingEvidenceInvalidFacet {
            challenged_receipt_ids: vec!["receipt-evidence-01".to_string()],
            invalidity: FindingEvidenceInvalidity::NoAffirmativeInvalidity,
        });
    body.reason = "evidence_resolved_valid".to_string();
    body.penalty_calculation = None;
    body.outcome_id = chio_finding::derive_outcome_id(&body)?;
    body.validate()?;
    let rejected = SignedExportEnvelope::sign(body, &keypair(31))?;

    let refused = resolve_final(&case, &identity, &rejected, APPEAL_FINAL_AT)
        .expect_err("only an upheld adjudication reaches the penalty lane");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::VerdictNotUpheld
    ));
    assert!(case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?
        .is_empty());
    Ok(())
}

#[test]
fn finding_challenge_an_outcome_the_store_never_recorded_authorizes_no_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    // Same verdict, same bindings, adjudicated one second later: a second
    // upheld envelope for this defect that the verdict record never named.
    let mut body = case.outcome.body.clone();
    body.evaluated_at = body.evaluated_at.saturating_add(1);
    body.outcome_id = chio_finding::derive_outcome_id(&body)?;
    body.validate()?;
    let substituted = SignedExportEnvelope::sign(body, &keypair(31))?;

    let refused = resolve_final(&case, &identity, &substituted, APPEAL_FINAL_AT)
        .expect_err("only the recorded adjudication may authorize the impairment");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    Ok(())
}

#[test]
fn finding_challenge_a_second_appeal_finality_reuses_the_root_intent() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let AppealResolution::Finalizing(first) =
        resolve_final(&case, &identity, &case.outcome, APPEAL_FINAL_AT)?
    else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };

    // A later retry must not mint a second authorization with a new
    // finalization time after the durable head already entered finalizing.
    let refused = resolve_final(&case, &identity, &case.outcome, APPEAL_FINAL_AT + 20)
        .expect_err("one liability authorizes one enforcement");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityState("pending_appeal")
    ));
    let intents = case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?;
    assert_eq!(
        intents.len(),
        5,
        "the replay records no sixth intent beside the five already fenced"
    );
    assert_eq!(first.effect_intent_keys.len(), 5);
    Ok(())
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
    let policy = SettlementPolicyConfig {
        finding_impairment_destination_allowlist: [
            EVM_BUYER_DESTINATION.to_string(),
            EVM_COMMUNITY_FUND.to_string(),
        ]
        .into_iter()
        .collect(),
        ..SettlementPolicyConfig::default()
    };
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

/// Whether the enforcement root behind a finalizing liability has been
/// published, as the operator's anchoring step would leave it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnforcementRoot {
    Confirmed,
    Unpublished,
}

/// One liability head driven to `finalizing` with its seller-impairment
/// intent fenced, paired with the enforcement the settlement choke point
/// verifies. The head carries exactly the allocation and vault the
/// enforcement names, as the appeal path leaves it.
struct FinalizingLiability {
    deployment: Deployment,
    coordinator: FindingChallengeCoordinator,
    liability_key: String,
    seller: PublicKey,
    intent_key: String,
    retraction_key: String,
    enforcement: SignedFindingChallengeEnforcement,
    penalty: SignedOpenMarketPenalty,
    snapshot: SignedFindingFinalizedBondSnapshot,
    confirm_retraction_after_impairment: bool,
}

fn finalizing_liability() -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(EnforcementRoot::Confirmed, true)
}

fn finalizing_liability_rooted(root: EnforcementRoot) -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(root, true)
}

fn finalizing_liability_pending_retraction() -> Result<FinalizingLiability, AnyError> {
    finalizing_liability_with(EnforcementRoot::Confirmed, false)
}

fn finalizing_liability_with(
    root: EnforcementRoot,
    confirm_retraction_after_impairment: bool,
) -> Result<FinalizingLiability, AnyError> {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &digest("upheld-outcome"),
        NOW + 1,
    )?;

    let liability_key = byte_hex64(0xb1);
    deployment
        .challenges
        .open_liability(&chio_store_sqlite::FindingLiabilityInput {
            liability_key: &liability_key,
            defect_key: &derive_defect_key(&finding.finding_id),
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            allocation_id: &byte_hex64(0xa1),
            venue_id: VENUE_ID,
            chain_id: &settlement_config()?.chain_id,
            vault_contract: BOND_VAULT_CONTRACT,
            vault_id: &chain_hash(0x44),
            opened_at: NOW,
        })?;
    deployment.challenges.uphold_liability(
        &liability_key,
        &challenge.body.challenge_id,
        1,
        NOW + 2 + CLAIM_WINDOW_SECS,
        NOW + 2,
    )?;
    // The sanction the impairment settles under. Dispatch requires it to
    // still be the live case head, exactly as the coordinator records it
    // when it upholds a liability.
    deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: FIXTURE_SANCTION_CASE_ID,
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            liability_key: &liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Sanction,
            case_state: "enforced",
            appeal_of_case_id: None,
            supersedes_case_id: None,
            recorded_at: NOW + 2,
        },
    )?;
    deployment.challenges.begin_appeal_window(
        &liability_key,
        FindingLiabilityState::UpheldPendingClaims,
        &admitted_terms_digest()?,
        259_200,
        NOW + 3,
    )?;
    deployment.challenges.begin_finalizing_under_sanction(
        &liability_key,
        FindingLiabilityState::PendingAppeal,
        FIXTURE_SANCTION_CASE_ID,
        NOW + 4,
    )?;

    let seller = keypair(73).public_key();
    let intent_key = byte_hex64(0xc1);
    let penalty = fixture_slash_penalty()?;
    let penalty_envelope_sha256 = signed_envelope_sha256(&penalty)?;
    deployment.challenges.record_effect_intent(
        &intent_key,
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair,
        &byte_hex64(0xd1),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    // The enforcement root the vault checks the impairment proof against,
    // fenced under the commitment this liability and penalty derive and
    // then driven to whatever the anchoring step left it in.
    deployment.challenges.record_effect_intent(
        &enforcement_root_intent_key(),
        chio_store_sqlite::FindingEffectIntentKind::RootIntent,
        &sha256_hex(root_intent_commitment(&liability_key, &penalty_envelope_sha256).as_bytes()),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    if root == EnforcementRoot::Confirmed {
        for state in [
            FindingEffectIntentState::Dispatched,
            FindingEffectIntentState::Confirmed,
        ] {
            deployment.challenges.advance_effect_intent(
                &enforcement_root_intent_key(),
                state,
                NOW + 6,
            )?;
        }
    }
    let retraction_key = byte_hex64(0xc3);
    deployment.challenges.record_effect_intent(
        &retraction_key,
        chio_store_sqlite::FindingEffectIntentKind::Retraction,
        &digest("status retraction"),
        Some(&liability_key),
        true,
        NOW + 5,
    )?;
    let (enforcement, snapshot) = enforcement_pair(
        &liability_key,
        &finding.finding_id,
        &seller,
        &intent_key,
        &penalty_envelope_sha256,
    )?;
    Ok(FinalizingLiability {
        deployment,
        coordinator,
        liability_key,
        seller,
        intent_key,
        retraction_key,
        enforcement,
        penalty,
        snapshot,
        confirm_retraction_after_impairment,
    })
}

impl FinalizingLiability {
    /// Run the settlement choke point against this head with the given
    /// publisher.
    fn finalize(
        &self,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<FindingFinalization, AnyError> {
        Ok(self.finalize_observing(&ScriptedObservations::qualified(), publisher, now)??)
    }

    /// The same run against a caller-scripted view of the chain, so a test
    /// can move the state the signed snapshot rests on under it.
    fn finalize_observing(
        &self,
        observations: &dyn chio_settle::FindingBondObservationSource,
        publisher: &dyn FindingImpairmentPublisher,
        now: u64,
    ) -> Result<Result<FindingFinalization, ChallengeCoordinatorError>, AnyError> {
        let mut outcome = self.coordinator.finalize(
            &self.liability_key,
            &self.enforcement,
            &self.penalty,
            &self.snapshot,
            &self.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &anchor_proof()?,
            observations,
            publisher,
            now,
        );
        if outcome.is_ok() && self.confirm_retraction_after_impairment {
            let seller_intent = self.intent()?;
            let head = self.head()?;
            if seller_intent.state == FindingEffectIntentState::Confirmed
                && head.state == FindingLiabilityState::Finalizing
                && !head.quarantined
            {
                let retraction = self
                    .deployment
                    .challenges
                    .get_effect_intent(&self.retraction_key)?
                    .ok_or("the retraction intent is durable")?;
                if retraction.state == FindingEffectIntentState::Pending {
                    self.deployment.challenges.advance_effect_intent(
                        &self.retraction_key,
                        FindingEffectIntentState::Dispatched,
                        now,
                    )?;
                    self.deployment.challenges.advance_effect_intent(
                        &self.retraction_key,
                        FindingEffectIntentState::Confirmed,
                        now,
                    )?;
                }
                self.deployment.challenges.settle_liability(
                    &self.liability_key,
                    FindingLiabilityState::Finalizing,
                    now,
                )?;
                if matches!(outcome, Ok(FindingFinalization::AwaitingEffects)) {
                    outcome = Ok(FindingFinalization::AlreadyConfirmed);
                }
            }
        }
        Ok(outcome)
    }

    fn intent_state(&self) -> Result<FindingEffectIntentState, AnyError> {
        Ok(self.intent()?.state)
    }

    fn intent(&self) -> Result<chio_store_sqlite::FindingEffectIntentRecord, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_effect_intent(&self.intent_key)?
            .ok_or("the impairment intent is durable")?)
    }

    fn head(&self) -> Result<chio_store_sqlite::FindingLiabilityRecord, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_liability(&self.liability_key)?
            .ok_or("liability head is durable")?)
    }
}

/// Domain-keyed identity of the enforcement-root effect the pair binds.
fn enforcement_root_intent_key() -> String {
    byte_hex64(0xc2)
}

/// The penalty-authority-signed slash the manual finalization fixture
/// binds. Its case id is the durable sanction head, so final dispatch can
/// compare the exact authority rather than merely seeing a sanction kind.
fn fixture_slash_penalty() -> Result<SignedOpenMarketPenalty, AnyError> {
    let artifact = OpenMarketPenaltyArtifact {
        schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_string(),
        penalty_id: "market-penalty-finalizing-fixture".to_string(),
        fee_schedule_id: "fee-schedule-finalizing-fixture".to_string(),
        charter_id: "charter-finalizing-fixture".to_string(),
        case_id: FIXTURE_SANCTION_CASE_ID.to_string(),
        governing_operator_id: OPERATOR_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        listing_id: LISTING_ID.to_string(),
        activation_id: None,
        subject_operator_id: Some(OPERATOR_ID.to_string()),
        abuse_class: OpenMarketAbuseClass::FraudulentListing,
        bond_class: OpenMarketBondClass::Listing,
        action: OpenMarketPenaltyAction::SlashBond,
        state: OpenMarketPenaltyState::Enforced,
        penalty_amount: usd(250),
        opened_at: NOW + 4,
        updated_at: NOW + 4,
        expires_at: Some(KEY_VALID_UNTIL),
        evidence_refs: vec![OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::External,
            reference_id: "outcome-finalizing-fixture".to_string(),
            uri: None,
            sha256: Some(byte_hex64(0xb4)),
        }],
        supersedes_penalty_id: None,
        issued_by: "market@chio.example".to_string(),
        note: None,
    };
    artifact.validate()?;
    Ok(SignedOpenMarketPenalty::sign(artifact, &keypair(33))?)
}

/// The leaf the vault burns for the anchored receipt in the example
/// proof, derived exactly as the impairment plan derives it.
fn anchor_evidence_hash() -> Result<String, AnyError> {
    let bytes = canonical_json_bytes(&anchor_proof()?.receipt.body())?;
    Ok(leaf_hash(&bytes).to_hex_prefixed())
}

/// The exact settlement pair the choke point verifies, plus the finding
/// and listing identities the liability head must carry.
fn enforcement_pair(
    liability_key: &str,
    finding_id: &str,
    seller: &PublicKey,
    seller_impair_intent_id: &str,
    penalty_envelope_sha256: &str,
) -> Result<
    (
        SignedFindingChallengeEnforcement,
        SignedFindingFinalizedBondSnapshot,
    ),
    AnyError,
> {
    enforcement_pair_at_vault(
        liability_key,
        finding_id,
        seller,
        seller_impair_intent_id,
        penalty_envelope_sha256,
        &chain_hash(0x44),
    )
}

/// The same pair against a caller-named vault, so a test can present an
/// instruction and observation that agree with each other and with the
/// live contract read while naming a vault the liability never did.
fn enforcement_pair_at_vault(
    liability_key: &str,
    finding_id: &str,
    seller: &PublicKey,
    seller_impair_intent_id: &str,
    penalty_envelope_sha256: &str,
    vault_id: &str,
) -> Result<
    (
        SignedFindingChallengeEnforcement,
        SignedFindingFinalizedBondSnapshot,
    ),
    AnyError,
> {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: settlement_config()?.chain_id,
        vault_contract: BOND_VAULT_CONTRACT.to_string(),
        vault_id: vault_id.to_string(),
        seller: seller.clone(),
        allocation_id: byte_hex64(0xa1),
        locked_amount: 500_000,
        held_amount: 120_000,
        slashed_amount: 0,
        currency: "USD".to_string(),
        block_number: 21_000_000,
        block_hash: chain_hash(0xbb),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: PINNED_KEY_EPOCH,
        observed_at: OBSERVED_AT,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    let signed_snapshot = SignedExportEnvelope::sign(snapshot, &keypair(34))?;
    let snapshot_digest = signed_envelope_sha256(&signed_snapshot)?;
    let mut enforcement = FindingChallengeEnforcement {
        schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_string(),
        enforcement_id: String::new(),
        liability_key: liability_key.to_string(),
        finding_id: finding_id.to_string(),
        listing_id: LISTING_ID.to_string(),
        outcome_id: byte_hex64(0xb3),
        outcome_envelope_sha256: byte_hex64(0xb4),
        penalty_envelope_sha256: penalty_envelope_sha256.to_string(),
        bond_snapshot_envelope_sha256: snapshot_digest,
        purchase_snapshot_digest: byte_hex64(0xb6),
        deterministic_allocation_digest: byte_hex64(0xb7),
        seller_allocation_id: byte_hex64(0xa1),
        vault: FindingVaultReference {
            chain_id: settlement_config()?.chain_id,
            vault_contract: BOND_VAULT_CONTRACT.to_string(),
            vault_id: vault_id.to_string(),
        },
        amount: usd(250),
        destinations: vec![
            FindingEnforcementDestination {
                destination: EVM_BUYER_DESTINATION.to_string(),
                amount: usd(150),
            },
            FindingEnforcementDestination {
                destination: EVM_COMMUNITY_FUND.to_string(),
                amount: usd(100),
            },
        ],
        effect_intents: vec![
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::SellerImpair,
                intent_id: seller_impair_intent_id.to_string(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::RootIntent,
                intent_id: enforcement_root_intent_key(),
            },
            FindingEffectIntentBinding {
                kind: chio_finding::FindingEffectIntentKind::Retraction,
                intent_id: byte_hex64(0xc3),
            },
        ],
        finalized_at: OBSERVED_AT + 100,
    };
    enforcement.enforcement_id = compute_enforcement_id(&enforcement)?;
    Ok((
        SignedExportEnvelope::sign(enforcement, &keypair(32))?,
        signed_snapshot,
    ))
}

#[test]
fn finding_challenge_quarantined_reconciliation_leaves_purchases_blocked() -> TestResult {
    let case = finalizing_liability()?;
    let outcome = case.finalize(&AmbiguousPublisher, SETTLEMENT_NOW)?;
    assert_eq!(
        outcome,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::StoredTransactionMissing
        }),
        "a consumed evidence hash with no transaction behind it is never a slash"
    );

    let liability = case.head()?;
    assert_eq!(liability.state, FindingLiabilityState::Finalizing);
    assert!(liability.publication_pending);
    assert!(liability.quarantined);
    assert!(
        case.deployment.purchases.sales_blocked(LISTING_ID)?,
        "a quarantined impairment keeps purchases denied"
    );
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Quarantined,
        "an evidence hash burned by an unknown transaction needs an operator"
    );
    Ok(())
}

#[test]
fn finding_challenge_an_unmined_broadcast_stays_dispatchable_and_settles_when_it_lands(
) -> TestResult {
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

    // The same transaction then mines and finalizes, and the liability
    // reaches its terminal instead of staying blocked forever.
    let second = case.finalize(&publisher, SETTLEMENT_NOW + 60)?;
    assert_eq!(
        second,
        FindingFinalization::Reconciled(FindingImpairmentOutcome::Confirmed {
            tx_hash: chain_hash(0x77)
        })
    );
    assert_eq!(publisher.attempts(), 2);
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Confirmed);
    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    Ok(())
}

#[test]
fn finding_challenge_a_reorged_transaction_receipt_never_settles() -> TestResult {
    let case = finalizing_liability()?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &ReorgedReceiptPublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a transaction missing from the immediate canonical recheck cannot settle");
    assert!(matches!(refused, ChallengeCoordinatorError::Settlement(_)));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Failed,
        "a receipt that failed its immediate recheck is not confirmed"
    );
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(parked.quarantined);
    assert!(parked.publication_pending);
    Ok(())
}

#[test]
fn finding_challenge_a_confirmed_impairment_settles_without_dispatching_again() -> TestResult {
    let case = finalizing_liability()?;
    // An attempt that confirmed the impairment and died before it could
    // settle the head leaves exactly this durable state.
    case.deployment.challenges.advance_effect_intent(
        &case.intent_key,
        FindingEffectIntentState::Dispatched,
        SETTLEMENT_NOW,
    )?;
    case.deployment.challenges.advance_effect_intent(
        &case.intent_key,
        FindingEffectIntentState::Confirmed,
        SETTLEMENT_NOW,
    )?;

    let resumed = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 1)?;
    assert_eq!(resumed, FindingFinalization::AlreadyConfirmed);
    let settled = case.head()?;
    assert_eq!(
        settled.state,
        FindingLiabilityState::Settled,
        "the resumed attempt finishes the settlement the interrupted one owed"
    );
    assert!(!settled.publication_pending);
    Ok(())
}

#[test]
fn finding_challenge_confirmed_recovery_reobserves_transaction_finality() -> TestResult {
    let case = finalizing_liability()?;
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.intent_key,
            state,
            SETTLEMENT_NOW,
        )?;
    }

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &ReorgedReceiptPublisher,
            SETTLEMENT_NOW + 1,
        )?
        .expect_err("recovery cannot inherit an earlier receipt observation");
    assert!(matches!(refused, ChallengeCoordinatorError::Settlement(_)));
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(parked.quarantined);
    Ok(())
}

#[test]
fn finding_challenge_confirmed_impairment_waits_for_retraction_before_settlement() -> TestResult {
    let case = finalizing_liability_pending_retraction()?;
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.intent_key,
            state,
            SETTLEMENT_NOW,
        )?;
    }

    let waiting = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 1)?;
    assert_eq!(waiting, FindingFinalization::AwaitingEffects);
    let pending = case.head()?;
    assert_eq!(pending.state, FindingLiabilityState::Finalizing);
    assert!(pending.publication_pending);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);

    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.retraction_key,
            state,
            SETTLEMENT_NOW + 2,
        )?;
    }
    let settled = case.finalize(&UnreachablePublisher, SETTLEMENT_NOW + 3)?;
    assert_eq!(settled, FindingFinalization::AlreadyConfirmed);
    let head = case.head()?;
    assert_eq!(head.state, FindingLiabilityState::Settled);
    assert!(!head.publication_pending);
    Ok(())
}

#[test]
fn finding_challenge_confirmed_impairment_settles_after_snapshot_expiry() -> TestResult {
    let case = finalizing_liability_pending_retraction()?;
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.intent_key,
            state,
            SETTLEMENT_NOW,
        )?;
    }

    let stale_at = OBSERVED_AT + MAX_SNAPSHOT_AGE_SECS + 1;
    assert_eq!(
        case.finalize(&UnreachablePublisher, stale_at)?,
        FindingFinalization::AwaitingEffects,
        "a landed impairment waits on signed effects without revalidating its old snapshot"
    );
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        case.deployment.challenges.advance_effect_intent(
            &case.retraction_key,
            state,
            stale_at + 1,
        )?;
    }
    assert_eq!(
        case.finalize(&UnreachablePublisher, stale_at + 2)?,
        FindingFinalization::AlreadyConfirmed
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Settled);
    Ok(())
}

#[test]
fn finding_challenge_a_superseded_sanction_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    // Another sanction recorded after the enforcement was signed and
    // fenced supersedes the one its penalty names. The head is still a
    // sanction, but it is not the exact authority this impairment binds.
    let head = case.head()?;
    case.deployment.challenges.record_governance_case(
        &chio_store_sqlite::FindingGovernanceCaseInput {
            case_id: "case-sanction-replacement-01",
            finding_id: &head.finding_id,
            listing_id: LISTING_ID,
            liability_key: &case.liability_key,
            case_kind: chio_store_sqlite::FindingGovernanceCaseKind::Sanction,
            case_state: "enforced",
            appeal_of_case_id: None,
            supersedes_case_id: Some(FIXTURE_SANCTION_CASE_ID),
            recorded_at: SETTLEMENT_NOW - 1,
        },
    )?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a superseded sanction authorizes no impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::AppealNotFinal(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "the impairment intent is never even dispatched"
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}

#[test]
fn finding_challenge_every_transient_publisher_failure_counts_one_attempt() -> TestResult {
    let case = finalizing_liability()?;
    for attempt in 1..=3_u64 {
        let refused = case
            .finalize_observing(
                &ScriptedObservations::qualified(),
                &UnreachableChainPublisher,
                SETTLEMENT_NOW + attempt,
            )?
            .expect_err("a publisher that cannot reach the chain reports no outcome");
        assert!(matches!(refused, ChallengeCoordinatorError::Publisher(_)));
        let intent = case.intent()?;
        assert_eq!(
            intent.attempt_count, attempt,
            "every dispatch an operator paid for is on the record"
        );
        assert_eq!(
            intent.state,
            FindingEffectIntentState::Failed,
            "the impairment stays dispatchable after a failure to reach the chain"
        );
    }
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_an_unpublished_enforcement_root_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability_rooted(EnforcementRoot::Unpublished)?;
    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("the vault call is authorized by a root that has not been published");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::EnforcementRootUnconfirmed(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "nothing was dispatched, so the impairment never left its fence"
    );
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_an_anchor_leaf_bound_elsewhere_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    // The same anchored receipt is already committed to other terms, which
    // is what a proof reused across enforcements looks like once the leaf
    // is fenced.
    case.deployment.challenges.record_effect_intent(
        &derive_anchor_evidence_intent_key(&anchor_evidence_hash()?),
        chio_store_sqlite::FindingEffectIntentKind::RootIntent,
        &digest("an impairment this proof already authorized"),
        Some(&case.liability_key),
        false,
        NOW + 7,
    )?;

    let refused = case
        .finalize_observing(
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("one anchored leaf authorizes one impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}

#[test]
fn finding_challenge_a_reorged_bond_observation_never_reaches_the_publisher() -> TestResult {
    let case = finalizing_liability()?;
    // The observer signed for a block the chain no longer carries at that
    // height, so what it reported about the collateral is unknown.
    let reorged = FindingBondObservationRecheck {
        block_hash: Some(chain_hash(0xcd)),
        ..qualified_observation()
    };

    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![reorged]),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )?
        .expect_err("a snapshot whose block was reorged out authorizes nothing");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Pending,
        "nothing was dispatched, so the intent never left its fence"
    );
    let parked = case.head()?;
    assert_eq!(parked.state, FindingLiabilityState::Finalizing);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

#[test]
fn finding_challenge_an_observer_cannot_weaken_deployment_finality() -> TestResult {
    let case = finalizing_liability()?;

    // The trusted observer signs a self-consistent snapshot at one
    // confirmation, then the finalization authority binds that exact
    // snapshot. The deployment still requires 64 confirmations, so neither
    // signature may weaken the operator-pinned chain policy.
    let mut snapshot_body = case.snapshot.body.clone();
    snapshot_body.finality_policy = "confirmations>=1".to_string();
    snapshot_body.observed_finality = FindingObservedFinality::Confirmations { depth: 1 };
    snapshot_body.snapshot_id = String::new();
    snapshot_body.snapshot_id = compute_snapshot_id(&snapshot_body)?;
    let snapshot = SignedExportEnvelope::sign(snapshot_body, &keypair(34))?;

    let mut enforcement_body = case.enforcement.body.clone();
    enforcement_body.bond_snapshot_envelope_sha256 = signed_envelope_sha256(&snapshot)?;
    enforcement_body.enforcement_id = String::new();
    enforcement_body.enforcement_id = compute_enforcement_id(&enforcement_body)?;
    let enforcement = SignedExportEnvelope::sign(enforcement_body, &keypair(32))?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &enforcement,
            &case.penalty,
            &snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &anchor_proof()?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("the observer cannot choose a shallower finality policy");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::Settlement(detail)
            if detail.contains("does not match the pinned finality requirement")
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}

#[test]
fn finding_challenge_an_operator_rotation_across_the_broadcast_never_settles() -> TestResult {
    let case = finalizing_liability()?;
    let publisher = MiningPublisher::new();

    // The first attempt broadcasts and comes back unmined, which leaves
    // the intent dispatchable.
    case.finalize(&publisher, SETTLEMENT_NOW)?;
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Failed);

    // The transaction then mines and finalizes, but the operator identity
    // the observation was qualified under rotated in the meantime. The
    // impairment is real and the intent confirms; the head must not.
    let rotated = FindingBondObservationRecheck {
        operator_key_epoch: 4,
        ..qualified_observation()
    };
    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![qualified_observation(), rotated]),
            &publisher,
            SETTLEMENT_NOW + 60,
        )?
        .expect_err("a rotated operator leaves the impairment for reconciliation");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert_eq!(
        case.intent_state()?,
        FindingEffectIntentState::Confirmed,
        "the transaction was proved to be this intent, so it is never redispatched"
    );
    let parked = case.head()?;
    assert_eq!(
        parked.state,
        FindingLiabilityState::Finalizing,
        "the head stays open for the operator who has to reconcile it"
    );
    assert!(parked.quarantined);
    assert!(case.deployment.purchases.sales_blocked(LISTING_ID)?);

    let still_rotated = FindingBondObservationRecheck {
        operator_key_epoch: 4,
        ..qualified_observation()
    };
    let refused = case
        .finalize_observing(
            &ScriptedObservations::then_qualified(vec![still_rotated]),
            &UnreachablePublisher,
            SETTLEMENT_NOW + 120,
        )?
        .expect_err("confirmed recovery must not bypass a quarantined observation");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::BondObservation(_)
    ));
    assert!(case.head()?.quarantined);

    let recovered = case.finalize_observing(
        &ScriptedObservations::qualified(),
        &UnreachablePublisher,
        SETTLEMENT_NOW + 180,
    )??;
    assert_eq!(recovered, FindingFinalization::AlreadyConfirmed);
    let settled = case.head()?;
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.quarantined);
    Ok(())
}

#[test]
fn finding_challenge_an_enforcement_naming_another_vault_never_reaches_the_publisher() -> TestResult
{
    let case = finalizing_liability()?;
    // An instruction, an observation, and a live contract read that all
    // agree with each other about a vault this liability was never opened
    // against. Every check downstream of the head is satisfied.
    let elsewhere = chain_hash(0x45);
    let (enforcement, snapshot) = enforcement_pair_at_vault(
        &case.liability_key,
        &case.enforcement.body.finding_id,
        &case.seller,
        &case.intent_key,
        &case.enforcement.body.penalty_envelope_sha256,
        &elsewhere,
    )?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &enforcement,
            &case.penalty,
            &snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot_for(&elsewhere),
            &anchor_proof()?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("one liability may only impair the vault it was opened against");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::LiabilityIdentity("vault_id")
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    assert_eq!(case.head()?.state, FindingLiabilityState::Finalizing);
    Ok(())
}

#[test]
fn finding_challenge_a_snapshot_from_an_expired_observer_key_authorizes_nothing() -> TestResult {
    let case = finalizing_liability()?;
    let mut config = market_config();
    config.settlement_observer.valid_until = case.snapshot.body.observed_at;
    let coordinator = case
        .deployment
        .coordinator_under(&config, FindingDisputeLockDisposition::Forfeited)?;

    let refused = coordinator
        .finalize(
            &case.liability_key,
            &case.enforcement,
            &case.penalty,
            &case.snapshot,
            &case.seller,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &anchor_proof()?,
            &ScriptedObservations::qualified(),
            &UnreachablePublisher,
            SETTLEMENT_NOW,
        )
        .expect_err("an expired observer key cannot authorize impairment");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::SettlementObserverLifecycle(_)
    ));
    assert_eq!(case.intent_state()?, FindingEffectIntentState::Pending);
    Ok(())
}

// ---------------------------------------------------------------------------
// The three class branches, each from real evidence to an enforced sanction
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_digest_mismatch_reaches_an_enforced_sanction() -> TestResult {
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
        std::collections::BTreeMap::from([(COMMUNITY_FUND_RAIL.to_string(), 300)])
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

#[test]
fn finding_challenge_evidence_invalid_reaches_an_enforced_sanction() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let challenger_sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let other_sale = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 50, NOW + 1)?;

    // The finding's own production evidence carries a signature that
    // belongs to another body, which is affirmative invalidity.
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &challenger_sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 3)?,
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
            NOW + 4,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(evaluated.outcome.body.reason, "evidence_signature_invalid");
    let FindingChallengeFacet::EvidenceInvalid(facet) = &evaluated.outcome.body.facet else {
        return Err("an evidence-invalid challenge carries an evidence-invalid facet".into());
    };
    assert_eq!(
        facet.invalidity,
        FindingEvidenceInvalidity::SignatureInvalid
    );

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        2,
        &[
            challenger_sale.purchase_key.clone(),
            other_sale.purchase_key.clone(),
        ],
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 5,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    assert_eq!(
        deployment
            .challenges
            .get_liability(&upheld.liability_key)?
            .ok_or("liability head is durable")?
            .purchase_cutoff_slot,
        Some(2)
    );

    // Two retained sales keep 100 units of exposure encumbered each, so the
    // checked candidate is the 300-unit base stake plus 200 units of open
    // encumbrance, inside the 5000-unit signed requirement.
    let sealed = &upheld.sealed;
    assert_eq!(sealed.total_realized_spend_units, 100);
    assert_eq!(sealed.distribution.slash, usd(500));
    assert_eq!(sealed.distribution.buyer_pool_units, 100);
    assert_eq!(sealed.distribution.community_fund_units, 400);
    let allocation = allocation_by_destination(&sealed.distribution);
    assert_eq!(
        allocation,
        std::collections::BTreeMap::from([
            (buyer_destination(41), 50),
            (buyer_destination(42), 50),
            (COMMUNITY_FUND_RAIL.to_string(), 400),
        ]),
        "each harmed buyer takes exactly its pro rata share and the remainder goes to the fund"
    );
    let summed: u64 = allocation.values().sum();
    assert_eq!(summed, sealed.distribution.slash.units);
    // The challenger filed this dispute and was also harmed by it. It is
    // paid as a buyer and nothing more: no bounty destination and no
    // challenge-administration pool appears in the distribution.
    assert!(!allocation.contains_key(CHALLENGER_BOUNTY_DESTINATION));
    assert!(!allocation.contains_key(CHALLENGE_POOL_DESTINATION));

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    assert_eq!(authorized.enforcement.body.amount, usd(500));
    assert_eq!(authorized.slash.penalty.body.penalty_amount, usd(500));
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    for destination in &authorized.enforcement.body.destinations {
        assert_ne!(destination.destination, CHALLENGER_BOUNTY_DESTINATION);
        assert_ne!(destination.destination, CHALLENGE_POOL_DESTINATION);
    }
    Ok(())
}

#[test]
fn finding_challenge_replay_contradiction_reaches_an_enforced_sanction() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;

    // The seller claimed the predicate holds; the reproduction shows the
    // candidate phase failing too.
    let case = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    assert_eq!(
        coordinator.admit_evaluation(&challenge_id, NOW + 2)?,
        EvaluationAdmission::Admitted
    );

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("a completed contradicting reproduction is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(
        evaluated.outcome.body.reason,
        "replay_contradiction_confirmed"
    );
    let FindingChallengeFacet::ReplayContradiction(facet) = &evaluated.outcome.body.facet else {
        return Err("a replay challenge carries a replay facet".into());
    };
    assert_eq!(
        facet.predicate_result,
        FindingReplayPredicateResult::ConfirmedContradiction
    );
    assert_eq!(facet.recipe_sha256, challenged.recipe_sha256);

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);
    assert_eq!(upheld.sealed.total_realized_spend_units, 60);
    // One retained sale keeps 100 units encumbered against the allocation.
    assert_eq!(upheld.sealed.distribution.slash, usd(400));
    assert_eq!(upheld.sealed.distribution.buyer_pool_units, 60);
    assert_eq!(
        allocation_by_destination(&upheld.sealed.distribution),
        std::collections::BTreeMap::from([
            (buyer_destination(41), 60),
            (COMMUNITY_FUND_RAIL.to_string(), 340),
        ])
    );

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        APPEAL_FINAL_AT,
    )?;
    assert_eq!(authorized.enforcement.body.amount, usd(400));
    assert_eq!(authorized.slash.penalty.body.penalty_amount, usd(400));
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The evaluator key's own lifecycle
// ---------------------------------------------------------------------------

#[test]
fn finding_market_configuration_validates_listing_and_snapshot_pins() -> TestResult {
    let mut duplicate_listing = market_config();
    duplicate_listing
        .listing
        .key_hex
        .clone_from(&duplicate_listing.venue.key_hex);
    assert!(duplicate_listing.validate().is_err());

    let mut circular_status_authority = market_config();
    circular_status_authority
        .authority_status
        .key_hex
        .clone_from(&circular_status_authority.governance_root.key_hex);
    assert!(circular_status_authority.validate().is_err());

    let mut unbounded_snapshot = market_config();
    unbounded_snapshot.max_snapshot_age_secs = 0;
    assert!(unbounded_snapshot.validate().is_err());
    Ok(())
}

#[test]
fn finding_challenge_an_evaluator_key_outside_its_pinned_lifecycle_signs_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let evidence = case.evidence();
    let at = NOW + 4;

    // The epoch the outcome carries states which key adjudicated, so a
    // caller may not declare one the pin does not hold.
    let mut request = evaluation_request(&case.challenge, &challenged, &evidence, &collateral, at);
    request.evaluator_key_epoch = PINNED_KEY_EPOCH + 1;
    assert!(matches!(
        coordinator
            .evaluate(&request)
            .expect_err("an epoch the pin does not carry adjudicates nothing"),
        ChallengeCoordinatorError::EvaluatorKeyEpoch
    ));

    // Status is returned by the injected resolver, then authenticated
    // against the independent status-authority pin. A governance-root
    // self-signature, another source, a revoked key, and a stale reading
    // all refuse before adjudication.
    let readings = [
        (
            TestAuthorityStatusResolver {
                status_ref_override: Some("revocations/some-other-roster".to_string()),
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status does not bind the configured pin",
        ),
        (
            TestAuthorityStatusResolver {
                revoked_authority: Some("challenge-evaluator".to_string()),
                ..TestAuthorityStatusResolver::live()
            },
            "key was revoked when the role acted",
        ),
        (
            TestAuthorityStatusResolver {
                observed_at_override: Some(at - 86_400),
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status is not a fresh post-action reading",
        ),
        (
            TestAuthorityStatusResolver {
                signer_seed: 1,
                ..TestAuthorityStatusResolver::live()
            },
            "revocation status signature is invalid",
        ),
    ];
    for (resolver, refused) in readings {
        let coordinator = deployment.coordinator_under_with_status(
            &market_config(),
            Arc::new(resolver),
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let request = evaluation_request(&case.challenge, &challenged, &evidence, &collateral, at);
        match coordinator
            .evaluate(&request)
            .expect_err("an unusable revocation status adjudicates nothing")
        {
            ChallengeCoordinatorError::EvaluatorRevocation(detail) => assert_eq!(detail, refused),
            other => return Err(format!("unexpected rejection for {refused}: {other}").into()),
        }
    }

    // A pin whose window has closed at the venue clock signs nothing, even
    // though the key material still matches.
    let mut retired = market_config();
    retired.challenge_evaluator.valid_until = at;
    let retired =
        deployment.coordinator_under(&retired, FindingDisputeLockDisposition::Forfeited)?;
    assert!(matches!(
        retired
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                at,
            ))
            .expect_err("an expired evaluator key adjudicates nothing"),
        ChallengeCoordinatorError::EvaluatorKeyWindow
    ));

    // None of that consumed an evaluation attempt against the challenge.
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("the challenge is durable")?
            .state,
        FindingChallengeState::Submitted
    );

    // The same adjudication under a live key signs an outcome carrying the
    // deployment's epoch.
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            at,
        ))?
        .ok_or("a live evaluator key adjudicates")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(evaluated.outcome.body.evaluator_key_epoch, PINNED_KEY_EPOCH);
    Ok(())
}

#[test]
fn finding_challenge_every_value_bearing_role_enforces_authenticated_lifecycle() -> TestResult {
    // Venue admission.
    {
        let deployment = deployment()?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let challenged = challenged_finding()?;
        let sale = settle_purchase(&deployment, "venue-life", BUYER_ONE_DESTINATION, 50, NOW)?;
        let case = evidence_invalid_case(
            &challenged,
            ProductionShape::ForeignSignature,
            &sale,
            Filing::Buyer,
        )?;
        live.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
        let revoked = deployment
            .coordinator_with_revoked_role("venue", FindingDisputeLockDisposition::Forfeited)?;
        let stake = usd(300);
        let required = usd(5_000);
        let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
        let evidence = case.evidence();
        assert!(matches!(
            revoked
                .evaluate(&evaluation_request(
                    &case.challenge,
                    &challenged,
                    &evidence,
                    &collateral,
                    NOW + 2,
                ))
                .expect_err("a revoked venue cannot authorize its admission"),
            ChallengeCoordinatorError::AuthorityLifecycle { role: "venue", .. }
        ));
    }

    // Bondless audit authorization.
    {
        let deployment = deployment()?;
        let revoked = deployment.coordinator_with_revoked_role(
            "audit-authority",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let challenge = venue_audit_challenge()?;
        let (_, raw) = finding_artifact()?;
        assert!(matches!(
            revoked
                .submit(&challenge, &raw, NOW)
                .expect_err("a revoked audit authority files no audit"),
            ChallengeCoordinatorError::AuthorityLifecycle { role: "audit", .. }
        ));
    }

    // Governance and penalty authorities both fail before a liability is
    // opened or sales are blocked.
    for (authority, role) in [("governance", "governance"), ("market-penalty", "penalty")] {
        let deployment = deployment()?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let ready = ready_to_uphold(&deployment, &live)?;
        let governance = governance()?;
        let revoked = deployment
            .coordinator_with_revoked_role(authority, FindingDisputeLockDisposition::Forfeited)?;
        let stake = usd(300);
        let required = usd(5_000);
        let refused = revoked
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
            .expect_err("a revoked authority opens no liability");
        assert!(matches!(
            refused,
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: actual,
                ..
            } if actual == role
        ));
        assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
        assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    }

    // Purchase records are authenticated before the sales-blocking
    // transaction starts.
    {
        let deployment = deployment()?;
        let sale = settle_purchase(&deployment, "purchase-life", BUYER_ONE_DESTINATION, 50, NOW)?;
        let live = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
        let ready = ready_to_uphold(&deployment, &live)?;
        let governance = governance()?;
        let revoked = deployment
            .coordinator_with_revoked_role("purchase", FindingDisputeLockDisposition::Forfeited)?;
        let stake = usd(300);
        let required = usd(5_000);
        assert!(matches!(
            revoked
                .uphold(
                    &ready.challenge_id,
                    &ready.challenge,
                    &ready.outcome,
                    &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
                    &market_terms(CLAIM_WINDOW_SECS)?,
                    1,
                    std::slice::from_ref(&sale.purchase_key),
                    &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
                    &governance.context(),
                    &governance.sanction_case,
                    NOW + 2,
                )
                .expect_err("a revoked purchase authority contributes no claim"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "purchase",
                ..
            }
        ));
        assert_eq!(liability_heads(&deployment, &ready.finding.finding_id)?, 0);
        assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    }

    // Finalization signs nothing under a revoked key.
    {
        let case = upheld_liability()?;
        let revoked = case.deployment.coordinator_with_revoked_role(
            "venue-finalization",
            FindingDisputeLockDisposition::Forfeited,
        )?;
        let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
        assert!(matches!(
            revoked
                .resolve_appeal(
                    &case.upheld.liability_key,
                    &case.outcome,
                    &identity,
                    &case.upheld.sealed,
                    &case.governance.context(),
                    &AppealDisposition::Final {
                        sanction_case: &case.governance.sanction_case,
                    },
                    &case.upheld.sanction_case_id,
                    &case.upheld.hold,
                    &hex64('7'),
                    APPEAL_FINAL_AT,
                )
                .expect_err("a revoked finalization authority signs no enforcement"),
            ChallengeCoordinatorError::AuthorityLifecycle {
                role: "finalization",
                ..
            }
        ));
    }
    Ok(())
}

#[test]
fn finding_challenge_listing_ceiling_comes_from_the_signed_schedule() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "ceiling", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    let stake = usd(300);
    let attacker_selected_ceiling = usd(50_000);
    let collateral = collateral_facts(
        &stake,
        &attacker_selected_ceiling,
        &deployment.allocation_id,
        5_000,
    );
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the challenge adjudicates")?;
    assert_eq!(
        evaluated
            .outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or("upheld outcome has a calculation")?
            .listing_required_amount_units,
        5_000,
        "the caller's inflated ceiling is not part of the calculation"
    );
    Ok(())
}

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

#[test]
fn finding_challenge_a_generic_digest_denial_cannot_sanction() -> TestResult {
    // No finding-delivery overlay: nothing establishes that the expectation
    // was the seller's own commitment or that the transform plan was frozen.
    assert_denial_cannot_sanction(
        &DenyShape {
            include_overlay: false,
            ..DenyShape::seller_origin()
        },
        "denial_not_seller_origin",
    )
}

#[test]
fn finding_challenge_an_output_policy_denial_cannot_sanction() -> TestResult {
    // The kernel compared the output against an expectation the operator
    // chose rather than the digest the signed finding committed.
    assert_denial_cannot_sanction(
        &DenyShape {
            expected_digest: Some(hex64('f')),
            ..DenyShape::seller_origin()
        },
        "denial_output_policy_expectation",
    )
}

// ---------------------------------------------------------------------------
// Cross-class pairings and the carried recipe preimage
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_every_cross_class_evidence_pairing_is_inadmissible() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;

    let digest = digest_mismatch_case(
        &deployment,
        &challenged,
        &DenyShape::seller_origin(),
        Filing::Buyer,
    )?;
    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    for challenge in [&digest.challenge, &invalid.challenge, &replay.challenge] {
        coordinator.submit(challenge, &challenged.raw_finding, NOW + 1)?;
    }

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = replay.reproductions();
    let bundles = [
        digest.evidence(),
        invalid.evidence(),
        replay.evidence(&reproductions),
    ];
    let challenges = [&digest.challenge, &invalid.challenge, &replay.challenge];

    for (challenge_index, challenge) in challenges.iter().enumerate() {
        for (bundle_index, bundle) in bundles.iter().enumerate() {
            if challenge_index == bundle_index {
                continue;
            }
            let evaluated = coordinator.evaluate(&evaluation_request(
                challenge,
                &challenged,
                bundle,
                &collateral,
                NOW + 2,
            ))?;
            assert!(
                evaluated.is_none(),
                "evidence from another class produces no verdict"
            );
            let record = deployment
                .challenges
                .get_challenge(&challenge.body.challenge_id)?
                .ok_or("the challenge is durable")?;
            assert_eq!(
                record.state,
                FindingChallengeState::Submitted,
                "an inadmissible submission never enters evaluation"
            );
            assert!(record.outcome_envelope_sha256.is_none());
        }
    }

    // The same three submissions adjudicate against the evidence their own
    // class selects, so the refusals above came from the pairing and not
    // from a submission that could never have been evaluated.
    for (challenge, bundle) in challenges.iter().zip(&bundles) {
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                challenge,
                &challenged,
                bundle,
                &collateral,
                NOW + 3,
            ))?
            .ok_or("the matching class pairing is admissible")?;
        assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    }
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        0
    );
    Ok(())
}

#[test]
fn finding_challenge_a_foreign_recipe_preimage_never_reaches_a_verdict() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;

    // A recipe that is canonical and binds the admitted profile, and is
    // not the recipe the finding committed.
    let mut foreign = replay_recipe(&challenged.profile_envelope_sha256);
    foreign.decision_rule_ref = "decision/replay-v2".to_string();
    let foreign_preimage = canonical_json_string(&foreign)?;
    assert_ne!(
        sha256_hex(foreign_preimage.as_bytes()),
        challenged.recipe_sha256
    );

    let phases = [PhaseShape::baseline_fails(), PhaseShape::candidate_fails()];
    let case = replay_case(
        &challenged,
        "foreign",
        &phases,
        Some(&foreign_preimage),
        &sale,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let reproductions = case.reproductions();
    let evidence = case.evidence(&reproductions);
    let evaluated = coordinator.evaluate(&evaluation_request(
        &case.challenge,
        &challenged,
        &evidence,
        &collateral,
        NOW + 2,
    ))?;
    assert!(
        evaluated.is_none(),
        "a preimage that is not the committed recipe is a different document"
    );
    let record = deployment
        .challenges
        .get_challenge(&case.challenge.body.challenge_id)?
        .ok_or("the challenge is durable")?;
    assert_eq!(record.state, FindingChallengeState::Submitted);
    assert!(record.outcome_envelope_sha256.is_none());

    // The same reproduction set against the committed recipe adjudicates,
    // so the refusal above is the preimage and nothing else.
    let committed = replay_case(&challenged, "committed", &phases, None, &sale)?;
    coordinator.submit(&committed.challenge, &challenged.raw_finding, NOW + 3)?;
    let reproductions = committed.reproductions();
    let evidence = committed.evidence(&reproductions);
    let adjudicated = coordinator
        .evaluate(&evaluation_request(
            &committed.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 4,
        ))?
        .ok_or("the committed recipe preimage is admissible")?;
    assert_eq!(adjudicated.state, FindingChallengeState::Upheld);
    Ok(())
}

#[test]
fn finding_challenge_a_malformed_recipe_preimage_is_refused_at_submission() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let sound = replay_case(
        &challenged,
        "sound",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    let FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        purchase_record_envelope_sha256,
        ..
    } = &sound.challenge.body.evidence
    else {
        return Err("a replay challenge carries a replay evidence branch".into());
    };

    // A preimage that is absent, and one whose bytes are not the canonical
    // encoding of the recipe they claim to be. Neither is the seller's
    // precommitment, so neither may open an adjudication at all.
    let non_canonical =
        serde_json::to_string_pretty(&replay_recipe(&challenged.profile_envelope_sha256))?;
    for preimage in [String::new(), non_canonical] {
        let branch = FindingChallengeEvidence::ReplayContradiction {
            reproduction: reproduction.clone(),
            recipe_preimage: preimage,
            purchase_record_envelope_sha256: purchase_record_envelope_sha256.clone(),
        };
        let authorization = challenged.buyer_authorization(
            "malformed",
            FindingChallengeStanding::FinalizedPurchase {
                purchase_key: sale.purchase_key.clone(),
                purchase_record_envelope_sha256: sale.record_envelope_sha256.clone(),
            },
        )?;
        let challenge = challenged.sign_challenge(
            authorization,
            branch,
            sound.challenge.body.affected_deliveries.clone(),
        )?;
        let refused = coordinator
            .submit(&challenge, &challenged.raw_finding, NOW + 1)
            .expect_err("a malformed recipe preimage is not a filing");
        let ChallengeCoordinatorError::ChallengeEnvelope(detail) = &refused else {
            return Err(format!("unexpected rejection: {refused}").into());
        };
        assert!(
            detail.contains("replay_contradiction.recipe_preimage"),
            "the carried preimage is what the validator refused: {detail}"
        );
        assert!(
            deployment
                .challenges
                .get_challenge(&challenge.body.challenge_id)?
                .is_none(),
            "a refused filing writes no challenge row"
        );
    }
    assert!(
        deployment.rail.charges().is_empty(),
        "a refused filing collects no dispute fee"
    );

    // The same filing carrying the committed preimage is admitted, so the
    // refusals above are the preimage and not the rest of the submission.
    coordinator.submit(&sound.challenge, &challenged.raw_finding, NOW + 1)?;
    assert!(deployment
        .challenges
        .get_challenge(&sound.challenge.body.challenge_id)?
        .is_some());
    Ok(())
}

// ---------------------------------------------------------------------------
// Payout derivation
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_harmed_buyer_allocation_is_capped_and_exactly_summed() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let challenger_sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let other_sale = settle_purchase(&deployment, "beta", BUYER_TWO_DESTINATION, 50, NOW + 1)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &challenger_sale,
        Filing::Buyer,
    )?;
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 2)?;

    // Live collateral below the checked candidate is the binding cap, and
    // it is below the verified harm as well, so every unit slashed reaches
    // a harmed buyer and none reaches the community fund.
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 80);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        2,
        &[
            challenger_sale.purchase_key.clone(),
            other_sale.purchase_key.clone(),
        ],
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    let sealed = &upheld.sealed;
    assert_eq!(sealed.distribution.slash, usd(80));
    assert_eq!(sealed.total_realized_spend_units, 100);
    assert_eq!(sealed.distribution.buyer_pool_units, 80);
    assert_eq!(sealed.distribution.community_fund_units, 0);
    let allocation = allocation_by_destination(&sealed.distribution);
    assert_eq!(
        allocation,
        std::collections::BTreeMap::from([
            (buyer_destination(41), 40),
            (buyer_destination(42), 40),
        ])
    );
    let summed: u64 = allocation.values().sum();
    assert_eq!(summed, sealed.distribution.slash.units);

    // Every destination in the distribution was admitted by the sale path.
    let admitted: Vec<String> = deployment
        .purchases
        .list_payout_destinations(&deployment.allocation_id)?
        .into_iter()
        .map(|(_, destination)| destination)
        .collect();
    for destination in allocation.keys() {
        assert!(
            admitted.contains(destination),
            "a payout destination that was never admitted must not be paid"
        );
    }
    assert!(!allocation.contains_key(CHALLENGER_BOUNTY_DESTINATION));
    Ok(())
}

#[test]
fn finding_challenge_a_payout_destination_that_was_never_admitted_is_refused() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase_with(
        &deployment,
        &deployment.allocation_id,
        "alpha",
        BUYER_ONE_DESTINATION,
        50,
        "USD",
        NOW,
        PayoutAdmission::Withheld,
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
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let refused = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )
    .expect_err("an unadmitted destination cannot be paid");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::UnadmittedPayoutDestination(_)
    ));
    let liability_key = derive_liability_key(
        &derive_defect_key(&challenged.finding.finding_id),
        VENUE_ID,
        &identity,
    );
    assert!(
        coordinator.sealed_claim(&liability_key)?.is_none(),
        "no accounting is sealed against a distribution that cannot be computed"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// A clean venue audit
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_a_clean_venue_audit_transfers_nothing() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::Sound,
        &sale,
        Filing::VenueAudit,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    let submitted = coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;
    assert!(submitted.dispute_fee_intent_key.is_none());
    assert!(submitted.dispute_bond_lock_id.is_none());

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
        .ok_or("a resolvable audit is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Rejected);
    assert_eq!(evaluated.outcome.body.reason, "challenged_evidence_valid");
    assert!(evaluated.outcome.body.penalty_calculation.is_none());
    assert_eq!(
        evaluated.bond_disposition, None,
        "a bondless audit has no disposition under any verdict"
    );

    assert!(
        deployment.rail.charges().is_empty(),
        "a clean audit moves nothing on the rail"
    );
    assert!(deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .is_none());
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        0
    );
    assert!(!deployment.purchases.sales_blocked(LISTING_ID)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Indeterminate results, the bounded retry, and the bond
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_an_indeterminate_result_retries_into_a_normal_verdict() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(&challenged, ProductionShape::Sound, &sale, Filing::Buyer)?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);

    // The resolver handed back a checkpoint that is not the artifact the
    // reference names. Nothing about the seller is established.
    let unresolved = case.unresolved_evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &unresolved,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("an unresolved input is still an adjudication")?;
    assert_eq!(
        first.outcome.body.verdict,
        chio_finding::FindingChallengeVerdict::Indeterminate
    );
    assert_eq!(
        first.outcome.body.reason,
        "evidence_checkpoint_not_established"
    );
    assert_eq!(first.state, FindingChallengeState::IndeterminateRetryable);
    assert_eq!(
        first.outcome.body.retry_deadline,
        Some(RETRY_POLICY_DEADLINE),
        "the evaluator signs the signed-artifact-derived retry horizon"
    );
    assert_eq!(
        deployment
            .challenges
            .get_challenge(&challenge_id)?
            .ok_or("challenge is durable")?
            .retry_deadline,
        Some(RETRY_POLICY_DEADLINE)
    );
    assert_eq!(first.bond_disposition, None);
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Locked,
        "an indeterminate result never forfeits an infrastructure failure"
    );

    // The retry resolves the same challenge against the artifact it names.
    let resolved = case.evidence();
    let second = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &resolved,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the retry adjudicates")?;
    assert_eq!(second.state, FindingChallengeState::Rejected);
    assert_eq!(second.outcome.body.reason, "challenged_evidence_valid");
    assert_eq!(
        second.bond_disposition,
        Some(FindingDisputeLockDisposition::Forfeited)
    );
    assert_eq!(
        deployment.rail.charges().len(),
        2,
        "a retry reuses the fee and bond funding identities"
    );
    Ok(())
}

#[test]
fn finding_challenge_retry_exhaustion_closes_indeterminate_and_returns_the_lock_once() -> TestResult
{
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(&challenged, ProductionShape::Sound, &sale, Filing::Buyer)?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let unresolved = case.unresolved_evidence();
    for (attempt, expected) in [
        (NOW + 2, FindingChallengeState::IndeterminateRetryable),
        (NOW + 3, FindingChallengeState::IndeterminateClosed),
    ] {
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &unresolved,
                &collateral,
                attempt,
            ))?
            .ok_or("an unresolved input is still an adjudication")?;
        assert_eq!(evaluated.state, expected);
        assert_eq!(
            evaluated.outcome.body.verdict,
            chio_finding::FindingChallengeVerdict::Indeterminate
        );
        if expected == FindingChallengeState::IndeterminateClosed {
            assert_eq!(evaluated.outcome.body.retry_deadline, None);
        }
    }

    // The single retry the store grants is spent, so a live window no
    // longer keeps the challenge open, and the lock comes back once.
    let lock = deployment
        .challenges
        .get_dispute_lock(&challenge_id)?
        .ok_or("lock is durable")?;
    assert_eq!(lock.state, FindingDisputeLockState::Returned);
    assert_eq!(
        coordinator.dispose_dispute_bond(&challenge_id, NOW + 4)?,
        Some(FindingDisputeLockDisposition::Returned),
        "replaying the disposition returns the same terminal"
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "an exhausted retry collects no second fee, funding, or return"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The nested replay mapping through the coordinator
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_the_nested_replay_mapping_holds_through_the_coordinator() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);

    let cases = [
        (
            vec![PhaseShape::baseline_fails(), PhaseShape::candidate_passes()],
            FindingReplayPredicateResult::Consistent,
            chio_finding::FindingChallengeVerdict::Rejected,
            FindingChallengeState::Rejected,
        ),
        (
            vec![PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
            FindingReplayPredicateResult::ConfirmedContradiction,
            chio_finding::FindingChallengeVerdict::Upheld,
            FindingChallengeState::Upheld,
        ),
        (
            vec![PhaseShape::baseline_fails()],
            FindingReplayPredicateResult::Indeterminate,
            chio_finding::FindingChallengeVerdict::Indeterminate,
            FindingChallengeState::IndeterminateRetryable,
        ),
    ];
    for (index, (phases, predicate_result, verdict, state)) in cases.into_iter().enumerate() {
        // Each filing posts its own exclusive lock, so the reproduction
        // sets reach the store as distinct challenges.
        let case = replay_case(
            &challenged,
            &format!("replay-{index}"),
            &phases,
            None,
            &sale,
        )?;
        coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

        let reproductions = case.reproductions();
        let evidence = case.evidence(&reproductions);
        let evaluated = coordinator
            .evaluate(&evaluation_request(
                &case.challenge,
                &challenged,
                &evidence,
                &collateral,
                NOW + 2,
            ))?
            .ok_or("every reproduction set above is admissible")?;
        assert_eq!(evaluated.outcome.body.verdict, verdict);
        assert_eq!(evaluated.state, state);
        let FindingChallengeFacet::ReplayContradiction(facet) = &evaluated.outcome.body.facet
        else {
            return Err("a replay challenge carries a replay facet".into());
        };
        assert_eq!(facet.predicate_result, predicate_result);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// One defect, one slash, across a duplicate filing and a restart
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_a_second_challenge_for_one_defect_authorizes_no_second_slash() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);

    // Two independent filings against the same defect: one contests the
    // evidence, the other reproduces the recipe.
    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    coordinator.submit(&invalid.challenge, &challenged.raw_finding, NOW + 1)?;
    coordinator.submit(&replay.challenge, &challenged.raw_finding, NOW + 1)?;

    let invalid_evidence = invalid.evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &invalid.challenge,
            &challenged,
            &invalid_evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the evidence filing is adjudicated")?;
    let reproductions = replay.reproductions();
    let replay_evidence = replay.evidence(&reproductions);
    let second = coordinator
        .evaluate(&evaluation_request(
            &replay.challenge,
            &challenged,
            &replay_evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;
    assert_eq!(first.state, FindingChallengeState::Upheld);
    assert_eq!(second.state, FindingChallengeState::Upheld);

    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &invalid.challenge,
        &first.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 4,
    )?;
    let refused = coordinator
        .uphold(
            &replay.challenge.body.challenge_id,
            &replay.challenge,
            &second.outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            1,
            std::slice::from_ref(&sale.purchase_key),
            &collateral,
            &governance.context(),
            &governance.sanction_case,
            NOW + 5,
        )
        .expect_err("one defect carries exactly one slashable liability");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));

    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1,
        "a second corroborating challenge joins the head rather than opening one"
    );
    let sealed = coordinator
        .sealed_claim(&upheld.liability_key)?
        .ok_or("the accounting is sealed once")?;
    assert_eq!(sealed.0, upheld.sealed.snapshot_digest);
    assert_eq!(sealed.1, upheld.sealed.allocation_digest);
    assert_eq!(
        deployment
            .challenges
            .get_liability(&upheld.liability_key)?
            .ok_or("liability head is durable")?
            .upheld_challenge_id,
        Some(invalid.challenge.body.challenge_id.clone()),
        "the head still names the challenge that carried it"
    );
    Ok(())
}

#[test]
fn finding_challenge_concurrent_upholds_authorize_one_slash() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let stake = usd(300);
    let required = usd(5_000);
    let collateral = collateral_facts(&stake, &required, &deployment.allocation_id, 5_000);
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let candidates = [sale.purchase_key.clone()];

    let invalid = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let replay = replay_case(
        &challenged,
        "replay",
        &[PhaseShape::baseline_fails(), PhaseShape::candidate_fails()],
        None,
        &sale,
    )?;
    coordinator.submit(&invalid.challenge, &challenged.raw_finding, NOW + 1)?;
    coordinator.submit(&replay.challenge, &challenged.raw_finding, NOW + 1)?;
    let invalid_evidence = invalid.evidence();
    let first = coordinator
        .evaluate(&evaluation_request(
            &invalid.challenge,
            &challenged,
            &invalid_evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("the evidence filing is adjudicated")?;
    let reproductions = replay.reproductions();
    let replay_evidence = replay.evidence(&reproductions);
    let second = coordinator
        .evaluate(&evaluation_request(
            &replay.challenge,
            &challenged,
            &replay_evidence,
            &collateral,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;

    // Both filings race the upheld transaction against the same liability
    // head, once at the call that opens the claim window and again at the
    // call that seals the payout past it. The compare-and-set admits one
    // of them and only one, in both races.
    let terms = market_terms(CLAIM_WINDOW_SECS)?;
    let race = |now: u64| {
        let filings = [
            (&invalid.challenge, &first.outcome),
            (&replay.challenge, &second.outcome),
        ];
        std::thread::scope(|scope| {
            let handles: Vec<_> = filings
                .into_iter()
                .map(|(challenge, outcome)| {
                    let coordinator = &coordinator;
                    let governance = &governance;
                    let identity = &identity;
                    let collateral = &collateral;
                    let candidates = &candidates;
                    let terms = &terms;
                    scope.spawn(move || {
                        coordinator.uphold(
                            &challenge.body.challenge_id,
                            challenge,
                            outcome,
                            identity,
                            terms,
                            1,
                            candidates,
                            collateral,
                            &governance.context(),
                            &governance.sanction_case,
                            now,
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(std::thread::ScopedJoinHandle::join)
                .collect::<Vec<_>>()
        })
    };

    let mut opened = 0_usize;
    for result in race(NOW + 4 - CLAIM_WINDOW_SECS) {
        if matches!(
            result.map_err(|_| "the upheld transaction panicked")?,
            Err(ChallengeCoordinatorError::ClaimWindowOpen)
        ) {
            opened += 1;
        }
    }
    assert_eq!(
        opened, 1,
        "one filing freezes the claim window and the other is refused"
    );

    let joined = race(NOW + 4);
    let mut upheld = Vec::new();
    let mut refused = 0_usize;
    for result in joined {
        match result.map_err(|_| "the upheld transaction panicked")? {
            Ok(liability) => upheld.push(liability),
            Err(_) => refused += 1,
        }
    }
    assert_eq!(upheld.len(), 1, "one defect authorizes exactly one slash");
    assert_eq!(refused, 1);
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1
    );

    let winner = upheld.first().ok_or("one filing carried the liability")?;
    let sealed = coordinator
        .sealed_claim(&winner.liability_key)?
        .ok_or("the accounting is sealed once")?;
    assert_eq!(sealed.0, winner.sealed.snapshot_digest);
    assert_eq!(sealed.1, winner.sealed.allocation_digest);
    assert_eq!(winner.sealed.distribution.buyer_pool_units, 50);
    Ok(())
}

#[test]
fn finding_challenge_a_restart_resumes_the_same_durable_state() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let sale = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 50, NOW)?;
    let case = evidence_invalid_case(
        &challenged,
        ProductionShape::ForeignSignature,
        &sale,
        Filing::Buyer,
    )?;
    let challenge_id = case.challenge.body.challenge_id.clone();
    coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 1)?;

    let stake = usd(300);
    let required = usd(5_000);
    let allocation_id = deployment.allocation_id.clone();
    let collateral = collateral_facts(&stake, &required, &allocation_id, 5_000);
    let evidence = case.evidence();
    let evaluated = coordinator
        .evaluate(&evaluation_request(
            &case.challenge,
            &challenged,
            &evidence,
            &collateral,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;
    let identity = liability_identity(&challenged.finding.finding_id, &allocation_id);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;

    drop(coordinator);
    let deployment = deployment.restart()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;

    // The durable state survives the restart exactly as it was left.
    let record = deployment
        .challenges
        .get_challenge(&challenge_id)?
        .ok_or("the challenge is durable")?;
    assert_eq!(record.state, FindingChallengeState::Upheld);
    assert_eq!(
        deployment
            .challenges
            .get_dispute_lock(&challenge_id)?
            .ok_or("lock is durable")?
            .state,
        FindingDisputeLockState::Returned
    );
    assert!(deployment.purchases.sales_blocked(LISTING_ID)?);

    // A resumed worker replays the filing and the upheld transaction. The
    // fee reconciles against the settled charge, the lock replays as the
    // same lock, and the penalty is the one already minted rather than a
    // second one.
    let resubmitted = coordinator.submit(&case.challenge, &challenged.raw_finding, NOW + 4)?;
    assert_eq!(
        resubmitted.write,
        chio_store_sqlite::FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        deployment.rail.charges().len(),
        3,
        "a restarted filing collects no second fee, funding, or return"
    );
    let replayed = coordinator.uphold(
        &challenge_id,
        &case.challenge,
        &evaluated.outcome,
        &identity,
        &market_terms(CLAIM_WINDOW_SECS)?,
        1,
        std::slice::from_ref(&sale.purchase_key),
        &collateral,
        &governance.context(),
        &governance.sanction_case,
        NOW + 3,
    )?;
    assert_eq!(replayed.liability_key, upheld.liability_key);
    assert_eq!(replayed.sealed, upheld.sealed);
    assert_eq!(
        replayed.hold.penalty_envelope_sha256, upheld.hold.penalty_envelope_sha256,
        "the replay re-derives the penalty it already minted"
    );
    assert_eq!(
        replayed.hold.evaluation.penalty_id,
        upheld.hold.evaluation.penalty_id
    );
    assert_eq!(
        liability_heads(&deployment, &challenged.finding.finding_id)?,
        1
    );
    Ok(())
}

#[test]
fn finding_challenge_construction_refuses_a_key_reused_across_roles() -> TestResult {
    let deployment = deployment()?;
    let mut config = market_config();
    // One key adjudicating and finalizing collapses the separation the
    // whole lane rests on.
    config.venue_finalization = authority_pin(31, "venue-finalization");
    let refused = FindingChallengeCoordinator::new(
        deployment.challenges.clone(),
        deployment.purchases.clone(),
        &config,
        keypair(31),
        keypair(31),
        keypair(33),
        Arc::new(TestAuthorityStatusResolver::live()),
        deployment.rail.clone(),
        deployment.filings.clone(),
        FindingDisputeLockDisposition::Forfeited,
    );
    match refused {
        Err(ChallengeCoordinatorError::Configuration(_)) => {}
        Err(other) => return Err(format!("unexpected rejection: {other}").into()),
        Ok(_) => return Err("a key reused across roles must not load".into()),
    }
    Ok(())
}

#[test]
fn finding_challenge_an_expired_reservation_neither_wedges_nor_inflates_the_claim() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, raw) = finding_artifact()?;
    let harmed = settle_purchase(&deployment, "alpha", BUYER_ONE_DESTINATION, 60, NOW)?;

    // A purchase that took the next slot and was then abandoned: nothing
    // settles it, denies it, or releases it, and its expiry passes before
    // adjudication. Without the expiry sweep it would hold slot two open
    // forever, and its encumbrance would inflate the sealed slash.
    deployment
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: "reservation-abandoned",
            purchase_intent_id: "intent-abandoned",
            authoritative_payment_operation_id: "payment-abandoned",
            payer_hex: &keypair(41).public_key().to_hex(),
            agent_id: "agent-buyer-01",
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            bid_envelope_sha256: &digest("bid-abandoned"),
            ask_digest: &digest("ask-abandoned"),
            admission_envelope_sha256: &deployment.admission_envelope_sha256,
            amount_units: 100,
            currency: "USD",
            expires_at: NOW + 5,
            encumbrance_id: "encumbrance-abandoned",
            allocation_id: &deployment.allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW + 1,
        })?;
    deployment
        .purchases
        .reserve_slot("reservation-abandoned", NOW + 1)?;

    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW + 2)?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id, 100, "USD")?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        NOW + 3,
    )?;

    let stake = usd(300);
    let required = usd(5_000);
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &challenge,
        &outcome,
        &liability_identity(&finding.finding_id, &deployment.allocation_id),
        2,
        &[harmed.purchase_key],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 7,
    )?;

    let reservation = deployment
        .purchases
        .get_reservation("reservation-abandoned")?
        .ok_or("abandoned reservation is durable")?;
    assert_eq!(
        reservation.state,
        chio_store_sqlite::FindingPurchaseReservationState::Expired,
        "the claim path retires the reservation instead of waiting on it"
    );
    // The sealed accounting reads live exposure only: the base stake plus
    // the settled sale's retained encumbrance, with nothing from the
    // reservation that could never settle.
    assert_eq!(upheld.sealed.distribution.slash.units, 400);
    assert_eq!(upheld.sealed.distribution.buyer_pool_units, 60);
    assert_eq!(upheld.sealed.total_realized_spend_units, 60);
    Ok(())
}

#[test]
fn finding_challenge_uphold_refuses_an_outcome_for_a_different_challenge() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let (finding, _) = finding_artifact()?;

    // Two distinct challenges on one finding and listing, each closed
    // upheld under its own signed outcome.
    let first = venue_audit_challenge()?;
    let mut second_body = first.body.clone();
    second_body.filed_at = NOW + 1;
    second_body.challenge_id = compute_challenge_id(&second_body)?;
    let second = SignedExportEnvelope::sign(second_body, &keypair(35))?;
    let mut outcomes = Vec::new();
    for (challenge, at) in [(&first, NOW), (&second, NOW + 1)] {
        deployment
            .challenges
            .submit_challenge(&chio_store_sqlite::FindingChallengeSubmission {
                challenge_id: &challenge.body.challenge_id,
                finding_id: &finding.finding_id,
                listing_id: LISTING_ID,
                challenge_envelope_sha256: &signed_envelope_sha256(challenge)?,
                authorization_branch:
                    chio_store_sqlite::FindingChallengeAuthorizationBranch::VenueAudit,
                evidence_class: chio_store_sqlite::FindingChallengeEvidenceClass::EvidenceInvalid,
                challenger_hex: None,
                submitted_at: at,
            })?;
        let outcome = upheld_outcome(challenge, &deployment.allocation_id, 0, "USD")?;
        close_challenge(
            &deployment,
            &challenge.body.challenge_id,
            FindingChallengeVerdict::Upheld,
            &signed_envelope_sha256(&outcome)?,
            at + 2,
        )?;
        outcomes.push(outcome);
    }
    let first_outcome = outcomes.remove(0);

    // The first challenge's outcome presented under the second
    // challenge's id: both are upheld on this finding and listing, so
    // only the envelope binding separates them.
    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&finding.finding_id, &deployment.allocation_id);
    let refused = coordinator
        .uphold(
            &second.body.challenge_id,
            &second,
            &first_outcome,
            &identity,
            &market_terms(CLAIM_WINDOW_SECS)?,
            0,
            &[],
            &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
            &governance.context(),
            &governance.sanction_case,
            NOW + 4,
        )
        .expect_err("an outcome upholds only the challenge its envelope digest names");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    assert_eq!(
        liability_heads(&deployment, &finding.finding_id)?,
        0,
        "a cross-bound outcome opens no liability"
    );

    // The true pair still upholds: the binding admits exactly the
    // challenge the outcome adjudicated.
    let upheld = uphold_across_claim_window(
        &coordinator,
        &market_terms(CLAIM_WINDOW_SECS)?,
        &first,
        &first_outcome,
        &identity,
        0,
        &[],
        &collateral_facts(&stake, &required, &deployment.allocation_id, 5_000),
        &governance.context(),
        &governance.sanction_case,
        NOW + 6,
    )?;
    assert_eq!(upheld.sealed.distribution.slash.units, 300);
    Ok(())
}
