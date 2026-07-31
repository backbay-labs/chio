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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chio_core::canonical_json_bytes;
use chio_core::canonical_json_string;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::merkle::MerkleTree;
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
    compute_allocation_id, compute_challenge_id, compute_enforcement_id,
    compute_failed_delivery_id, compute_finding_id, compute_profile_id, compute_snapshot_id,
    derive_purchase_key, sign_finding, signed_envelope_sha256, Finding, FindingAffectedDelivery,
    FindingAuthorityKeyPolicy, FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass,
    FindingBuyerSubmission, FindingChallenge, FindingChallengeAuthorization,
    FindingChallengeEnforcement, FindingChallengeEvidence, FindingChallengeFacet,
    FindingChallengeStanding, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingCheckpointRef, FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingEffectIntentBinding, FindingEnforcementDestination,
    FindingEvidenceClass, FindingEvidenceInvalidity, FindingFacetKind, FindingFailedDelivery,
    FindingFinalizedBondSnapshot, FindingGuaranteeClass, FindingHoldReleaseTerminal,
    FindingObservedFinality, FindingOutcomeClass, FindingPredicate, FindingPurchaseRecord,
    FindingReceiptRef, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingReplayObservation,
    FindingReplayPredicateResult, FindingReplayRecipeInput, FindingReplayReproduction,
    FindingReplayTerminalResult, FindingResourceCaps, FindingVaultReference,
    FindingVenueAuditAuthorization, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingChallengeOutcome, SignedFindingChallengeVerifierProfile,
    SignedFindingFailedDelivery, SignedFindingFinalizedBondSnapshot, SignedFindingPurchaseRecord,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_SCHEMA_V1, FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1,
    FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
    FINDING_PURCHASE_RECORD_SCHEMA_V1, FINDING_REPLAY_OBSERVATION_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
};
use chio_finding_challenge::{
    FindingChallengeClassEvidence, FindingDigestMismatchEvidence, FindingEvidenceInvalidEvidence,
    FindingReplayContradictionEvidence, FindingResolvedReproduction,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{
    build_checkpoint, build_inclusion_proof, checkpoint_body_sha256, checkpoint_log_id,
    KernelCheckpoint,
};
use chio_open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
    SignedOpenMarketFeeSchedule,
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
use chio_open_market::penalty::OpenMarketPenaltyEffectiveState;
use chio_settle::{
    settlement_devnet_rpc_egress_contract, EvmBondSnapshot, EvmTransactionReceipt,
    FindingImpairmentAttempt, FindingImpairmentOutcome, FindingImpairmentPublishError,
    FindingImpairmentPublisher, FindingImpairmentQuarantine, FindingVaultRejection,
    PreparedEvmCall, SettlementChainConfig, SettlementEvidenceConfig, SettlementFinalityStatus,
    SettlementOracleConfig, SettlementPolicyConfig, StoredImpairmentTransaction,
};
use chio_store_sqlite::finding_market_store::SqliteFindingMarketStore;
use chio_store_sqlite::{
    FindingChallengeState, FindingChallengeVerdict, FindingDisputeLockDisposition,
    FindingDisputeLockState, FindingEffectIntentState, FindingLiabilityState,
    FindingPurchaseDeliveryInput, FindingPurchaseReservationInput, SqliteAuthorityStore,
    SqliteFindingChallengeStore, SqliteFindingPurchaseStore,
};

use crate::trust_control::finding_challenge_coordinator::{
    derive_defect_key, derive_liability_key, AppealDisposition, AppealResolution,
    AuthorizedImpairment, ChallengeCoordinatorError, ChallengeEvaluationRequest,
    EvaluationAdmission, FindingChallengeCoordinator, FindingCollateralFacts, FindingFinalization,
    FindingLiabilityIdentity, FindingPenaltyGovernance, UpheldLiability,
};
use crate::trust_control::{FindingAuthorityPin, FindingMarketConfig, FindingPoolPin};
use crate::trust_control::{FindingRailInstruction, FindingRailObservation, FindingRailObserver};

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
const REGISTERED_EXPOSURE_CAP: u64 = 450;

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
const EVIDENCE_FIRST_SEQ: u64 = 100;
const EVIDENCE_LAST_SEQ: u64 = 101;
const DENY_AT: u64 = 1_745_000_000;
const DENY_CHECKPOINT_SEQ: u64 = 2;
const DENY_RECEIPT_SEQ: u64 = 200;
const REPLAY_AT: u64 = 1_746_000_000;
const REPLAY_CHECKPOINT_SEQ: u64 = 3;
const REPLAY_FIRST_SEQ: u64 = 300;
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
        key_epoch: 1,
        valid_from: 1,
        valid_until: u64::MAX,
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn market_config() -> FindingMarketConfig {
    FindingMarketConfig {
        venue_id: VENUE_ID.to_string(),
        venue: authority_pin(6, "venue"),
        governance_root: authority_pin(1, "governance"),
        verifier_report: authority_pin(15, "verifier-report"),
        collateral: authority_pin(4, "collateral"),
        purchase: authority_pin(16, "purchase"),
        failed_delivery: authority_pin(17, "failed-delivery"),
        challenge_evaluator: authority_pin(31, "challenge-evaluator"),
        venue_finalization: authority_pin(32, "venue-finalization"),
        market_penalty: authority_pin(33, "market-penalty"),
        settlement_observer: authority_pin(34, "settlement-observer"),
        audit_authority: authority_pin(35, "audit-authority"),
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
/// to move, so a test can prove which pool a charge actually reached.
#[derive(Default)]
struct RecordingRail {
    instructions: Mutex<Vec<FindingRailInstruction>>,
}

impl RecordingRail {
    fn charges(&self) -> Vec<FindingRailInstruction> {
        self.instructions
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl FindingRailObserver for RecordingRail {
    fn dispatch(
        &self,
        instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String> {
        if let Ok(mut guard) = self.instructions.lock() {
            guard.push(instruction.clone());
        }
        Ok(FindingRailObservation {
            instruction_sha256: digest("observation"),
            amount_units: instruction.amount_units,
            currency: instruction.currency.clone(),
            rail_destination: instruction.rail_destination.clone(),
            rail: "venue-ledger".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

struct Deployment {
    _temp: tempfile::TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    _authority: SqliteAuthorityStore,
    _market: SqliteFindingMarketStore,
    purchases: SqliteFindingPurchaseStore,
    challenges: SqliteFindingChallengeStore,
    allocation_id: String,
    rail: Arc<RecordingRail>,
}

fn deployment() -> Result<Deployment, AnyError> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database: PathBuf = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    secure_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let market = authority.finding_market_store();
    let purchases = authority.finding_purchase_store();
    let challenges = authority.finding_challenge_store();
    let allocation_id = consume_allocation(&market, LISTING_ID)?;
    purchases.register_community_fund_destination(&allocation_id, COMMUNITY_FUND_RAIL, NOW)?;
    Ok(Deployment {
        _temp: temp,
        database,
        lock_root,
        _authority: authority,
        _market: market,
        purchases,
        challenges,
        allocation_id,
        rail: Arc::new(RecordingRail::default()),
    })
}

impl Deployment {
    fn coordinator(
        &self,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<FindingChallengeCoordinator, AnyError> {
        Ok(FindingChallengeCoordinator::new(
            self.challenges.clone(),
            self.purchases.clone(),
            &market_config(),
            keypair(31),
            keypair(32),
            keypair(33),
            self.rail.clone(),
            failed_challenge_disposition,
        )?)
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
            _market,
            purchases,
            challenges,
            allocation_id,
            rail,
        } = self;
        // The serving lock lives on the open handles, so every one of them
        // closes before the database can be served again.
        drop(challenges);
        drop(purchases);
        drop(_market);
        drop(_authority);
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let market = authority.finding_market_store();
        let purchases = authority.finding_purchase_store();
        let challenges = authority.finding_challenge_store();
        Ok(Self {
            _temp,
            database,
            lock_root,
            _authority: authority,
            _market: market,
            purchases,
            challenges,
            allocation_id,
            rail,
        })
    }
}

fn consume_allocation(
    market: &SqliteFindingMarketStore,
    listing_id: &str,
) -> Result<String, AnyError> {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: keypair(4).public_key(),
        seller: keypair(22).public_key(),
        authorization_envelope_sha256: hex64('1'),
        finding_id: finding_artifact()?.0.finding_id,
        listing_id: listing_id.to_string(),
        terms_envelope_sha256: hex64('2'),
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
    let signed = SignedExportEnvelope::sign(backing.clone(), &keypair(4))?;
    let envelope = String::from_utf8(canonical_json_bytes(&signed)?)?;
    market.register_allocation(&envelope, &backing, NOW)?;
    market.consume_allocation(&backing.allocation_id)?;
    Ok(backing.allocation_id)
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
    ) -> FindingChallengeAuthorization {
        let buyer = keypair(41);
        FindingChallengeAuthorization::BuyerSubmission(Box::new(FindingBuyerSubmission {
            challenger: buyer.public_key(),
            dispute_fee_terminal: FindingDisputeFeeTerminal {
                fee_schedule_envelope_sha256: hex64('5'),
                event: FindingDisputeFeeEvent::ChallengeFiling,
                payer: buyer.public_key(),
                amount: usd(25),
                beneficiary_pool_principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
                rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
            },
            dispute_lock_ref: FindingDisputeLockRef {
                lock_id: format!("dispute-lock-{lock_tag}"),
                class: FindingDisputeBondClass::Dispute,
                fee_schedule_envelope_sha256: hex64('5'),
                amount: usd(40),
                expiry: NOW + 86_400,
            },
            standing,
        }))
    }

    fn venue_authorization(&self) -> FindingChallengeAuthorization {
        FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
            audit_epoch_envelope_sha256: hex64('1'),
            selection_digest: hex64('2'),
            authorization_digest: hex64('3'),
        })
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
            terms_envelope_sha256: hex64('2'),
            profile_envelope_sha256: self.profile_envelope_sha256.clone(),
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
}

impl DigestMismatchCase {
    fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        FindingChallengeClassEvidence::DigestMismatch(FindingDigestMismatchEvidence {
            failed_delivery: &self.failed_delivery,
            deny_receipt: &self.deny_receipt,
            deny_checkpoint: &self.deny_checkpoint,
        })
    }
}

fn digest_mismatch_case(
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
            ),
            vec![ChallengedFinding::affected_delivery(
                &deny_receipt_ref,
                &deny_checkpoint_ref,
            )],
        ),
        Filing::VenueAudit => (challenged.venue_authorization(), Vec::new()),
    };
    Ok(DigestMismatchCase {
        challenge: challenged.sign_challenge(authorization, evidence, affected)?,
        failed_delivery,
        deny_receipt,
        deny_checkpoint,
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
    /// A checkpoint carrying the named identity but not the artifact the
    /// reference names, which is an unresolved input rather than a
    /// contradiction.
    unresolved_checkpoint: KernelCheckpoint,
}

impl EvidenceInvalidCase {
    fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        self.evidence_against(&self.checkpoint)
    }

    fn unresolved_evidence(&self) -> FindingChallengeClassEvidence<'_> {
        self.evidence_against(&self.unresolved_checkpoint)
    }

    fn evidence_against<'a>(
        &'a self,
        checkpoint: &'a KernelCheckpoint,
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
            purchase_record: &self.purchase_record,
            challenged_receipts: &self.receipts,
            challenged_checkpoint: checkpoint,
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
            ),
            vec![ChallengedFinding::affected_delivery(
                &first_ref,
                &evidence.reference,
            )],
        ),
        Filing::VenueAudit => (challenged.venue_authorization(), Vec::new()),
    };
    Ok(EvidenceInvalidCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
        receipts: evidence.receipts,
        checkpoint: evidence.checkpoint,
        unresolved_checkpoint,
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
}

impl ReplayCase {
    fn reproductions(&self) -> Vec<FindingResolvedReproduction<'_>> {
        self.receipts
            .iter()
            .map(|receipt| FindingResolvedReproduction {
                receipt,
                checkpoint: &self.checkpoint,
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
    );
    let affected = vec![ChallengedFinding::affected_delivery(
        &receipt_reference(
            resolved
                .first()
                .ok_or("a reproduction set is never empty")?,
        ),
        &checkpoint_ref,
    )];
    Ok(ReplayCase {
        challenge: challenged.sign_challenge(authorization, branch, affected)?,
        purchase_record: standing.record.clone(),
        receipts: resolved,
        checkpoint,
    })
}

fn buyer_challenge(buyer: &Keypair) -> Result<SignedFindingChallenge, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let mut body = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw.as_bytes()),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
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
                    fee_schedule_envelope_sha256: hex64('5'),
                    event: FindingDisputeFeeEvent::ChallengeFiling,
                    payer: buyer.public_key(),
                    amount: usd(25),
                    beneficiary_pool_principal_id: CHALLENGE_POOL_PRINCIPAL.to_string(),
                    rail_destination: CHALLENGE_POOL_DESTINATION.to_string(),
                },
                dispute_lock_ref: FindingDisputeLockRef {
                    lock_id: "dispute-lock-01".to_string(),
                    class: FindingDisputeBondClass::Dispute,
                    fee_schedule_envelope_sha256: hex64('5'),
                    amount: usd(40),
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

fn venue_audit_challenge() -> Result<SignedFindingChallenge, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let mut body = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw.as_bytes()),
        listing_id: LISTING_ID.to_string(),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
        backing_envelope_sha256: hex64('6'),
        filed_at: NOW,
        affected_deliveries: Vec::new(),
        authorization: FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
            audit_epoch_envelope_sha256: hex64('1'),
            selection_digest: hex64('2'),
            authorization_digest: hex64('3'),
        }),
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
        tag,
        destination,
        realized_spend_units,
        now,
        PayoutAdmission::Admitted,
    )
}

fn settle_purchase_with(
    deployment: &Deployment,
    tag: &str,
    destination: &str,
    realized_spend_units: u64,
    now: u64,
    admission: PayoutAdmission,
) -> Result<SettledPurchase, AnyError> {
    let (finding, _) = finding_artifact()?;
    let reservation_id = format!("reservation-{tag}");
    let payment_operation_id = format!("payment-{tag}");
    let bid = digest(&format!("bid-{tag}"));
    let buyer = keypair(41);
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
            admission_envelope_sha256: &hex64('c'),
            amount_units: 100,
            currency: "USD",
            expires_at: now + 3_600,
            encumbrance_id: &format!("encumbrance-{tag}"),
            allocation_id: &deployment.allocation_id,
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
        venue_admission_envelope_sha256: hex64('c'),
        accepted_price: usd(100),
        realized_spend: usd(realized_spend_units),
        seller_backing_envelope_sha256: hex64('6'),
        encumbrance_id: format!("encumbrance-{tag}"),
        delivery_receipt_id: format!("receipt-delivery-{tag}"),
        payment_reference: payment_operation_id,
        payout_destination: destination.to_string(),
        recorded_at: now,
    };
    record.validate()?;
    let purchase_key = record.purchase_key.clone();
    let signed = SignedFindingPurchaseRecord::sign(record, &keypair(16))?;
    let record_json = canonical_json_bytes(&signed)?;
    let record_sha256 = sha256_hex(&record_json);
    if admission == PayoutAdmission::Admitted {
        deployment.purchases.admit_payout_destination(
            &deployment.allocation_id,
            destination,
            now,
        )?;
    }
    deployment
        .purchases
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &reservation_id,
            purchase_key: &purchase_key,
            record_json: &record_json,
            record_sha256: &record_sha256,
            delivery_receipt_id: &format!("receipt-delivery-{tag}"),
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
            penalty_expires_at: Some(NOW + 100_000),
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
            opened_at: Some(NOW - 600),
            updated_at: Some(NOW - 600),
            expires_at: Some(NOW + 900_000),
            note: None,
        },
        NOW - 600,
    )?;
    Ok(SignedGenericGovernanceCase::sign(artifact, signer)?)
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
            dispute_fee: usd(25),
            market_participation_fee: usd(500),
            bond_requirements: vec![OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Listing,
                required_amount: usd(5_000),
                collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                slashable: true,
            }],
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
    FindingCollateralFacts {
        base_finding_stake: stake,
        listing_required_amount: required,
        live_allocated_collateral_units: live,
        allocation_id,
    }
}

/// One adjudication request over real evidence, at the venue clock.
fn evaluation_request<'a>(
    challenge: &'a SignedFindingChallenge,
    challenged: &'a ChallengedFinding,
    evidence: &'a FindingChallengeClassEvidence<'a>,
    allocation_id: &'a str,
    collateral: &'a FindingCollateralFacts<'a>,
    retry_deadline: Option<u64>,
    now: u64,
) -> ChallengeEvaluationRequest<'a> {
    ChallengeEvaluationRequest {
        challenge,
        raw_finding: &challenged.raw_finding,
        profile: &challenged.profile,
        evidence,
        backing_allocation_id: allocation_id,
        collateral,
        retry_deadline,
        evaluator_key_epoch: 1,
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
) -> Result<chio_finding::SignedFindingChallengeOutcome, AnyError> {
    let mut outcome = chio_finding::FindingChallengeOutcome {
        schema: chio_finding::FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_string(),
        outcome_id: String::new(),
        challenge_envelope_sha256: signed_envelope_sha256(challenge)?,
        finding_id: challenge.body.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        backing_allocation_id: allocation_id.to_string(),
        authorization: challenge.body.authorization.kind(),
        evidence_kind: challenge.body.evidence.kind(),
        verifier_profile_envelope_sha256: hex64('3'),
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
            open_per_sale_encumbrance_units: 0,
            computed_exposure_units: 300,
            listing_required_amount_units: 5_000,
            live_allocated_collateral_units: 5_000,
            penalty_amount: usd(300),
        }),
        evaluator_key_epoch: 1,
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
    assert_eq!(charges.len(), 1, "one filing, one dispute-fee charge");
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
        1,
        "a replayed filing reconciles against the settled charge"
    );
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

    // An indeterminate verdict inside a signed retry window retains the
    // same lock: no forfeiture, no return, no second charge.
    let state = close_challenge(
        &deployment,
        &challenge_id,
        FindingChallengeVerdict::Indeterminate {
            retry_deadline: Some(NOW + 100),
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
    let admission = coordinator.admit_evaluation(&challenge_id, NOW + 200)?;
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
        coordinator.dispose_dispute_bond(&challenge_id, NOW + 201)?,
        Some(FindingDisputeLockDisposition::Returned)
    );
    assert_eq!(
        deployment.rail.charges().len(),
        1,
        "a retry reuses the same fee identity and charges nothing further"
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
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        &signed_envelope_sha256(&outcome)?,
        NOW + 3,
    )?;

    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&finding.finding_id, &deployment.allocation_id);
    let upheld = coordinator.uphold(
        &challenge.body.challenge_id,
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
    outcome: SignedFindingChallengeOutcome,
}

fn ready_to_uphold(
    deployment: &Deployment,
    coordinator: &FindingChallengeCoordinator,
) -> Result<ReadyToUphold, AnyError> {
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW)?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id)?;
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
        outcome,
    })
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
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
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
            &ready.outcome,
            &liability_identity(&ready.finding.finding_id, &deployment.allocation_id),
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
        NOW + 20,
    )?;
    let AppealResolution::Finalizing(authorized) = resolution else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };
    assert_eq!(
        authorized.slash.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
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
        4,
        "seller impairment, root anchor, retraction, and the bond disposition"
    );
    for intent in &intents {
        assert_eq!(intent.state, FindingEffectIntentState::Pending);
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
    assert_eq!(authorized.effect_intent_keys.len(), 4);

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
            NOW + 20,
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

    let refused = resolve_final(&case, &elsewhere, &case.outcome, NOW + 20)
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

    let refused = resolve_final(&case, &identity, &rejected, NOW + 20)
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

    let refused = resolve_final(&case, &identity, &substituted, NOW + 20)
        .expect_err("only the recorded adjudication may authorize the impairment");
    assert!(matches!(refused, ChallengeCoordinatorError::OutcomeBinding));
    Ok(())
}

#[test]
fn finding_challenge_a_second_appeal_finality_collides_on_the_root_intent() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let AppealResolution::Finalizing(first) =
        resolve_final(&case, &identity, &case.outcome, NOW + 20)?
    else {
        return Err("appeal finality with no reversal authorizes the impairment".into());
    };

    // A replay off a re-minted penalty carries a different penalty
    // envelope. The intent is keyed on the liability rather than on that
    // envelope, so the second one collides with what is already durable.
    let refused = resolve_final(&case, &identity, &case.outcome, NOW + 40)
        .expect_err("one liability authorizes one enforcement");
    assert!(matches!(
        refused,
        ChallengeCoordinatorError::ChallengeStore(_)
    ));
    let intents = case
        .deployment
        .challenges
        .list_effect_intents(&case.upheld.liability_key)?;
    assert_eq!(
        intents.len(),
        4,
        "the replay records no fifth intent beside the four already fenced"
    );
    assert_eq!(first.effect_intent_keys.len(), 4);
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
        policy: SettlementPolicyConfig::default(),
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
}

impl FindingImpairmentPublisher for MiningPublisher {
    fn publish(
        &self,
        _intent: &chio_settle::FindingImpairmentIntent,
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
        Ok(FindingImpairmentAttempt::Observed {
            stored: StoredImpairmentTransaction {
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
        })
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
    enforcement: SignedFindingChallengeEnforcement,
    snapshot: SignedFindingFinalizedBondSnapshot,
}

fn finalizing_liability() -> Result<FinalizingLiability, AnyError> {
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
        NOW + 2,
    )?;
    deployment.challenges.begin_appeal_window(
        &liability_key,
        FindingLiabilityState::UpheldPendingClaims,
        NOW + 3,
    )?;
    deployment.challenges.begin_finalizing(
        &liability_key,
        FindingLiabilityState::PendingAppeal,
        NOW + 4,
    )?;

    let seller = keypair(73).public_key();
    let intent_key = byte_hex64(0xc1);
    deployment.challenges.record_effect_intent(
        &intent_key,
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair,
        &byte_hex64(0xd1),
        Some(&liability_key),
        NOW + 5,
    )?;
    let (enforcement, snapshot) =
        enforcement_pair(&liability_key, &finding.finding_id, &seller, &intent_key)?;
    Ok(FinalizingLiability {
        deployment,
        coordinator,
        liability_key,
        seller,
        intent_key,
        enforcement,
        snapshot,
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
        Ok(self.coordinator.finalize(
            &self.liability_key,
            &self.enforcement,
            &self.snapshot,
            &self.seller,
            MAX_SNAPSHOT_AGE_SECS,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot(),
            &anchor_proof()?,
            publisher,
            now,
        )?)
    }

    fn intent_state(&self) -> Result<FindingEffectIntentState, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_effect_intent(&self.intent_key)?
            .ok_or("the impairment intent is durable")?
            .state)
    }

    fn head(&self) -> Result<chio_store_sqlite::FindingLiabilityRecord, AnyError> {
        Ok(self
            .deployment
            .challenges
            .get_liability(&self.liability_key)?
            .ok_or("liability head is durable")?)
    }
}

/// The exact settlement pair the choke point verifies, plus the finding
/// and listing identities the liability head must carry.
fn enforcement_pair(
    liability_key: &str,
    finding_id: &str,
    seller: &PublicKey,
    seller_impair_intent_id: &str,
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
        operator_key_epoch: 3,
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
        penalty_envelope_sha256: byte_hex64(0xb5),
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
                intent_id: byte_hex64(0xc2),
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
        &elsewhere,
    )?;

    let refused = case
        .coordinator
        .finalize(
            &case.liability_key,
            &enforcement,
            &snapshot,
            &case.seller,
            MAX_SNAPSHOT_AGE_SECS,
            &settlement_config()?,
            &settlement_config()?.operator_address,
            &evm_vault_snapshot_for(&elsewhere),
            &anchor_proof()?,
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

// ---------------------------------------------------------------------------
// The three class branches, each from real evidence to an enforced sanction
// ---------------------------------------------------------------------------

#[test]
fn finding_challenge_digest_mismatch_reaches_an_enforced_sanction() -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(&challenged, &DenyShape::seller_origin(), Filing::Buyer)?;
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
            &deployment.allocation_id,
            &collateral,
            None,
            NOW + 2,
        ))?
        .ok_or("an authenticated seller-origin mismatch is adjudicated")?;
    assert_eq!(evaluated.state, FindingChallengeState::Upheld);
    assert_eq!(
        evaluated.outcome.body.verdict,
        chio_finding::FindingChallengeVerdict::Upheld
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

    // The denied reveal never took a slot, so the cutoff is the empty line
    // and the claim window is trivially closed.
    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = coordinator.uphold(
        &challenge_id,
        &evaluated.outcome,
        &identity,
        0,
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
    assert_eq!(liability.purchase_cutoff_slot, Some(0));
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
        NOW + 20,
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
            &deployment.allocation_id,
            &collateral,
            None,
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
    let upheld = coordinator.uphold(
        &challenge_id,
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
            (BUYER_ONE_DESTINATION.to_string(), 50),
            (BUYER_TWO_DESTINATION.to_string(), 50),
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
        NOW + 20,
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
            &deployment.allocation_id,
            &collateral,
            None,
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
    let upheld = coordinator.uphold(
        &challenge_id,
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
            (BUYER_ONE_DESTINATION.to_string(), 60),
            (COMMUNITY_FUND_RAIL.to_string(), 340),
        ])
    );

    let authorized = impair_after_appeal(
        &coordinator,
        &governance,
        &upheld,
        &evaluated.outcome,
        &identity,
        NOW + 20,
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
// Denials that look like fraud and are not
// ---------------------------------------------------------------------------

/// Adjudicate one digest-mismatch denial and prove it reached the seller
/// sanction gate nowhere: no liability, no penalty, no block.
fn assert_denial_cannot_sanction(shape: &DenyShape, expected_reason: &str) -> TestResult {
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let governance = governance()?;
    let challenged = challenged_finding()?;
    let case = digest_mismatch_case(&challenged, shape, Filing::Buyer)?;
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
            &deployment.allocation_id,
            &collateral,
            None,
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
            &evaluated.outcome,
            &identity,
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

    let digest = digest_mismatch_case(&challenged, &DenyShape::seller_origin(), Filing::Buyer)?;
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
                &deployment.allocation_id,
                &collateral,
                None,
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
                FindingChallengeState::Evaluating,
                "an inadmissible submission never advances to a verdict state"
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
                &deployment.allocation_id,
                &collateral,
                None,
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
        &deployment.allocation_id,
        &collateral,
        None,
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
    assert_eq!(record.state, FindingChallengeState::Evaluating);
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
            &deployment.allocation_id,
            &collateral,
            None,
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
        );
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
            &deployment.allocation_id,
            &collateral,
            None,
            NOW + 3,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let upheld = coordinator.uphold(
        &case.challenge.body.challenge_id,
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
            (BUYER_ONE_DESTINATION.to_string(), 40),
            (BUYER_TWO_DESTINATION.to_string(), 40),
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
        "alpha",
        BUYER_ONE_DESTINATION,
        50,
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
            &deployment.allocation_id,
            &collateral,
            None,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;

    let identity = liability_identity(&challenged.finding.finding_id, &deployment.allocation_id);
    let refused = coordinator
        .uphold(
            &case.challenge.body.challenge_id,
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
            &deployment.allocation_id,
            &collateral,
            None,
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
            &deployment.allocation_id,
            &collateral,
            Some(NOW + 1_000),
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
            &deployment.allocation_id,
            &collateral,
            Some(NOW + 1_000),
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
        1,
        "a retry reuses the same fee identity and charges nothing further"
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
                &deployment.allocation_id,
                &collateral,
                Some(NOW + 1_000),
                attempt,
            ))?
            .ok_or("an unresolved input is still an adjudication")?;
        assert_eq!(evaluated.state, expected);
        assert_eq!(
            evaluated.outcome.body.verdict,
            chio_finding::FindingChallengeVerdict::Indeterminate
        );
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
        1,
        "an exhausted retry collects no second fee"
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
            FindingChallengeState::IndeterminateClosed,
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
                &deployment.allocation_id,
                &collateral,
                None,
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
            &deployment.allocation_id,
            &collateral,
            None,
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
            &deployment.allocation_id,
            &collateral,
            None,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;
    assert_eq!(first.state, FindingChallengeState::Upheld);
    assert_eq!(second.state, FindingChallengeState::Upheld);

    let upheld = coordinator.uphold(
        &invalid.challenge.body.challenge_id,
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
            &second.outcome,
            &identity,
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
            &deployment.allocation_id,
            &collateral,
            None,
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
            &deployment.allocation_id,
            &collateral,
            None,
            NOW + 3,
        ))?
        .ok_or("the replay filing is adjudicated")?;

    // Both filings race the upheld transaction against the same liability
    // head. The compare-and-set admits one of them and only one.
    let filings = [
        (&invalid.challenge.body.challenge_id, &first.outcome),
        (&replay.challenge.body.challenge_id, &second.outcome),
    ];
    let joined = std::thread::scope(|scope| {
        let handles: Vec<_> = filings
            .into_iter()
            .map(|(challenge_id, outcome)| {
                let coordinator = &coordinator;
                let governance = &governance;
                let identity = &identity;
                let collateral = &collateral;
                let candidates = &candidates;
                scope.spawn(move || {
                    coordinator.uphold(
                        challenge_id,
                        outcome,
                        identity,
                        1,
                        candidates,
                        collateral,
                        &governance.context(),
                        &governance.sanction_case,
                        NOW + 4,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(std::thread::ScopedJoinHandle::join)
            .collect::<Vec<_>>()
    });

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
            &allocation_id,
            &collateral,
            None,
            NOW + 2,
        ))?
        .ok_or("a receipt that does not verify is adjudicated")?;
    let identity = liability_identity(&challenged.finding.finding_id, &allocation_id);
    let upheld = coordinator.uphold(
        &challenge_id,
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
        1,
        "a restarted filing collects no second dispute fee"
    );
    let replayed = coordinator.uphold(
        &challenge_id,
        &evaluated.outcome,
        &identity,
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
        deployment.rail.clone(),
        FindingDisputeLockDisposition::Forfeited,
    );
    match refused {
        Err(ChallengeCoordinatorError::Configuration(_)) => {}
        Err(other) => return Err(format!("unexpected rejection: {other}").into()),
        Ok(_) => return Err("a key reused across roles must not load".into()),
    }
    Ok(())
}
