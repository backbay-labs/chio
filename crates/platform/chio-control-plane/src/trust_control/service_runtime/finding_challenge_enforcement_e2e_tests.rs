//! End-to-end coverage for the finding challenge and audit lane: a buyer
//! files a challenge and pays for it, a venue audit files one and pays
//! nothing, a verdict disposes the bond it earned, an upheld verdict
//! blocks the listing and freezes the purchase cutoff, the sealed
//! accounting sums exactly, the three penalty branches hold, reverse, and
//! slash, an unresolved appeal quarantines instead of impairing, and an
//! ambiguous impairment leaves the liability parked with purchases still
//! denied.
//!
//! One sqlite authority store backs the market, purchase, and challenge
//! stores, so the upheld transaction runs against the same connection and
//! the same serving-owner fence the sale path uses.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chio_core::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    compute_allocation_id, compute_enforcement_id, compute_finding_id, compute_snapshot_id,
    derive_purchase_key, sign_finding, signed_envelope_sha256, Finding, FindingBondBacking,
    FindingBondClass, FindingBuyerSubmission, FindingChallenge, FindingChallengeAuthorization,
    FindingChallengeEnforcement, FindingChallengeEvidence, FindingChallengeStanding,
    FindingCheckpointRef, FindingCollateralVault, FindingDescriptor, FindingDisputeBondClass,
    FindingDisputeFeeEvent, FindingDisputeFeeTerminal, FindingDisputeLockRef,
    FindingEffectIntentBinding, FindingEnforcementDestination, FindingEvidenceClass,
    FindingFinalizedBondSnapshot, FindingGuaranteeClass, FindingObservedFinality,
    FindingOutcomeClass, FindingPurchaseRecord, FindingReceiptRef, FindingVaultReference,
    FindingVenueAuditAuthorization, SignedFindingChallenge, SignedFindingChallengeEnforcement,
    SignedFindingFinalizedBondSnapshot, SignedFindingPurchaseRecord,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1,
    FINDING_CHALLENGE_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
    FINDING_PURCHASE_RECORD_SCHEMA_V1, FINDING_SCHEMA_V1,
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
    settlement_devnet_rpc_egress_contract, EvmBondSnapshot, FindingImpairmentAttempt,
    FindingImpairmentOutcome, FindingImpairmentPublishError, FindingImpairmentPublisher,
    FindingImpairmentQuarantine, FindingVaultRejection, PreparedEvmCall, SettlementChainConfig,
    SettlementEvidenceConfig, SettlementOracleConfig, SettlementPolicyConfig,
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
    ChallengeCoordinatorError, EvaluationAdmission, FindingChallengeCoordinator,
    FindingCollateralFacts, FindingLiabilityIdentity, FindingPenaltyGovernance,
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
const NOW: u64 = 1_750_000_000;
const REGISTERED_EXPOSURE_CAP: u64 = 450;

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
        fee_schedule_operator_keys: vec![keypair(24).public_key().to_hex()],
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

/// The seller's signed finding plus its exact canonical bytes. The
/// challenge binds the digest of those bytes, so the pair travels
/// together.
fn finding_artifact() -> Result<(Finding, String), AnyError> {
    let issuer = keypair(9);
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#challenge-lane".to_string(),
            context_sha256: hex64('7'),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::MeteredAttested,
        payload_sha256: hex64('8'),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: vec!["receipt-evidence-01".to_string()],
        evidence_checkpoint_ref: "checkpoint-evidence-01".to_string(),
        evidence_cost: usd(10),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "bond:pending-allocation".to_string(),
        status_feed_ref: "status-feed/venue-challenge".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    let signed = sign_finding(finding, &issuer)?;
    let raw = String::from_utf8(canonical_json_bytes(&signed)?)?;
    Ok((signed, raw))
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

/// Open one reservation, take its slot, and close it against a real
/// purchase-authority-signed record, so the claim snapshot reads exactly
/// what the sale path would have written.
fn settle_purchase(
    deployment: &Deployment,
    tag: &str,
    destination: &str,
    realized_spend_units: u64,
    now: u64,
) -> Result<String, AnyError> {
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
    deployment
        .purchases
        .admit_payout_destination(&deployment.allocation_id, destination, now)?;
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
    Ok(purchase_key)
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

fn governance() -> Result<Governance, AnyError> {
    let signer = governing_keypair();
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
        fee_schedule: sample_fee_schedule(&signer)?,
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
            governing_signer: &self.listing.signer_key,
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

/// Drive one challenge through the store to a terminal verdict, exactly
/// as the evaluator's own recorded verdict would.
fn close_challenge(
    deployment: &Deployment,
    challenge_id: &str,
    verdict: FindingChallengeVerdict,
    now: u64,
) -> Result<FindingChallengeState, AnyError> {
    deployment.challenges.begin_evaluation(challenge_id, now)?;
    Ok(deployment
        .challenges
        .record_verdict(challenge_id, verdict, &digest(challenge_id), now)?)
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
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        NOW + 3,
    )?;
    let outcome = upheld_outcome(&challenge, &deployment.allocation_id)?;

    let stake = usd(300);
    let required = usd(5_000);
    let identity = liability_identity(&finding.finding_id, &deployment.allocation_id);
    let upheld = coordinator.uphold(
        &challenge.body.challenge_id,
        &outcome,
        &identity,
        2,
        &[first, second],
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
    EvmBondSnapshot {
        vault_id: chain_hash(0x44),
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
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: settlement_config()?.chain_id,
        vault_contract: BOND_VAULT_CONTRACT.to_string(),
        vault_id: chain_hash(0x44),
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
            vault_id: chain_hash(0x44),
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
    let deployment = deployment()?;
    let coordinator = deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?;
    let (finding, raw) = finding_artifact()?;
    let challenge = buyer_challenge(&keypair(41))?;
    coordinator.submit(&challenge, &raw, NOW)?;
    close_challenge(
        &deployment,
        &challenge.body.challenge_id,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    )?;

    // Drive the head to finalizing on the same listing the sale path
    // blocks, then fence the impairment the enforcement names.
    let liability_key = byte_hex64(0xb1);
    deployment
        .challenges
        .open_liability(&chio_store_sqlite::FindingLiabilityInput {
            liability_key: &liability_key,
            defect_key: &derive_defect_key(&finding.finding_id),
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            allocation_id: &deployment.allocation_id,
            venue_id: VENUE_ID,
            chain_id: "chio-devnet",
            vault_contract: BOND_VAULT_CONTRACT,
            vault_id: "vault-01",
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

    let seller = keypair(73);
    let seller_impair_intent_id = byte_hex64(0xc1);
    deployment.challenges.record_effect_intent(
        &seller_impair_intent_id,
        chio_store_sqlite::FindingEffectIntentKind::SellerImpair,
        &byte_hex64(0xd1),
        Some(&liability_key),
        NOW + 5,
    )?;
    let (enforcement, snapshot) = enforcement_pair(
        &liability_key,
        &finding.finding_id,
        &seller.public_key(),
        &seller_impair_intent_id,
    )?;

    let outcome = coordinator.finalize(
        &liability_key,
        &enforcement,
        &snapshot,
        &seller.public_key(),
        MAX_SNAPSHOT_AGE_SECS,
        &settlement_config()?,
        &settlement_config()?.operator_address,
        &evm_vault_snapshot(),
        &anchor_proof()?,
        &AmbiguousPublisher,
        SETTLEMENT_NOW,
    )?;
    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::StoredTransactionMissing
        },
        "a consumed evidence hash with no transaction behind it is never a slash"
    );

    let liability = deployment
        .challenges
        .get_liability(&liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(liability.state, FindingLiabilityState::Finalizing);
    assert!(liability.publication_pending);
    assert!(liability.quarantined);
    assert!(
        deployment.purchases.sales_blocked(LISTING_ID)?,
        "a quarantined impairment keeps purchases denied"
    );
    assert_eq!(
        deployment
            .challenges
            .get_effect_intent(&seller_impair_intent_id)?
            .ok_or("the impairment intent is durable")?
            .state,
        FindingEffectIntentState::Quarantined
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
