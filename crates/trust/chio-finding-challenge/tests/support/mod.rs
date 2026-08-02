//! One coherent market world, built from the real artifact types.
//!
//! Nothing here is a mock. The findings are signed, the receipts are kernel
//! signed and Merkle committed to real checkpoints, the profile is governance
//! signed, and every digest is derived rather than asserted, because the
//! evaluator's whole job is to reject anything that only claims to bind.
//!
//! Construction order is forced by the artifacts themselves: receipts and
//! checkpoints exist before the profile can pin their logs, the profile
//! exists before the recipe can commit it, the recipe exists before the
//! finding can commit it, and the finding exists before any delivery or
//! reproduction evidence can name it.

#![allow(dead_code)]

use std::error::Error;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{
    canonical_json_bytes, canonical_json_string, DeliveryContract, DeliveryResult, FindingDelivery,
    FindingDeliverySettlementMode, FindingMediaTypeCheck, FindingTransformProfile, MerkleTree,
    DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA, FINDING_DELIVERY_METADATA_KEY,
    FINDING_DELIVERY_SCHEMA,
};
use chio_finding::{
    compute_challenge_id, compute_failed_delivery_id, compute_finding_id, compute_profile_id,
    derive_outcome_id, derive_purchase_key, sign_finding, signed_envelope_sha256,
    verify_outcome_challenge_binding, Finding, FindingAffectedDelivery, FindingAuthorityKeyPolicy,
    FindingBbsIssuerPolicy, FindingBuyerSubmission, FindingChallenge,
    FindingChallengeAuthorization, FindingChallengeEvidence, FindingChallengeOutcome,
    FindingChallengeStanding, FindingChallengeVerdict, FindingChallengeVerifierProfile,
    FindingCheckpointLogPolicy, FindingCheckpointRef, FindingClaimedVerdict, FindingDescriptor,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingEvidenceClass, FindingFacetKind, FindingFailedDelivery,
    FindingGuaranteeClass, FindingHoldReleaseTerminal, FindingKeyRevocation, FindingOutcomeClass,
    FindingPenaltyCalculation, FindingPredicate, FindingPurchaseRecord, FindingReceiptRef,
    FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayObservation, FindingReplayRecipeInput,
    FindingReplayReproduction, FindingReplayTerminalResult, FindingResourceCaps,
    FindingVenueAuditAuthorization, SignedFindingChallenge, SignedFindingChallengeVerifierProfile,
    SignedFindingFailedDelivery, SignedFindingKeyRevocation, SignedFindingPurchaseRecord,
    FINDING_CHALLENGE_OUTCOME_SCHEMA_V1, FINDING_CHALLENGE_SCHEMA_V1,
    FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_KEY_REVOCATION_SCHEMA_V1,
    FINDING_PURCHASE_RECORD_SCHEMA_V1, FINDING_REPLAY_OBSERVATION_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
};
use chio_finding_challenge::{
    FindingChallengeAdjudication, FindingChallengeClassEvidence, FindingChallengeEvaluation,
    FindingChallengeEvaluationInput, FindingChallengeInadmissible, FindingChallengeReason,
    FindingDigestMismatchEvidence, FindingEvidenceInvalidEvidence,
    FindingReplayContradictionEvidence, FindingResolvedReproduction, FindingRevokedKeyProof,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_body_sha256,
    checkpoint_log_id, CheckpointTransparencySummary, KernelCheckpoint,
};

pub type TestResult = Result<(), Box<dyn Error>>;
pub type Built<T> = Result<T, Box<dyn Error>>;

pub const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const HEX64_ALT: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
pub const HEX64_THIRD: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
pub const LISTING_ID: &str = "finding-listing-01";
pub const PAYMENT_OPERATION_ID: &str = "payment-operation-42";
pub const RESERVATION_ID: &str = "reservation-42";
pub const PURCHASE_INTENT_ID: &str = "purchase-intent-42";
pub const REPLAY_RUN_ID: &str = "replay-run-42";
pub const PUBLISHED_AT: u64 = 1_700_000_000;
pub const KEY_VALID_FROM: u64 = 1_600_000_000;
pub const KEY_VALID_UNTIL: u64 = 1_900_000_000;

pub fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
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

/// A receipt whose action commitment agrees with its parameters.
fn signed_receipt(
    kernel: &Keypair,
    timestamp: u64,
    tool_name: &str,
    action: ToolCallAction,
    decision: Decision,
    content_hash: &str,
    metadata: Option<serde_json::Value>,
) -> Built<ChioReceipt> {
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

fn resolve(
    receipt: ChioReceipt,
    leaves: &[Vec<u8>],
    leaf_index: usize,
    checkpoint_seq: u64,
    receipt_seq: u64,
) -> Built<ResolvedReceiptEvidence> {
    let tree = MerkleTree::from_leaves(leaves)?;
    let canonical_receipt_bytes = canonical_json_bytes(&receipt)?;
    Ok(ResolvedReceiptEvidence {
        receipt,
        canonical_receipt_bytes,
        inclusion_proof: build_inclusion_proof(&tree, leaf_index, checkpoint_seq, receipt_seq)?,
    })
}

/// The local log identity a kernel key publishes under, derived through the
/// same helper the checkpoint verifier uses.
fn log_id_for(kernel: &Keypair) -> Built<String> {
    let probe = build_checkpoint(1, 1, 1, &[b"probe".to_vec()], kernel)?;
    Ok(checkpoint_log_id(&probe))
}

fn checkpoint_reference(checkpoint: &KernelCheckpoint) -> Built<FindingCheckpointRef> {
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

/// The full market world every case builds on.
pub struct World {
    pub governance: Keypair,
    pub governance_key: PublicKey,
    pub issuer: Keypair,
    pub buyer: Keypair,
    pub audit_authority: Keypair,
    pub audit_authority_key: PublicKey,
    pub purchase_authority: Keypair,
    pub failed_delivery_authority: Keypair,
    pub production_kernel: Keypair,
    pub delivery_kernel: Keypair,
    pub replay_kernel: Keypair,
    pub profile: SignedFindingChallengeVerifierProfile,
    pub profile_envelope_sha256: String,
    pub recipe: FindingReplayRecipeInput,
    pub recipe_preimage: String,
    pub recipe_sha256: String,
    pub finding: Finding,
    pub raw_finding: String,
    pub finding_artifact_sha256: String,
    pub evidence_receipts: Vec<ResolvedReceiptEvidence>,
    pub evidence_checkpoint: KernelCheckpoint,
    pub evidence_checkpoint_ref: FindingCheckpointRef,
}

/// How the finding under challenge classifies itself.
#[derive(Debug, Clone, Copy)]
pub struct FindingClasses {
    pub guarantee: FindingGuaranteeClass,
    pub evidence: FindingEvidenceClass,
}

impl Default for FindingClasses {
    fn default() -> Self {
        Self {
            guarantee: FindingGuaranteeClass::DeterministicReplay,
            evidence: FindingEvidenceClass::Verified,
        }
    }
}

/// How the two production evidence receipts are built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProductionShape {
    #[default]
    Sound,
    /// The checkpoint commits a first receipt whose signature belongs to
    /// another body, so the venue's own log carries the broken envelope.
    CheckpointedForeignSignature,
    /// The log commits the sound first receipt, and the bytes offered to the
    /// evaluator carry another body's signature. The receipt identifier is a
    /// content address over the body alone, so the finding that names it is
    /// byte for byte identical either way.
    SuppliedForeignSignature,
    /// The first receipt's action commitment contradicts its parameters.
    ActionCommitmentBroken,
    /// The receipts are signed by a key the profile pins for another role.
    ForeignSigner,
    /// The first receipt is signed before the production key's validity
    /// window opens.
    SignedBeforeKeyWindow,
}

pub fn world() -> Built<World> {
    world_with(FindingClasses::default(), ProductionShape::Sound)
}

pub fn world_with_classes(classes: FindingClasses) -> Built<World> {
    world_with(classes, ProductionShape::Sound)
}

pub fn world_with(classes: FindingClasses, production: ProductionShape) -> Built<World> {
    let governance = keypair(1);
    let issuer = keypair(3);
    let buyer = keypair(41);
    let audit_authority = keypair(42);
    let purchase_authority = keypair(16);
    let failed_delivery_authority = keypair(17);
    let production_kernel = keypair(21);
    let delivery_kernel = keypair(12);
    let replay_kernel = keypair(13);

    let production_signer = if production == ProductionShape::ForeignSigner {
        &delivery_kernel
    } else {
        &production_kernel
    };

    // Step 1: the production evidence, which the finding will name by id.
    let first_action = ToolCallAction::from_parameters(serde_json::json!({ "step": 0 }))?;
    let first_action = match production {
        ProductionShape::ActionCommitmentBroken => ToolCallAction {
            parameters: first_action.parameters,
            parameter_hash: HEX64_THIRD.to_string(),
        },
        _ => first_action,
    };
    let first_signed_at = match production {
        ProductionShape::SignedBeforeKeyWindow => KEY_VALID_FROM - 1,
        _ => 1_690_000_000,
    };
    let mut first = signed_receipt(
        production_signer,
        first_signed_at,
        "finding.produce",
        first_action,
        Decision::Allow,
        HEX64,
        None,
    )?;
    let second = signed_receipt(
        production_signer,
        1_690_000_001,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 1 }))?,
        Decision::Allow,
        HEX64_ALT,
        None,
    )?;
    if production == ProductionShape::CheckpointedForeignSignature {
        first.signature = second.signature.clone();
    }
    let first_bytes = canonical_json_bytes(&first)?;
    let second_bytes = canonical_json_bytes(&second)?;
    let leaves = vec![first_bytes, second_bytes];
    let evidence_checkpoint = build_checkpoint(1, 1, 2, &leaves, &production_kernel)?;
    let evidence_checkpoint_ref = checkpoint_reference(&evidence_checkpoint)?;
    let first_id = first.id.clone();
    let second_id = second.id.clone();
    // The swap happens after the log committed its leaves, so these are the
    // bytes a challenger supplies rather than the bytes the venue published.
    if production == ProductionShape::SuppliedForeignSignature {
        first.signature = second.signature.clone();
    }
    let evidence_receipts = vec![
        resolve(first, &leaves, 0, 1, 1)?,
        resolve(second, &leaves, 1, 1, 2)?,
    ];

    // Step 2: the governance profile, which pins every role and log.
    let mut profile_body = FindingChallengeVerifierProfile {
        schema: chio_finding::FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "venue-operator".to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(&production_kernel.public_key(), "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(&delivery_kernel.public_key(), "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(&replay_kernel.public_key(), "replay"),
            },
        ],
        checkpoint_logs: vec![
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&production_kernel)?,
                signer: key_policy(&production_kernel.public_key(), "production-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&delivery_kernel)?,
                signer: key_policy(&delivery_kernel.public_key(), "delivery-log"),
            },
            FindingCheckpointLogPolicy {
                log_id: log_id_for(&replay_kernel)?,
                signer: key_policy(&replay_kernel.public_key(), "replay-log"),
            },
        ],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: HEX64.to_string(),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: KEY_VALID_FROM,
            valid_until: KEY_VALID_UNTIL,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![HEX64.to_string()],
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
        purchase_authority: key_policy(&purchase_authority.public_key(), "purchase"),
        failed_delivery_authority: key_policy(
            &failed_delivery_authority.public_key(),
            "failed-delivery",
        ),
        issued_at: KEY_VALID_FROM,
        expires_at: KEY_VALID_UNTIL,
    };
    profile_body.profile_id = compute_profile_id(&profile_body)?;
    let profile = SignedExportEnvelope::sign(profile_body, &governance)?;
    let profile_envelope_sha256 = signed_envelope_sha256(&profile)?;

    // Step 3: the recipe commits the admitted profile.
    let recipe = recipe_body(&profile_envelope_sha256);
    let recipe_preimage = canonical_json_string(&recipe)?;
    let recipe_sha256 = sha256_hex(recipe_preimage.as_bytes());

    // Step 4: the finding commits the recipe, the receipts, and the log.
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "rust/workspace/test-failure".to_string(),
            context_sha256: HEX64.to_string(),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: classes.guarantee,
        payload_sha256: HEX64.to_string(),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: vec![first_id, second_id],
        evidence_checkpoint_ref: evidence_checkpoint_ref.checkpoint_ref.clone(),
        evidence_cost: usd(10),
        runtime_assurance_tier: None,
        evidence_class: classes.evidence,
        replay_recipe_sha256: Some(recipe_sha256.clone()),
        intent_commitment_receipt_id: None,
        bond_ref: "bond:finding-allocation".to_string(),
        status_feed_ref: "status-feed/venue".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: PUBLISHED_AT,
        expires_at: KEY_VALID_UNTIL,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &issuer)?;
    let raw_finding = canonical_json_string(&finding)?;
    let finding_artifact_sha256 = sha256_hex(raw_finding.as_bytes());

    Ok(World {
        governance_key: governance.public_key(),
        governance,
        issuer,
        buyer,
        audit_authority_key: audit_authority.public_key(),
        audit_authority,
        purchase_authority,
        failed_delivery_authority,
        production_kernel,
        delivery_kernel,
        replay_kernel,
        profile,
        profile_envelope_sha256,
        recipe,
        recipe_preimage,
        recipe_sha256,
        finding,
        raw_finding,
        finding_artifact_sha256,
        evidence_receipts,
        evidence_checkpoint,
        evidence_checkpoint_ref,
    })
}

fn recipe_body(profile_envelope_sha256: &str) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: HEX64.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: HEX64.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: HEX64_ALT.to_string(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: HEX64.to_string(),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: HEX64.to_string(),
            platform: "linux/amd64".to_string(),
            network_policy: "deny_all".to_string(),
            clock_policy: "fixed:1700000000".to_string(),
            randomness_policy: "seed:42".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
        },
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

impl World {
    pub fn input<'a>(
        &'a self,
        challenge: &'a SignedFindingChallenge,
        evidence: &'a FindingChallengeClassEvidence<'a>,
    ) -> FindingChallengeEvaluationInput<'a> {
        FindingChallengeEvaluationInput {
            challenge,
            pinned_audit_authority: &self.audit_authority_key,
            raw_finding: &self.raw_finding,
            profile: &self.profile,
            governance_authority: &self.governance_key,
            evidence,
        }
    }

    fn affected_delivery(&self, receipt_ref: &FindingReceiptRef) -> FindingAffectedDelivery {
        FindingAffectedDelivery {
            receipt_id: receipt_ref.receipt_id.clone(),
            receipt_sha256: receipt_ref.receipt_sha256.clone(),
            checkpoint_ref: self.evidence_checkpoint_ref.checkpoint_ref.clone(),
            checkpoint_sha256: self.evidence_checkpoint_ref.checkpoint_sha256.clone(),
        }
    }

    fn buyer_authorization(
        &self,
        standing: FindingChallengeStanding,
    ) -> FindingChallengeAuthorization {
        FindingChallengeAuthorization::BuyerSubmission(Box::new(FindingBuyerSubmission {
            challenger: self.buyer.public_key(),
            dispute_fee_terminal: FindingDisputeFeeTerminal {
                fee_schedule_envelope_sha256: HEX64.to_string(),
                event: FindingDisputeFeeEvent::ChallengeFiling,
                payer: self.buyer.public_key(),
                amount: usd(2_500),
                beneficiary_pool_principal_id: "pool:challenge-administration".to_string(),
                rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            },
            dispute_lock_ref: FindingDisputeLockRef {
                lock_id: "dispute-lock-42".to_string(),
                class: FindingDisputeBondClass::Dispute,
                fee_schedule_envelope_sha256: HEX64.to_string(),
                amount: usd(10_000),
                expiry: 1_760_000_000,
            },
            standing,
        }))
    }

    pub fn venue_authorization(&self) -> FindingChallengeAuthorization {
        FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
            audit_epoch_envelope_sha256: HEX64.to_string(),
            selection_digest: HEX64_ALT.to_string(),
            authorization_digest: HEX64_THIRD.to_string(),
        })
    }

    pub fn sign_challenge(
        &self,
        authorization: FindingChallengeAuthorization,
        evidence: FindingChallengeEvidence,
        affected: Vec<FindingAffectedDelivery>,
    ) -> Built<SignedFindingChallenge> {
        self.sign_challenge_with_admission(authorization, evidence, affected, HEX64)
    }

    fn sign_challenge_with_admission(
        &self,
        authorization: FindingChallengeAuthorization,
        evidence: FindingChallengeEvidence,
        affected: Vec<FindingAffectedDelivery>,
        venue_admission_envelope_sha256: &str,
    ) -> Built<SignedFindingChallenge> {
        let signer = match &authorization {
            FindingChallengeAuthorization::BuyerSubmission(_) => &self.buyer,
            FindingChallengeAuthorization::VenueAudit(_) => &self.audit_authority,
        };
        let mut challenge = FindingChallenge {
            schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
            challenge_id: String::new(),
            finding_id: self.finding.finding_id.clone(),
            finding_artifact_sha256: self.finding_artifact_sha256.clone(),
            listing_id: LISTING_ID.to_string(),
            terms_envelope_sha256: HEX64.to_string(),
            profile_envelope_sha256: self.profile_envelope_sha256.clone(),
            venue_admission_envelope_sha256: venue_admission_envelope_sha256.to_string(),
            backing_envelope_sha256: HEX64_ALT.to_string(),
            filed_at: 1_750_000_000,
            affected_deliveries: affected,
            authorization,
            evidence,
        };
        challenge.challenge_id = compute_challenge_id(&challenge)?;
        Ok(SignedExportEnvelope::sign(challenge, signer)?)
    }

    /// The settled purchase record both evidence classes rest on.
    pub fn purchase_record(&self) -> Built<SignedFindingPurchaseRecord> {
        self.purchase_record_shaped(StandingShape::Sound)
    }

    /// The same record, built to fail exactly one standing gate.
    pub fn purchase_record_shaped(
        &self,
        shape: StandingShape,
    ) -> Built<SignedFindingPurchaseRecord> {
        let buyer = match shape {
            StandingShape::ForeignBuyer => keypair(77).public_key(),
            _ => self.buyer.public_key(),
        };
        let record = FindingPurchaseRecord {
            schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_string(),
            purchase_key: derive_purchase_key(HEX64_THIRD, PAYMENT_OPERATION_ID),
            purchase_intent_id: PURCHASE_INTENT_ID.to_string(),
            authoritative_payment_operation_id: PAYMENT_OPERATION_ID.to_string(),
            buyer: buyer.clone(),
            payer: self.buyer.public_key(),
            finding_id: match shape {
                StandingShape::ForeignFinding => HEX64_ALT.to_string(),
                _ => self.finding.finding_id.clone(),
            },
            listing_id: match shape {
                StandingShape::ForeignListing => "finding-listing-02".to_string(),
                _ => LISTING_ID.to_string(),
            },
            accepted_bid_envelope_sha256: HEX64_THIRD.to_string(),
            venue_admission_envelope_sha256: HEX64.to_string(),
            accepted_price: usd(5_000),
            realized_spend: usd(5_000),
            seller_backing_envelope_sha256: match shape {
                StandingShape::ForeignBacking => HEX64_THIRD.to_string(),
                _ => HEX64_ALT.to_string(),
            },
            encumbrance_id: "encumbrance-42".to_string(),
            delivery_receipt_id: "delivery-receipt-42".to_string(),
            payment_reference: "payment-reference-42".to_string(),
            payout_destination: chio_finding::buyer_refund_destination(&buyer),
            // The only difference of an unnamed record: it is a settled
            // record of the same sale that the challenge does not name.
            recorded_at: match shape {
                StandingShape::UnnamedRecord => 1_740_000_001,
                StandingShape::OutsideAuthorityWindow => KEY_VALID_UNTIL + 1,
                _ => 1_740_000_000,
            },
        };
        let authority = match shape {
            StandingShape::ForeignAuthority => &self.buyer,
            _ => &self.purchase_authority,
        };
        Ok(SignedExportEnvelope::sign(record, authority)?)
    }

    /// A revocation statement for one key, built against the production
    /// role's own pinned key policy so only the shape under test can fail to
    /// bind.
    pub fn revocation(
        &self,
        key: &PublicKey,
        revoked_from: u64,
        shape: RevocationShape,
    ) -> Built<RevokedKey> {
        let policy = self
            .profile
            .body
            .receipt_signers
            .iter()
            .find(|signer| signer.role == FindingReceiptRole::Production)
            .map(|signer| &signer.policy)
            .ok_or("the profile pins a production signer")?;
        let body = FindingKeyRevocation {
            schema: FINDING_KEY_REVOCATION_SCHEMA_V1.to_string(),
            revocation_status_ref: match shape {
                RevocationShape::ForeignFeed => "revocations/elsewhere".to_string(),
                _ => policy.revocation_status_ref.clone(),
            },
            authority_id: match shape {
                RevocationShape::ForeignAuthority => "authority-elsewhere".to_string(),
                _ => policy.authority_id.clone(),
            },
            key: key.clone(),
            key_epoch: match shape {
                RevocationShape::ForeignEpoch => policy.key_epoch + 1,
                _ => policy.key_epoch,
            },
            revoked_from,
            recorded_at: 1_740_000_000,
        };
        let signer = match shape {
            RevocationShape::ForeignSigner => &self.buyer,
            _ => &self.governance,
        };
        Ok(RevokedKey {
            statement: SignedExportEnvelope::sign(body, signer)?,
        })
    }
}

// ---------------------------------------------------------------------------
// digest_mismatch
// ---------------------------------------------------------------------------

/// Which key signed the denial receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenySigner {
    Delivery,
    Production,
}

/// The shape of one denial terminal, so a test can build the exact denial it
/// means rather than mutate a signed one.
pub struct DenyShape {
    pub include_contract: bool,
    pub include_overlay: bool,
    pub contract_result: DeliveryResult,
    pub overlay_digest_check: DeliveryResult,
    pub media_type_check: FindingMediaTypeCheck,
    /// `None` uses the finding's committed payload digest.
    pub expected_digest: Option<String>,
    pub observed_digest: String,
    pub signer: DenySigner,
    pub decision: Decision,
    /// Sign an otherwise valid receipt whose action hash contradicts its
    /// parameters.
    pub break_action_commitment: bool,
    /// Supply a checkpoint that is not the one the references name.
    pub substitute_checkpoint: bool,
}

impl DenyShape {
    /// The authenticated seller-origin mismatch: the only shape that upholds.
    pub fn seller_origin() -> Self {
        Self {
            include_contract: true,
            include_overlay: true,
            contract_result: DeliveryResult::Mismatched,
            overlay_digest_check: DeliveryResult::Mismatched,
            media_type_check: FindingMediaTypeCheck::NotEvaluated,
            expected_digest: None,
            observed_digest: HEX64_ALT.to_string(),
            signer: DenySigner::Delivery,
            decision: Decision::Deny {
                reason: "delivered output does not match the committed output digest".to_string(),
                guard: "delivery_contract".to_string(),
            },
            break_action_commitment: false,
            substitute_checkpoint: false,
        }
    }

    /// A denial whose digest comparison passed: the reveal was refused by
    /// some other guard, so there is no mismatch to adjudicate.
    pub fn matched() -> Self {
        Self {
            contract_result: DeliveryResult::Matched,
            overlay_digest_check: DeliveryResult::Matched,
            media_type_check: FindingMediaTypeCheck::Matched,
            observed_digest: HEX64.to_string(),
            decision: Decision::Deny {
                reason: "capability does not authorize this reveal".to_string(),
                guard: "capability".to_string(),
            },
            ..Self::seller_origin()
        }
    }
}

pub struct DigestCase {
    pub challenge: SignedFindingChallenge,
    pub failed_delivery: SignedFindingFailedDelivery,
    pub deny_receipt: ResolvedReceiptEvidence,
    pub deny_checkpoint: KernelCheckpoint,
    pub checkpoint_transparency: CheckpointTransparencySummary,
}

impl DigestCase {
    pub fn evidence(&self) -> FindingChallengeClassEvidence<'_> {
        FindingChallengeClassEvidence::DigestMismatch(FindingDigestMismatchEvidence {
            failed_delivery: &self.failed_delivery,
            deny_receipt: &self.deny_receipt,
            deny_checkpoint: &self.deny_checkpoint,
            checkpoint_transparency: &self.checkpoint_transparency,
        })
    }
}

pub fn digest_case(world: &World, shape: &DenyShape) -> Built<DigestCase> {
    digest_case_for(world, shape, true)
}

pub fn venue_digest_case(world: &World, shape: &DenyShape) -> Built<DigestCase> {
    digest_case_for(world, shape, false)
}

fn digest_case_for(world: &World, shape: &DenyShape, buyer_filing: bool) -> Built<DigestCase> {
    let expected_digest = shape
        .expected_digest
        .clone()
        .unwrap_or_else(|| world.finding.payload_sha256.clone());
    let mut metadata = serde_json::Map::new();
    if shape.include_contract {
        let contract = DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
            expected_digest: expected_digest.clone(),
            observed_digest: shape.observed_digest.clone(),
            result: shape.contract_result,
        };
        metadata.insert(
            DELIVERY_CONTRACT_METADATA_KEY.to_string(),
            serde_json::to_value(&contract)?,
        );
    }
    if shape.include_overlay {
        let overlay = FindingDelivery {
            schema: FINDING_DELIVERY_SCHEMA.to_string(),
            finding_id: world.finding.finding_id.clone(),
            listing_id: LISTING_ID.to_string(),
            transform_profile: FindingTransformProfile::Identity,
            digest_check: shape.overlay_digest_check,
            media_type_check: shape.media_type_check,
            settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
            accepted_bid_envelope_sha256: HEX64_THIRD.to_string(),
            venue_admission_envelope_sha256: HEX64.to_string(),
            reservation_id: RESERVATION_ID.to_string(),
            purchase_intent_id: PURCHASE_INTENT_ID.to_string(),
            authoritative_payment_operation_id: PAYMENT_OPERATION_ID.to_string(),
        };
        metadata.insert(
            FINDING_DELIVERY_METADATA_KEY.to_string(),
            serde_json::to_value(&overlay)?,
        );
    }
    let kernel = match shape.signer {
        DenySigner::Delivery => &world.delivery_kernel,
        DenySigner::Production => &world.production_kernel,
    };
    let mut action = ToolCallAction::from_parameters(serde_json::json!({ "finding": "reveal" }))?;
    if shape.break_action_commitment {
        action.parameter_hash = HEX64_THIRD.to_string();
    }
    let receipt = signed_receipt(
        kernel,
        1_745_000_000,
        "finding.reveal",
        action,
        shape.decision.clone(),
        &shape.observed_digest,
        Some(serde_json::Value::Object(metadata)),
    )?;
    let leaves = vec![canonical_json_bytes(&receipt)?];
    let deny_checkpoint = build_checkpoint(1, 1, 1, &leaves, kernel)?;
    let named_checkpoint_ref = checkpoint_reference(&deny_checkpoint)?;
    let deny_receipt = resolve(receipt, &leaves, 0, 1, 1)?;
    let deny_receipt_ref = receipt_reference(&deny_receipt);

    let mut terminal = FindingFailedDelivery {
        schema: FINDING_FAILED_DELIVERY_SCHEMA_V1.to_string(),
        failed_delivery_id: String::new(),
        buyer: world.buyer.public_key(),
        finding_id: world.finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        accepted_bid_envelope_sha256: HEX64_THIRD.to_string(),
        reservation_id: RESERVATION_ID.to_string(),
        purchase_intent_id: PURCHASE_INTENT_ID.to_string(),
        authoritative_payment_operation_id: PAYMENT_OPERATION_ID.to_string(),
        hold_attempt_reference: "hold-attempt-42".to_string(),
        release_terminal: FindingHoldReleaseTerminal::Released,
        deny_receipt_id: deny_receipt_ref.receipt_id.clone(),
        deny_receipt_sha256: deny_receipt_ref.receipt_sha256.clone(),
        deny_checkpoint_ref: named_checkpoint_ref.checkpoint_ref.clone(),
        deny_checkpoint_sha256: named_checkpoint_ref.checkpoint_sha256.clone(),
        realized_spend_units: 0,
        currency: "USD".to_string(),
        payout_eligible: false,
        recorded_at: 1_745_000_500,
    };
    terminal.failed_delivery_id = compute_failed_delivery_id(&terminal)?;
    let failed_delivery = SignedExportEnvelope::sign(terminal, &world.failed_delivery_authority)?;
    let failed_delivery_envelope_sha256 = signed_envelope_sha256(&failed_delivery)?;

    let evidence = FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: failed_delivery_envelope_sha256.clone(),
        deny_receipt_ref: deny_receipt_ref.clone(),
        deny_checkpoint_ref: named_checkpoint_ref,
    };
    let authorization = if buyer_filing {
        world.buyer_authorization(FindingChallengeStanding::FailedDelivery {
            failed_delivery_id: failed_delivery.body.failed_delivery_id.clone(),
            failed_delivery_envelope_sha256,
        })
    } else {
        world.venue_authorization()
    };
    let affected = if buyer_filing {
        vec![world.affected_delivery(&deny_receipt_ref)]
    } else {
        Vec::new()
    };
    let challenge = world.sign_challenge(authorization, evidence, affected)?;

    // A substituted checkpoint proves the same leaves under a different
    // identity, so the reference no longer resolves.
    let deny_checkpoint = if shape.substitute_checkpoint {
        build_checkpoint(7, 1, 1, &leaves, kernel)?
    } else {
        deny_checkpoint
    };

    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&deny_checkpoint))?;
    Ok(DigestCase {
        challenge,
        failed_delivery,
        deny_receipt,
        deny_checkpoint,
        checkpoint_transparency,
    })
}

// ---------------------------------------------------------------------------
// evidence_invalid
// ---------------------------------------------------------------------------

/// How the challenged evidence subset is presented.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EvidenceShape {
    #[default]
    Sound,
    /// The venue's own checkpoint with one resolver-supplied sibling hash
    /// altered in the unsigned inclusion path.
    ContradictoryCheckpoint,
    /// The venue's own checkpoint, with a resolver-supplied inclusion wrapper
    /// that disagrees with it about the tree.
    InconsistentProof,
    /// A checkpoint that is not the artifact the reference names at all.
    UnresolvedCheckpoint,
    /// A checkpoint carrying the pinned log signer's key in its body and
    /// another key's signature over it.
    ForgedCheckpoint,
    /// The challenge contests a receipt the finding never named.
    UnnamedReceipt,
    /// The challenge names a checkpoint other than the one the finding
    /// committed.
    ForeignCheckpoint,
}

/// How the standing record, and the standing the challenge declares over it,
/// are built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StandingShape {
    #[default]
    Sound,
    /// Signed by a key the profile does not pin as the purchase authority.
    ForeignAuthority,
    /// The evidence carries a settled record other than the one the challenge
    /// names.
    UnnamedRecord,
    /// The record settles a different finding.
    ForeignFinding,
    /// The record settles a different listing.
    ForeignListing,
    /// The record was sold under a different backing revision.
    ForeignBacking,
    /// The record was sold under another venue admission.
    ForeignAdmission,
    /// The record settles after the purchase authority's key policy closes.
    OutsideAuthorityWindow,
    /// The record names a buyer other than the challenger.
    ForeignBuyer,
    /// The declared standing names a purchase key the record does not carry.
    ForeignPurchaseKey,
}

pub struct EvidenceCase {
    pub challenge: SignedFindingChallenge,
    pub purchase_record: SignedFindingPurchaseRecord,
    pub challenged_receipts: Vec<ResolvedReceiptEvidence>,
    pub challenged_checkpoint: KernelCheckpoint,
    pub checkpoint_transparency: CheckpointTransparencySummary,
    pub revoked_keys: Vec<RevokedKey>,
}

/// How one offered revocation statement is built. Every shape but `Sound`
/// leaves a well formed, well signed statement and changes exactly one of the
/// members that bind it to the key policy the profile pins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RevocationShape {
    #[default]
    Sound,
    /// Signed by a key that is not the pinned governance root.
    ForeignSigner,
    /// Published on a feed the key policy does not name.
    ForeignFeed,
    /// Names an authority other than the one the key policy identifies.
    ForeignAuthority,
    /// Names a key epoch other than the one the key policy pins.
    ForeignEpoch,
}

/// An owned revocation statement, so a case can hand out borrowed views.
pub struct RevokedKey {
    pub statement: SignedFindingKeyRevocation,
}

impl EvidenceCase {
    pub fn revocation_proofs(&self) -> Vec<FindingRevokedKeyProof<'_>> {
        self.revoked_keys
            .iter()
            .map(|proof| FindingRevokedKeyProof {
                statement: &proof.statement,
            })
            .collect()
    }

    pub fn evidence<'a>(
        &'a self,
        proofs: &'a [FindingRevokedKeyProof<'a>],
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::EvidenceInvalid(FindingEvidenceInvalidEvidence {
            purchase_record: &self.purchase_record,
            challenged_receipts: &self.challenged_receipts,
            challenged_checkpoint: &self.challenged_checkpoint,
            checkpoint_transparency: &self.checkpoint_transparency,
            revoked_keys: proofs,
        })
    }
}

pub fn evidence_case(world: &World, shape: EvidenceShape) -> Built<EvidenceCase> {
    build_evidence_case(world, shape, StandingShape::Sound, Vec::new())
}

pub fn evidence_case_with_revocations(
    world: &World,
    shape: EvidenceShape,
    revoked_keys: Vec<RevokedKey>,
) -> Built<EvidenceCase> {
    build_evidence_case(world, shape, StandingShape::Sound, revoked_keys)
}

pub fn evidence_case_with_standing(world: &World, standing: StandingShape) -> Built<EvidenceCase> {
    build_evidence_case(world, EvidenceShape::Sound, standing, Vec::new())
}

fn build_evidence_case(
    world: &World,
    shape: EvidenceShape,
    standing: StandingShape,
    revoked_keys: Vec<RevokedKey>,
) -> Built<EvidenceCase> {
    let purchase_record = world.purchase_record_shaped(standing)?;
    // Every shape but the unnamed record names the record it carries, so the
    // gate under test is the only one that can fail.
    let purchase_record_envelope_sha256 = match standing {
        StandingShape::UnnamedRecord => signed_envelope_sha256(&world.purchase_record()?)?,
        _ => signed_envelope_sha256(&purchase_record)?,
    };
    let declared_purchase_key = match standing {
        StandingShape::ForeignPurchaseKey => derive_purchase_key(HEX64, PAYMENT_OPERATION_ID),
        _ => purchase_record.body.purchase_key.clone(),
    };
    let mut challenged_refs: Vec<FindingReceiptRef> = world
        .evidence_receipts
        .iter()
        .map(receipt_reference)
        .collect();
    let mut challenged_receipts = world
        .evidence_receipts
        .iter()
        .map(clone_resolved)
        .collect::<Built<Vec<ResolvedReceiptEvidence>>>()?;
    if shape == EvidenceShape::UnnamedReceipt {
        let unnamed = unnamed_production_receipt(world)?;
        challenged_refs[0] = receipt_reference(&unnamed);
        challenged_receipts[0] = unnamed;
    }
    // The checkpoint is chosen before the challenge is signed because the
    // challenge binds its digest and each negative case must control whether
    // that reference resolves independently from the inclusion wrapper.
    let challenged_checkpoint = match shape {
        EvidenceShape::Sound
        | EvidenceShape::UnnamedReceipt
        | EvidenceShape::InconsistentProof
        | EvidenceShape::ContradictoryCheckpoint => world.evidence_checkpoint.clone(),
        EvidenceShape::UnresolvedCheckpoint => build_checkpoint(
            1,
            1,
            2,
            &[
                challenged_receipts[0].canonical_receipt_bytes.clone(),
                b"other-leaf-b".to_vec(),
            ],
            &world.production_kernel,
        )?,
        // The same leaves and identity the venue published, signed by a key
        // that is not the pinned log signer.
        EvidenceShape::ForgedCheckpoint => {
            let leaves: Vec<Vec<u8>> = challenged_receipts
                .iter()
                .map(|resolved| resolved.canonical_receipt_bytes.clone())
                .collect();
            let mut forged = build_checkpoint(1, 1, 2, &leaves, &keypair(88))?;
            forged.body.kernel_key = world.production_kernel.public_key();
            forged
        }
        // A checkpoint of the same log at a sequence the finding never
        // committed, so its identity is another artifact's.
        EvidenceShape::ForeignCheckpoint => build_checkpoint(
            9,
            900,
            901,
            &[b"other-leaf-a".to_vec(), b"other-leaf-b".to_vec()],
            &world.production_kernel,
        )?,
    };
    match shape {
        // The wrapper is unsigned, so even a structurally consistent path
        // whose sibling hash does not reach the signed root proves nothing.
        EvidenceShape::ContradictoryCheckpoint => {
            challenged_receipts[0].inclusion_proof.proof.audit_path[0] =
                chio_core_types::hashing::Hash::from_bytes([0x5a; 32]);
        }
        EvidenceShape::InconsistentProof => {
            for resolved in challenged_receipts.iter_mut() {
                resolved.inclusion_proof.proof.tree_size =
                    resolved.inclusion_proof.proof.tree_size.saturating_add(1);
            }
        }
        _ => {}
    }
    let challenged_checkpoint_ref = match shape {
        EvidenceShape::Sound
        | EvidenceShape::UnnamedReceipt
        | EvidenceShape::InconsistentProof
        | EvidenceShape::ContradictoryCheckpoint
        | EvidenceShape::ForgedCheckpoint
        | EvidenceShape::ForeignCheckpoint => checkpoint_reference(&challenged_checkpoint)?,
        // The reference names the real checkpoint; the resolver supplied
        // another one.
        EvidenceShape::UnresolvedCheckpoint => world.evidence_checkpoint_ref.clone(),
    };
    let evidence = FindingChallengeEvidence::EvidenceInvalid {
        challenged_evidence_receipt_refs: challenged_refs.clone(),
        challenged_checkpoint_ref,
        purchase_record_envelope_sha256: purchase_record_envelope_sha256.clone(),
    };
    let authorization = world.buyer_authorization(FindingChallengeStanding::FinalizedPurchase {
        purchase_key: declared_purchase_key,
        purchase_record_envelope_sha256,
    });
    let affected = vec![world.affected_delivery(&challenged_refs[0])];
    let venue_admission_envelope_sha256 = match standing {
        StandingShape::ForeignAdmission => HEX64_THIRD,
        _ => HEX64,
    };
    let challenge = world.sign_challenge_with_admission(
        authorization,
        evidence,
        affected,
        venue_admission_envelope_sha256,
    )?;

    // Negative shapes may intentionally carry a checkpoint whose signature
    // cannot produce valid derived transparency. Keep the supplied summary
    // empty so the evaluator, rather than fixture setup, performs the
    // fail-closed rejection.
    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&challenged_checkpoint))
            .unwrap_or_default();
    Ok(EvidenceCase {
        challenge,
        purchase_record,
        challenged_receipts,
        challenged_checkpoint,
        checkpoint_transparency,
        revoked_keys,
    })
}

/// A production receipt built exactly like the finding's own evidence, which
/// the finding does not name.
fn unnamed_production_receipt(world: &World) -> Built<ResolvedReceiptEvidence> {
    let receipt = signed_receipt(
        &world.production_kernel,
        1_690_000_002,
        "finding.produce",
        ToolCallAction::from_parameters(serde_json::json!({ "step": 2 }))?,
        Decision::Allow,
        HEX64_THIRD,
        None,
    )?;
    let leaves = vec![canonical_json_bytes(&receipt)?];
    resolve(receipt, &leaves, 0, 1, 100)
}

fn clone_resolved(evidence: &ResolvedReceiptEvidence) -> Built<ResolvedReceiptEvidence> {
    Ok(ResolvedReceiptEvidence {
        receipt: evidence.receipt.clone(),
        canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
        inclusion_proof: serde_json::from_value(serde_json::to_value(&evidence.inclusion_proof)?)?,
    })
}

// ---------------------------------------------------------------------------
// replay_contradiction
// ---------------------------------------------------------------------------

/// How one reproduction phase is presented.
#[derive(Debug, Clone, Copy)]
pub struct PhaseShape {
    pub phase: FindingRecipePhaseKind,
    pub terminal: FindingReplayTerminalResult,
    pub exit_code: i64,
}

impl PhaseShape {
    pub fn baseline_fails() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Baseline,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 1,
        }
    }

    pub fn baseline_passes() -> Self {
        Self {
            exit_code: 0,
            ..Self::baseline_fails()
        }
    }

    pub fn candidate_passes() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Candidate,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 0,
        }
    }

    pub fn candidate_fails() -> Self {
        Self {
            exit_code: 1,
            ..Self::candidate_passes()
        }
    }
}

/// Knobs for the reproduction set as a whole.
pub struct ReplayShape {
    pub phases: Vec<PhaseShape>,
    /// Replace the carried recipe preimage with different canonical bytes.
    pub recipe_preimage: Option<String>,
    /// Sign the reproduction receipts with a key outside the replay role.
    pub signer: Option<u8>,
    /// Break the receipt-to-observation digest commitment.
    pub break_content_commitment: bool,
    /// Sign a receipt whose action hash contradicts its own parameters.
    pub break_action_commitment: bool,
    /// Report an environment other than the one the recipe committed.
    pub environment_digest: Option<String>,
    /// Decision carried by each replay receipt.
    pub decision: Decision,
}

impl Default for ReplayShape {
    fn default() -> Self {
        Self {
            phases: vec![PhaseShape::baseline_fails(), PhaseShape::candidate_passes()],
            recipe_preimage: None,
            signer: None,
            break_content_commitment: false,
            break_action_commitment: false,
            environment_digest: None,
            decision: Decision::Allow,
        }
    }
}

pub struct ReplayCase {
    pub challenge: SignedFindingChallenge,
    pub purchase_record: SignedFindingPurchaseRecord,
    pub receipts: Vec<ResolvedReceiptEvidence>,
    pub checkpoint: KernelCheckpoint,
    pub checkpoint_transparency: CheckpointTransparencySummary,
}

impl ReplayCase {
    pub fn reproductions(&self) -> Vec<FindingResolvedReproduction<'_>> {
        self.receipts
            .iter()
            .map(|receipt| FindingResolvedReproduction {
                receipt,
                checkpoint: &self.checkpoint,
                checkpoint_transparency: &self.checkpoint_transparency,
            })
            .collect()
    }

    pub fn evidence<'a>(
        &'a self,
        reproductions: &'a [FindingResolvedReproduction<'a>],
    ) -> FindingChallengeClassEvidence<'a> {
        FindingChallengeClassEvidence::ReplayContradiction(FindingReplayContradictionEvidence {
            purchase_record: &self.purchase_record,
            reproductions,
        })
    }
}

pub fn replay_case(world: &World, shape: &ReplayShape) -> Built<ReplayCase> {
    let purchase_record = world.purchase_record()?;
    let purchase_record_envelope_sha256 = signed_envelope_sha256(&purchase_record)?;
    let recipe_preimage = shape
        .recipe_preimage
        .clone()
        .unwrap_or_else(|| world.recipe_preimage.clone());
    let recipe_digest = sha256_hex(recipe_preimage.as_bytes());

    let kernel = match shape.signer {
        Some(seed) => keypair(seed),
        None => world.replay_kernel.clone(),
    };
    // The digest a run reports for its environment is the digest of the
    // environment the recipe committed, derived the same way the consumer
    // derives it.
    let environment_digest = match &shape.environment_digest {
        Some(digest) => digest.clone(),
        None => committed_environment_digest(&world.recipe)?,
    };

    let mut observation_texts = Vec::with_capacity(shape.phases.len());
    let mut receipts = Vec::with_capacity(shape.phases.len());
    let mut leaves = Vec::with_capacity(shape.phases.len());
    for (index, phase) in shape.phases.iter().enumerate() {
        let observation = FindingReplayObservation {
            schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
            recipe_digest: recipe_digest.clone(),
            verifier_profile_digest: world.profile_envelope_sha256.clone(),
            phase_id: phase.phase,
            runner_manifest_digest: HEX64.to_string(),
            resolved_input_bundle_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => HEX64.to_string(),
                FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
            },
            environment_digest: environment_digest.clone(),
            terminal_result: phase.terminal,
            exit_code: phase.exit_code,
            report_digest: match phase.phase {
                FindingRecipePhaseKind::Baseline => HEX64.to_string(),
                FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
            },
            replay_run_id: REPLAY_RUN_ID.to_string(),
        };
        let text = canonical_json_string(&observation)?;
        let content_hash = if shape.break_content_commitment {
            HEX64_THIRD.to_string()
        } else {
            sha256_hex(text.as_bytes())
        };
        let mut action = ToolCallAction::from_parameters(serde_json::json!({
            "replay_run_id": REPLAY_RUN_ID,
            "phase": index,
        }))?;
        if shape.break_action_commitment {
            action.parameter_hash = HEX64_THIRD.to_string();
        }
        let receipt = signed_receipt(
            &kernel,
            1_746_000_000 + index as u64,
            "finding.replay",
            action,
            shape.decision.clone(),
            &content_hash,
            None,
        )?;
        leaves.push(canonical_json_bytes(&receipt)?);
        receipts.push(receipt);
        observation_texts.push(text);
    }
    let checkpoint = build_checkpoint(1, 1, receipts.len() as u64, &leaves, &kernel)?;
    let checkpoint_ref = checkpoint_reference(&checkpoint)?;
    let mut resolved = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        resolved.push(resolve(receipt, &leaves, index, 1, 1 + index as u64)?);
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

    let evidence = FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage,
        purchase_record_envelope_sha256: purchase_record_envelope_sha256.clone(),
    };
    let authorization = world.buyer_authorization(FindingChallengeStanding::FinalizedPurchase {
        purchase_key: purchase_record.body.purchase_key.clone(),
        purchase_record_envelope_sha256,
    });
    let affected = vec![world.affected_delivery(&receipt_reference(&world.evidence_receipts[0]))];
    let challenge = world.sign_challenge(authorization, evidence, affected)?;

    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&checkpoint))?;
    Ok(ReplayCase {
        challenge,
        purchase_record,
        receipts: resolved,
        checkpoint,
        checkpoint_transparency,
    })
}

/// The digest of the environment a recipe commits: sha256 over the canonical
/// JSON of the recipe's `environment` member.
pub fn committed_environment_digest(recipe: &FindingReplayRecipeInput) -> Built<String> {
    Ok(sha256_hex(&canonical_json_bytes(&recipe.environment)?))
}

/// A recipe that differs from the committed one, for the preimage-mismatch
/// negatives. It stays strictly canonical, so the only thing wrong with it is
/// that it is not the recipe the finding committed.
pub fn foreign_recipe_preimage(world: &World) -> Built<String> {
    let mut recipe = world.recipe.clone();
    recipe.decision_rule_ref = "decision/replay-v2".to_string();
    Ok(canonical_json_string(&recipe)?)
}

/// The finding's bytes with one member changed, so the artifact no longer
/// verifies as the issuer signed it.
pub fn tampered_finding(world: &World) -> Built<String> {
    let mut finding = world.finding.clone();
    finding.bond_ref = "bond:another-allocation".to_string();
    Ok(canonical_json_string(&finding)?)
}

/// The same governance profile reissued under a different operator, so its
/// envelope digest differs while every signature stays valid.
pub fn reissued_profile(
    world: &World,
    operator: &str,
) -> Built<SignedFindingChallengeVerifierProfile> {
    let mut body = world.profile.body.clone();
    body.operator = operator.to_string();
    body.profile_id = compute_profile_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &world.governance)?)
}

/// A profile whose envelope has the pinned governance signature but whose
/// signed body names a different governance authority.
pub fn profile_with_foreign_governance_authority(
    world: &World,
) -> Built<SignedFindingChallengeVerifierProfile> {
    let mut body = world.profile.body.clone();
    body.governance_authority = keypair(99).public_key();
    body.profile_id = compute_profile_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &world.governance)?)
}

/// Re-sign an otherwise unchanged buyer challenge against a replacement
/// profile, preserving every unrelated binding.
pub fn buyer_challenge_bound_to_profile(
    world: &World,
    challenge: &SignedFindingChallenge,
    profile: &SignedFindingChallengeVerifierProfile,
) -> Built<SignedFindingChallenge> {
    let mut body = challenge.body.clone();
    body.profile_envelope_sha256 = signed_envelope_sha256(profile)?;
    body.challenge_id = compute_challenge_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &world.buyer)?)
}

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------

fn failure(message: String) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message))
}

/// Require an adjudication with exactly this reason, and confirm the verdict
/// the caller would act on is the one the reason implies.
pub fn expect_reason(
    evaluation: &FindingChallengeEvaluation,
    expected: FindingChallengeReason,
) -> Built<FindingChallengeAdjudication> {
    let Some(adjudication) = evaluation.adjudication() else {
        return Err(failure(format!(
            "expected an adjudication with {expected:?}, got {evaluation:?}"
        )));
    };
    if adjudication.reason() != expected {
        return Err(failure(format!(
            "expected {expected:?}, got {:?}",
            adjudication.reason()
        )));
    }
    if adjudication.verdict() != expected.verdict() {
        return Err(failure(format!(
            "verdict {:?} does not follow from {expected:?}",
            adjudication.verdict()
        )));
    }
    Ok(adjudication.clone())
}

/// Require inadmissibility, and that no verdict was produced at all.
pub fn expect_inadmissible(
    evaluation: &FindingChallengeEvaluation,
    expected: &FindingChallengeInadmissible,
) -> TestResult {
    match evaluation {
        FindingChallengeEvaluation::Inadmissible(actual) if actual == expected => {}
        other => {
            return Err(failure(format!(
                "expected inadmissible {expected:?}, got {other:?}"
            )))
        }
    }
    if evaluation.verdict().is_some() {
        return Err(failure(
            "an inadmissible submission produced a verdict".to_string(),
        ));
    }
    Ok(())
}

/// Assemble the outcome a coordinator would sign from an adjudication, and
/// prove the artifact family accepts it. The penalty calculation exists only
/// on the upheld path, which is the family's own rule.
pub fn outcome_for(
    world: &World,
    challenge: &SignedFindingChallenge,
    adjudication: &FindingChallengeAdjudication,
) -> Built<FindingChallengeOutcome> {
    let penalty_calculation = match adjudication.verdict() {
        FindingChallengeVerdict::Upheld => Some(FindingPenaltyCalculation {
            base_finding_stake_units: 100_000,
            open_per_sale_encumbrance_units: 20_000,
            computed_exposure_units: 120_000,
            listing_required_amount_units: 150_000,
            live_allocated_collateral_units: 130_000,
            penalty_amount: usd(120_000),
        }),
        FindingChallengeVerdict::Rejected | FindingChallengeVerdict::Indeterminate => None,
    };
    let mut outcome = FindingChallengeOutcome {
        schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_string(),
        outcome_id: String::new(),
        challenge_envelope_sha256: signed_envelope_sha256(challenge)?,
        finding_id: world.finding.finding_id.clone(),
        listing_id: LISTING_ID.to_string(),
        backing_allocation_id: HEX64_ALT.to_string(),
        authorization: challenge.body.authorization.kind(),
        audit_epoch_envelope_sha256: match &challenge.body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(_) => None,
            FindingChallengeAuthorization::VenueAudit(audit) => {
                Some(audit.audit_epoch_envelope_sha256.clone())
            }
        },
        evidence_kind: challenge.body.evidence.kind(),
        verifier_profile_envelope_sha256: world.profile_envelope_sha256.clone(),
        evidence_bundle_digest: HEX64.to_string(),
        verdict: adjudication.verdict(),
        facet: adjudication.facet().clone(),
        reason: adjudication.reason().to_string(),
        trigger_digest: HEX64_THIRD.to_string(),
        retry_deadline: None,
        penalty_calculation,
        evaluator_key_epoch: 1,
        evaluated_at: 1_750_000_500,
    };
    outcome.outcome_id = derive_outcome_id(&outcome)?;
    outcome.validate()?;
    verify_outcome_challenge_binding(&outcome, challenge)?;
    Ok(outcome)
}
