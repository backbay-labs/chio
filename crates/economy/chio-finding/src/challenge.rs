//! `chio.finding.challenge.v1`: the signed submission that opens a dispute
//! against one admitted finding listing.
//!
//! Two independent closed unions gate every submission. The authorization
//! union names either a buyer, with its standing, its collected dispute fee,
//! and its live exclusive dispute lock, or a venue audit, with its signed
//! epoch authorization and no bond, fee, forfeiture, or reward member at
//! all. The evidence union names exactly one mechanical class. Both unions
//! are closed in this validator and in the registered schema, so a
//! submission that mixes branches fails before anything reads its content.
//!
//! The compatibility matrix between the evidence class and the challenged
//! finding's guarantee/evidence classes is equally closed, but it needs the
//! finding, which this artifact deliberately does not carry: it carries the
//! finding's digest instead. [`ensure_challenge_class_compatibility`] is
//! therefore exposed separately for the surface that holds both.
//!
//! `affected_deliveries` entries are atomic and content-bound. They carry no
//! buyer identity, amount, or payout address, because a challenger cannot be
//! trusted to name victims or destinations: the payout set is derived from
//! the authoritative purchase index at the frozen cutoff, never from these
//! hints.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::envelope::require_ed25519;
use crate::recipe::FindingReplayRecipeInput;
use crate::replay_observation::{FindingReplayObservation, MAX_REPLAY_OBSERVATION_BYTES};
use crate::types::{FindingEvidenceClass, FindingGuaranteeClass};
use crate::validate::{
    parse_canonical_json_text, require_bounded_id, require_currency, require_hex64,
    require_nonzero, FindingError,
};

/// Signed challenge submission.
pub const FINDING_CHALLENGE_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_CHALLENGE_V1_SCHEMA;

/// Bound on the affected-delivery hint set carried for standing.
pub const MAX_CHALLENGE_AFFECTED_DELIVERIES: usize = 64;

/// Bound on the contested evidence subset of an `evidence_invalid` challenge.
pub const MAX_CHALLENGE_CHALLENGED_EVIDENCE_REFS: usize = 64;

/// Bound on the reproduction set of a `replay_contradiction` challenge.
pub const MAX_CHALLENGE_REPRODUCTIONS: usize = 16;

/// Bound on the carried canonical recipe preimage.
pub const MAX_CHALLENGE_RECIPE_PREIMAGE_BYTES: usize = 65_536;

/// An atomic, content-bound receipt reference. The digest travels with the
/// identifier so a reference cannot be repointed at other content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReceiptRef {
    pub receipt_id: String,
    pub receipt_sha256: String,
}

impl FindingReceiptRef {
    fn validate(&self, label: &'static str) -> Result<(), FindingError> {
        require_bounded_id(&self.receipt_id, label)?;
        require_hex64(&self.receipt_sha256, label)
    }
}

/// An atomic, content-bound checkpoint reference.
///
/// `checkpoint_sha256` is the digest of the CANONICAL CHECKPOINT BODY,
/// following the transparency-record convention, not the digest of the
/// signed envelope carrying it. The distinction matters: a checkpoint
/// re-signed by a rotated key keeps its body digest, so binding the body
/// is what makes the reference stable across a legitimate rotation while
/// still refusing substituted content. Every producer and every verifier
/// of this reference must agree on that reading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingCheckpointRef {
    pub checkpoint_ref: String,
    pub checkpoint_sha256: String,
}

impl FindingCheckpointRef {
    fn validate(&self, label: &'static str) -> Result<(), FindingError> {
        require_bounded_id(&self.checkpoint_ref, label)?;
        require_hex64(&self.checkpoint_sha256, label)
    }
}

/// One delivery the challenger claims was affected: receipt and checkpoint,
/// each bound to its own digest. No buyer identity, amount, or payout
/// address is encodable here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAffectedDelivery {
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub checkpoint_ref: String,
    pub checkpoint_sha256: String,
}

impl FindingAffectedDelivery {
    fn validate(&self) -> Result<(), FindingError> {
        require_bounded_id(&self.receipt_id, "affected_deliveries[].receipt_id")?;
        require_hex64(&self.receipt_sha256, "affected_deliveries[].receipt_sha256")?;
        require_bounded_id(&self.checkpoint_ref, "affected_deliveries[].checkpoint_ref")?;
        require_hex64(
            &self.checkpoint_sha256,
            "affected_deliveries[].checkpoint_sha256",
        )
    }
}

/// Charge point for the dispute fee. Closed vocabulary with exactly one
/// member: the shipped publication and participation events are pinned to
/// the audit pool and are deliberately not encodable here, so a seller
/// cannot redirect a participation fee into the challenge lane or the
/// reverse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisputeFeeEvent {
    ChallengeFiling,
}

/// The settled dispute-fee terminal a buyer submission carries. The
/// beneficiary is the admission-pinned challenge-administration pool, never
/// the audit pool and never the seller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDisputeFeeTerminal {
    pub fee_schedule_envelope_sha256: String,
    pub event: FindingDisputeFeeEvent,
    pub payer: PublicKey,
    pub amount: MonetaryAmount,
    pub beneficiary_pool_principal_id: String,
    pub rail_destination: String,
}

impl FindingDisputeFeeTerminal {
    fn validate(&self) -> Result<(), FindingError> {
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "dispute_fee_terminal.fee_schedule_envelope_sha256",
        )?;
        require_ed25519(&self.payer, "dispute_fee_terminal.payer")?;
        require_nonzero(self.amount.units, "dispute_fee_terminal.amount")?;
        require_currency(
            &self.amount.currency,
            "dispute_fee_terminal.amount.currency",
        )?;
        require_bounded_id(
            &self.beneficiary_pool_principal_id,
            "dispute_fee_terminal.beneficiary_pool_principal_id",
        )?;
        require_bounded_id(
            &self.rail_destination,
            "dispute_fee_terminal.rail_destination",
        )
    }
}

/// Bond class of a challenge lock. Closed vocabulary with exactly one
/// member: a lock held under the publication or listing class is a
/// different promise and rejects at parse time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisputeBondClass {
    Dispute,
}

/// Reference to the live exclusive lock the buyer's collateral sits in. The
/// lock itself lives in the venue's collateral store; this reference is what
/// the coordinator resolves before evaluation, and a stale, reused, or
/// wrong-class lock fails that resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDisputeLockRef {
    pub lock_id: String,
    pub class: FindingDisputeBondClass,
    pub fee_schedule_envelope_sha256: String,
    pub amount: MonetaryAmount,
    pub expiry: u64,
}

impl FindingDisputeLockRef {
    fn validate(&self) -> Result<(), FindingError> {
        require_bounded_id(&self.lock_id, "dispute_lock_ref.lock_id")?;
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "dispute_lock_ref.fee_schedule_envelope_sha256",
        )?;
        require_nonzero(self.amount.units, "dispute_lock_ref.amount")?;
        require_currency(&self.amount.currency, "dispute_lock_ref.amount.currency")?;
        require_nonzero(self.expiry, "dispute_lock_ref.expiry")
    }
}

/// Class-specific standing for a buyer submission.
///
/// A denied reveal creates no purchase record, so its standing is the signed
/// failed-delivery terminal; a settled sale's standing is its purchase
/// record. The branch MUST agree with the evidence class, and its digest
/// MUST equal the digest the evidence branch already binds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingChallengeStanding {
    FailedDelivery {
        failed_delivery_id: String,
        failed_delivery_envelope_sha256: String,
    },
    FinalizedPurchase {
        purchase_key: String,
        purchase_record_envelope_sha256: String,
    },
}

impl FindingChallengeStanding {
    fn validate(&self) -> Result<(), FindingError> {
        match self {
            FindingChallengeStanding::FailedDelivery {
                failed_delivery_id,
                failed_delivery_envelope_sha256,
            } => {
                require_hex64(failed_delivery_id, "standing.failed_delivery_id")?;
                require_hex64(
                    failed_delivery_envelope_sha256,
                    "standing.failed_delivery_envelope_sha256",
                )
            }
            FindingChallengeStanding::FinalizedPurchase {
                purchase_key,
                purchase_record_envelope_sha256,
            } => {
                require_hex64(purchase_key, "standing.purchase_key")?;
                require_hex64(
                    purchase_record_envelope_sha256,
                    "standing.purchase_record_envelope_sha256",
                )
            }
        }
    }
}

/// Which authorization branch a challenge used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingChallengeAuthorizationKind {
    BuyerSubmission,
    VenueAudit,
}

/// A buyer's authorization: who is filing, what they paid, what they locked,
/// and the standing that lets them file at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingBuyerSubmission {
    /// Must equal the envelope signer.
    pub challenger: PublicKey,
    pub dispute_fee_terminal: FindingDisputeFeeTerminal,
    pub dispute_lock_ref: FindingDisputeLockRef,
    pub standing: FindingChallengeStanding,
}

impl FindingBuyerSubmission {
    fn validate(&self) -> Result<(), FindingError> {
        require_ed25519(&self.challenger, "challenger")?;
        self.dispute_fee_terminal.validate()?;
        self.dispute_lock_ref.validate()?;
        self.standing.validate()
    }
}

/// A venue audit's authorization: the signed epoch it belongs to and the
/// digests that prove this listing was selected under it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingVenueAuditAuthorization {
    pub audit_epoch_envelope_sha256: String,
    pub selection_digest: String,
    pub authorization_digest: String,
}

impl FindingVenueAuditAuthorization {
    fn validate(&self) -> Result<(), FindingError> {
        require_hex64(
            &self.audit_epoch_envelope_sha256,
            "venue_audit.audit_epoch_envelope_sha256",
        )?;
        require_hex64(&self.selection_digest, "venue_audit.selection_digest")?;
        require_hex64(
            &self.authorization_digest,
            "venue_audit.authorization_digest",
        )
    }
}

/// The closed authorization union.
///
/// `venue_audit` has no challenger, lock, fee, forfeiture, or reward member
/// by construction, so a venue audit cannot acquire a bond disposition and a
/// buyer cannot borrow the audit authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingChallengeAuthorization {
    /// Boxed: the buyer branch carries a key and two monetary bindings and
    /// is an order of magnitude larger than the audit branch. The
    /// indirection does not change the encoding.
    BuyerSubmission(Box<FindingBuyerSubmission>),
    VenueAudit(FindingVenueAuditAuthorization),
}

impl FindingChallengeAuthorization {
    /// Branch tag, for surfaces that record which authorization applied.
    #[must_use]
    pub fn kind(&self) -> FindingChallengeAuthorizationKind {
        match self {
            FindingChallengeAuthorization::BuyerSubmission(_) => {
                FindingChallengeAuthorizationKind::BuyerSubmission
            }
            FindingChallengeAuthorization::VenueAudit(_) => {
                FindingChallengeAuthorizationKind::VenueAudit
            }
        }
    }

    fn validate(&self) -> Result<(), FindingError> {
        match self {
            FindingChallengeAuthorization::BuyerSubmission(submission) => submission.validate(),
            FindingChallengeAuthorization::VenueAudit(audit) => audit.validate(),
        }
    }
}

/// One reproduction tuple: the mediated replay receipt, its checkpoint, and
/// the exact observation preimage whose digest that receipt committed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReplayReproduction {
    pub receipt_ref: FindingReceiptRef,
    pub checkpoint_ref: FindingCheckpointRef,
    /// Canonical `chio.finding.replay-observation.v1` TEXT.
    pub observation_bytes: String,
}

/// Which mechanical evidence class a challenge presented.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingChallengeEvidenceKind {
    DigestMismatch,
    EvidenceInvalid,
    ReplayContradiction,
}

/// The closed evidence union. Each branch carries exactly the references its
/// class needs; a member belonging to another class rejects at parse time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingChallengeEvidence {
    DigestMismatch {
        failed_delivery_envelope_sha256: String,
        deny_receipt_ref: FindingReceiptRef,
        deny_checkpoint_ref: FindingCheckpointRef,
    },
    EvidenceInvalid {
        challenged_evidence_receipt_refs: Vec<FindingReceiptRef>,
        challenged_checkpoint_ref: FindingCheckpointRef,
        purchase_record_envelope_sha256: String,
    },
    ReplayContradiction {
        reproduction: Vec<FindingReplayReproduction>,
        /// Canonical `chio.finding.replay-recipe-input.v1` TEXT.
        recipe_preimage: String,
        purchase_record_envelope_sha256: String,
    },
}

impl FindingChallengeEvidence {
    /// Class tag, for surfaces that record which branch applied.
    #[must_use]
    pub fn kind(&self) -> FindingChallengeEvidenceKind {
        match self {
            FindingChallengeEvidence::DigestMismatch { .. } => {
                FindingChallengeEvidenceKind::DigestMismatch
            }
            FindingChallengeEvidence::EvidenceInvalid { .. } => {
                FindingChallengeEvidenceKind::EvidenceInvalid
            }
            FindingChallengeEvidence::ReplayContradiction { .. } => {
                FindingChallengeEvidenceKind::ReplayContradiction
            }
        }
    }

    /// Structural validation. The carried preimages are strict-parsed and
    /// cross-bound to the profile the challenge names, so a reproduction set
    /// that belongs to another recipe or another profile cannot ride along.
    fn validate(&self, profile_envelope_sha256: &str) -> Result<(), FindingError> {
        match self {
            FindingChallengeEvidence::DigestMismatch {
                failed_delivery_envelope_sha256,
                deny_receipt_ref,
                deny_checkpoint_ref,
            } => {
                require_hex64(
                    failed_delivery_envelope_sha256,
                    "digest_mismatch.failed_delivery_envelope_sha256",
                )?;
                deny_receipt_ref.validate("digest_mismatch.deny_receipt_ref")?;
                deny_checkpoint_ref.validate("digest_mismatch.deny_checkpoint_ref")
            }
            FindingChallengeEvidence::EvidenceInvalid {
                challenged_evidence_receipt_refs,
                challenged_checkpoint_ref,
                purchase_record_envelope_sha256,
            } => {
                if challenged_evidence_receipt_refs.is_empty() {
                    return Err(FindingError::MissingEntry(
                        "evidence_invalid.challenged_evidence_receipt_refs",
                    ));
                }
                if challenged_evidence_receipt_refs.len() > MAX_CHALLENGE_CHALLENGED_EVIDENCE_REFS {
                    return Err(FindingError::SizeLimitExceeded(
                        "evidence_invalid.challenged_evidence_receipt_refs",
                    ));
                }
                let mut seen = BTreeSet::new();
                for receipt_ref in challenged_evidence_receipt_refs {
                    receipt_ref.validate("evidence_invalid.challenged_evidence_receipt_refs[]")?;
                    if !seen.insert(receipt_ref.receipt_id.as_str()) {
                        return Err(FindingError::DuplicateEntry(
                            "evidence_invalid.challenged_evidence_receipt_refs[]",
                        ));
                    }
                }
                challenged_checkpoint_ref.validate("evidence_invalid.challenged_checkpoint_ref")?;
                require_hex64(
                    purchase_record_envelope_sha256,
                    "evidence_invalid.purchase_record_envelope_sha256",
                )
            }
            FindingChallengeEvidence::ReplayContradiction {
                reproduction,
                recipe_preimage,
                purchase_record_envelope_sha256,
            } => {
                require_hex64(
                    purchase_record_envelope_sha256,
                    "replay_contradiction.purchase_record_envelope_sha256",
                )?;
                let recipe: FindingReplayRecipeInput = parse_canonical_json_text(
                    recipe_preimage,
                    "replay_contradiction.recipe_preimage",
                    MAX_CHALLENGE_RECIPE_PREIMAGE_BYTES,
                )?;
                recipe.validate()?;
                if recipe.verifier_profile_envelope_sha256 != profile_envelope_sha256 {
                    return Err(FindingError::InvalidField(
                        "replay_contradiction.recipe_preimage",
                    ));
                }
                let recipe_digest = recipe.canonical_sha256()?;
                if reproduction.is_empty() {
                    return Err(FindingError::MissingEntry(
                        "replay_contradiction.reproduction",
                    ));
                }
                if reproduction.len() > MAX_CHALLENGE_REPRODUCTIONS {
                    return Err(FindingError::SizeLimitExceeded(
                        "replay_contradiction.reproduction",
                    ));
                }
                let mut seen_receipts = BTreeSet::new();
                let mut replay_run_id: Option<String> = None;
                for tuple in reproduction {
                    tuple
                        .receipt_ref
                        .validate("replay_contradiction.reproduction[].receipt_ref")?;
                    tuple
                        .checkpoint_ref
                        .validate("replay_contradiction.reproduction[].checkpoint_ref")?;
                    if !seen_receipts.insert(tuple.receipt_ref.receipt_id.as_str()) {
                        return Err(FindingError::DuplicateEntry(
                            "replay_contradiction.reproduction[].receipt_ref",
                        ));
                    }
                    let observation: FindingReplayObservation = parse_canonical_json_text(
                        &tuple.observation_bytes,
                        "replay_contradiction.reproduction[].observation_bytes",
                        MAX_REPLAY_OBSERVATION_BYTES,
                    )?;
                    observation.validate()?;
                    if observation.recipe_digest != recipe_digest
                        || observation.verifier_profile_digest != profile_envelope_sha256
                    {
                        return Err(FindingError::InvalidField(
                            "replay_contradiction.reproduction[].observation_bytes",
                        ));
                    }
                    match &replay_run_id {
                        Some(run_id) if *run_id != observation.replay_run_id => {
                            return Err(FindingError::InvalidField(
                                "replay_contradiction.reproduction[].observation_bytes",
                            ));
                        }
                        Some(_) => {}
                        None => replay_run_id = Some(observation.replay_run_id.clone()),
                    }
                }
                Ok(())
            }
        }
    }
}

/// Signed challenge body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingChallenge {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `challenge_id`
    /// cleared. This is a deduplication key only; it never authorizes a
    /// slash.
    pub challenge_id: String,
    pub finding_id: String,
    pub finding_artifact_sha256: String,
    pub listing_id: String,
    pub terms_envelope_sha256: String,
    pub profile_envelope_sha256: String,
    /// Exact retained venue admission whose backing governed the sale.
    pub venue_admission_envelope_sha256: String,
    pub backing_envelope_sha256: String,
    pub filed_at: u64,
    /// Standing hints only, never the payout set.
    pub affected_deliveries: Vec<FindingAffectedDelivery>,
    pub authorization: FindingChallengeAuthorization,
    pub evidence: FindingChallengeEvidence,
}

/// Signed envelope for the challenge.
pub type SignedFindingChallenge = SignedExportEnvelope<FindingChallenge>;

impl FindingChallenge {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_CHALLENGE_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.challenge_id, "challenge_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.finding_artifact_sha256, "finding_artifact_sha256")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(&self.terms_envelope_sha256, "terms_envelope_sha256")?;
        require_hex64(&self.profile_envelope_sha256, "profile_envelope_sha256")?;
        require_hex64(
            &self.venue_admission_envelope_sha256,
            "venue_admission_envelope_sha256",
        )?;
        require_hex64(&self.backing_envelope_sha256, "backing_envelope_sha256")?;
        require_nonzero(self.filed_at, "filed_at")?;
        if self.affected_deliveries.len() > MAX_CHALLENGE_AFFECTED_DELIVERIES {
            return Err(FindingError::SizeLimitExceeded("affected_deliveries"));
        }
        let mut seen_deliveries = BTreeSet::new();
        for delivery in &self.affected_deliveries {
            delivery.validate()?;
            if !seen_deliveries.insert(delivery.receipt_id.as_str()) {
                return Err(FindingError::DuplicateEntry("affected_deliveries[]"));
            }
        }
        self.authorization.validate()?;
        self.evidence.validate(&self.profile_envelope_sha256)?;
        self.validate_standing()?;
        self.verify_challenge_id()
    }

    /// A buyer submission needs standing of the class its evidence branch
    /// selected, bound to the same artifact digest that branch already
    /// names. A venue audit carries no standing at all.
    fn validate_standing(&self) -> Result<(), FindingError> {
        let FindingChallengeAuthorization::BuyerSubmission(submission) = &self.authorization else {
            return Ok(());
        };
        if self.affected_deliveries.is_empty() {
            return Err(FindingError::MissingEntry("affected_deliveries"));
        }
        match (&submission.standing, &self.evidence) {
            (
                FindingChallengeStanding::FailedDelivery {
                    failed_delivery_envelope_sha256: standing_digest,
                    ..
                },
                FindingChallengeEvidence::DigestMismatch {
                    failed_delivery_envelope_sha256,
                    ..
                },
            ) if standing_digest == failed_delivery_envelope_sha256 => Ok(()),
            (
                FindingChallengeStanding::FinalizedPurchase {
                    purchase_record_envelope_sha256: standing_digest,
                    ..
                },
                FindingChallengeEvidence::EvidenceInvalid {
                    purchase_record_envelope_sha256,
                    ..
                }
                | FindingChallengeEvidence::ReplayContradiction {
                    purchase_record_envelope_sha256,
                    ..
                },
            ) if standing_digest == purchase_record_envelope_sha256 => Ok(()),
            _ => Err(FindingError::InvalidField("standing")),
        }
    }

    /// Recompute and compare the content-addressed challenge id.
    pub fn verify_challenge_id(&self) -> Result<(), FindingError> {
        let expected = compute_challenge_id(self)?;
        if expected == self.challenge_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("challenge_id"))
        }
    }
}

/// Content-addressed challenge id: sha256 over the canonical body with
/// `challenge_id` cleared.
pub fn compute_challenge_id(challenge: &FindingChallenge) -> Result<String, FindingError> {
    let mut body = challenge.clone();
    body.challenge_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// The closed guarantee/evidence compatibility matrix.
///
/// It is normative and it is the only gate between a challenge class and the
/// finding it targets:
///
/// - `digest_mismatch` admits any guarantee and evidence class, because its
///   standing is the signed failed-delivery terminal the evidence branch
///   already binds rather than anything the finding claimed;
/// - `evidence_invalid` requires an `observed` or `verified` evidence class,
///   because an asserted finding has no evidence to invalidate;
/// - `replay_contradiction` requires `deterministic_replay` and `verified`,
///   because only those findings committed a recipe to contradict.
///
/// Every other pairing rejects before evaluation. The challenge does not
/// carry the finding, so the surface that resolves both calls this.
pub fn ensure_challenge_class_compatibility(
    evidence_kind: FindingChallengeEvidenceKind,
    guarantee_class: FindingGuaranteeClass,
    evidence_class: FindingEvidenceClass,
) -> Result<(), FindingError> {
    match evidence_kind {
        FindingChallengeEvidenceKind::DigestMismatch => Ok(()),
        FindingChallengeEvidenceKind::EvidenceInvalid => match evidence_class {
            FindingEvidenceClass::Observed | FindingEvidenceClass::Verified => Ok(()),
            FindingEvidenceClass::Asserted => Err(FindingError::InvalidField(
                "evidence_invalid.evidence_class",
            )),
        },
        FindingChallengeEvidenceKind::ReplayContradiction => {
            if guarantee_class != FindingGuaranteeClass::DeterministicReplay {
                return Err(FindingError::InvalidField(
                    "replay_contradiction.guarantee_class",
                ));
            }
            if evidence_class != FindingEvidenceClass::Verified {
                return Err(FindingError::InvalidField(
                    "replay_contradiction.evidence_class",
                ));
            }
            Ok(())
        }
    }
}

/// Verify a signed challenge.
///
/// A buyer submission is authorized by the challenger it names: the envelope
/// signer MUST equal that key, so a buyer cannot file under another buyer's
/// standing. A venue audit is authorized only by the externally pinned audit
/// authority, so a buyer cannot file a bondless audit.
pub fn verify_signed_challenge(
    signed: &SignedFindingChallenge,
    pinned_audit_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    match &signed.body.authorization {
        FindingChallengeAuthorization::BuyerSubmission(submission) => {
            crate::envelope::verify_pinned_envelope(signed, &submission.challenger, "challenge")
        }
        FindingChallengeAuthorization::VenueAudit(_) => {
            crate::envelope::verify_pinned_envelope(signed, pinned_audit_authority, "challenge")
        }
    }
}
