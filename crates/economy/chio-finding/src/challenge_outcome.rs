//! `chio.finding.challenge-outcome.v1`: the evaluator-signed verdict for one
//! challenge.
//!
//! The verdict vocabulary is `upheld | rejected | indeterminate`, and the
//! third member is load-bearing: whenever authority, retention, resolver, or
//! infrastructure inputs cannot be established, the evaluator says so
//! instead of clearing the seller. An indeterminate outcome creates no hold,
//! sanction, liability transition, audit reward, or forfeiture, and only
//! `upheld` may enter the penalty lane. The facet vocabulary of the shipped
//! verifier report has no indeterminate member and is deliberately not
//! reused here.
//!
//! The body binds the exact signed challenge ENVELOPE digest. A digest over
//! the challenge body alone is a different identity: it omits the signer and
//! the signature, so it would let an unsigned or differently signed body
//! claim the same outcome. Only the envelope digest is accepted.
//!
//! `outcome_id` derives from a domain-separated preimage over the whole
//! canonical body with only `outcome_id` cleared. The envelope signature
//! lives outside the body and is therefore excluded by construction, which
//! is what lets the penalty lane bind `reference_id` to this id and `sha256`
//! to the envelope digest as two independent facts.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{PublicKey, SigningAlgorithm};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::challenge::{
    FindingChallengeAuthorizationKind, FindingChallengeEvidenceKind, SignedFindingChallenge,
};
use crate::envelope::signed_envelope_sha256;
use crate::profile::FindingPredicate;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_i_json_u64, require_non_empty,
    require_nonzero, FindingError,
};

/// Evaluator-signed challenge outcome.
pub const FINDING_CHALLENGE_OUTCOME_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_CHALLENGE_OUTCOME_V1_SCHEMA;

/// Domain separator for the outcome-id preimage. The trailing NUL keeps the
/// separator unambiguous against the canonical body bytes that follow it.
const OUTCOME_ID_DOMAIN: &[u8] = b"chio.finding.challenge-outcome.v1\0";

/// Bound on the challenged-receipt list an `evidence_invalid` facet reports.
pub const MAX_OUTCOME_CHALLENGED_RECEIPTS: usize = 64;

/// Bound on the observation-digest list a replay facet reports.
pub const MAX_OUTCOME_OBSERVATION_DIGESTS: usize = 16;

/// The class-independent verdict. Closed and total: an evaluator that cannot
/// establish its inputs returns `indeterminate` rather than clearing or
/// condemning the seller.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingChallengeVerdict {
    Upheld,
    Rejected,
    Indeterminate,
}

/// The nested replay predicate result. Only the replay branch carries it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingReplayPredicateResult {
    ConfirmedContradiction,
    Consistent,
    Indeterminate,
}

/// Total mapping from the nested replay result onto the class-independent
/// verdict. The order is normative: a confirmed contradiction upholds, a
/// consistent reproduction rejects, and anything the runner could not
/// establish is indeterminate.
#[must_use]
pub fn verdict_for_replay_predicate(
    result: FindingReplayPredicateResult,
) -> FindingChallengeVerdict {
    match result {
        FindingReplayPredicateResult::ConfirmedContradiction => FindingChallengeVerdict::Upheld,
        FindingReplayPredicateResult::Consistent => FindingChallengeVerdict::Rejected,
        FindingReplayPredicateResult::Indeterminate => FindingChallengeVerdict::Indeterminate,
    }
}

/// Why a challenged evidence subset failed, or did not. Closed vocabulary:
/// only affirmative invalidity under the profile effective at publication
/// can support fraud, and everything the evaluator merely could not resolve
/// is separated out so it can never become a sanction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingEvidenceInvalidity {
    /// A receipt signature that does not verify.
    SignatureInvalid,
    /// A checkpoint proof that contradicts the claimed membership.
    CheckpointContradiction,
    /// A receipt that does not bind the claim it was offered for.
    SemanticCrossBindingFailure,
    /// A signing key proven revoked or compromised at publication time.
    KeyRevokedAtPublication,
    /// The subset was resolved and is valid.
    NoAffirmativeInvalidity,
    /// Retention, resolver, or trust inputs could not be established.
    InputsUnavailable,
}

impl FindingEvidenceInvalidity {
    /// Total mapping onto the class-independent verdict.
    #[must_use]
    pub fn verdict(self) -> FindingChallengeVerdict {
        match self {
            FindingEvidenceInvalidity::SignatureInvalid
            | FindingEvidenceInvalidity::CheckpointContradiction
            | FindingEvidenceInvalidity::SemanticCrossBindingFailure
            | FindingEvidenceInvalidity::KeyRevokedAtPublication => FindingChallengeVerdict::Upheld,
            FindingEvidenceInvalidity::NoAffirmativeInvalidity => FindingChallengeVerdict::Rejected,
            FindingEvidenceInvalidity::InputsUnavailable => FindingChallengeVerdict::Indeterminate,
        }
    }
}

/// The `digest_mismatch` facet: what the finding committed, what the reveal
/// delivered, and under which output profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDigestMismatchFacet {
    pub committed_payload_sha256: String,
    pub delivered_output_sha256: String,
    /// Must be `identity`: an operator-policy transform denial is not
    /// seller fraud and can never reach the sanction gate.
    pub transform_profile: String,
    /// Always zero on this path; a denied reveal moved no value.
    pub realized_spend_units: u64,
}

/// The `evidence_invalid` facet: exactly which receipts were contested and
/// what the evaluator affirmatively established about them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingEvidenceInvalidFacet {
    pub challenged_receipt_ids: Vec<String>,
    pub invalidity: FindingEvidenceInvalidity,
}

/// The `replay_contradiction` facet: the run, the recipe it reproduced, the
/// committed predicate, and that predicate's result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReplayContradictionFacet {
    pub replay_run_id: String,
    pub recipe_sha256: String,
    pub predicate: FindingPredicate,
    pub predicate_result: FindingReplayPredicateResult,
    pub observation_digests: Vec<String>,
}

/// The class facet, nested beneath the evidence branch that produced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingChallengeFacet {
    DigestMismatch(FindingDigestMismatchFacet),
    EvidenceInvalid(FindingEvidenceInvalidFacet),
    ReplayContradiction(FindingReplayContradictionFacet),
}

impl FindingChallengeFacet {
    /// Which evidence branch this facet belongs to.
    #[must_use]
    pub fn kind(&self) -> FindingChallengeEvidenceKind {
        match self {
            FindingChallengeFacet::DigestMismatch(_) => {
                FindingChallengeEvidenceKind::DigestMismatch
            }
            FindingChallengeFacet::EvidenceInvalid(_) => {
                FindingChallengeEvidenceKind::EvidenceInvalid
            }
            FindingChallengeFacet::ReplayContradiction(_) => {
                FindingChallengeEvidenceKind::ReplayContradiction
            }
        }
    }

    fn validate(&self, verdict: FindingChallengeVerdict) -> Result<(), FindingError> {
        match self {
            FindingChallengeFacet::DigestMismatch(facet) => {
                require_hex64(
                    &facet.committed_payload_sha256,
                    "digest_mismatch.committed_payload_sha256",
                )?;
                require_hex64(
                    &facet.delivered_output_sha256,
                    "digest_mismatch.delivered_output_sha256",
                )?;
                if facet.transform_profile != "identity" {
                    return Err(FindingError::InvalidField(
                        "digest_mismatch.transform_profile",
                    ));
                }
                if facet.realized_spend_units != 0 {
                    return Err(FindingError::InvalidField(
                        "digest_mismatch.realized_spend_units",
                    ));
                }
                if verdict == FindingChallengeVerdict::Upheld
                    && facet.committed_payload_sha256 == facet.delivered_output_sha256
                {
                    return Err(FindingError::InvalidField("digest_mismatch.verdict"));
                }
                Ok(())
            }
            FindingChallengeFacet::EvidenceInvalid(facet) => {
                if facet.challenged_receipt_ids.is_empty() {
                    return Err(FindingError::MissingEntry(
                        "evidence_invalid.challenged_receipt_ids",
                    ));
                }
                if facet.challenged_receipt_ids.len() > MAX_OUTCOME_CHALLENGED_RECEIPTS {
                    return Err(FindingError::SizeLimitExceeded(
                        "evidence_invalid.challenged_receipt_ids",
                    ));
                }
                let mut seen = BTreeSet::new();
                for receipt_id in &facet.challenged_receipt_ids {
                    require_bounded_id(receipt_id, "evidence_invalid.challenged_receipt_ids[]")?;
                    if !seen.insert(receipt_id.as_str()) {
                        return Err(FindingError::DuplicateEntry(
                            "evidence_invalid.challenged_receipt_ids[]",
                        ));
                    }
                }
                if facet.invalidity.verdict() != verdict {
                    return Err(FindingError::InvalidField("evidence_invalid.verdict"));
                }
                Ok(())
            }
            FindingChallengeFacet::ReplayContradiction(facet) => {
                require_bounded_id(&facet.replay_run_id, "replay_contradiction.replay_run_id")?;
                require_hex64(&facet.recipe_sha256, "replay_contradiction.recipe_sha256")?;
                if facet.observation_digests.is_empty() {
                    return Err(FindingError::MissingEntry(
                        "replay_contradiction.observation_digests",
                    ));
                }
                if facet.observation_digests.len() > MAX_OUTCOME_OBSERVATION_DIGESTS {
                    return Err(FindingError::SizeLimitExceeded(
                        "replay_contradiction.observation_digests",
                    ));
                }
                let mut seen = BTreeSet::new();
                for digest in &facet.observation_digests {
                    require_hex64(digest, "replay_contradiction.observation_digests[]")?;
                    if !seen.insert(digest.as_str()) {
                        return Err(FindingError::DuplicateEntry(
                            "replay_contradiction.observation_digests[]",
                        ));
                    }
                }
                if verdict_for_replay_predicate(facet.predicate_result) != verdict {
                    return Err(FindingError::InvalidField("replay_contradiction.verdict"));
                }
                Ok(())
            }
        }
    }
}

/// The checked penalty calculation an upheld outcome carries.
///
/// Every member of the predeclared formula is recorded so the penalty lane
/// can recheck it instead of trusting a single number:
/// `computed_exposure = base_finding_stake + open_per_sale_encumbrances`,
/// bounded by the signed listing requirement, and
/// `penalty = min(live_allocated_collateral, computed_exposure)`. Overflow
/// and a computed exposure above the signed requirement reject; nothing is
/// silently clamped.
///
/// Two range invariants keep a signed calculation acceptable everywhere it
/// is read. Every unit member stays inside the I-JSON safe-integer range,
/// because a consumer that parses the canonical bytes with a
/// double-precision number type would silently round anything above it. And
/// the resulting penalty is nonzero: an upheld outcome over exhausted live
/// collateral authorizes no sanction, and a zero amount is refused by every
/// downstream monetary type, so the calculation is rejected here rather
/// than signed and stranded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPenaltyCalculation {
    pub base_finding_stake_units: u64,
    pub open_per_sale_encumbrance_units: u64,
    pub computed_exposure_units: u64,
    pub listing_required_amount_units: u64,
    pub live_allocated_collateral_units: u64,
    pub penalty_amount: MonetaryAmount,
}

impl FindingPenaltyCalculation {
    fn validate(&self) -> Result<(), FindingError> {
        require_i_json_u64(
            self.base_finding_stake_units,
            "penalty_calculation.base_finding_stake_units",
        )?;
        require_i_json_u64(
            self.open_per_sale_encumbrance_units,
            "penalty_calculation.open_per_sale_encumbrance_units",
        )?;
        require_i_json_u64(
            self.computed_exposure_units,
            "penalty_calculation.computed_exposure_units",
        )?;
        require_i_json_u64(
            self.listing_required_amount_units,
            "penalty_calculation.listing_required_amount_units",
        )?;
        require_i_json_u64(
            self.live_allocated_collateral_units,
            "penalty_calculation.live_allocated_collateral_units",
        )?;
        let computed = self
            .base_finding_stake_units
            .checked_add(self.open_per_sale_encumbrance_units)
            .ok_or(FindingError::AmountOverflow("penalty_calculation"))?;
        if computed != self.computed_exposure_units {
            return Err(FindingError::InvalidField(
                "penalty_calculation.computed_exposure_units",
            ));
        }
        if computed > self.listing_required_amount_units {
            return Err(FindingError::InvalidField(
                "penalty_calculation.listing_required_amount_units",
            ));
        }
        let expected = computed.min(self.live_allocated_collateral_units);
        if expected != self.penalty_amount.units {
            return Err(FindingError::InvalidField(
                "penalty_calculation.penalty_amount",
            ));
        }
        require_nonzero(
            self.penalty_amount.units,
            "penalty_calculation.penalty_amount",
        )?;
        require_currency(
            &self.penalty_amount.currency,
            "penalty_calculation.penalty_amount.currency",
        )
    }
}

/// Challenge outcome body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingChallengeOutcome {
    pub schema: String,
    /// Derived from the domain-separated canonical body; see
    /// [`derive_outcome_id`].
    pub outcome_id: String,
    /// Digest of the exact signed challenge ENVELOPE, never of its body.
    pub challenge_envelope_sha256: String,
    pub finding_id: String,
    pub listing_id: String,
    pub backing_allocation_id: String,
    pub authorization: FindingChallengeAuthorizationKind,
    /// Exact signed audit-epoch envelope authorized by the challenge.
    /// Present only for venue-audit outcomes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_epoch_envelope_sha256: Option<String>,
    pub evidence_kind: FindingChallengeEvidenceKind,
    pub verifier_profile_envelope_sha256: String,
    pub evidence_bundle_digest: String,
    pub verdict: FindingChallengeVerdict,
    pub facet: FindingChallengeFacet,
    pub reason: String,
    /// Digest of the exact input set that triggered this evaluation.
    pub trigger_digest: String,
    /// End of the signed retry window granted by an indeterminate outcome.
    /// Absent when no retry is granted or the verdict is terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_deadline: Option<u64>,
    /// Present exactly when the verdict is `upheld`; nothing else may enter
    /// the penalty lane, so nothing else carries a calculation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub penalty_calculation: Option<FindingPenaltyCalculation>,
    /// Stable identity and exact historical key policy that authorized this
    /// evaluator signature. The durable outcome-envelope digest pins these
    /// fields after adjudication, allowing later stages to re-resolve the
    /// policy even after the deployment rotates to a newer evaluator key.
    pub evaluator_authority_id: String,
    pub evaluator_key: PublicKey,
    pub evaluator_key_epoch: u64,
    pub evaluator_valid_from: u64,
    pub evaluator_valid_until: u64,
    pub evaluator_revocation_status_ref: String,
    pub evaluated_at: u64,
}

/// Evaluator-signed envelope for the outcome.
pub type SignedFindingChallengeOutcome = SignedExportEnvelope<FindingChallengeOutcome>;

impl FindingChallengeOutcome {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_CHALLENGE_OUTCOME_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.outcome_id, "outcome_id")?;
        require_hex64(&self.challenge_envelope_sha256, "challenge_envelope_sha256")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(&self.backing_allocation_id, "backing_allocation_id")?;
        match (self.authorization, &self.audit_epoch_envelope_sha256) {
            (FindingChallengeAuthorizationKind::VenueAudit, Some(digest)) => {
                require_hex64(digest, "audit_epoch_envelope_sha256")?;
            }
            (FindingChallengeAuthorizationKind::BuyerSubmission, None) => {}
            _ => return Err(FindingError::InvalidField("audit_epoch_envelope_sha256")),
        }
        require_hex64(
            &self.verifier_profile_envelope_sha256,
            "verifier_profile_envelope_sha256",
        )?;
        require_hex64(&self.evidence_bundle_digest, "evidence_bundle_digest")?;
        if self.facet.kind() != self.evidence_kind {
            return Err(FindingError::InvalidField("facet"));
        }
        self.facet.validate(self.verdict)?;
        require_non_empty(&self.reason, "reason")?;
        require_hex64(&self.trigger_digest, "trigger_digest")?;
        match (&self.penalty_calculation, self.verdict) {
            (Some(calculation), FindingChallengeVerdict::Upheld) => calculation.validate()?,
            (None, FindingChallengeVerdict::Rejected | FindingChallengeVerdict::Indeterminate) => {}
            (Some(_), _) => return Err(FindingError::InvalidField("penalty_calculation")),
            (None, FindingChallengeVerdict::Upheld) => {
                return Err(FindingError::MissingEntry("penalty_calculation"))
            }
        }
        require_bounded_id(&self.evaluator_authority_id, "evaluator_authority_id")?;
        if self.evaluator_key.algorithm() != SigningAlgorithm::Ed25519
            || self.evaluator_key.is_weak_ed25519()
        {
            return Err(FindingError::InvalidField("evaluator_key"));
        }
        require_nonzero(self.evaluator_key_epoch, "evaluator_key_epoch")?;
        require_i_json_u64(self.evaluator_valid_from, "evaluator_valid_from")?;
        require_nonzero(self.evaluator_valid_until, "evaluator_valid_until")?;
        if self.evaluator_valid_until <= self.evaluator_valid_from {
            return Err(FindingError::InvalidField("evaluator_valid_until"));
        }
        require_bounded_id(
            &self.evaluator_revocation_status_ref,
            "evaluator_revocation_status_ref",
        )?;
        require_nonzero(self.evaluated_at, "evaluated_at")?;
        if self.evaluated_at < self.evaluator_valid_from
            || self.evaluated_at >= self.evaluator_valid_until
        {
            return Err(FindingError::InvalidField("evaluated_at"));
        }
        match (self.verdict, self.retry_deadline) {
            (FindingChallengeVerdict::Indeterminate, Some(deadline)) => {
                require_i_json_u64(deadline, "retry_deadline")?;
                if deadline <= self.evaluated_at {
                    return Err(FindingError::InvalidField("retry_deadline"));
                }
            }
            (FindingChallengeVerdict::Upheld | FindingChallengeVerdict::Rejected, Some(_)) => {
                return Err(FindingError::InvalidField("retry_deadline"));
            }
            (_, None) => {}
        }
        self.verify_outcome_id()
    }

    /// Recompute and compare the derived outcome id.
    pub fn verify_outcome_id(&self) -> Result<(), FindingError> {
        let expected = derive_outcome_id(self)?;
        if expected == self.outcome_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("outcome_id"))
        }
    }
}

/// Derive the outcome id: sha256 over the domain-separated canonical body
/// with only `outcome_id` cleared. The envelope signature is outside the
/// body and is therefore excluded by construction.
pub fn derive_outcome_id(outcome: &FindingChallengeOutcome) -> Result<String, FindingError> {
    let mut body = outcome.clone();
    body.outcome_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    let mut preimage = Vec::with_capacity(OUTCOME_ID_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(OUTCOME_ID_DOMAIN);
    preimage.extend_from_slice(&bytes);
    Ok(chio_core_types::crypto::sha256_hex(&preimage))
}

/// Verify that an outcome binds the exact signed challenge envelope.
///
/// The comparison is against the digest of the COMPLETE envelope. A digest
/// over the challenge body alone is a different identity and fails here,
/// which is what keeps an unsigned body from claiming a signed challenge's
/// outcome.
pub fn verify_outcome_challenge_binding(
    outcome: &FindingChallengeOutcome,
    challenge: &SignedFindingChallenge,
) -> Result<(), FindingError> {
    let expected = signed_envelope_sha256(challenge)?;
    if expected == outcome.challenge_envelope_sha256 {
        Ok(())
    } else {
        Err(FindingError::ArtifactIdMismatch(
            "challenge_envelope_sha256",
        ))
    }
}

/// Verify a signed outcome against the externally pinned evaluator
/// authority. Role separation is pinned outside this artifact: a key valid
/// as a venue, purchase, or enforcement authority is rejected here.
pub fn verify_signed_challenge_outcome(
    signed: &SignedFindingChallengeOutcome,
    pinned_evaluator_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, pinned_evaluator_authority, "challenge_outcome")
}
