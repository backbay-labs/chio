//! The machine-readable reason vocabulary and its total verdict mapping.
//!
//! The verdict is derived from the reason rather than chosen beside it. That
//! is the whole point of this type: "the evidence was evaluable and did not
//! show fraud" and "the inputs could not be established" are different facts
//! with different consequences, and a coordinator that confused them would
//! either sanction a seller for an outage or forfeit a buyer's bond for one.

use core::fmt;

use chio_finding::FindingChallengeVerdict;

/// Which of the three disjoint classes a reason belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeReasonClass {
    /// Fraud was affirmatively established under the committed profile.
    AffirmativeFraud,
    /// The evidence was evaluable and did not show fraud.
    EvaluatedClean,
    /// Authority, retention, resolver, or infrastructure inputs could not be
    /// established, so nothing was decided about the seller.
    InputsNotEstablished,
}

impl FindingChallengeReasonClass {
    /// The verdict this class produces. Total and normative.
    #[must_use]
    pub fn verdict(self) -> FindingChallengeVerdict {
        match self {
            FindingChallengeReasonClass::AffirmativeFraud => FindingChallengeVerdict::Upheld,
            FindingChallengeReasonClass::EvaluatedClean => FindingChallengeVerdict::Rejected,
            FindingChallengeReasonClass::InputsNotEstablished => {
                FindingChallengeVerdict::Indeterminate
            }
        }
    }
}

/// Why the evaluator reached its verdict.
///
/// Closed vocabulary. Each variant belongs to exactly one
/// [`FindingChallengeReasonClass`], and that membership is what fixes the
/// verdict, so a reason cannot be attached to a verdict it does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingChallengeReason {
    /// The kernel denied the reveal because the delivered output did not hash
    /// to the digest the signed finding committed, under the marked identity
    /// output profile. This is seller-origin fraud.
    SellerOriginDigestMismatch,
    /// A challenged evidence receipt did not verify against its own embedded
    /// kernel key.
    EvidenceSignatureInvalid,
    /// The checkpoint proof offered for the challenged subset positively
    /// contradicts the claimed membership.
    EvidenceCheckpointContradiction,
    /// A challenged evidence receipt does not bind the claim it was offered
    /// for: its own action commitment contradicts its parameters.
    EvidenceSemanticCrossBindingFailure,
    /// A challenged evidence receipt was signed by a key proven revoked or
    /// compromised at publication time.
    EvidenceKeyRevokedAtPublication,
    /// The committed predicate, applied to the completed reproduction
    /// observations, contradicts the verdict the recipe claimed.
    ReplayContradictionConfirmed,

    /// The delivered output hashed to the committed digest; there was no
    /// mismatch to adjudicate.
    DeliveredOutputMatchesCommitment,
    /// The denial carried no finding-delivery overlay, so it is a generic
    /// digest denial rather than an authenticated seller-origin mismatch.
    DenialNotSellerOrigin,
    /// The denial compared the delivered output against an expected digest
    /// that is not the finding's committed payload digest, which makes it an
    /// operator output-policy denial rather than seller fraud.
    DenialOutputPolicyExpectation,
    /// The denial was a reveal-envelope media-type denial, which is not
    /// seller fraud.
    DenialMediaTypeMismatch,
    /// The challenged evidence subset resolved and is valid.
    ChallengedEvidenceValid,
    /// The reproduction agrees with the verdict the recipe claimed.
    ReplayReproductionConsistent,

    /// The failed-delivery or delivery-receipt authority could not be
    /// established under the committed profile.
    DeliveryAuthorityNotEstablished,
    /// The delivery evidence named by the challenge did not resolve to the
    /// artifact it names, or does not carry the blocks the class requires.
    DeliveryEvidenceNotEstablished,
    /// The checkpoint proving the denial could not be established.
    DeliveryCheckpointNotEstablished,
    /// A challenged evidence receipt did not resolve to the artifact the
    /// finding names.
    EvidenceReceiptNotEstablished,
    /// The checkpoint covering the challenged subset could not be
    /// established under the committed profile.
    EvidenceCheckpointNotEstablished,
    /// A signer of the challenged evidence is not an authority this profile
    /// establishes for that role and time.
    EvidenceAuthorityNotEstablished,
    /// A challenged evidence signing key was revoked only after publication,
    /// which is a key-lifecycle event rather than retroactive fabrication.
    EvidenceKeyRevokedAfterPublication,
    /// A reproduction receipt was not signed by the profile's replay-role
    /// authority, or that authority was not valid when the receipt was
    /// issued.
    ReplayAuthorityNotEstablished,
    /// A reproduction observation did not resolve against its terminal
    /// receipt, its checkpoint, or the committed recipe.
    ReplayObservationNotEstablished,
    /// A reproduction phase did not run to completion: it failed, timed out,
    /// exhausted a committed resource cap, or the runner itself errored.
    ReplayRunIncomplete,
    /// The reproduction set does not present exactly the phases the
    /// committed predicate reads.
    ReplayPhasesAmbiguous,
    /// The committed predicate is not one the governance profile admits.
    ReplayPredicateNotAdmitted,
}

impl FindingChallengeReason {
    /// The class this reason belongs to.
    #[must_use]
    pub fn class(self) -> FindingChallengeReasonClass {
        match self {
            FindingChallengeReason::SellerOriginDigestMismatch
            | FindingChallengeReason::EvidenceSignatureInvalid
            | FindingChallengeReason::EvidenceCheckpointContradiction
            | FindingChallengeReason::EvidenceSemanticCrossBindingFailure
            | FindingChallengeReason::EvidenceKeyRevokedAtPublication
            | FindingChallengeReason::ReplayContradictionConfirmed => {
                FindingChallengeReasonClass::AffirmativeFraud
            }
            FindingChallengeReason::DeliveredOutputMatchesCommitment
            | FindingChallengeReason::DenialNotSellerOrigin
            | FindingChallengeReason::DenialOutputPolicyExpectation
            | FindingChallengeReason::DenialMediaTypeMismatch
            | FindingChallengeReason::ChallengedEvidenceValid
            | FindingChallengeReason::ReplayReproductionConsistent => {
                FindingChallengeReasonClass::EvaluatedClean
            }
            FindingChallengeReason::DeliveryAuthorityNotEstablished
            | FindingChallengeReason::DeliveryEvidenceNotEstablished
            | FindingChallengeReason::DeliveryCheckpointNotEstablished
            | FindingChallengeReason::EvidenceReceiptNotEstablished
            | FindingChallengeReason::EvidenceCheckpointNotEstablished
            | FindingChallengeReason::EvidenceAuthorityNotEstablished
            | FindingChallengeReason::EvidenceKeyRevokedAfterPublication
            | FindingChallengeReason::ReplayAuthorityNotEstablished
            | FindingChallengeReason::ReplayObservationNotEstablished
            | FindingChallengeReason::ReplayRunIncomplete
            | FindingChallengeReason::ReplayPhasesAmbiguous
            | FindingChallengeReason::ReplayPredicateNotAdmitted => {
                FindingChallengeReasonClass::InputsNotEstablished
            }
        }
    }

    /// The verdict this reason produces, derived from its class.
    #[must_use]
    pub fn verdict(self) -> FindingChallengeVerdict {
        self.class().verdict()
    }

    /// Stable machine token for logs, stores, and outcome bodies.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            FindingChallengeReason::SellerOriginDigestMismatch => "seller_origin_digest_mismatch",
            FindingChallengeReason::EvidenceSignatureInvalid => "evidence_signature_invalid",
            FindingChallengeReason::EvidenceCheckpointContradiction => {
                "evidence_checkpoint_contradiction"
            }
            FindingChallengeReason::EvidenceSemanticCrossBindingFailure => {
                "evidence_semantic_cross_binding_failure"
            }
            FindingChallengeReason::EvidenceKeyRevokedAtPublication => {
                "evidence_key_revoked_at_publication"
            }
            FindingChallengeReason::ReplayContradictionConfirmed => {
                "replay_contradiction_confirmed"
            }
            FindingChallengeReason::DeliveredOutputMatchesCommitment => {
                "delivered_output_matches_commitment"
            }
            FindingChallengeReason::DenialNotSellerOrigin => "denial_not_seller_origin",
            FindingChallengeReason::DenialOutputPolicyExpectation => {
                "denial_output_policy_expectation"
            }
            FindingChallengeReason::DenialMediaTypeMismatch => "denial_media_type_mismatch",
            FindingChallengeReason::ChallengedEvidenceValid => "challenged_evidence_valid",
            FindingChallengeReason::ReplayReproductionConsistent => {
                "replay_reproduction_consistent"
            }
            FindingChallengeReason::DeliveryAuthorityNotEstablished => {
                "delivery_authority_not_established"
            }
            FindingChallengeReason::DeliveryEvidenceNotEstablished => {
                "delivery_evidence_not_established"
            }
            FindingChallengeReason::DeliveryCheckpointNotEstablished => {
                "delivery_checkpoint_not_established"
            }
            FindingChallengeReason::EvidenceReceiptNotEstablished => {
                "evidence_receipt_not_established"
            }
            FindingChallengeReason::EvidenceCheckpointNotEstablished => {
                "evidence_checkpoint_not_established"
            }
            FindingChallengeReason::EvidenceAuthorityNotEstablished => {
                "evidence_authority_not_established"
            }
            FindingChallengeReason::EvidenceKeyRevokedAfterPublication => {
                "evidence_key_revoked_after_publication"
            }
            FindingChallengeReason::ReplayAuthorityNotEstablished => {
                "replay_authority_not_established"
            }
            FindingChallengeReason::ReplayObservationNotEstablished => {
                "replay_observation_not_established"
            }
            FindingChallengeReason::ReplayRunIncomplete => "replay_run_incomplete",
            FindingChallengeReason::ReplayPhasesAmbiguous => "replay_phases_ambiguous",
            FindingChallengeReason::ReplayPredicateNotAdmitted => "replay_predicate_not_admitted",
        }
    }

    /// Human-readable statement of the same fact, for the outcome body.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            FindingChallengeReason::SellerOriginDigestMismatch => {
                "the delivered reveal did not hash to the digest the signed finding committed, under the marked identity output profile"
            }
            FindingChallengeReason::EvidenceSignatureInvalid => {
                "a challenged evidence receipt failed strict verification against its own kernel key"
            }
            FindingChallengeReason::EvidenceCheckpointContradiction => {
                "the checkpoint proof offered for the challenged evidence contradicts the claimed membership"
            }
            FindingChallengeReason::EvidenceSemanticCrossBindingFailure => {
                "a challenged evidence receipt does not bind the action it commits"
            }
            FindingChallengeReason::EvidenceKeyRevokedAtPublication => {
                "a challenged evidence receipt was signed by a key proven revoked at publication"
            }
            FindingChallengeReason::ReplayContradictionConfirmed => {
                "the committed predicate over the completed observations contradicts the claimed verdict"
            }
            FindingChallengeReason::DeliveredOutputMatchesCommitment => {
                "the delivered output hashed to the committed payload digest"
            }
            FindingChallengeReason::DenialNotSellerOrigin => {
                "the denial carries no finding-delivery overlay and is therefore a generic digest denial"
            }
            FindingChallengeReason::DenialOutputPolicyExpectation => {
                "the denial compared the output against an expectation other than the committed payload digest"
            }
            FindingChallengeReason::DenialMediaTypeMismatch => {
                "the denial was a reveal-envelope media-type denial"
            }
            FindingChallengeReason::ChallengedEvidenceValid => {
                "the challenged evidence subset resolved and is valid under the committed profile"
            }
            FindingChallengeReason::ReplayReproductionConsistent => {
                "the reproduction agrees with the verdict the recipe claimed"
            }
            FindingChallengeReason::DeliveryAuthorityNotEstablished => {
                "the delivery or failed-delivery authority is not established by the committed profile"
            }
            FindingChallengeReason::DeliveryEvidenceNotEstablished => {
                "the delivery evidence did not resolve to the artifact the challenge names"
            }
            FindingChallengeReason::DeliveryCheckpointNotEstablished => {
                "the checkpoint proving the denial could not be established"
            }
            FindingChallengeReason::EvidenceReceiptNotEstablished => {
                "a challenged evidence receipt did not resolve to the artifact the finding names"
            }
            FindingChallengeReason::EvidenceCheckpointNotEstablished => {
                "the checkpoint covering the challenged evidence could not be established"
            }
            FindingChallengeReason::EvidenceAuthorityNotEstablished => {
                "a signer of the challenged evidence is not established for that role and time"
            }
            FindingChallengeReason::EvidenceKeyRevokedAfterPublication => {
                "a challenged evidence signing key was revoked only after publication"
            }
            FindingChallengeReason::ReplayAuthorityNotEstablished => {
                "a reproduction receipt is not signed by the profile's replay authority"
            }
            FindingChallengeReason::ReplayObservationNotEstablished => {
                "a reproduction observation did not resolve against its receipt, checkpoint, or recipe"
            }
            FindingChallengeReason::ReplayRunIncomplete => {
                "a reproduction phase did not run to completion"
            }
            FindingChallengeReason::ReplayPhasesAmbiguous => {
                "the reproduction set does not present exactly the phases the predicate reads"
            }
            FindingChallengeReason::ReplayPredicateNotAdmitted => {
                "the committed predicate is not admitted by the governance profile"
            }
        }
    }
}

impl fmt::Display for FindingChallengeReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message())
    }
}
