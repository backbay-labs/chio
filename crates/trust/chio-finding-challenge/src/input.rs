//! The evaluator's inputs and results.
//!
//! Everything the adjudication reads is an argument. There is no resolver
//! trait, clock read, or store handle here by design: a coordinator that
//! could inject resolution could also inject a different answer, and the
//! whole value of a separately signed outcome is that its inputs are exactly
//! the ones the outcome names.

use chio_core_types::crypto::PublicKey;
use chio_finding::{
    FindingAuthorityKeyPolicy, FindingChallengeFacet, FindingChallengeVerdict, FindingError,
    SignedFindingAuthorityStatus, SignedFindingChallenge, SignedFindingChallengeVerifierProfile,
    SignedFindingFailedDelivery, SignedFindingKeyRevocation, SignedFindingPurchaseRecord,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{CheckpointTransparencySummary, KernelCheckpoint};

use crate::ingress::FindingIngressError;
use crate::reason::FindingChallengeReason;

/// Everything one adjudication reads.
pub struct FindingChallengeEvaluationInput<'a> {
    /// The signed challenge. The caller has already verified the envelope at
    /// ingress; this evaluator re-verifies it from the bytes rather than
    /// trusting that it was done.
    pub challenge: &'a SignedFindingChallenge,
    /// The externally pinned audit authority. A venue audit is authorized by
    /// this key alone, so a buyer cannot file a bondless audit.
    pub pinned_audit_authority: &'a PublicKey,
    /// The EXACT canonical bytes of the signed finding artifact. The typed
    /// view is re-derived here; a deserialized `Finding` is never accepted in
    /// its place.
    pub raw_finding: &'a str,
    /// The governance-signed verifier profile the challenge names. It is the
    /// profile effective at publication, and it is what pins every role key
    /// this adjudication is allowed to trust.
    pub profile: &'a SignedFindingChallengeVerifierProfile,
    /// The governance root that must have signed the profile envelope.
    pub governance_authority: &'a PublicKey,
    /// Profile digest pinned by the exact retained, authenticated admission.
    /// This is independent of the caller-controlled challenge and profile.
    pub pinned_admission_profile_envelope_sha256: &'a str,
    /// Purchase-authority policy from the exact retained, venue-signed
    /// admission the challenge names. This may differ from the reusable
    /// verifier profile after an admission-specific rotation.
    pub pinned_purchase_authority: &'a FindingAuthorityKeyPolicy,
    /// Fresh authenticated lifecycle reading for the admission-pinned
    /// purchase authority. Required whenever the selected evidence relies on
    /// a purchase record for standing.
    pub purchase_authority_status: Option<&'a SignedFindingAuthorityStatus>,
    /// Independent signer for authenticated readings from the revocation
    /// references pinned by role policies.
    pub pinned_authority_status_key: &'a PublicKey,
    /// Trusted evaluation time supplied by the coordinator. The evaluator
    /// remains pure and uses this only to bound signed role-status readings.
    pub evaluated_at: u64,
    /// Exactly the evidence the challenge's evidence class selects. A branch
    /// that does not match the challenge's class is inadmissible.
    pub evidence: &'a FindingChallengeClassEvidence<'a>,
}

/// The resolved evidence for exactly one class.
pub enum FindingChallengeClassEvidence<'a> {
    DigestMismatch(FindingDigestMismatchEvidence<'a>),
    EvidenceInvalid(FindingEvidenceInvalidEvidence<'a>),
    ReplayContradiction(FindingReplayContradictionEvidence<'a>),
}

/// Resolved evidence for a `digest_mismatch` challenge.
pub struct FindingDigestMismatchEvidence<'a> {
    /// The failed-delivery-authority-signed terminal the challenge names.
    pub failed_delivery: &'a SignedFindingFailedDelivery,
    /// Authenticated reading of the failed-delivery authority's exact
    /// revocation reference, observed no earlier than the terminal.
    pub failed_delivery_authority_status: &'a SignedFindingAuthorityStatus,
    /// Fresh authenticated lifecycle reading for the delivery receipt role.
    pub delivery_authority_status: &'a SignedFindingAuthorityStatus,
    /// The denial receipt, with the exact canonical bytes that were the
    /// checkpoint leaf and the inclusion proof over them.
    pub deny_receipt: &'a ResolvedReceiptEvidence,
    /// The checkpoint the denial is proved against.
    pub deny_checkpoint: &'a KernelCheckpoint,
    /// Retained publication records for the exact checkpoint set.
    pub checkpoint_transparency: &'a CheckpointTransparencySummary,
}

/// Resolved evidence for an `evidence_invalid` challenge.
pub struct FindingEvidenceInvalidEvidence<'a> {
    /// The purchase-authority-signed record that establishes standing.
    pub purchase_record: &'a SignedFindingPurchaseRecord,
    /// Exactly the contested receipts, in the order the challenge names
    /// them.
    pub challenged_receipts: &'a [ResolvedReceiptEvidence],
    /// The checkpoint the contested subset is proved against.
    pub challenged_checkpoint: &'a KernelCheckpoint,
    /// Retained publication records for the exact checkpoint set.
    pub checkpoint_transparency: &'a CheckpointTransparencySummary,
    /// What the caller resolved from the revocation feeds the profile pins.
    /// A statement that only holds from after publication is a key-lifecycle
    /// event, not retroactive fabrication, and cannot uphold.
    pub revoked_keys: &'a [FindingRevokedKeyProof<'a>],
}

/// One offered revocation or compromise proof.
///
/// The proof IS the governance-signed statement. Nothing about a revocation
/// can be asserted beside it: the key, the epoch, the feed, and the instant
/// the withdrawal holds from are all members of a body the governance root
/// signed. A caller who does not hold that signature cannot express the
/// claim at all, which is what keeps a challenger-chosen timestamp from
/// turning a checkpointed production receipt into affirmative fraud.
pub struct FindingRevokedKeyProof<'a> {
    /// The signed statement. The evaluator re-verifies it against the same
    /// pinned governance root that authorized the profile.
    pub statement: &'a SignedFindingKeyRevocation,
}

/// Resolved evidence for a `replay_contradiction` challenge.
pub struct FindingReplayContradictionEvidence<'a> {
    /// The purchase-authority-signed record that establishes standing.
    pub purchase_record: &'a SignedFindingPurchaseRecord,
    /// Fresh authenticated lifecycle reading for the replay receipt role.
    pub replay_authority_status: &'a SignedFindingAuthorityStatus,
    /// One resolved reproduction per challenge tuple, in challenge order.
    pub reproductions: &'a [FindingResolvedReproduction<'a>],
}

/// One resolved reproduction tuple: the mediated runner receipt and the
/// checkpoint that proves it.
pub struct FindingResolvedReproduction<'a> {
    pub receipt: &'a ResolvedReceiptEvidence,
    pub checkpoint: &'a KernelCheckpoint,
    pub checkpoint_transparency: &'a CheckpointTransparencySummary,
}

/// Why a submission never became evaluable.
///
/// An inadmissible submission has no verdict. It creates no hold, no
/// sanction, and no liability transition, and no outcome may be signed for
/// it, which is what keeps a malformed or cross-class filing from consuming
/// an adjudication slot it never qualified for.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingChallengeInadmissible {
    #[error("challenge submission rejected: {0}")]
    ChallengeRejected(FindingError),
    #[error("verifier profile rejected: {0}")]
    ProfileRejected(FindingError),
    #[error("challenge names a verifier profile other than the one supplied")]
    ProfileBindingMismatch,
    #[error("verifier profile is not the one retained by the authenticated admission")]
    AdmissionProfileBindingMismatch,
    #[error("raw finding ingress failed: {0}")]
    FindingIngress(FindingIngressError),
    #[error("finding artifact rejected: {0}")]
    FindingRejected(FindingError),
    #[error("challenge does not bind the supplied finding: {0}")]
    FindingBindingMismatch(&'static str),
    #[error("challenge class is not compatible with the finding: {0}")]
    ClassIncompatible(FindingError),
    #[error("supplied evidence belongs to another challenge class")]
    ClassEvidenceMismatch,
    #[error("standing artifact rejected: {0}")]
    StandingRejected(FindingError),
    #[error("purchase authority is not established for the instant the standing record settled")]
    StandingAuthorityNotEstablished,
    #[error("failed-delivery authority is not established for the instant the standing terminal was recorded")]
    FailedDeliveryAuthorityNotEstablished,
    #[error("standing artifact does not bind the challenge: {0}")]
    StandingBindingMismatch(&'static str),
    #[error("evidence reference does not bind the challenge: {0}")]
    EvidenceBindingMismatch(&'static str),
    #[error("supplied evidence set does not match the challenge: {0}")]
    EvidenceSetMismatch(&'static str),
    #[error("finding commits no replay recipe")]
    RecipeCommitmentAbsent,
    #[error("carried recipe preimage rejected: {0}")]
    RecipePreimageRejected(FindingIngressError),
    #[error("carried recipe preimage does not hash to the committed recipe digest")]
    RecipePreimageMismatch,
    #[error("carried replay observation rejected: {0}")]
    ObservationRejected(FindingIngressError),
    #[error("carried replay observation does not bind the committed recipe: {0}")]
    ObservationBindingMismatch(&'static str),
}

/// One adjudicated challenge: the verdict, the typed nested facet, and the
/// reason the verdict follows from.
///
/// The verdict is not a separate field a caller may set. It is derived from
/// the reason at construction, and the facet is built from the same decision,
/// so the three can never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingChallengeAdjudication {
    verdict: FindingChallengeVerdict,
    facet: FindingChallengeFacet,
    reason: FindingChallengeReason,
}

impl FindingChallengeAdjudication {
    pub(crate) fn new(facet: FindingChallengeFacet, reason: FindingChallengeReason) -> Self {
        Self {
            verdict: reason.verdict(),
            facet,
            reason,
        }
    }

    /// The class-independent verdict.
    #[must_use]
    pub fn verdict(&self) -> FindingChallengeVerdict {
        self.verdict
    }

    /// The typed nested facet, ready to place under the outcome's evidence
    /// branch.
    #[must_use]
    pub fn facet(&self) -> &FindingChallengeFacet {
        &self.facet
    }

    /// The machine-readable reason.
    #[must_use]
    pub fn reason(&self) -> FindingChallengeReason {
        self.reason
    }

    /// Consume the adjudication into the parts an outcome body needs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FindingChallengeVerdict,
        FindingChallengeFacet,
        FindingChallengeReason,
    ) {
        (self.verdict, self.facet, self.reason)
    }
}

/// The result of one adjudication attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum FindingChallengeEvaluation {
    /// The submission never became evaluable. There is no verdict.
    Inadmissible(FindingChallengeInadmissible),
    /// The submission was evaluated to exactly one of the three verdicts.
    Adjudicated(FindingChallengeAdjudication),
}

impl FindingChallengeEvaluation {
    /// The verdict, when one exists. An inadmissible submission has none;
    /// callers must not substitute a default.
    #[must_use]
    pub fn verdict(&self) -> Option<FindingChallengeVerdict> {
        match self {
            FindingChallengeEvaluation::Inadmissible(_) => None,
            FindingChallengeEvaluation::Adjudicated(adjudication) => Some(adjudication.verdict()),
        }
    }

    /// The adjudication, when the submission was evaluable.
    #[must_use]
    pub fn adjudication(&self) -> Option<&FindingChallengeAdjudication> {
        match self {
            FindingChallengeEvaluation::Inadmissible(_) => None,
            FindingChallengeEvaluation::Adjudicated(adjudication) => Some(adjudication),
        }
    }

    /// Whether this result may enter the penalty lane. Only an upheld
    /// adjudication may.
    #[must_use]
    pub fn authorizes_penalty(&self) -> bool {
        self.verdict() == Some(FindingChallengeVerdict::Upheld)
    }
}
