//! Authentication of the committed draw behind a bondless venue audit.

use chio_finding::{
    audit_epoch_precommitment_sha256, signed_envelope_sha256, verify_signed_audit_epoch,
    verify_signed_audit_round_authorization, FindingChallenge, FindingChallengeAuthorization,
};
use chio_open_market::finding_audit::select_audit_targets;

use crate::input::{
    FindingChallengeEvaluationInput, FindingChallengeInadmissible,
    FindingVenueAuditSelectionEvidence,
};

pub(crate) fn require_venue_audit_selection(
    input: &FindingChallengeEvaluationInput<'_>,
    challenge: &FindingChallenge,
) -> Result<(), FindingChallengeInadmissible> {
    let FindingChallengeAuthorization::VenueAudit(audit) = &challenge.authorization else {
        if input.venue_audit_selection.is_some() {
            return Err(
                FindingChallengeInadmissible::VenueAuditSelectionNotEstablished(
                    "buyer submission carried audit evidence",
                ),
            );
        }
        return Ok(());
    };
    let evidence = input.venue_audit_selection.as_ref().ok_or(
        FindingChallengeInadmissible::VenueAuditSelectionNotEstablished("round evidence absent"),
    )?;
    require_exact_round(input, challenge, audit, evidence)
}

fn require_exact_round(
    input: &FindingChallengeEvaluationInput<'_>,
    challenge: &FindingChallenge,
    audit: &chio_finding::FindingVenueAuditAuthorization,
    evidence: &FindingVenueAuditSelectionEvidence<'_>,
) -> Result<(), FindingChallengeInadmissible> {
    let reject = FindingChallengeInadmissible::VenueAuditSelectionNotEstablished;
    let epoch_digest =
        signed_envelope_sha256(evidence.epoch).map_err(|_| reject("epoch digest"))?;
    if epoch_digest != audit.audit_epoch_envelope_sha256 {
        return Err(reject("audit_epoch_envelope_sha256"));
    }
    verify_signed_audit_epoch(
        evidence.epoch,
        input.pinned_audit_authority,
        evidence.pinned_randomness_witness,
    )
    .map_err(|_| reject("epoch signature"))?;
    let authorization_digest = signed_envelope_sha256(evidence.authorization)
        .map_err(|_| reject("authorization digest"))?;
    if authorization_digest != audit.authorization_digest
        || authorization_digest != evidence.epoch.body.authorization_digest
    {
        return Err(reject("authorization_digest"));
    }
    verify_signed_audit_round_authorization(
        evidence.authorization,
        evidence.pinned_governance_authority,
    )
    .map_err(|_| reject("authorization signature"))?;
    evidence
        .authorization
        .body
        .validate()
        .map_err(|_| reject("authorization body"))?;
    if evidence.authorization.body.authorized_at > evidence.epoch.body.committed_at
        || evidence.authorization.body.expires_at <= evidence.epoch.body.committed_at
        || evidence.authorization.body.epoch_precommitment_sha256
            != audit_epoch_precommitment_sha256(&evidence.epoch.body)
                .map_err(|_| reject("epoch precommitment"))?
        || challenge.filed_at <= evidence.epoch.body.committed_at
    {
        return Err(reject("authorization epoch"));
    }
    let selection = select_audit_targets(
        &evidence.epoch.body,
        evidence.pinned_randomness_witness,
        evidence.revealed_seed,
        evidence.eligible,
    )
    .map_err(|_| reject("committed draw"))?;
    let drawn = selection
        .iter()
        .find(|target| {
            target.finding_id == challenge.finding_id && target.listing_id == challenge.listing_id
        })
        .ok_or(reject("selection"))?;
    if drawn.draw != audit.selection_digest {
        return Err(reject("selection_digest"));
    }
    Ok(())
}
