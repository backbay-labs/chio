//! Standing binding for the two classes whose evidence rests on a settled
//! sale.
//!
//! A purchase record is standing only when it is the authority-signed record
//! for THIS finding, THIS listing, and, for a buyer filing, THIS challenger.
//! A venue audit carries no standing at all, so the record is bound to the
//! evidence branch alone.

use chio_finding::{
    signed_envelope_sha256, verify_signed_purchase_record, FindingChallengeAuthorization,
    FindingChallengeStanding, FindingPurchaseRecord, SignedFindingPurchaseRecord,
};

use crate::evaluate::EvaluationContext;
use crate::input::FindingChallengeInadmissible;
use crate::receipts::policy_covers;

/// Bind a signed purchase record to the challenge that offered it.
pub(crate) fn bind_purchase_record<'a>(
    context: &EvaluationContext<'_>,
    record: &'a SignedFindingPurchaseRecord,
    purchase_record_envelope_sha256: &str,
) -> Result<&'a FindingPurchaseRecord, FindingChallengeInadmissible> {
    let envelope_digest =
        signed_envelope_sha256(record).map_err(FindingChallengeInadmissible::StandingRejected)?;
    if envelope_digest != purchase_record_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "purchase_record_envelope_sha256",
        ));
    }
    let purchase_authority = &context.profile.purchase_authority;
    verify_signed_purchase_record(record, &purchase_authority.key)
        .map_err(FindingChallengeInadmissible::StandingRejected)?;
    let body = &record.body;
    // A key policy states when the key WAS an authority, not that it is one
    // now, so the instant the record is tested at is the one it settled at.
    // Without this, a key that expired or that governance withdrew could still
    // mint standing for any buyer it names, and standing is what admits a
    // challenge to the evidence-invalid and replay branches at all.
    if !policy_covers(purchase_authority, body.recorded_at) {
        return Err(FindingChallengeInadmissible::StandingAuthorityNotEstablished);
    }
    if body.finding_id != context.finding.finding_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "finding_id",
        ));
    }
    if body.listing_id != context.challenge.listing_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "listing_id",
        ));
    }
    if body.seller_backing_envelope_sha256 != context.challenge.backing_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "seller_backing_envelope_sha256",
        ));
    }
    if body.venue_admission_envelope_sha256 != context.challenge.venue_admission_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "venue_admission_envelope_sha256",
        ));
    }
    if let Some(challenger) = context.challenger {
        if body.buyer != *challenger {
            return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                "buyer",
            ));
        }
        match &context.challenge.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                match &submission.standing {
                    FindingChallengeStanding::FinalizedPurchase { purchase_key, .. }
                        if *purchase_key == body.purchase_key => {}
                    _ => {
                        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                            "purchase_key",
                        ))
                    }
                }
            }
            FindingChallengeAuthorization::VenueAudit(_) => {}
        }
    }
    Ok(body)
}
