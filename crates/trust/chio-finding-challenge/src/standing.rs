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
    verify_signed_purchase_record(record, &context.profile.purchase_authority.key)
        .map_err(FindingChallengeInadmissible::StandingRejected)?;
    let body = &record.body;
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
