use super::{
    live_admission_epoch, verify_status_operator_authority_lifecycle, FindingMarketConfig,
    FindingSearchAdmissionView, SignedFindingAdmission, SignedFindingAuthorityStatus,
    SqliteFindingMarketStore,
};

/// A stored admission is CURRENT only while its envelope is unexpired,
/// its allocation remains consumed by the active admission, participation
/// fees are paid through the present audit epoch, and the exact status floor
/// remains live under the configured feed authority.
pub(super) fn current_admission_view(
    store: &SqliteFindingMarketStore,
    config: &FindingMarketConfig,
    authority_status: Option<&SignedFindingAuthorityStatus>,
    finding_id: &str,
    now: u64,
) -> Option<FindingSearchAdmissionView> {
    let authority_status = authority_status?;
    verify_status_operator_authority_lifecycle(
        authority_status,
        config,
        &config.status_feed_operator.feed_id,
        now,
        "admission view",
    )
    .ok()?;
    store
        .require_verified_live_status(
            &config.status_feed_operator.feed_id,
            finding_id,
            &config.status_feed_operator.authorization_sha256,
            now,
        )
        .ok()?;
    let snapshot = store.get_current_admission(finding_id).ok().flatten()?;
    let admission: SignedFindingAdmission = serde_json::from_str(&snapshot.envelope_json).ok()?;
    let current_epoch = live_admission_epoch(store, &snapshot, &admission, now)?;
    let paid_through = store
        .paid_through_epoch(
            finding_id,
            &snapshot.listing_id,
            &admission.body.fee_schedule_envelope_sha256,
        )
        .ok()
        .flatten()?;
    if paid_through < current_epoch {
        return None;
    }
    Some(FindingSearchAdmissionView {
        admission_id: snapshot.admission_id,
        envelope_sha256: snapshot.envelope_sha256,
        expires_at: snapshot.expires_at,
    })
}
