use super::{
    live_admission_epoch, verify_status_operator_authority_lifecycle,
    verify_venue_authority_lifecycle, FindingMarketConfig, FindingSearchAdmissionView,
    SignedFindingAdmission, SignedFindingAuthorityStatus, SqliteFindingMarketStore,
    SqliteFindingStatusStore,
};

/// A stored admission is CURRENT only while its envelope is unexpired,
/// its allocation remains consumed by the active admission, participation
/// fees are paid through the present audit epoch, and the exact status floor
/// remains live under the configured feed authority.
pub(super) fn current_admission_view(
    store: &SqliteFindingMarketStore,
    status_store: &SqliteFindingStatusStore,
    config: &FindingMarketConfig,
    status_operator_authority_status: Option<&SignedFindingAuthorityStatus>,
    venue_authority_status: Option<&SignedFindingAuthorityStatus>,
    finding_id: &str,
    now: u64,
) -> Option<FindingSearchAdmissionView> {
    let status_operator_authority_status = status_operator_authority_status?;
    let status_epoch = status_store
        .get_current_epoch(&config.status_feed_operator.feed_id)
        .ok()?;
    verify_status_operator_authority_lifecycle(
        status_operator_authority_status,
        config,
        &config.status_feed_operator.feed_id,
        status_epoch.generated_at,
        now,
        "admission view",
    )
    .ok()?;
    store
        .require_verified_live_status(
            &config.status_feed_operator.feed_id,
            finding_id,
            &config.status_feed_operator.authorization_sha256,
            status_operator_authority_status.body.observed_at,
            now,
            config.status_max_epoch_age_secs,
        )
        .ok()?;
    let snapshot = store.get_current_admission(finding_id).ok().flatten()?;
    let admission: SignedFindingAdmission = serde_json::from_str(&snapshot.envelope_json).ok()?;
    verify_venue_authority_lifecycle(&admission, venue_authority_status?, config, now).ok()?;
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
