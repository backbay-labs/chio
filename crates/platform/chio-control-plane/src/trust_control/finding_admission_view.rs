use super::super::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use super::{
    require_status_feed_through, verify_seller_authorization_lifecycle,
    verify_status_operator_authority_lifecycle, verify_venue_authority_lifecycle,
    FindingAdmissionSnapshot, FindingAllocationState, FindingAuthorityKeyPolicy,
    FindingAuthorityPin, FindingMarketConfig, FindingSearchAdmissionView, SignedFindingAdmission,
    SignedFindingAuthorityStatus, SignedFindingMarketTerms, SignedFindingSellerAuthorization,
    SqliteFindingMarketStore, SqliteFindingStatusStore, FINDING_AUTHORITY_STATUS_MAX_AGE_SECS,
    FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
};
use chio_store_sqlite::SqliteFindingPurchaseStore;

/// Return the current payable audit epoch only while the stored admission
/// still owns its backing and remains inside its signed lifetime.
pub(super) fn live_admission_epoch(
    store: &SqliteFindingMarketStore,
    snapshot: &FindingAdmissionSnapshot,
    admission: &SignedFindingAdmission,
    now: u64,
) -> Option<u64> {
    if now >= snapshot.expires_at || snapshot.allocation_state != FindingAllocationState::Consumed {
        return None;
    }
    let terms_bytes = store
        .get_recipe_blob(&admission.body.terms_envelope_sha256)
        .ok()
        .flatten()?;
    let terms: SignedFindingMarketTerms = serde_json::from_slice(&terms_bytes).ok()?;
    let epoch_length = terms.body.audit_epoch_length_secs.max(1);
    Some(now.saturating_sub(snapshot.activated_at) / epoch_length)
}

pub(super) fn terminal_authority_pin(policy: &FindingAuthorityKeyPolicy) -> FindingAuthorityPin {
    FindingAuthorityPin {
        authority_id: policy.authority_id.clone(),
        key_hex: policy.key.to_hex(),
        key_epoch: policy.key_epoch,
        valid_from: policy.valid_from,
        valid_until: policy.valid_until,
        revocation_status_ref: policy.revocation_status_ref.clone(),
    }
}

pub(super) fn verify_terminal_authority_lifecycle(
    policy: &FindingAuthorityKeyPolicy,
    authority_status: &SignedFindingAuthorityStatus,
    config: &FindingMarketConfig,
    admission_issued_at: u64,
    now: u64,
) -> Result<(), String> {
    policy
        .validate("admission terminal authority")
        .map_err(|error| error.to_string())?;
    if now < policy.valid_from || now >= policy.valid_until {
        return Err("admission terminal authority is outside its validity window".to_owned());
    }
    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    chio_finding::verify_signed_authority_status(authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live for the admission view".to_owned());
    }
    if status.status_ref != policy.revocation_status_ref
        || status.authority_id != policy.authority_id
        || status.key != policy.key
        || status.key_epoch != policy.key_epoch
    {
        return Err("terminal authority status does not bind the admitted policy".to_owned());
    }
    if status.observed_at < admission_issued_at
        || status.observed_at < policy.valid_from
        || status.observed_at >= policy.valid_until
        || status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("terminal authority status is not a fresh current reading".to_owned());
    }
    if status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= now)
    {
        return Err("terminal authority is revoked for the admission view".to_owned());
    }
    Ok(())
}

pub(super) fn verify_current_admission_authorities(
    store: &SqliteFindingMarketStore,
    config: &FindingMarketConfig,
    authority_status_resolver: &dyn FindingAuthorityStatusResolver,
    venue_authority_status: &SignedFindingAuthorityStatus,
    admission: &SignedFindingAdmission,
    now: u64,
) -> Result<(), String> {
    let listing_key = config.listing.key().map_err(|error| error.to_string())?;
    if !config.listing.covers(now) {
        return Err("configured listing authority is not live for the admission view".to_owned());
    }
    let listing_status = authority_status_resolver
        .resolve(&config.listing, now)
        .map_err(|error| format!("listing authority status resolution failed: {error}"))?;
    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    chio_finding::verify_signed_authority_status(&listing_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &listing_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live for the admission view".to_owned());
    }
    if status.status_ref != config.listing.revocation_status_ref
        || status.authority_id != config.listing.authority_id
        || status.key != listing_key
        || status.key_epoch != config.listing.key_epoch
    {
        return Err("listing authority status does not bind the deployment pin".to_owned());
    }
    if status.observed_at < admission.body.issued_at
        || status.observed_at < config.listing.valid_from
        || status.observed_at >= config.listing.valid_until
        || status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("listing authority status is not a fresh current reading".to_owned());
    }
    if status
        .revoked_from
        .is_some_and(|revoked_from| revoked_from <= now)
    {
        return Err("listing authority is revoked for the admission view".to_owned());
    }
    verify_venue_authority_lifecycle(admission, venue_authority_status, config, now)?;
    for policy in [
        &admission.body.purchase_authority,
        &admission.body.failed_delivery_authority,
    ] {
        let authority_status = authority_status_resolver
            .resolve(&terminal_authority_pin(policy), now)
            .map_err(|error| format!("terminal authority status resolution failed: {error}"))?;
        verify_terminal_authority_lifecycle(
            policy,
            &authority_status,
            config,
            admission.body.issued_at,
            now,
        )?;
    }
    let authorization_bytes = store
        .get_recipe_blob(&admission.body.seller_authorization_envelope_sha256)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "admission-bound seller authorization is not retained".to_owned())?;
    let authorization: SignedFindingSellerAuthorization =
        serde_json::from_slice(&authorization_bytes)
            .map_err(|_| "admission-bound seller authorization is malformed".to_owned())?;
    chio_finding::verify_signed_seller_authorization(&authorization)
        .map_err(|error| error.to_string())?;
    if now < authorization.body.issued_at || now >= authorization.body.expires_at {
        return Err("seller authorization is not live for the admission view".to_owned());
    }
    let seller_pin = FindingAuthorityPin {
        authority_id: authorization.body.authorization_id.clone(),
        key_hex: authorization.body.issuer.to_hex(),
        key_epoch: FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
        valid_from: authorization.body.issued_at,
        valid_until: authorization.body.expires_at,
        revocation_status_ref: authorization.body.revocation_status_ref.clone(),
    };
    let seller_status = authority_status_resolver
        .resolve(&seller_pin, now)
        .map_err(|error| format!("seller authorization status resolution failed: {error}"))?;
    verify_seller_authorization_lifecycle(&authorization, &seller_status, config, now)
}

/// A stored admission is CURRENT only while its envelope is unexpired,
/// its allocation remains consumed by the active admission, participation
/// fees are paid through the present audit epoch, and the exact status floor
/// remains live under the configured feed authority.
pub(super) fn current_admission_view(
    store: &SqliteFindingMarketStore,
    purchase_store: &SqliteFindingPurchaseStore,
    status_store: &SqliteFindingStatusStore,
    config: &FindingMarketConfig,
    authority_status_resolver: Option<&dyn FindingAuthorityStatusResolver>,
    status_operator_authority_status: Option<&SignedFindingAuthorityStatus>,
    venue_authority_status: Option<&SignedFindingAuthorityStatus>,
    finding_id: &str,
    now: u64,
) -> Option<FindingSearchAdmissionView> {
    let status_operator_authority_status = status_operator_authority_status?;
    require_status_feed_through(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        &config.status_feed_operator.feed_id,
        now,
        now,
    )
    .ok()?;
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
    if purchase_store.sales_blocked(&snapshot.listing_id).ok()? {
        return None;
    }
    let admission: SignedFindingAdmission = serde_json::from_str(&snapshot.envelope_json).ok()?;
    let authority_status_resolver = authority_status_resolver?;
    verify_current_admission_authorities(
        store,
        config,
        authority_status_resolver,
        venue_authority_status?,
        &admission,
        now,
    )
    .ok()?;
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
        envelope_json: snapshot.envelope_json,
    })
}
