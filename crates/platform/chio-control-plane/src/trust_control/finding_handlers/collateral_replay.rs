use super::*;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingCollateralRegistrationRequest {
    pub(super) backing: SignedFindingBondBacking,
    pub(super) collateral_authority_status: SignedFindingAuthorityStatus,
}

pub(super) fn verify_collateral_authority_lifecycle(
    backing: &SignedFindingBondBacking,
    authority_status: &SignedFindingAuthorityStatus,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<PublicKey, String> {
    if !config.collateral.covers(backing.body.issued_at) || !config.collateral.covers(now) {
        return Err("finding collateral authority is not live".to_owned());
    }
    let collateral_key = config.collateral.key().map_err(|error| error.to_string())?;
    chio_finding::verify_signed_bond_backing(backing, &collateral_key)
        .map_err(|error| error.to_string())?;
    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_authority_status(authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live".to_owned());
    }
    if status.status_ref != config.collateral.revocation_status_ref
        || status.authority_id != config.collateral.authority_id
        || status.key != collateral_key
        || status.key_epoch != config.collateral.key_epoch
    {
        return Err("collateral authority status does not bind the deployment pin".to_owned());
    }
    if status.observed_at < backing.body.issued_at {
        return Err("collateral authority status predates backing issuance".to_owned());
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("collateral authority status is not a fresh current reading".to_owned());
    }
    if status.revoked_from.is_some() {
        return Err("collateral authority is revoked".to_owned());
    }
    Ok(collateral_key)
}

pub(super) fn prepare_collateral_registration(
    backing: &SignedFindingBondBacking,
) -> Result<String, Response> {
    let envelope_json = chio_core::canonical_json_bytes(backing)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
        .map_err(|()| {
            plain_http_error(StatusCode::BAD_REQUEST, "backing failed canonicalization")
        })?;
    Ok(envelope_json)
}
