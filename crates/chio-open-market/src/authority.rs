use crate::crypto::PublicKey;
use crate::evaluation::OpenMarketPenaltyEvaluationRequest;
use crate::fee_schedule::SignedOpenMarketFeeSchedule;
use crate::governance::generic::{SignedGenericGovernanceCase, SignedGenericGovernanceCharter};
use crate::listing::{
    ensure_generic_listing_signed_by_namespace_owner, SignedGenericListing,
    SignedGenericTrustActivation,
};
use crate::penalty::{OpenMarketPenaltyIssueRequest, SignedOpenMarketPenalty};

pub(crate) fn verify_signed_listing(
    listing: &SignedGenericListing,
    label: &str,
) -> Result<(), String> {
    ensure_generic_listing_signed_by_namespace_owner(listing, label)
}

pub(crate) fn verify_signed_activation(
    activation: &SignedGenericTrustActivation,
) -> Result<(), String> {
    activation.body.validate()?;
    if !activation
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("trust activation signature is invalid".to_string());
    }
    Ok(())
}

pub(crate) fn verify_signed_charter(
    charter: &SignedGenericGovernanceCharter,
) -> Result<(), String> {
    charter.body.validate()?;
    if !charter
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("governance charter signature is invalid".to_string());
    }
    Ok(())
}

pub(crate) fn verify_signed_case(case: &SignedGenericGovernanceCase) -> Result<(), String> {
    case.body.validate()?;
    if !case.verify_signature().map_err(|error| error.to_string())? {
        return Err("governance case signature is invalid".to_string());
    }
    Ok(())
}

pub(crate) fn verify_signed_fee_schedule(
    schedule: &SignedOpenMarketFeeSchedule,
) -> Result<(), String> {
    schedule.body.validate()?;
    if !schedule
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("fee schedule signature is invalid".to_string());
    }
    Ok(())
}

pub(crate) fn verify_signed_penalty(penalty: &SignedOpenMarketPenalty) -> Result<(), String> {
    penalty.body.validate()?;
    if !penalty
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("penalty signature is invalid".to_string());
    }
    Ok(())
}

pub(crate) fn ensure_open_market_issue_authority_signers(
    request: &OpenMarketPenaltyIssueRequest,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    ensure_matching_signer_key(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key(
        "governance charter",
        &request.charter.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key("governance case", &request.case.signer_key, trusted_signers)?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_matching_signer_key("trust activation", &activation.signer_key, trusted_signers)?;
    }
    Ok(())
}

pub(crate) fn ensure_open_market_evaluation_authority_signers(
    request: &OpenMarketPenaltyEvaluationRequest,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    ensure_matching_signer_key(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key(
        "governance charter",
        &request.charter.signer_key,
        trusted_signers,
    )?;
    ensure_matching_signer_key("governance case", &request.case.signer_key, trusted_signers)?;
    ensure_matching_signer_key("penalty", &request.penalty.signer_key, trusted_signers)?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_matching_signer_key("trust activation", &activation.signer_key, trusted_signers)?;
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        ensure_matching_signer_key("prior penalty", &prior_penalty.signer_key, trusted_signers)?;
    }
    Ok(())
}

fn ensure_matching_signer_key(
    label: &str,
    signer_key: &PublicKey,
    trusted_signers: &[PublicKey],
) -> Result<(), String> {
    if !trusted_signers
        .iter()
        .any(|trusted_signer| trusted_signer == signer_key)
    {
        return Err(format!(
            "{label} signer does not match a trusted open-market governing authority signer"
        ));
    }
    Ok(())
}
