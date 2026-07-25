use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::Serialize;

use crate::{FiscalDomain, FiscalError};

pub(super) const MAX_SIGNED_LIFECYCLE_BYTES: usize = 1_048_576;

pub(super) fn all_fiscal_domains() -> [FiscalDomain; 5] {
    [
        FiscalDomain::TierLimits,
        FiscalDomain::MarketplaceDiscountPerHundred,
        FiscalDomain::DecisionPremiumBasisPoints,
        FiscalDomain::InsurancePremiumSchedule,
        FiscalDomain::OpenMarketFeeAndBondSchedule,
    ]
}

pub(super) fn require_text(value: &str, field: &'static str) -> Result<(), FiscalError> {
    if value.trim().is_empty() {
        Err(FiscalError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn require_positive(value: u64, field: &'static str) -> Result<(), FiscalError> {
    if value == 0 {
        Err(FiscalError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn require_digest(value: &str, field: &'static str) -> Result<(), FiscalError> {
    if is_digest(value) {
        Ok(())
    } else {
        Err(FiscalError::InvalidField(field))
    }
}

pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn is_iso_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

pub(super) fn lifecycle_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, FiscalError> {
    canonical_json_bytes(&(domain, value))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))
}

pub(super) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, FiscalError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))
}

pub(super) fn signed_envelope_digest<T: Serialize>(
    signed: &SignedExportEnvelope<T>,
) -> Result<String, FiscalError> {
    canonical_digest(signed)
}

pub(super) fn verify_envelope<T>(signed: &SignedExportEnvelope<T>) -> Result<(), FiscalError>
where
    T: Serialize + Clone,
{
    if !signed
        .verify_signature()
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))?
    {
        return Err(FiscalError::InvalidSignature);
    }
    let bytes = canonical_json_bytes(signed)
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_LIFECYCLE_BYTES {
        return Err(FiscalError::InvalidField("signed_lifecycle.size"));
    }
    Ok(())
}
