use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
pub use chio_core_types::{
    CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA, CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const FACTOR_ASSIGNMENT_BIND_ACTION: &str = "factor.assignment_bind";
pub const FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_SCHEMA: &str =
    CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA;
pub const FACTOR_NORMALIZED_ASSIGNMENT_REQUEST_SCHEMA: &str =
    "chio.factor.normalized-assignment-request.v1";
pub const FACTOR_RECEIVABLE_CLAIM_SCHEMA: &str = "chio.factor.receivable-claim.v1";
pub const FACTOR_ASSIGNMENT_OFFER_SCHEMA: &str = "chio.factor.assignment-offer.v1";
pub const FACTOR_DISCOUNT_QUOTE_SCHEMA: &str = "chio.factor.discount-quote.v1";
pub const FACTOR_ASSIGNMENT_AGREEMENT_SCHEMA: &str = CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA;
pub const FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_SCHEMA: &str =
    CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA;
pub const FACTOR_ASSIGNMENT_NOT_APPLIED_SCHEMA: &str = CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA;

const NORMALIZED_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"chio.factor.normalized-assignment-request.digest.v1\0";
const CLAIM_ID_DOMAIN: &[u8] = b"chio.factor.receivable-claim.id.v1\0";
const CLAIM_DIGEST_DOMAIN: &[u8] = b"chio.factor.receivable-claim.digest.v1\0";
const OFFER_ID_DOMAIN: &[u8] = b"chio.factor.assignment-offer.id.v1\0";
const OFFER_DIGEST_DOMAIN: &[u8] = b"chio.factor.assignment-offer.digest.v1\0";
const QUOTE_ID_DOMAIN: &[u8] = b"chio.factor.discount-quote.id.v1\0";
const QUOTE_DIGEST_DOMAIN: &[u8] = b"chio.factor.discount-quote.digest.v1\0";
const AUTHORIZATION_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio.factor.assignment-bind-authorization.body.v1\0";
const AGREEMENT_BODY_DIGEST_DOMAIN: &[u8] = b"chio.factor.assignment-agreement.body.v1\0";
const AGREEMENT_SIGNATURE_DIGEST_DOMAIN: &[u8] = b"chio.factor.assignment-agreement.signature.v1\0";
const AUTHORIZATION_SET_DIGEST_DOMAIN: &[u8] = b"chio.factor.assignment-authorization-set.v1\0";
const ACKNOWLEDGEMENT_ID_DOMAIN: &[u8] = b"chio.factor.assignment-acknowledgement.id.v1\0";
const ACKNOWLEDGEMENT_BODY_DIGEST_DOMAIN: &[u8] =
    b"chio.factor.assignment-acknowledgement.body.v1\0";
const NOT_APPLIED_ID_DOMAIN: &[u8] = b"chio.factor.assignment-not-applied.id.v1\0";
const NOT_APPLIED_BODY_DIGEST_DOMAIN: &[u8] = b"chio.factor.assignment-not-applied.body.v1\0";
const MAX_TEXT_CHARS: usize = 2_048;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const BASIS_POINTS_DENOMINATOR: u16 = 10_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FactorError {
    #[error("invalid factor field '{0}'")]
    InvalidField(&'static str),
    #[error("factor binding does not match")]
    BindingMismatch,
    #[error("factor authority verification failed")]
    AuthorityVerification,
    #[error("factor artifact is not current")]
    NotCurrent,
    #[error("factor arithmetic overflow")]
    ArithmeticOverflow,
    #[error("factor canonicalization failed: {0}")]
    Canonicalization(String),
}

pub type FactorAuthorizationError = FactorError;

mod authorization;
mod claim;
mod request;
mod result;

pub use authorization::*;
pub use claim::*;
pub use request::*;
pub use result::*;

fn discounted_amount(
    face_value: &MonetaryAmount,
    discount_bps: u16,
) -> Result<MonetaryAmount, FactorError> {
    validate_amount("discount_face_value", face_value, false)?;
    validate_basis_points(discount_bps)?;
    let retained_bps = BASIS_POINTS_DENOMINATOR
        .checked_sub(discount_bps)
        .ok_or(FactorError::ArithmeticOverflow)?;
    let numerator = u128::from(face_value.units)
        .checked_mul(u128::from(retained_bps))
        .ok_or(FactorError::ArithmeticOverflow)?;
    let units = numerator / u128::from(BASIS_POINTS_DENOMINATOR);
    Ok(MonetaryAmount {
        units: u64::try_from(units).map_err(|_| FactorError::ArithmeticOverflow)?,
        currency: face_value.currency.clone(),
    })
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, FactorError> {
    canonical_json_bytes(value).map_err(|error| FactorError::Canonicalization(error.to_string()))
}

fn parse_canonical<T>(bytes: &[u8], artifact: &str) -> Result<T, FactorError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| FactorError::Canonicalization(error.to_string()))?;
    if canonical_bytes(&value)?.as_slice() != bytes {
        return Err(FactorError::Canonicalization(format!(
            "{artifact} is not canonical"
        )));
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], value: &impl Serialize) -> Result<String, FactorError> {
    let bytes = canonical_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

fn validate_text(field: &'static str, value: &str) -> Result<(), FactorError> {
    let disallowed_control =
        |character: char| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f);
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_TEXT_CHARS
        || value.chars().any(disallowed_control)
    {
        Err(FactorError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), FactorError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(FactorError::InvalidField(field))
    }
}

fn validate_positive(field: &'static str, value: u64) -> Result<(), FactorError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(FactorError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_basis_points(value: u16) -> Result<(), FactorError> {
    if value > BASIS_POINTS_DENOMINATOR {
        Err(FactorError::InvalidField("discount_bps"))
    } else {
        Ok(())
    }
}

fn validate_amount(
    field: &'static str,
    amount: &MonetaryAmount,
    allow_zero: bool,
) -> Result<(), FactorError> {
    if (!allow_zero && amount.units == 0)
        || amount.units > I_JSON_MAX_SAFE_INTEGER
        || amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        Err(FactorError::InvalidField(field))
    } else {
        Ok(())
    }
}
