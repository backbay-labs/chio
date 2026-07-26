use chio_core_types::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use serde::de::DeserializeOwned;
use serde::Serialize;

mod contract;
mod delivery;
mod evidence;
mod predicate;
mod verdict;

pub use contract::*;
pub use delivery::*;
pub use evidence::*;
pub use predicate::*;
pub use verdict::*;

pub const OUTCOME_ARTIFACT_SCHEMAS: &[(&str, &str)] = &[
    (
        "request.schema.json",
        chio_core_types::capability::governance::VERIFIED_OUTCOME_REQUEST_SCHEMA,
    ),
    ("predicate.schema.json", OUTCOME_PREDICATE_SCHEMA),
    ("pricing.schema.json", OUTCOME_PRICING_SCHEMA),
    ("sla.schema.json", OUTCOME_SLA_SCHEMA),
    ("eligibility.schema.json", OUTCOME_ELIGIBILITY_SCHEMA),
    (
        "delivery-checkpoint.schema.json",
        OUTCOME_DELIVERY_CHECKPOINT_SCHEMA,
    ),
    (
        "delivery-acknowledgement.schema.json",
        OUTCOME_DELIVERY_ACKNOWLEDGEMENT_SCHEMA,
    ),
    (
        "delivery-nonacceptance.schema.json",
        OUTCOME_DELIVERY_NONACCEPTANCE_SCHEMA,
    ),
    (
        "output-provenance.schema.json",
        OUTCOME_OUTPUT_PROVENANCE_SCHEMA,
    ),
    (
        "contractual-zero.schema.json",
        OUTCOME_CONTRACTUAL_ZERO_SCHEMA,
    ),
    ("verdict.schema.json", OUTCOME_VERDICT_SCHEMA),
];

const MAX_TEXT_CHARS: usize = 2_048;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OutcomeError {
    #[error("invalid outcome field `{0}`")]
    InvalidField(&'static str),
    #[error("outcome artifact binding does not match")]
    BindingMismatch,
    #[error("outcome artifact authority verification failed")]
    AuthorityVerification,
    #[error("outcome artifact is not current")]
    NotCurrent,
    #[error("illegal outcome lifecycle transition")]
    IllegalTransition,
    #[error("outcome arithmetic overflow")]
    ArithmeticOverflow,
    #[error("outcome JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("outcome artifact is not canonical: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone)]
pub struct OutcomeSignerTrustV1 {
    principal_id: String,
    key: PublicKey,
    key_epoch: u64,
    max_lifetime_ms: u64,
}

impl OutcomeSignerTrustV1 {
    pub fn new(
        principal_id: String,
        key: PublicKey,
        key_epoch: u64,
        max_lifetime_ms: u64,
    ) -> Result<Self, OutcomeError> {
        validate_text("trusted_principal_id", &principal_id)?;
        validate_time("trusted_key_epoch", key_epoch)?;
        validate_time("max_lifetime_ms", max_lifetime_ms)?;
        Ok(Self {
            principal_id,
            key,
            key_epoch,
            max_lifetime_ms,
        })
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn max_lifetime_ms(&self) -> u64 {
        self.max_lifetime_ms
    }
}

pub fn canonical_outcome_bytes(value: &impl Serialize) -> Result<Vec<u8>, OutcomeError> {
    let encoded = canonical_json_bytes(value)
        .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?;
    let input = std::str::from_utf8(&encoded)
        .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?;
    canonical_json_bytes_from_str(input)
        .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
}

pub fn load_canonical_outcome_json<T>(bytes: &[u8]) -> Result<T, OutcomeError>
where
    T: DeserializeOwned,
{
    let input =
        std::str::from_utf8(bytes).map_err(|error| OutcomeError::InvalidJson(error.to_string()))?;
    let canonical = canonical_json_bytes_from_str(input)
        .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?;
    if canonical.as_slice() != bytes {
        return Err(OutcomeError::Canonicalization(
            "input bytes differ from RFC 8785 form".to_owned(),
        ));
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|error| OutcomeError::InvalidJson(error.to_string()))?;
    Ok(value)
}

pub(super) fn domain_digest(domain: &[u8], value: &impl Serialize) -> Result<String, OutcomeError> {
    let bytes = canonical_outcome_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

pub(super) fn domain_digest_without_field(
    domain: &[u8],
    value: &impl Serialize,
    field: &'static str,
) -> Result<String, OutcomeError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or(OutcomeError::InvalidField("artifact_body"))?;
    if object.remove(field).is_none() {
        return Err(OutcomeError::InvalidField(field));
    }
    domain_digest(domain, &value)
}

pub(super) fn envelope_digest(value: &impl Serialize) -> Result<String, OutcomeError> {
    canonical_outcome_bytes(value).map(|bytes| sha256_hex(&bytes))
}

pub(super) fn validate_text(field: &'static str, value: &str) -> Result<(), OutcomeError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_TEXT_CHARS
        || value.chars().any(char::is_control)
    {
        Err(OutcomeError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn validate_digest(field: &'static str, value: &str) -> Result<(), OutcomeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(OutcomeError::InvalidField(field))
    }
}

pub(super) fn validate_time(field: &'static str, value: u64) -> Result<(), OutcomeError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(OutcomeError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn validate_window(issued_at: u64, expires_at: u64) -> Result<(), OutcomeError> {
    validate_time("issued_at_unix_ms", issued_at)?;
    validate_time("expires_at_unix_ms", expires_at)?;
    if expires_at <= issued_at {
        return Err(OutcomeError::InvalidField("validity_window"));
    }
    Ok(())
}

pub(super) fn validate_current_window(
    issued_at: u64,
    expires_at: u64,
    max_lifetime_ms: u64,
    trusted_now_unix_ms: u64,
) -> Result<(), OutcomeError> {
    validate_window(issued_at, expires_at)?;
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(OutcomeError::NotCurrent)?;
    if lifetime > max_lifetime_ms
        || trusted_now_unix_ms < issued_at
        || trusted_now_unix_ms >= expires_at
    {
        return Err(OutcomeError::NotCurrent);
    }
    Ok(())
}

pub(super) fn validate_money(
    amount: &MonetaryAmount,
    allow_zero: bool,
) -> Result<(), OutcomeError> {
    if (!allow_zero && amount.units == 0)
        || amount.units > I_JSON_MAX_SAFE_INTEGER
        || amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(OutcomeError::InvalidField("amount"));
    }
    Ok(())
}
