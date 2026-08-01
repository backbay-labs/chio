use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Deserializer, Serialize};

use super::ChannelError;

pub(super) const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
pub(super) const MAX_TEXT_BYTES: usize = 2_048;

pub(super) fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ChannelError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

pub(super) fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(super) fn validate_text(field: &'static str, value: &str) -> Result<(), ChannelError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ChannelError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_digest(field: &'static str, value: &str) -> Result<(), ChannelError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChannelError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_currency(currency: &str) -> Result<(), ChannelError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ChannelError::InvalidField("currency"));
    }
    Ok(())
}

pub(super) fn validate_positive(field: &'static str, value: u64) -> Result<(), ChannelError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        return Err(ChannelError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_chain_id(value: &str) -> Result<(), ChannelError> {
    let Some(numeric) = value.strip_prefix("eip155:") else {
        return Err(ChannelError::InvalidField("chain_id"));
    };
    if numeric.starts_with('0')
        || numeric
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .is_none()
    {
        return Err(ChannelError::InvalidField("chain_id"));
    }
    Ok(())
}

pub(super) fn validate_evm_address(field: &'static str, value: &str) -> Result<(), ChannelError> {
    if value.len() != 42
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChannelError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_evm_hash(field: &'static str, value: &str) -> Result<(), ChannelError> {
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChannelError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn parse_base_units(value: &str) -> Result<u128, ChannelError> {
    if value.is_empty()
        || value.len() > 39
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ChannelError::InvalidField("token_base_units"));
    }
    value
        .parse::<u128>()
        .map_err(|_| ChannelError::InvalidField("token_base_units"))
}
