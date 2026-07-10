use std::collections::HashSet;

use crate::capability::scope::MonetaryAmount;
use crate::error::Web3ContractError;

pub(crate) fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), Web3ContractError> {
    if value.trim().is_empty() {
        return Err(Web3ContractError::MissingField(field));
    }
    if value.trim() != value {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}

pub(crate) fn ensure_b256_hex(value: &str, field: &'static str) -> Result<(), Web3ContractError> {
    let hex = value.strip_prefix("0x").ok_or_else(|| {
        Web3ContractError::InvalidBinding(format!(
            "{field} must be a 0x-prefixed 32-byte hex value"
        ))
    })?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Web3ContractError::InvalidBinding(format!(
            "{field} must be a 0x-prefixed 32-byte hex value"
        )));
    }
    Ok(())
}

pub(crate) fn evm_addresses_match(left: &str, right: &str) -> Result<bool, Web3ContractError> {
    let left_hex = evm_address_hex(left).ok_or_else(invalid_evm_address)?;
    let right_hex = evm_address_hex(right).ok_or_else(invalid_evm_address)?;
    Ok(left_hex.eq_ignore_ascii_case(right_hex))
}

pub(crate) fn ensure_evm_address(
    value: &str,
    field: &'static str,
) -> Result<(), Web3ContractError> {
    evm_address_hex(value)
        .ok_or_else(|| {
            Web3ContractError::invalid_settlement(format!(
                "{field} must be a 0x-prefixed 20-byte hex EVM address"
            ))
        })
        .map(|_| ())
}

fn evm_address_hex(value: &str) -> Option<&str> {
    let hex = value.strip_prefix("0x")?;
    if hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

fn invalid_evm_address() -> Web3ContractError {
    Web3ContractError::invalid_settlement(
        "EVM address fields must be 0x-prefixed 20-byte hex values",
    )
}

pub(crate) fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), Web3ContractError> {
    let mut seen = HashSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(Web3ContractError::DuplicateValue(value.clone()));
        }
    }
    Ok(())
}

pub(crate) fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), Web3ContractError>
where
    T: Eq + std::hash::Hash + Copy + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn ensure_money(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), Web3ContractError> {
    if amount.units == 0 {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} must be non-zero"
        )));
    }
    if amount.currency.trim().is_empty() {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} currency is required"
        )));
    }
    if amount.currency.len() != 3
        || !amount
            .currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(Web3ContractError::invalid_settlement(format!(
            "{field} currency must be a 3-letter uppercase code"
        )));
    }
    Ok(())
}
