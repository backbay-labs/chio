use std::collections::HashSet;

use crate::capability::MonetaryAmount;
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
