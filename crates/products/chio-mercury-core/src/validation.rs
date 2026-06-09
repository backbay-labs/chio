use crate::receipt_metadata::MercuryContractError;

pub(crate) fn ensure_non_empty(
    field: &'static str,
    value: &str,
) -> Result<(), MercuryContractError> {
    if value.trim().is_empty() {
        return Err(MercuryContractError::EmptyField(field));
    }
    if value.trim() != value {
        return Err(MercuryContractError::PaddedField(field));
    }
    Ok(())
}

pub(crate) fn ensure_optional_non_empty(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), MercuryContractError> {
    if let Some(value) = value {
        ensure_non_empty(field, value)?;
    }
    Ok(())
}
