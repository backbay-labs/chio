use crate::capability::scope::MonetaryAmount;

pub(crate) fn validate_monetary_amount(value: &MonetaryAmount, field: &str) -> Result<(), String> {
    if value.units == 0 {
        return Err(format!("{field}.units must be greater than zero"));
    }
    validate_non_empty(&value.currency, &format!("{field}.currency"))
}

pub(crate) fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
