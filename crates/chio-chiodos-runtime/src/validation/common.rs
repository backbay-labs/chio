use crate::error::ChiodosRuntimeError;

pub(super) fn validate_acceptance_failure_code(
    accepted: bool,
    failure_code: Option<&str>,
    missing_code: &'static str,
    unexpected_code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if accepted && failure_code.is_some() {
        return Err(ChiodosRuntimeError::Rejected {
            code: unexpected_code,
            detail: "accepted runtime report cannot carry a failure code".to_string(),
        });
    }
    if !accepted && failure_code.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: missing_code,
            detail: "rejected runtime report must carry a failure code".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn rejected<T>(code: &'static str, detail: &str) -> Result<T, ChiodosRuntimeError> {
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: detail.to_string(),
    })
}

pub(crate) fn ensure_sha256_hash(
    hash: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if is_sha256_hex(hash) {
        return Ok(());
    }
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: format!("runtime evidence hash {hash} is not sha256 hex"),
    })
}

pub(super) fn ensure_optional_sha256(
    hash: Option<&str>,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(hash) = hash {
        ensure_sha256_hash(hash, code)?;
    }
    Ok(())
}

pub(crate) fn validate_non_empty(
    value: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: "runtime orchestration field must not be empty".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_state_label(
    value: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime orchestration label {value:?} is invalid"),
        });
    }
    Ok(())
}

pub(crate) fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

pub(crate) fn required_string_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<String, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value
            .get(*field)
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
        {
            return Ok(item.to_string());
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

pub(crate) fn required_u64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<u64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_u64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

pub(crate) fn required_f64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<f64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_f64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}
