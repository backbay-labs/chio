use super::*;

pub(super) fn canonical_json_string<T: serde::Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json_bytes(value).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

pub(super) fn validate_verdict_string(verdict: &str) -> Result<(), VerifierError> {
    match verdict {
        "allow" | "deny" => Ok(()),
        other => Err(VerifierError::PolicyVerdictDisagreement(format!(
            "unsupported verdict {other:?}; expected allow or deny"
        ))),
    }
}

pub(super) fn validate_policy_verdict(
    verdict: &crate::bilateral_dsse::PolicyVerdict,
    field: &str,
) -> Result<(), VerifierError> {
    validate_verdict_string(&verdict.verdict)?;
    validate_non_empty_policy_field(&verdict.policy_id, field, "policy_id")?;
    validate_non_empty_policy_field(&verdict.policy_version, field, "policy_version")?;
    Ok(())
}

fn validate_non_empty_policy_field(
    value: &str,
    parent: &str,
    field: &str,
) -> Result<(), VerifierError> {
    if value.is_empty() {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "{parent}.{field} must be non-empty"
        )));
    }
    Ok(())
}

pub(super) fn validate_hash_record(
    record: &crate::bilateral_dsse::HashRecord,
    field: &str,
) -> Result<(), String> {
    if record.alg != "sha256" {
        return Err(format!("{field}.alg must be sha256"));
    }
    if !is_sha256_hex(&record.value) {
        return Err(format!("{field}.value must be 64 lowercase hex"));
    }
    Ok(())
}

pub(super) fn receipt_canonical_digest_hex(receipt: &ChioReceipt) -> Result<String, VerifierError> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
