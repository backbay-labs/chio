use super::*;

pub fn validate_policy_evaluation_summary(
    summary: &PolicyEvaluationSummary,
) -> Result<(), BilateralCoSigningError> {
    validate_policy_verdict(&summary.server_a_verdict, "server_a_verdict")?;
    validate_policy_verdict(&summary.server_b_verdict, "server_b_verdict")?;
    if summary.server_a_verdict.verdict != summary.server_b_verdict.verdict {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: server_a={} server_b={}",
            summary.server_a_verdict.verdict, summary.server_b_verdict.verdict
        )));
    }
    if let Some(joint) = &summary.joint_disposition {
        validate_verdict_string(joint)?;
        if joint != &summary.server_a_verdict.verdict {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "predicate.schema_invalid: joint_disposition={} disagrees with server_a/b verdict={}",
                joint, summary.server_a_verdict.verdict
            )));
        }
    }
    Ok(())
}

/// Admission paths require unanimous `allow`. Cryptographic bilateral
/// verification may still attest `deny` for audit and dispute review.
pub fn require_policy_evaluation_allow_admission(
    summary: &PolicyEvaluationSummary,
) -> Result<(), BilateralCoSigningError> {
    validate_policy_evaluation_summary(summary)?;
    if summary.server_a_verdict.verdict != "allow" {
        return Err(BilateralCoSigningError::CanonicalJson(
            "policy_evaluation_summary requires allow verdict for admission".to_string(),
        ));
    }
    Ok(())
}

fn validate_policy_verdict(
    verdict: &PolicyVerdict,
    field: &str,
) -> Result<(), BilateralCoSigningError> {
    validate_verdict_string(&verdict.verdict)?;
    validate_non_empty_policy_field(&verdict.policy_id, field, "policy_id")?;
    validate_non_empty_policy_field(&verdict.policy_version, field, "policy_version")?;
    Ok(())
}

fn validate_verdict_string(verdict: &str) -> Result<(), BilateralCoSigningError> {
    match verdict {
        "allow" | "deny" => Ok(()),
        other => Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: unsupported verdict {other:?}; expected allow or deny"
        ))),
    }
}

fn validate_non_empty_policy_field(
    value: &str,
    parent: &str,
    field: &str,
) -> Result<(), BilateralCoSigningError> {
    if value.is_empty() {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: {parent}.{field} must be non-empty"
        )));
    }
    Ok(())
}
