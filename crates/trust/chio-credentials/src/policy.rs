fn challenge_presentation_options(
    challenge: &PassportPresentationChallenge,
) -> PassportPresentationOptions {
    PassportPresentationOptions {
        issuer_allowlist: challenge.issuer_allowlist.clone(),
        max_credentials: challenge.max_credentials,
    }
}

fn validate_unit_interval(field: &'static str, value: Option<f64>) -> Result<(), CredentialError> {
    if let Some(value) = value {
        if !(0.0..=1.0).contains(&value) {
            return Err(CredentialError::InvalidVerifierThreshold { field, value });
        }
    }
    Ok(())
}

fn verify_signed_passport_verifier_policy_body(
    body: &SignedPassportVerifierPolicyBody,
) -> Result<(), CredentialError> {
    if !is_supported_passport_verifier_policy_schema(&body.schema) {
        return Err(CredentialError::InvalidSignedVerifierPolicySchema);
    }
    if body.policy_id.trim().is_empty() {
        return Err(CredentialError::MissingSignedVerifierPolicyId);
    }
    if body.verifier.trim().is_empty() {
        return Err(CredentialError::MissingSignedVerifierVerifier);
    }
    if body.created_at > body.expires_at {
        return Err(CredentialError::InvalidSignedVerifierPolicyValidityWindow);
    }
    body.policy.validate()?;
    Ok(())
}

fn evaluate_credential_against_policy(
    index: usize,
    credential: &ReputationCredential,
    now: u64,
    policy: &PassportVerifierPolicy,
) -> CredentialPolicyEvaluation {
    let mut reasons = Vec::new();
    let metrics = &credential.unsigned.credential_subject.metrics;
    let evidence = &credential.unsigned.evidence;

    if !policy.issuer_allowlist.is_empty()
        && !policy
            .issuer_allowlist
            .contains(&credential.unsigned.issuer)
    {
        reasons.push(format!(
            "issuer {} is not in the allowlist",
            credential.unsigned.issuer
        ));
    }

    if let Some(minimum) = policy.min_composite_score {
        require_metric_min(
            &mut reasons,
            "composite_score",
            metrics.composite_score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_reliability {
        require_metric_min(
            &mut reasons,
            "reliability",
            metrics.reliability.score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_least_privilege {
        require_metric_min(
            &mut reasons,
            "least_privilege",
            metrics.least_privilege.score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_delegation_hygiene {
        require_metric_min(
            &mut reasons,
            "delegation_hygiene",
            metrics.delegation_hygiene.score,
            minimum,
        );
    }
    if let Some(maximum) = policy.max_boundary_pressure {
        require_metric_max(
            &mut reasons,
            "boundary_pressure",
            metrics.boundary_pressure.deny_ratio,
            maximum,
        );
    }

    if let Some(minimum) = policy.min_receipt_count {
        if evidence.receipt_count < minimum {
            reasons.push(format!(
                "receipt_count {} is below required minimum {}",
                evidence.receipt_count, minimum
            ));
        }
    }
    if let Some(minimum) = policy.min_lineage_records {
        if evidence.lineage_records < minimum {
            reasons.push(format!(
                "lineage_records {} is below required minimum {}",
                evidence.lineage_records, minimum
            ));
        }
    }
    if let Some(minimum) = policy.min_history_days {
        if metrics.history_depth.span_days < minimum {
            reasons.push(format!(
                "history_depth_days {} is below required minimum {}",
                metrics.history_depth.span_days, minimum
            ));
        }
    }
    if let Some(max_days) = policy.max_attestation_age_days {
        let age_seconds = now.saturating_sub(evidence.query.until);
        let max_age_seconds = u64::from(max_days).saturating_mul(86_400);
        if age_seconds > max_age_seconds {
            reasons.push(format!(
                "attestation_age_days {:.2} exceeds maximum {}",
                age_seconds as f64 / 86_400.0,
                max_days
            ));
        }
    }
    if policy.require_checkpoint_coverage {
        if evidence.uncheckpointed_receipts > 0 {
            reasons.push(format!(
                "credential evidence has {} uncheckpointed receipt(s)",
                evidence.uncheckpointed_receipts
            ));
        }
        if evidence.checkpoint_roots.is_empty() {
            reasons.push("credential evidence does not include checkpoint roots".to_string());
        }
    }
    if policy.require_receipt_log_urls && evidence.receipt_log_urls.is_empty() {
        reasons.push("credential evidence does not include receipt log URLs".to_string());
    }
    if policy.require_enterprise_identity_provenance
        && credential.unsigned.enterprise_identity_provenance.is_none()
    {
        reasons.push("credential does not include enterprise identity provenance".to_string());
    }
    let enterprise_provider_ids = credential
        .unsigned
        .enterprise_identity_provenance
        .as_ref()
        .map(|provenance| vec![provenance.provider_id.clone()])
        .unwrap_or_default();

    CredentialPolicyEvaluation {
        index,
        issuer: credential.unsigned.issuer.clone(),
        accepted: reasons.is_empty(),
        reasons,
        issuance_date: credential.unsigned.issuance_date.clone(),
        expiration_date: credential.unsigned.expiration_date.clone(),
        attestation_until: evidence.query.until,
        receipt_count: evidence.receipt_count,
        lineage_records: evidence.lineage_records,
        uncheckpointed_receipts: evidence.uncheckpointed_receipts,
        composite_score: metrics.composite_score.as_option(),
        reliability: metrics.reliability.score.as_option(),
        least_privilege: metrics.least_privilege.score.as_option(),
        delegation_hygiene: metrics.delegation_hygiene.score.as_option(),
        boundary_pressure: metrics.boundary_pressure.deny_ratio.as_option(),
        enterprise_identity_present: credential.unsigned.enterprise_identity_provenance.is_some(),
        enterprise_provider_ids,
    }
}

fn require_metric_min(reasons: &mut Vec<String>, field: &str, value: MetricValue, minimum: f64) {
    match value.as_option() {
        Some(value) if value >= minimum => {}
        Some(value) => reasons.push(format!(
            "{field} {} is below required minimum {}",
            value, minimum
        )),
        None => reasons.push(format!("{field} is unknown but policy requires a minimum")),
    }
}

fn require_metric_max(reasons: &mut Vec<String>, field: &str, value: MetricValue, maximum: f64) {
    match value.as_option() {
        Some(value) if value <= maximum => {}
        Some(value) => reasons.push(format!(
            "{field} {} exceeds allowed maximum {}",
            value, maximum
        )),
        None => reasons.push(format!("{field} is unknown but policy requires a maximum")),
    }
}
