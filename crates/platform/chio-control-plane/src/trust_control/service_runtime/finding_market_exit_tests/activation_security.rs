use super::*;

#[test]
fn activation_rejects_reports_predating_signed_inputs() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let governance = keypair(1);
    let profile = build_profile(
        &governance,
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let config = market_config();
    let evaluation_time = stack.web.report.body.evaluation_time;
    let now = evaluation_time.saturating_add(FINDING_AUTHORITY_STATUS_MAX_AGE_SECS + 1);
    let live_status = signed_verifier_authority_status(now, None)?;

    let mut postdated_profile_body = profile.body.clone();
    postdated_profile_body.issued_at = evaluation_time.saturating_add(1);
    postdated_profile_body.profile_id = compute_profile_id(&postdated_profile_body)?;
    let postdated_profile = SignedExportEnvelope::sign(postdated_profile_body, &governance)?;
    assert!(verify_report_authority_lifecycle(
        &stack.web.report,
        &live_status,
        &postdated_profile,
        &stack.web.finding,
        &config,
        now,
    )
    .is_err());

    let mut postdated_finding = stack.web.finding.clone();
    postdated_finding.issued_at = evaluation_time.saturating_add(1);
    assert!(verify_report_authority_lifecycle(
        &stack.web.report,
        &live_status,
        &profile,
        &postdated_finding,
        &config,
        now,
    )
    .is_err());
    Ok(())
}

#[test]
fn activation_requires_profile_pinned_settlement_authorities() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let profile = build_profile(
        &keypair(1),
        checkpoint_log_id(&stack.web.checkpoint),
        &recipe_dependencies().runner_manifest_sha256,
    )?;
    let config = market_config();
    verify_profile_settlement_authorities(&profile, &stack.web.admission, &config)
        .map_err(std::io::Error::other)?;

    let mut changed_admission = stack.web.admission.clone();
    changed_admission
        .body
        .purchase_authority
        .rotation_policy_ref
        .push_str("-other");
    assert!(verify_profile_settlement_authorities(&profile, &changed_admission, &config).is_err());

    let mut changed_config = config;
    changed_config.failed_delivery.valid_from =
        changed_config.failed_delivery.valid_from.saturating_add(1);
    assert!(
        verify_profile_settlement_authorities(&profile, &stack.web.admission, &changed_config)
            .is_err()
    );
    Ok(())
}
