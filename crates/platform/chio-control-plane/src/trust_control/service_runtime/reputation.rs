use super::*;

pub fn issue_signed_portable_reputation_summary(
    config: &TrustServiceConfig,
    request: &PortableReputationSummaryIssueRequest,
) -> Result<SignedPortableReputationSummary, CliError> {
    if config.receipt_db_path.is_none() {
        return Err(CliError::cli_other_error(
            "trust service is missing receipt_db_path for portable reputation summary issuance"
                .to_string(),
        ));
    }
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let read_context = chio_kernel::ReceiptReadContext::admin_service();
    let trusted_kernel_keys = vec![signer_keypair.public_key().to_hex()];
    let inspection = crate::issuance::inspect_local_reputation_with_read_context(
        &request.subject_key,
        config.receipt_db_path.as_deref(),
        config.budget_db_path.as_deref(),
        request.since,
        request.until,
        config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &read_context,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let Some(receipt_db_path) = config.receipt_db_path.as_deref() else {
        return Err(CliError::cli_other_error(
            "receipt db path is required for imported trust reporting".to_string(),
        ));
    };
    let imported_trust = crate::reputation::build_imported_trust_report(
        receipt_db_path,
        &inspection.subject_key,
        inspection.since,
        inspection.until,
        issued_at,
        &inspection.scoring,
    )?;
    let artifact = build_portable_reputation_summary_artifact(
        &local_operator.operator_id,
        request,
        &inspection.scorecard,
        chio_credentials::PortableReputationSummaryArtifactContext {
            issuer_operator_name: local_operator.operator_name.clone(),
            effective_score: inspection.effective_score,
            probationary: inspection.probationary,
            imported_signal_count: Some(imported_trust.signal_count),
            accepted_imported_signal_count: Some(imported_trust.accepted_count),
            issued_at,
        },
    )?;
    SignedPortableReputationSummary::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign portable reputation summary artifact: {error}"
        ))
    })
}

pub fn issue_signed_portable_negative_event(
    config: &TrustServiceConfig,
    request: &PortableNegativeEventIssueRequest,
) -> Result<SignedPortableNegativeEvent, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.published_at.unwrap_or(now_unix_secs()?);
    let artifact = build_portable_negative_event_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )?;
    SignedPortableNegativeEvent::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign portable negative event artifact: {error}"
        ))
    })
}

pub fn evaluate_portable_reputation_request(
    request: &PortableReputationEvaluationRequest,
) -> Result<PortableReputationEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_portable_reputation(request, now)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}
