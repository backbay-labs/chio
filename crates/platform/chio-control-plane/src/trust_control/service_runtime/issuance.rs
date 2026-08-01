use super::*;
use chio_fiscal::{FiscalDomain, FiscalResolution};
use chio_open_market::fiscal_adapter::{
    build_fiscal_open_market_fee_schedule_artifact, build_fiscal_open_market_penalty_artifact,
    evaluate_fiscal_open_market_penalty, materialize_fiscal_open_market_fee_schedule,
    FiscalLegacyFeeScheduleBinding, FiscalOpenMarketSchedule,
};

pub fn issue_signed_generic_trust_activation(
    config: &TrustServiceConfig,
    request: &GenericTrustActivationIssueRequest,
) -> Result<SignedGenericTrustActivation, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.requested_at.unwrap_or(now_unix_secs()?);
    let artifact = build_generic_trust_activation_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )
    .map_err(CliError::cli_other_error)?;
    SignedGenericTrustActivation::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!("failed to sign trust activation artifact: {error}"))
    })
}

pub fn evaluate_generic_trust_activation_request(
    config: &TrustServiceConfig,
    request: &GenericTrustActivationEvaluationRequest,
) -> Result<GenericTrustActivationEvaluation, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let trusted_authority_signers = trusted_authority_public_keys(config)?;
    let current_signer = signer_keypair.public_key();
    let trusted_local_operator_signer = if let Some(activation) = request.activation.as_ref() {
        ensure_signed_by_trusted_authority(
            "trust activation",
            &activation.signer_key,
            &trusted_authority_signers,
        )?;
        &activation.signer_key
    } else {
        &current_signer
    };
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_trust_activation(request, now, trusted_local_operator_signer)
        .map_err(CliError::cli_other_error)
}

pub fn issue_signed_generic_governance_charter(
    config: &TrustServiceConfig,
    request: &GenericGovernanceCharterIssueRequest,
) -> Result<SignedGenericGovernanceCharter, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let artifact = build_generic_governance_charter_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )
    .map_err(CliError::cli_other_error)?;
    SignedGenericGovernanceCharter::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign governance charter artifact: {error}"
        ))
    })
}

pub fn issue_signed_generic_governance_case(
    config: &TrustServiceConfig,
    request: &GenericGovernanceCaseIssueRequest,
) -> Result<SignedGenericGovernanceCase, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
    let artifact =
        build_generic_governance_case_artifact(&local_operator.operator_id, request, issued_at)
            .map_err(CliError::cli_other_error)?;
    SignedGenericGovernanceCase::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!("failed to sign governance case artifact: {error}"))
    })
}

pub fn evaluate_generic_governance_case_request(
    request: &GenericGovernanceCaseEvaluationRequest,
) -> Result<GenericGovernanceCaseEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_governance_case(request, now).map_err(CliError::cli_other_error)
}

pub(crate) fn issue_signed_open_market_fee_schedule(
    config: &TrustServiceConfig,
    request: &OpenMarketFeeScheduleIssueRequest,
    fiscal_runtime: Option<&TrustFiscalRuntime>,
) -> Result<SignedOpenMarketFeeSchedule, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let (artifact, governed_schedule_id) = if let Some(runtime) = fiscal_runtime {
        runtime
            .with_resolver(|resolver| {
                match resolver.resolve::<FiscalOpenMarketSchedule>(
                    FiscalDomain::OpenMarketFeeAndBondSchedule,
                    None,
                ) {
                    FiscalResolution::Governed { schedule_id, .. } => Ok((
                        materialize_fiscal_open_market_fee_schedule(resolver)
                            .map_err(|error| error.to_string())?,
                        Some(schedule_id),
                    )),
                    FiscalResolution::Fallback(_) => Ok((
                        build_fiscal_open_market_fee_schedule_artifact(
                            &local_operator.operator_id,
                            local_operator.operator_name.clone(),
                            request,
                            issued_at,
                            resolver,
                        )
                        .map_err(|error| error.to_string())?,
                        None,
                    )),
                    FiscalResolution::Denied(reason) => {
                        Err(format!("fiscal open-market economics denied: {reason:?}"))
                    }
                }
            })
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .map_err(CliError::cli_other_error)?
    } else {
        (
            build_open_market_fee_schedule_artifact(
                &local_operator.operator_id,
                local_operator.operator_name.clone(),
                request,
                issued_at,
            )
            .map_err(CliError::cli_other_error)?,
            None,
        )
    };
    let signed = SignedOpenMarketFeeSchedule::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign open-market fee schedule artifact: {error}"
        ))
    })?;
    if let (Some(runtime), Some(schedule_id)) = (fiscal_runtime, governed_schedule_id) {
        runtime
            .bind_legacy_fee_schedule(&schedule_id, &signed)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    Ok(signed)
}

pub(crate) fn issue_signed_open_market_penalty(
    config: &TrustServiceConfig,
    request: &OpenMarketPenaltyIssueRequest,
    fiscal_runtime: Option<&TrustFiscalRuntime>,
) -> Result<SignedOpenMarketPenalty, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let trusted_authority_signers = trusted_authority_public_keys(config)?;
    ensure_open_market_issue_signed_by_trusted_authority(request, &trusted_authority_signers)?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
    let artifact = if let Some(runtime) = fiscal_runtime {
        runtime
            .with_resolver(|resolver| {
                let binding = fiscal_binding(runtime, resolver)?;
                build_fiscal_open_market_penalty_artifact(
                    &local_operator.operator_id,
                    request,
                    issued_at,
                    binding.as_ref(),
                    resolver,
                    &trusted_authority_signers,
                )
                .map_err(|error| error.to_string())
            })
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .map_err(CliError::cli_other_error)?
    } else {
        build_open_market_penalty_artifact_with_trusted_signers(
            &local_operator.operator_id,
            request,
            issued_at,
            &trusted_authority_signers,
        )
        .map_err(CliError::cli_other_error)?
    };
    SignedOpenMarketPenalty::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign open-market penalty artifact: {error}"
        ))
    })
}

pub(crate) fn evaluate_open_market_penalty_request(
    config: &TrustServiceConfig,
    request: &OpenMarketPenaltyEvaluationRequest,
    fiscal_runtime: Option<&TrustFiscalRuntime>,
) -> Result<OpenMarketPenaltyEvaluation, CliError> {
    let trusted_authority_signers = trusted_authority_public_keys(config)?;
    ensure_open_market_evaluation_signed_by_trusted_authority(request, &trusted_authority_signers)?;
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    if let Some(runtime) = fiscal_runtime {
        runtime
            .with_resolver(|resolver| {
                let binding = fiscal_binding(runtime, resolver)?;
                evaluate_fiscal_open_market_penalty(
                    request,
                    now,
                    binding.as_ref(),
                    resolver,
                    &trusted_authority_signers,
                )
                .map_err(|error| error.to_string())
            })
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .map_err(CliError::cli_other_error)
    } else {
        evaluate_open_market_penalty_with_trusted_signers(request, now, &trusted_authority_signers)
            .map_err(CliError::cli_other_error)
    }
}

fn fiscal_binding(
    runtime: &TrustFiscalRuntime,
    resolver: &chio_fiscal::FiscalResolver<'_>,
) -> Result<Option<FiscalLegacyFeeScheduleBinding>, String> {
    match resolver
        .resolve::<FiscalOpenMarketSchedule>(FiscalDomain::OpenMarketFeeAndBondSchedule, None)
    {
        FiscalResolution::Governed { schedule_id, .. } => runtime
            .legacy_fee_schedule_binding(&schedule_id)
            .map_err(|error| error.to_string()),
        FiscalResolution::Fallback(_) => Ok(None),
        FiscalResolution::Denied(reason) => {
            Err(format!("fiscal open-market economics denied: {reason:?}"))
        }
    }
}

fn ensure_open_market_issue_signed_by_trusted_authority(
    request: &OpenMarketPenaltyIssueRequest,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    ensure_signed_by_trusted_authority(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance charter",
        &request.charter.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance case",
        &request.case.signer_key,
        trusted_authority_signers,
    )?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_signed_by_trusted_authority(
            "trust activation",
            &activation.signer_key,
            trusted_authority_signers,
        )?;
    }
    Ok(())
}

fn ensure_open_market_evaluation_signed_by_trusted_authority(
    request: &OpenMarketPenaltyEvaluationRequest,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    ensure_signed_by_trusted_authority(
        "open-market fee schedule",
        &request.fee_schedule.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance charter",
        &request.charter.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "governance case",
        &request.case.signer_key,
        trusted_authority_signers,
    )?;
    ensure_signed_by_trusted_authority(
        "open-market penalty",
        &request.penalty.signer_key,
        trusted_authority_signers,
    )?;
    if let Some(activation) = request.activation.as_ref() {
        ensure_signed_by_trusted_authority(
            "trust activation",
            &activation.signer_key,
            trusted_authority_signers,
        )?;
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        ensure_signed_by_trusted_authority(
            "prior open-market penalty",
            &prior_penalty.signer_key,
            trusted_authority_signers,
        )?;
    }
    Ok(())
}

pub(crate) fn ensure_signed_by_trusted_authority(
    label: &str,
    signer_key: &PublicKey,
    trusted_authority_signers: &[PublicKey],
) -> Result<(), CliError> {
    if !trusted_authority_signers
        .iter()
        .any(|trusted_signer| trusted_signer == signer_key)
    {
        return Err(CliError::cli_other_error(format!(
            "{label} signer does not match a trusted trust-control authority signer"
        )));
    }
    Ok(())
}

fn trusted_authority_public_keys(config: &TrustServiceConfig) -> Result<Vec<PublicKey>, CliError> {
    let status = authority_status_for_config(config)?;
    if !status.configured {
        return Err(CliError::cli_other_error(
            "trust-control authority is not configured".to_string(),
        ));
    }
    let mut trusted = status
        .trusted_public_keys
        .iter()
        .map(|value| PublicKey::from_hex(value))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(current) = status.public_key.as_deref() {
        let current = PublicKey::from_hex(current)?;
        if !trusted.iter().any(|public_key| public_key == &current) {
            trusted.push(current);
        }
    }
    if trusted.is_empty() {
        return Err(CliError::cli_other_error(
            "trust-control authority did not publish any trusted signing keys".to_string(),
        ));
    }
    Ok(trusted)
}

pub(crate) fn evaluate_federation_policy_request(
    state: &TrustServiceState,
    request: &FederationAdmissionEvaluationRequest,
    now: u64,
) -> Result<FederationAdmissionEvaluationResponse, CliError> {
    let (_, registry) = load_federation_policy_registry_for_admin(&state.config)?;
    let record = registry.get(&request.policy_id).cloned().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "federation policy `{}` was not found",
            request.policy_id
        ))
    })?;
    verify_federation_admission_policy_record(&record)?;

    let policy = &record.policy.body;
    let proof_of_work_required = record.anti_sybil.proof_of_work_bits.is_some();
    let proof_of_work_verified = record
        .anti_sybil
        .proof_of_work_bits
        .map(|difficulty_bits| {
            request.proof_of_work_nonce.as_deref().is_some_and(|nonce| {
                verify_admission_proof_of_work(
                    &request.policy_id,
                    &request.subject_key,
                    nonce,
                    difficulty_bits,
                )
            })
        })
        .unwrap_or(true);
    let bond_backed_required = record.anti_sybil.bond_backed_only;
    let bond_backed_satisfied = !bond_backed_required
        || request.requested_admission_class == GenericTrustAdmissionClass::BondBacked;

    let mut response = FederationAdmissionEvaluationResponse {
        policy_id: request.policy_id.clone(),
        subject_key: request.subject_key.clone(),
        requested_admission_class: request.requested_admission_class,
        accepted: false,
        decision_reason: String::new(),
        proof_of_work_required,
        proof_of_work_verified,
        bond_backed_required,
        bond_backed_satisfied,
        minimum_reputation_score: record.minimum_reputation_score,
        observed_reputation_score: None,
        rate_limit: None,
    };

    if !policy
        .allowed_admission_classes
        .contains(&request.requested_admission_class)
    {
        response.decision_reason =
            "requested admission class is not allowed by the signed federation policy".to_string();
        return Ok(response);
    }

    if proof_of_work_required && !proof_of_work_verified {
        response.decision_reason =
            "proof-of-work nonce did not satisfy the configured federation policy difficulty"
                .to_string();
        return Ok(response);
    }

    if !bond_backed_satisfied {
        response.decision_reason =
            "federation policy requires bond_backed admission for permissionless entry".to_string();
        return Ok(response);
    }

    if let Some(minimum_score) = record.minimum_reputation_score {
        let read_context = chio_kernel::ReceiptReadContext::admin_service();
        let trusted_kernel_keys = trusted_kernel_keys_from_service_config(&state.config)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust service authority material is configured but could not be loaded for federation admission: {error}"
                ))
            })?
            .unwrap_or_default();
        let inspection = crate::issuance::inspect_local_reputation_with_read_context(
            &request.subject_key,
            state.config.receipt_db_path.as_deref(),
            state.config.budget_db_path.as_deref(),
            None,
            None,
            state.config.issuance_policy.as_ref(),
            &trusted_kernel_keys,
            &read_context,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to inspect local reputation for federation admission: {error}"
            ))
        })?;
        response.observed_reputation_score = Some(inspection.effective_score);
        if inspection.effective_score < minimum_score {
            response.decision_reason = format!(
                "effective local reputation score {:.4} is below the federation threshold {:.4}",
                inspection.effective_score, minimum_score
            );
            return Ok(response);
        }
    }

    if let Some(limit) = record.anti_sybil.rate_limit.as_ref() {
        let mut limiter = state
            .federation_admission_rate_limiter
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(
                    "federation admission rate limiter is poisoned".to_string(),
                )
            })?;
        let status = limiter.check_and_record(&request.policy_id, &request.subject_key, limit, now);
        let limited = status.retry_after_seconds.is_some();
        response.rate_limit = Some(status);
        if limited {
            response.decision_reason =
                "federation admission rate limit exceeded for the configured policy window"
                    .to_string();
            return Ok(response);
        }
    }

    response.accepted = true;
    response.decision_reason =
        "subject satisfied the configured federation reputation and anti-sybil controls"
            .to_string();
    Ok(response)
}
