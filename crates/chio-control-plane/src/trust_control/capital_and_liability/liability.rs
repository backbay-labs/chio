use super::*;

pub fn issue_signed_liability_provider(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    report: &LiabilityProviderReport,
    supersedes_provider_record_id: Option<&str>,
) -> Result<SignedLiabilityProvider, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    report.validate().map_err(CliError::cli_other_error)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_provider_artifact(
        report.clone(),
        issued_at,
        supersedes_provider_record_id.map(ToOwned::to_owned),
    )?;
    let signed = SignedLiabilityProvider::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability provider artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_provider(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_providers(
    receipt_db_path: &Path,
    query: &LiabilityProviderListQuery,
) -> Result<LiabilityProviderListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_providers(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn resolve_liability_provider(
    receipt_db_path: &Path,
    query: &LiabilityProviderResolutionQuery,
) -> Result<LiabilityProviderResolutionReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .resolve_liability_provider(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn build_liability_provider_artifact(
    report: LiabilityProviderReport,
    issued_at: u64,
    supersedes_provider_record_id: Option<String>,
) -> Result<LiabilityProviderArtifact, CliError> {
    report.validate().map_err(CliError::cli_other_error)?;
    let lifecycle_state = report.lifecycle_state;
    let provider_record_id_input = canonical_json_bytes(&(
        LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
        issued_at,
        lifecycle_state,
        &supersedes_provider_record_id,
        &report,
    ))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let provider_record_id = format!("lpr-{}", sha256_hex(&provider_record_id_input));
    Ok(LiabilityProviderArtifact {
        schema: LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_record_id,
        issued_at,
        lifecycle_state,
        supersedes_provider_record_id,
        report,
    })
}

pub fn issue_signed_liability_quote_request(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteRequestIssueRequest,
) -> Result<SignedLiabilityQuoteRequest, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request.provider_id.clone(),
            jurisdiction: request.jurisdiction.clone(),
            coverage_class: request.coverage_class,
            currency: request.requested_coverage_amount.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_quote_request_artifact(request, &resolution, issued_at)?;
    let signed = SignedLiabilityQuoteRequest::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability quote request artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_request(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_quote_response(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteResponseIssueRequest,
) -> Result<SignedLiabilityQuoteResponse, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request.quote_request.body.provider_policy.coverage_class,
            currency: request.quote_request.body.provider_policy.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request.quote_request.body.quote_request_id,
            request
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_quote_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityQuoteResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability quote response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_response(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_placement(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityPlacementIssueRequest,
) -> Result<SignedLiabilityPlacement, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_placement_artifact(request, issued_at)?;
    let signed = SignedLiabilityPlacement::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability placement artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_placement(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_pricing_authority(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityPricingAuthorityIssueRequest,
) -> Result<SignedLiabilityPricingAuthority, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request.quote_request.body.provider_policy.coverage_class,
            currency: request.quote_request.body.provider_policy.currency.clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request.quote_request.body.quote_request_id,
            request
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_pricing_authority_artifact(request, issued_at)?;
    let signed = SignedLiabilityPricingAuthority::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability pricing authority artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_pricing_authority(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_bound_coverage(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityBoundCoverageIssueRequest,
) -> Result<SignedLiabilityBoundCoverage, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_bound_coverage_artifact(request, issued_at)?;
    let signed = SignedLiabilityBoundCoverage::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability bound coverage artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_bound_coverage(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_auto_bind(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityAutoBindIssueRequest,
) -> Result<SignedLiabilityAutoBindDecision, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::cli_other_error(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    if request.authority.body.expires_at <= unix_timestamp_now() {
        return Err(CliError::cli_other_error(format!(
            "liability pricing authority `{}` is stale",
            request.authority.body.authority_id
        )));
    }
    let quoted_terms = request
        .quote_response
        .body
        .quoted_terms
        .as_ref()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "liability auto-bind requires a quoted quote response".to_string(),
            )
        })?;
    if quoted_terms.expires_at <= unix_timestamp_now() {
        return Err(CliError::cli_other_error(format!(
            "liability quote response `{}` is stale",
            request.quote_response.body.quote_response_id
        )));
    }
    if !request.authority.body.auto_bind_enabled {
        return Err(CliError::cli_other_error(format!(
            "liability pricing authority `{}` does not permit automatic binding",
            request.authority.body.authority_id
        )));
    }
    if request
        .quote_response
        .body
        .quote_request
        .body
        .quote_request_id
        != request.authority.body.quote_request.body.quote_request_id
    {
        return Err(CliError::cli_other_error(
            "liability auto-bind quote response must match the delegated pricing authority"
                .to_string(),
        ));
    }
    if quoted_terms.quoted_coverage_amount.units > request.authority.body.max_coverage_amount.units
    {
        return Err(CliError::cli_other_error(
            "liability auto-bind cannot be issued because quoted coverage exceeds pricing authority ceiling"
                .to_string(),
        ));
    }
    if quoted_terms.quoted_premium_amount.units > request.authority.body.max_premium_amount.units {
        return Err(CliError::cli_other_error(
            "liability auto-bind cannot be issued because quoted premium exceeds pricing authority ceiling"
                .to_string(),
        ));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let placement_request = LiabilityPlacementIssueRequest {
        quote_response: request.quote_response.clone(),
        selected_coverage_amount: quoted_terms.quoted_coverage_amount.clone(),
        selected_premium_amount: quoted_terms.quoted_premium_amount.clone(),
        effective_from: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        placement_ref: request.placement_ref.clone(),
        notes: request.notes.clone(),
    };
    let placement_artifact = build_liability_placement_artifact(&placement_request, issued_at)?;
    let signed_placement =
        SignedLiabilityPlacement::sign(placement_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability placement artifact: {error}"
            ))
        })?;
    let bound_request = LiabilityBoundCoverageIssueRequest {
        placement: signed_placement.clone(),
        policy_number: request.policy_number.clone(),
        carrier_reference: request.carrier_reference.clone(),
        bound_at: Some(issued_at),
        effective_from: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: request
            .quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        coverage_amount: quoted_terms.quoted_coverage_amount.clone(),
        premium_amount: quoted_terms.quoted_premium_amount.clone(),
    };
    let bound_artifact = build_liability_bound_coverage_artifact(&bound_request, issued_at)?;
    let signed_bound =
        SignedLiabilityBoundCoverage::sign(bound_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability bound coverage artifact: {error}"
            ))
        })?;
    let decision_artifact = build_liability_auto_bind_decision_artifact(
        request,
        issued_at,
        signed_placement,
        signed_bound,
    )?;
    let signed =
        SignedLiabilityAutoBindDecision::sign(decision_artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability auto-bind decision artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_auto_bind_decision(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_market_workflows(
    receipt_db_path: &Path,
    query: &LiabilityMarketWorkflowQuery,
) -> Result<LiabilityMarketWorkflowReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_market_workflows(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn issue_signed_liability_claim_package(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPackageIssueRequest,
) -> Result<SignedLiabilityClaimPackage, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_package_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimPackage::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim package artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_package(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_response(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimResponseIssueRequest,
) -> Result<SignedLiabilityClaimResponse, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_response(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_dispute(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimDisputeIssueRequest,
) -> Result<SignedLiabilityClaimDispute, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_dispute_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimDispute::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim dispute artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_dispute(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_adjudication(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimAdjudicationIssueRequest,
) -> Result<SignedLiabilityClaimAdjudication, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_adjudication_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimAdjudication::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim adjudication artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_adjudication(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_payout_instruction(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPayoutInstructionIssueRequest,
) -> Result<SignedLiabilityClaimPayoutInstruction, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_payout_instruction_artifact(request, issued_at)?;
    let signed =
        SignedLiabilityClaimPayoutInstruction::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim payout instruction artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_payout_instruction(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_payout_receipt(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPayoutReceiptIssueRequest,
) -> Result<SignedLiabilityClaimPayoutReceipt, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_payout_receipt_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimPayoutReceipt::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim payout receipt artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_payout_receipt(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_settlement_instruction(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimSettlementInstructionIssueRequest,
) -> Result<SignedLiabilityClaimSettlementInstruction, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_settlement_instruction_artifact(request, issued_at)?;
    let signed =
        SignedLiabilityClaimSettlementInstruction::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim settlement instruction artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_settlement_instruction(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_settlement_receipt(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimSettlementReceiptIssueRequest,
) -> Result<SignedLiabilityClaimSettlementReceipt, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_settlement_receipt_artifact(request, issued_at)?;
    let signed =
        SignedLiabilityClaimSettlementReceipt::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim settlement receipt artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_settlement_receipt(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_claim_workflows(
    receipt_db_path: &Path,
    query: &LiabilityClaimWorkflowQuery,
) -> Result<LiabilityClaimWorkflowReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_claim_workflows(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn build_liability_provider_policy_reference(
    resolution: &LiabilityProviderResolutionReport,
) -> LiabilityProviderPolicyReference {
    LiabilityProviderPolicyReference {
        provider_id: resolution.provider.body.report.provider_id.clone(),
        provider_record_id: resolution.provider.body.provider_record_id.clone(),
        display_name: resolution.provider.body.report.display_name.clone(),
        jurisdiction: resolution.matched_policy.jurisdiction.clone(),
        coverage_class: resolution.query.coverage_class,
        currency: resolution.query.currency.clone(),
        required_evidence: resolution.matched_policy.required_evidence.clone(),
        max_coverage_amount: resolution.matched_policy.max_coverage_amount.clone(),
        claims_supported: resolution.matched_policy.claims_supported,
        quote_ttl_seconds: resolution.matched_policy.quote_ttl_seconds,
        bound_coverage_supported: resolution.support_boundary.bound_coverage_supported,
    }
}

fn build_liability_quote_request_artifact(
    request: &LiabilityQuoteRequestIssueRequest,
    resolution: &LiabilityProviderResolutionReport,
    issued_at: u64,
) -> Result<LiabilityQuoteRequestArtifact, CliError> {
    let artifact = LiabilityQuoteRequestArtifact {
        schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: format!(
            "lqqr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_id,
                    &request.jurisdiction,
                    request.coverage_class,
                    &request.requested_coverage_amount,
                    request.requested_effective_from,
                    request.requested_effective_until,
                    &request.risk_package.body.subject_key,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        provider_policy: build_liability_provider_policy_reference(resolution),
        requested_coverage_amount: request.requested_coverage_amount.clone(),
        requested_effective_from: request.requested_effective_from,
        requested_effective_until: request.requested_effective_until,
        risk_package: request.risk_package.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_quote_response_artifact(
    request: &LiabilityQuoteResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityQuoteResponseArtifact, CliError> {
    let disposition = request.disposition.clone();
    let artifact = LiabilityQuoteResponseArtifact {
        schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        quote_response_id: format!(
            "lqqs-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_request.body.quote_request_id,
                    &request.provider_quote_ref,
                    &disposition,
                    &request.supersedes_quote_response_id,
                    &request.quoted_terms,
                    &request.decline_reason,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_request: request.quote_request.clone(),
        provider_quote_ref: request.provider_quote_ref.clone(),
        disposition,
        supersedes_quote_response_id: request.supersedes_quote_response_id.clone(),
        quoted_terms: request.quoted_terms.clone(),
        decline_reason: request.decline_reason.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_pricing_authority_artifact(
    request: &LiabilityPricingAuthorityIssueRequest,
    issued_at: u64,
) -> Result<LiabilityPricingAuthorityArtifact, CliError> {
    let artifact = LiabilityPricingAuthorityArtifact {
        schema: LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA.to_string(),
        authority_id: format!(
            "lqpa-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_request.body.quote_request_id,
                    &request.facility.body.facility_id,
                    &request.underwriting_decision.body.decision_id,
                    &request.envelope,
                    &request.max_coverage_amount,
                    &request.max_premium_amount,
                    request.expires_at,
                    request.auto_bind_enabled,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_request: request.quote_request.clone(),
        provider_policy: request.quote_request.body.provider_policy.clone(),
        facility: request.facility.clone(),
        underwriting_decision: request.underwriting_decision.clone(),
        capital_book: request.capital_book.clone(),
        envelope: request.envelope.clone(),
        max_coverage_amount: request.max_coverage_amount.clone(),
        max_premium_amount: request.max_premium_amount.clone(),
        expires_at: request.expires_at,
        auto_bind_enabled: request.auto_bind_enabled,
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_placement_artifact(
    request: &LiabilityPlacementIssueRequest,
    issued_at: u64,
) -> Result<LiabilityPlacementArtifact, CliError> {
    let artifact = LiabilityPlacementArtifact {
        schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
        placement_id: format!(
            "lqpl-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_response.body.quote_response_id,
                    &request.selected_coverage_amount,
                    &request.selected_premium_amount,
                    request.effective_from,
                    request.effective_until,
                    &request.placement_ref,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        quote_response: request.quote_response.clone(),
        selected_coverage_amount: request.selected_coverage_amount.clone(),
        selected_premium_amount: request.selected_premium_amount.clone(),
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        placement_ref: request.placement_ref.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_bound_coverage_artifact(
    request: &LiabilityBoundCoverageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityBoundCoverageArtifact, CliError> {
    let bound_at = request.bound_at.unwrap_or(issued_at);
    let artifact = LiabilityBoundCoverageArtifact {
        schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
        bound_coverage_id: format!(
            "lqbc-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.placement.body.placement_id,
                    &request.policy_number,
                    &request.carrier_reference,
                    bound_at,
                    request.effective_from,
                    request.effective_until,
                    &request.coverage_amount,
                    &request.premium_amount,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        placement: request.placement.clone(),
        policy_number: request.policy_number.clone(),
        carrier_reference: request.carrier_reference.clone(),
        bound_at,
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        coverage_amount: request.coverage_amount.clone(),
        premium_amount: request.premium_amount.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_auto_bind_decision_artifact(
    request: &LiabilityAutoBindIssueRequest,
    issued_at: u64,
    placement: SignedLiabilityPlacement,
    bound_coverage: SignedLiabilityBoundCoverage,
) -> Result<LiabilityAutoBindDecisionArtifact, CliError> {
    let artifact = LiabilityAutoBindDecisionArtifact {
        schema: LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: format!(
            "lqab-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.authority.body.authority_id,
                    &request.quote_response.body.quote_response_id,
                    &request.policy_number,
                    &request.carrier_reference,
                    &placement.body.placement_id,
                    &bound_coverage.body.bound_coverage_id,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        authority: request.authority.clone(),
        quote_response: request.quote_response.clone(),
        disposition: LiabilityAutoBindDisposition::AutoBound,
        findings: Vec::new(),
        placement: Some(placement),
        bound_coverage: Some(bound_coverage),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_evidence_refs(
    request: &LiabilityClaimPackageIssueRequest,
) -> Vec<LiabilityClaimEvidenceReference> {
    let mut refs = Vec::with_capacity(request.receipt_ids.len() + 4);
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request.bound_coverage.body.bound_coverage_id.clone(),
        observed_at: Some(request.bound_coverage.body.issued_at),
        locator: Some(format!(
            "policy:{}",
            request.bound_coverage.body.policy_number
        )),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ExposureLedger,
        reference_id: format!(
            "{}:{}",
            request.exposure.body.schema, request.exposure.body.generated_at
        ),
        observed_at: Some(request.exposure.body.generated_at),
        locator: request.exposure.body.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditBond,
        reference_id: request.bond.body.bond_id.clone(),
        observed_at: Some(request.bond.body.issued_at),
        locator: request.bond.body.report.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditLossLifecycle,
        reference_id: request.loss_event.body.event_id.clone(),
        observed_at: Some(request.loss_event.body.issued_at),
        locator: Some(format!("{:?}", request.loss_event.body.event_kind)),
    });
    refs.extend(request.receipt_ids.iter().cloned().map(|receipt_id| {
        LiabilityClaimEvidenceReference {
            kind: LiabilityClaimEvidenceKind::Receipt,
            reference_id: receipt_id,
            observed_at: None,
            locator: None,
        }
    }));
    refs
}

fn build_liability_claim_package_artifact(
    request: &LiabilityClaimPackageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPackageArtifact, CliError> {
    let evidence_refs = build_liability_claim_evidence_refs(request);
    let artifact = LiabilityClaimPackageArtifact {
        schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
        claim_id: format!(
            "lcp-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.bound_coverage.body.bound_coverage_id,
                    &request.claimant,
                    request.claim_event_at,
                    &request.claim_amount,
                    &request.claim_ref,
                    &request.narrative,
                    &request.receipt_ids,
                    &request.bond.body.bond_id,
                    &request.loss_event.body.event_id,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        bound_coverage: request.bound_coverage.clone(),
        exposure: request.exposure.clone(),
        bond: request.bond.clone(),
        loss_event: request.loss_event.clone(),
        claimant: request.claimant.clone(),
        claim_event_at: request.claim_event_at,
        claim_amount: request.claim_amount.clone(),
        claim_ref: request.claim_ref.clone(),
        narrative: request.narrative.clone(),
        receipt_ids: request.receipt_ids.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_response_artifact(
    request: &LiabilityClaimResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimResponseArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request
            .claim
            .body
            .bound_coverage
            .body
            .bound_coverage_id
            .clone(),
        observed_at: Some(request.claim.body.bound_coverage.body.issued_at),
        locator: Some(request.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimResponseArtifact {
        schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        claim_response_id: format!(
            "lcr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.claim.body.claim_id,
                    &request.provider_response_ref,
                    request.disposition,
                    &request.covered_amount,
                    &request.response_note,
                    &request.denial_reason,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        claim: request.claim.clone(),
        provider_response_ref: request.provider_response_ref.clone(),
        disposition: request.disposition,
        covered_amount: request.covered_amount.clone(),
        response_note: request.response_note.clone(),
        denial_reason: request.denial_reason.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_dispute_artifact(
    request: &LiabilityClaimDisputeIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimDisputeArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimResponse,
        reference_id: request.provider_response.body.claim_response_id.clone(),
        observed_at: Some(request.provider_response.body.issued_at),
        locator: Some(request.provider_response.body.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimDisputeArtifact {
        schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
        dispute_id: format!(
            "lcd-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_response.body.claim_response_id,
                    &request.opened_by,
                    &request.reason,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        provider_response: request.provider_response.clone(),
        opened_by: request.opened_by.clone(),
        reason: request.reason.clone(),
        note: request.note.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_adjudication_artifact(
    request: &LiabilityClaimAdjudicationIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimAdjudicationArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimDispute,
        reference_id: request.dispute.body.dispute_id.clone(),
        observed_at: Some(request.dispute.body.issued_at),
        locator: Some(
            request
                .dispute
                .body
                .provider_response
                .body
                .claim
                .body
                .claim_id
                .clone(),
        ),
    }];
    let artifact = LiabilityClaimAdjudicationArtifact {
        schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
        adjudication_id: format!(
            "lca-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.dispute.body.dispute_id,
                    &request.adjudicator,
                    request.outcome,
                    &request.awarded_amount,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        dispute: request.dispute.clone(),
        adjudicator: request.adjudicator.clone(),
        outcome: request.outcome,
        awarded_amount: request.awarded_amount.clone(),
        note: request.note.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn liability_claim_adjudication_awarded_amount(
    adjudication: &SignedLiabilityClaimAdjudication,
) -> Result<MonetaryAmount, CliError> {
    match adjudication.body.outcome {
        LiabilityClaimAdjudicationOutcome::ClaimUpheld
        | LiabilityClaimAdjudicationOutcome::PartialSettlement => {
            adjudication.body.awarded_amount.clone().ok_or_else(|| {
                CliError::cli_other_error(
                    "claim payout instructions require adjudications with awarded_amount"
                        .to_string(),
                )
            })
        }
        LiabilityClaimAdjudicationOutcome::ProviderUpheld => Err(CliError::cli_other_error(
            "claim payout instructions require a payable adjudication outcome".to_string(),
        )),
    }
}

fn build_liability_claim_payout_instruction_artifact(
    request: &LiabilityClaimPayoutInstructionIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPayoutInstructionArtifact, CliError> {
    let payout_amount = liability_claim_adjudication_awarded_amount(&request.adjudication)?;
    let artifact = LiabilityClaimPayoutInstructionArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        payout_instruction_id: format!(
            "lpi-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.adjudication.body.adjudication_id,
                    &request.capital_instruction.body.instruction_id,
                    &payout_amount,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        adjudication: request.adjudication.clone(),
        capital_instruction: request.capital_instruction.clone(),
        payout_amount,
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_payout_receipt_artifact(
    request: &LiabilityClaimPayoutReceiptIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPayoutReceiptArtifact, CliError> {
    let artifact = LiabilityClaimPayoutReceiptArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        payout_receipt_id: format!(
            "lprc-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.payout_instruction.body.payout_instruction_id,
                    &request.payout_receipt_ref,
                    request.reconciliation_state,
                    &request.observed_execution,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        payout_instruction: request.payout_instruction.clone(),
        payout_receipt_ref: request.payout_receipt_ref.clone(),
        reconciliation_state: request.reconciliation_state,
        observed_execution: request.observed_execution.clone(),
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_settlement_instruction_artifact(
    request: &LiabilityClaimSettlementInstructionIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimSettlementInstructionArtifact, CliError> {
    validate_capital_execution_envelope(
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        issued_at,
    )
    .map_err(CliError::from)?;
    let artifact = LiabilityClaimSettlementInstructionArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        settlement_instruction_id: format!(
            "lcsi-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.payout_receipt.body.payout_receipt_id,
                    &request.capital_book.body.subject_key,
                    request.settlement_kind,
                    &request.settlement_amount,
                    &request.topology,
                    &request.authority_chain,
                    &request.execution_window,
                    &request.rail,
                    &request.settlement_reference,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        payout_receipt: request.payout_receipt.clone(),
        capital_book: request.capital_book.clone(),
        settlement_kind: request.settlement_kind,
        settlement_amount: request.settlement_amount.clone(),
        topology: request.topology.clone(),
        authority_chain: request.authority_chain.clone(),
        execution_window: request.execution_window.clone(),
        rail: request.rail.clone(),
        settlement_reference: request.settlement_reference.clone(),
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_settlement_receipt_artifact(
    request: &LiabilityClaimSettlementReceiptIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimSettlementReceiptArtifact, CliError> {
    let artifact = LiabilityClaimSettlementReceiptArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        settlement_receipt_id: format!(
            "lcsr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request
                        .settlement_instruction
                        .body
                        .settlement_instruction_id,
                    &request.settlement_receipt_ref,
                    request.reconciliation_state,
                    &request.observed_execution,
                    &request.observed_payer_id,
                    &request.observed_payee_id,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        settlement_instruction: request.settlement_instruction.clone(),
        settlement_receipt_ref: request.settlement_receipt_ref.clone(),
        reconciliation_state: request.reconciliation_state,
        observed_execution: request.observed_execution.clone(),
        observed_payer_id: request.observed_payer_id.clone(),
        observed_payee_id: request.observed_payee_id.clone(),
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}
