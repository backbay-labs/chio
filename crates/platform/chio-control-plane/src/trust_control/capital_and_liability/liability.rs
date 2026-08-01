use super::*;

/// Operator-supplied predeclared roster policy for liability adjudication.
///
/// `roster_anchor` is the id or hash of the signed roster artifact that
/// `roster` was drawn from (for example a `chio-trust-market-context`
/// `AdjudicationJurisdictionReceipt`). It is recorded on the adjudication so
/// the audit trail shows which ex-ante roster was applied and the check is not
/// per-adjudication fabricable.
#[derive(Debug, Clone, Deserialize)]
pub struct RosterPolicy {
    pub roster: Vec<String>,
    pub allowed_decision_rules: Vec<String>,
    pub roster_anchor: String,
}

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
    policy: &RosterPolicy,
) -> Result<SignedLiabilityClaimAdjudication, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_adjudication_artifact(request, issued_at, policy)?;
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
    policy: &RosterPolicy,
) -> Result<SignedLiabilityClaimPayoutInstruction, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_payout_instruction_artifact(request, issued_at, policy)?;
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
    policy: &RosterPolicy,
) -> Result<SignedLiabilityClaimSettlementInstruction, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact =
        build_liability_claim_settlement_instruction_artifact(request, issued_at, policy)?;
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
    policy: &RosterPolicy,
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
                    &request.decision_rule_ref,
                    &policy.roster_anchor,
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
        decision_rule_ref: request.decision_rule_ref.clone(),
        roster_anchor_ref: Some(policy.roster_anchor.clone()),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    artifact
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
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
    policy: &RosterPolicy,
) -> Result<LiabilityClaimPayoutInstructionArtifact, CliError> {
    request
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
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
    policy: &RosterPolicy,
) -> Result<LiabilityClaimSettlementInstructionArtifact, CliError> {
    request
        .payout_receipt
        .body
        .payout_instruction
        .body
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
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

#[cfg(test)]
mod roster_enforcement {
    use super::*;
    use chio_core::receipt::lineage::SignedExportEnvelope;
    use chio_kernel::{
        CapitalExecutionRailKind, CreditLossLifecycleSummary, LiabilityClaimSettlementRoleBinding,
    };
    use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};

    // Pinned adjudication_id for fixed inputs used in the golden regression test.
    // If this value changes, verify that the id-fold tuple change was intentional
    // and update this const. Construction-time goldens change when the tuple fields
    // change; wire-format signature goldens are unaffected.
    const ADJUDICATION_ID_GOLDEN_ANCHOR_A: &str =
        "lca-96d5df5192950bcfbd3d140286c79347d800dce8d945dffd4da9752530e9a038";

    fn sign_export<T: serde::Serialize + Clone>(body: T) -> SignedExportEnvelope<T> {
        let kp = Keypair::generate();
        SignedExportEnvelope::sign(body, &kp).test_unwrap("sign export")
    }

    fn usd(units: u64) -> MonetaryAmount {
        MonetaryAmount {
            units,
            currency: "USD".to_string(),
        }
    }

    fn stub_exposure_report() -> SignedExposureLedgerReport {
        let kp = Keypair::generate();
        SignedExposureLedgerReport::sign(
            ExposureLedgerReport {
                schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: ExposureLedgerSupportBoundary::default(),
                summary: ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                positions: vec![ExposureLedgerCurrencyPosition {
                    currency: "USD".to_string(),
                    governed_max_exposure_units: 10_000,
                    reserved_units: 0,
                    settled_units: 0,
                    pending_units: 0,
                    failed_units: 0,
                    provisional_loss_units: 0,
                    recovered_units: 0,
                    quoted_premium_units: 0,
                    active_quoted_premium_units: 0,
                }],
                receipts: Vec::new(),
                decisions: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign exposure report")
    }

    fn stub_credit_bond() -> SignedCreditBond {
        let kp = Keypair::generate();
        let exposure = stub_exposure_report();
        SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: "bond-1".to_string(),
                issued_at: 10,
                expires_at: 1_800_000_000,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 10,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: exposure.body.summary.clone(),
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: None,
                    terms: None,
                    findings: Vec::new(),
                },
            },
            &kp,
        )
        .test_unwrap("sign credit bond")
    }

    fn stub_credit_loss_lifecycle() -> SignedCreditLossLifecycle {
        let kp = Keypair::generate();
        SignedCreditLossLifecycle::sign(
            CreditLossLifecycleArtifact {
                schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
                event_id: "loss-t1".to_string(),
                issued_at: 11,
                bond_id: "bond-1".to_string(),
                event_kind: CreditLossLifecycleEventKind::Delinquency,
                projected_bond_lifecycle_state: CreditBondLifecycleState::Active,
                reserve_control_source_id: None,
                authority_chain: Vec::new(),
                execution_window: None,
                rail: None,
                observed_execution: None,
                reconciled_state: None,
                execution_state: None,
                appeal_state: None,
                appeal_window_ends_at: None,
                description: Some("test loss marker".to_string()),
                report: CreditLossLifecycleReport {
                    schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
                    generated_at: 11,
                    query: CreditLossLifecycleQuery {
                        bond_id: "bond-1".to_string(),
                        event_kind: CreditLossLifecycleEventKind::Delinquency,
                        amount: Some(usd(1_000)),
                    },
                    summary: CreditLossLifecycleSummary {
                        bond_id: "bond-1".to_string(),
                        facility_id: None,
                        capability_id: None,
                        agent_subject: Some("subject-1".to_string()),
                        tool_server: None,
                        tool_name: None,
                        current_bond_lifecycle_state: CreditBondLifecycleState::Active,
                        projected_bond_lifecycle_state: CreditBondLifecycleState::Active,
                        current_delinquent_amount: Some(usd(1_000)),
                        current_recovered_amount: None,
                        current_written_off_amount: None,
                        current_released_reserve_amount: None,
                        current_slashed_reserve_amount: None,
                        outstanding_delinquent_amount: Some(usd(1_000)),
                        releaseable_reserve_amount: Some(usd(2_000)),
                        reserve_control_source_id: None,
                        execution_state: None,
                        appeal_state: None,
                        appeal_window_ends_at: None,
                        event_amount: Some(usd(1_000)),
                    },
                    support_boundary: CreditLossLifecycleSupportBoundary::default(),
                    findings: Vec::new(),
                },
            },
            &kp,
        )
        .test_unwrap("sign credit loss lifecycle")
    }

    fn stub_risk_package() -> SignedCreditProviderRiskPackage {
        let kp = Keypair::generate();
        let exposure = stub_exposure_report();
        let scorecard = SignedCreditScorecardReport::sign(
            CreditScorecardReport {
                schema: CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: CreditScorecardSupportBoundary::default(),
                summary: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: CreditScorecardProbationStatus {
                    probationary: false,
                    reasons: Vec::new(),
                    receipt_count: 1,
                    span_days: 1,
                    target_receipt_count: 1,
                    target_span_days: 1,
                },
                dimensions: Vec::new(),
                anomalies: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign scorecard");
        SignedCreditProviderRiskPackage::sign(
            CreditProviderRiskPackage {
                schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CreditProviderRiskPackageQuery::default()
                },
                support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
                exposure,
                scorecard,
                facility_report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditFacilityDisposition::Grant,
                    prerequisites: CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: CreditFacilitySupportBoundary::default(),
                    terms: None,
                    findings: Vec::new(),
                },
                compliance_score: None,
                latest_facility: None,
                runtime_assurance: None,
                certification: CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: CreditRecentLossHistory {
                    summary: CreditRecentLossSummary {
                        matching_loss_events: 0,
                        returned_loss_events: 0,
                        failed_settlement_events: 0,
                        provisional_loss_events: 0,
                        recovered_events: 0,
                    },
                    entries: Vec::new(),
                },
                evidence_refs: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign risk package")
    }

    /// Build a signed adjudication whose adjudicator is NOT on the roster.
    /// The nested chain just needs to type-check; it is never validated because
    /// the roster gate fires first.
    fn sample_signed_off_roster_adjudication() -> SignedLiabilityClaimAdjudication {
        let risk_package = stub_risk_package();
        let provider_policy = LiabilityProviderPolicyReference {
            provider_id: "provider-1".to_string(),
            provider_record_id: "lpr-1".to_string(),
            display_name: "Provider One".to_string(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: LiabilityCoverageClass::ToolExecution,
            currency: "USD".to_string(),
            required_evidence: Vec::new(),
            max_coverage_amount: Some(usd(10_000)),
            claims_supported: true,
            quote_ttl_seconds: 3_600,
            bound_coverage_supported: true,
        };
        let quote_request = sign_export(LiabilityQuoteRequestArtifact {
            schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
            quote_request_id: "lqr-t1".to_string(),
            issued_at: 1_700_000_000,
            provider_policy,
            requested_coverage_amount: usd(10_000),
            requested_effective_from: 1_700_010_000,
            requested_effective_until: 1_700_020_000,
            risk_package,
            notes: None,
        });
        let quote_response = sign_export(LiabilityQuoteResponseArtifact {
            schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
            quote_response_id: "lqp-t1".to_string(),
            issued_at: 1_700_000_120,
            quote_request: quote_request.clone(),
            provider_quote_ref: "quote-ref-t1".to_string(),
            disposition: LiabilityQuoteDisposition::Quoted,
            supersedes_quote_response_id: None,
            quoted_terms: Some(LiabilityQuoteTerms {
                quoted_coverage_amount: usd(10_000),
                quoted_premium_amount: usd(500),
                quoted_deductible_amount: None,
                expires_at: 1_700_003_000,
            }),
            decline_reason: None,
        });
        let placement = sign_export(LiabilityPlacementArtifact {
            schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
            placement_id: "lpl-t1".to_string(),
            issued_at: 1_700_000_160,
            quote_response: quote_response.clone(),
            selected_coverage_amount: usd(10_000),
            selected_premium_amount: usd(500),
            effective_from: quote_response
                .body
                .quote_request
                .body
                .requested_effective_from,
            effective_until: quote_response
                .body
                .quote_request
                .body
                .requested_effective_until,
            placement_ref: None,
            notes: None,
        });
        let bound_coverage = sign_export(LiabilityBoundCoverageArtifact {
            schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
            bound_coverage_id: "lbc-t1".to_string(),
            issued_at: 1_700_000_170,
            placement: placement.clone(),
            policy_number: "POL-T1".to_string(),
            carrier_reference: None,
            bound_at: 1_700_000_171,
            effective_from: placement.body.effective_from,
            effective_until: placement.body.effective_until,
            coverage_amount: placement.body.selected_coverage_amount.clone(),
            premium_amount: placement.body.selected_premium_amount.clone(),
        });
        let claim_package = sign_export(LiabilityClaimPackageArtifact {
            schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
            claim_id: "clm-t1".to_string(),
            issued_at: 1_700_010_400,
            bound_coverage: bound_coverage.clone(),
            exposure: stub_exposure_report(),
            bond: stub_credit_bond(),
            loss_event: stub_credit_loss_lifecycle(),
            claimant: "subject-1".to_string(),
            claim_event_at: 1_700_010_500,
            claim_amount: usd(9_000),
            claim_ref: None,
            narrative: "tool execution loss".to_string(),
            receipt_ids: vec!["rcpt-t1".to_string()],
            evidence_refs: Vec::new(),
        });
        let claim_response = sign_export(LiabilityClaimResponseArtifact {
            schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
            claim_response_id: "clr-t1".to_string(),
            issued_at: 1_700_010_600,
            claim: claim_package.clone(),
            provider_response_ref: "provider-t1".to_string(),
            disposition: LiabilityClaimResponseDisposition::Denied,
            covered_amount: None,
            response_note: None,
            denial_reason: Some("policy exclusion".to_string()),
            evidence_refs: Vec::new(),
        });
        let dispute = sign_export(LiabilityClaimDisputeArtifact {
            schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
            dispute_id: "lcd-t1".to_string(),
            issued_at: 1_700_010_700,
            provider_response: claim_response.clone(),
            opened_by: "subject-1".to_string(),
            reason: "disputed denial".to_string(),
            note: None,
            evidence_refs: Vec::new(),
        });
        sign_export(LiabilityClaimAdjudicationArtifact {
            schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
            adjudication_id: "lca-off-roster-t1".to_string(),
            issued_at: 1_700_010_800,
            dispute,
            adjudicator: "off.roster.adjudicator".to_string(),
            outcome: LiabilityClaimAdjudicationOutcome::PartialSettlement,
            awarded_amount: Some(usd(5_000)),
            note: None,
            decision_rule_ref: Some("rule.partial-settlement.v1".to_string()),
            roster_anchor_ref: Some("roster-anchor-abc".to_string()),
            evidence_refs: Vec::new(),
        })
    }

    fn stub_capital_instruction() -> SignedCapitalExecutionInstruction {
        sign_export(CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-fixture-t1".to_string(),
            issued_at: 1_700_010_850,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "src-fixture-1".to_string(),
            source_kind: CapitalBookSourceKind::FacilityCommitment,
            governed_receipt_id: None,
            completion_flow_row_id: None,
            action: CapitalExecutionInstructionAction::TransferFunds,
            owner_role: CapitalExecutionRole::FacilityProvider,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(usd(5_000)),
            authority_chain: Vec::new(),
            execution_window: CapitalExecutionWindow {
                not_before: 1_700_010_850,
                not_after: 1_800_000_000,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Api,
                rail_id: "rail-fixture-1".to_string(),
                custody_provider_id: "custody-fixture-1".to_string(),
                source_account_ref: None,
                destination_account_ref: None,
                jurisdiction: None,
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::NotObserved,
            related_instruction_id: None,
            observed_execution: None,
            support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
            evidence_refs: Vec::new(),
            description: "fixture transfer".to_string(),
        })
    }

    fn build_payout_instruction_with_policy(
        adjudication: &SignedLiabilityClaimAdjudication,
        policy: &RosterPolicy,
    ) -> Result<LiabilityClaimPayoutInstructionArtifact, CliError> {
        let request = LiabilityClaimPayoutInstructionIssueRequest {
            adjudication: adjudication.clone(),
            capital_instruction: stub_capital_instruction(),
            note: None,
        };
        build_liability_claim_payout_instruction_artifact(&request, 1_700_010_900, policy)
    }

    fn stub_payout_receipt_wrapping(
        adjudication: &SignedLiabilityClaimAdjudication,
    ) -> SignedLiabilityClaimPayoutReceipt {
        let payout_instruction = sign_export(LiabilityClaimPayoutInstructionArtifact {
            schema: LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            payout_instruction_id: "lpi-fixture-t1".to_string(),
            issued_at: 1_700_010_900,
            adjudication: adjudication.clone(),
            capital_instruction: stub_capital_instruction(),
            payout_amount: usd(5_000),
            note: None,
        });
        sign_export(LiabilityClaimPayoutReceiptArtifact {
            schema: LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
            payout_receipt_id: "lprc-fixture-t1".to_string(),
            issued_at: 1_700_011_000,
            payout_instruction,
            payout_receipt_ref: "receipt-fixture-t1".to_string(),
            reconciliation_state: LiabilityClaimPayoutReconciliationState::Matched,
            observed_execution: CapitalExecutionObservation {
                observed_at: 1_700_011_000,
                external_reference_id: "exec-fixture-t1".to_string(),
                amount: usd(5_000),
            },
            note: None,
        })
    }

    fn stub_capital_book() -> SignedCapitalBookReport {
        let kp = Keypair::generate();
        SignedCapitalBookReport::sign(
            CapitalBookReport {
                schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
                generated_at: 1_700_000_100,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                support_boundary: CapitalBookSupportBoundary::default(),
                summary: CapitalBookSummary {
                    matching_receipts: 0,
                    returned_receipts: 0,
                    matching_facilities: 0,
                    returned_facilities: 0,
                    matching_bonds: 0,
                    returned_bonds: 0,
                    matching_loss_events: 0,
                    returned_loss_events: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    funding_sources: 0,
                    ledger_events: 0,
                    truncated_receipts: false,
                    truncated_facilities: false,
                    truncated_bonds: false,
                    truncated_loss_events: false,
                },
                sources: Vec::new(),
                events: Vec::new(),
            },
            &kp,
        )
        .test_unwrap("sign capital book")
    }

    fn build_settlement_instruction_with_policy(
        adjudication: &SignedLiabilityClaimAdjudication,
        policy: &RosterPolicy,
    ) -> Result<LiabilityClaimSettlementInstructionArtifact, CliError> {
        let payout_receipt = stub_payout_receipt_wrapping(adjudication);
        let kp = Keypair::generate();
        let facility_provider_id = kp.public_key().to_hex();
        let request = LiabilityClaimSettlementInstructionIssueRequest {
            payout_receipt,
            capital_book: stub_capital_book(),
            settlement_kind: LiabilityClaimSettlementKind::FacilityReimbursement,
            settlement_amount: usd(5_000),
            topology: LiabilityClaimSettlementRoleTopology {
                payer: LiabilityClaimSettlementRoleBinding {
                    role: CapitalExecutionRole::FacilityProvider,
                    party_id: facility_provider_id.clone(),
                    jurisdiction: None,
                    note: None,
                },
                payee: LiabilityClaimSettlementRoleBinding {
                    role: CapitalExecutionRole::AgentCounterparty,
                    party_id: "subject-1".to_string(),
                    jurisdiction: None,
                    note: None,
                },
                beneficiary: None,
            },
            authority_chain: Vec::new(),
            execution_window: CapitalExecutionWindow {
                not_before: 1_700_011_100,
                not_after: 1_800_000_000,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Api,
                rail_id: "rail-settle-fixture-t1".to_string(),
                custody_provider_id: "custody-fixture-1".to_string(),
                source_account_ref: None,
                destination_account_ref: None,
                jurisdiction: None,
            },
            settlement_reference: None,
            note: None,
        };
        build_liability_claim_settlement_instruction_artifact(&request, 1_700_011_100, policy)
    }

    #[test]
    fn payout_and_settlement_constructors_reject_off_roster_adjudication() {
        let policy = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec!["rule.partial-settlement.v1".to_string()],
            roster_anchor: "roster-anchor-abc".to_string(),
        };
        let off_roster = sample_signed_off_roster_adjudication();
        let payout_err = build_payout_instruction_with_policy(&off_roster, &policy)
            .test_unwrap_err("off-roster adjudication must be denied at payout construction");
        assert!(
            payout_err
                .to_string()
                .contains("not on the predeclared roster"),
            "expected roster error, got: {payout_err}",
        );
        let settle_err = build_settlement_instruction_with_policy(&off_roster, &policy)
            .test_unwrap_err("off-roster adjudication must be denied at settlement construction");
        assert!(
            settle_err
                .to_string()
                .contains("not on the predeclared roster"),
            "expected roster error, got: {settle_err}",
        );
    }

    #[test]
    fn adjudication_id_folds_decision_rule_and_roster_anchor() {
        // Verifies that changing decision_rule_ref or roster_anchor changes the derived id,
        // and pins the id for a fixed input so regressions in the derivation are caught.
        let policy_a = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec![
                "rule.partial-settlement.v1".to_string(),
                "rule.full-settlement.v1".to_string(),
            ],
            roster_anchor: "anchor-a".to_string(),
        };
        let policy_b = RosterPolicy {
            roster: vec!["arbiter.on-roster".to_string()],
            allowed_decision_rules: vec![
                "rule.partial-settlement.v1".to_string(),
                "rule.full-settlement.v1".to_string(),
            ],
            roster_anchor: "anchor-b".to_string(),
        };
        let off_roster = sample_signed_off_roster_adjudication();
        // Build a request whose adjudicator IS on the roster so the gate passes.
        let on_roster_dispute = off_roster.body.dispute.clone();
        // request_base uses rule-a; request_rule_b uses rule-b but same anchor.
        let request_base = LiabilityClaimAdjudicationIssueRequest {
            dispute: on_roster_dispute.clone(),
            adjudicator: "arbiter.on-roster".to_string(),
            outcome: LiabilityClaimAdjudicationOutcome::PartialSettlement,
            awarded_amount: Some(usd(5_000)),
            decision_rule_ref: Some("rule.partial-settlement.v1".to_string()),
            note: None,
        };
        let request_rule_b = LiabilityClaimAdjudicationIssueRequest {
            decision_rule_ref: Some("rule.full-settlement.v1".to_string()),
            ..request_base.clone()
        };
        let artifact_anchor_a =
            build_liability_claim_adjudication_artifact(&request_base, 1_700_010_800, &policy_a)
                .test_unwrap("build with anchor-a");
        let artifact_anchor_b =
            build_liability_claim_adjudication_artifact(&request_base, 1_700_010_800, &policy_b)
                .test_unwrap("build with anchor-b");
        let artifact_rule_b =
            build_liability_claim_adjudication_artifact(&request_rule_b, 1_700_010_800, &policy_a)
                .test_unwrap("build with rule-b");

        // Varying roster_anchor must change the id.
        assert_ne!(
            artifact_anchor_a.adjudication_id, artifact_anchor_b.adjudication_id,
            "different roster_anchor must produce different adjudication_id",
        );
        // Varying decision_rule_ref must independently change the id.
        assert_ne!(
            artifact_anchor_a.adjudication_id, artifact_rule_b.adjudication_id,
            "different decision_rule_ref must produce different adjudication_id",
        );
        assert_eq!(
            artifact_anchor_a.roster_anchor_ref.as_deref(),
            Some("anchor-a")
        );
        assert_eq!(
            artifact_anchor_b.roster_anchor_ref.as_deref(),
            Some("anchor-b")
        );

        // Golden: pin the derivation for the fixed-input artifact_anchor_a so any change
        // to the id-fold tuple is immediately caught.
        // Construction-time goldens change when the tuple fields change; wire-format
        // signature goldens are unaffected.
        assert_eq!(
            artifact_anchor_a.adjudication_id, ADJUDICATION_ID_GOLDEN_ANCHOR_A,
            "adjudication_id derivation changed for fixed inputs",
        );
    }
}
