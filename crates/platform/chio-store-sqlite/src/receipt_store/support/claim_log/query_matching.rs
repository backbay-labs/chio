use super::*;

pub(crate) fn query_underwriting_appeal(
    tx: &rusqlite::Transaction<'_>,
    appeal_id: &str,
) -> Result<Option<UnderwritingAppealRecord>, ReceiptStoreError> {
    let row = tx
        .query_row(
            "SELECT decision_id, requested_by, reason, status, note, created_at, updated_at,
                resolved_by, replacement_decision_id
         FROM underwriting_appeals
         WHERE appeal_id = ?1",
            params![appeal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?;

    row.map(
        |(
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        )| {
            Ok(UnderwritingAppealRecord {
                schema: chio_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
                appeal_id: appeal_id.to_string(),
                decision_id,
                requested_by,
                reason,
                status: parse_underwriting_appeal_status(&status)?,
                note,
                created_at: created_at.max(0) as u64,
                updated_at: updated_at.max(0) as u64,
                resolved_by,
                replacement_decision_id,
            })
        },
    )
    .transpose()
}

pub(crate) fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<UnderwritingAppealStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn load_underwriting_appeal_rows(
    connection: &Connection,
) -> Result<Vec<UnderwritingAppealRecord>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT appeal_id, decision_id, requested_by, reason, status, note, created_at,
                updated_at, resolved_by, replacement_decision_id
         FROM underwriting_appeals
         ORDER BY updated_at DESC, appeal_id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        ) = row.map_err(ReceiptStoreError::from)?;
        Ok(UnderwritingAppealRecord {
            schema: chio_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status: parse_underwriting_appeal_status(&status)?,
            note,
            created_at: created_at.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            resolved_by,
            replacement_decision_id,
        })
    })
    .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn underwriting_decision_matches_query(
    decision: &SignedUnderwritingDecision,
    lifecycle_state: UnderwritingDecisionLifecycleState,
    latest_appeal_status: Option<UnderwritingAppealStatus>,
    query: &UnderwritingDecisionQuery,
) -> bool {
    let filters = &decision.body.evaluation.input.filters;
    let decision_id_matches = query
        .decision_id
        .as_deref()
        .is_none_or(|decision_id| decision.body.decision_id == decision_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let outcome_matches = query
        .outcome
        .is_none_or(|outcome| decision.body.evaluation.outcome == outcome);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let appeal_matches = query
        .appeal_status
        .is_none_or(|status| latest_appeal_status == Some(status));

    decision_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && outcome_matches
        && lifecycle_matches
        && appeal_matches
}

pub(crate) fn effective_credit_facility_lifecycle_state(
    facility: &SignedCreditFacility,
    persisted: CreditFacilityLifecycleState,
    now: u64,
) -> CreditFacilityLifecycleState {
    if persisted == CreditFacilityLifecycleState::Active && facility.body.expires_at <= now {
        CreditFacilityLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn effective_credit_bond_lifecycle_state(
    bond: &SignedCreditBond,
    persisted: CreditBondLifecycleState,
    now: u64,
) -> CreditBondLifecycleState {
    if persisted == CreditBondLifecycleState::Active && bond.body.expires_at <= now {
        CreditBondLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn credit_facility_matches_query(
    facility: &SignedCreditFacility,
    lifecycle_state: CreditFacilityLifecycleState,
    query: &CreditFacilityListQuery,
) -> bool {
    let filters = &facility.body.report.filters;
    let facility_id_matches = query
        .facility_id
        .as_deref()
        .is_none_or(|facility_id| facility.body.facility_id == facility_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| facility.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn credit_bond_matches_query(
    bond: &SignedCreditBond,
    lifecycle_state: CreditBondLifecycleState,
    query: &CreditBondListQuery,
) -> bool {
    let filters = &bond.body.report.filters;
    let bond_id_matches = query
        .bond_id
        .as_deref()
        .is_none_or(|bond_id| bond.body.bond_id == bond_id);
    let facility_id_matches = query.facility_id.as_deref().is_none_or(|facility_id| {
        bond.body.report.latest_facility_id.as_deref() == Some(facility_id)
    });
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| bond.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    bond_id_matches
        && facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn liability_provider_matches_query(
    provider: &SignedLiabilityProvider,
    lifecycle_state: LiabilityProviderLifecycleState,
    query: &LiabilityProviderListQuery,
) -> bool {
    let report = &provider.body.report;
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| report.provider_id == provider_id);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        report
            .policies
            .iter()
            .any(|policy| policy.jurisdiction.eq_ignore_ascii_case(jurisdiction))
    });
    let coverage_matches = query.coverage_class.is_none_or(|coverage_class| {
        report
            .policies
            .iter()
            .any(|policy| policy.coverage_classes.contains(&coverage_class))
    });
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        report.policies.iter().any(|policy| {
            policy
                .supported_currencies
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(currency))
        })
    });

    provider_id_matches
        && lifecycle_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_provider_policy_matches_resolution(
    policy: &chio_kernel::LiabilityJurisdictionPolicy,
    query: &LiabilityProviderResolutionQuery,
) -> bool {
    policy
        .jurisdiction
        .eq_ignore_ascii_case(&query.jurisdiction)
        && policy.coverage_classes.contains(&query.coverage_class)
        && policy
            .supported_currencies
            .iter()
            .any(|currency| currency.eq_ignore_ascii_case(&query.currency))
}

pub(crate) fn liability_market_workflow_matches_query(
    quote_request: &SignedLiabilityQuoteRequest,
    query: &LiabilityMarketWorkflowQuery,
) -> bool {
    let request = &quote_request.body;
    let quote_request_id_matches = query
        .quote_request_id
        .as_deref()
        .is_none_or(|quote_request_id| request.quote_request_id == quote_request_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| request.provider_policy.provider_id == provider_id);
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| request.risk_package.body.subject_key == subject);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        request
            .provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let coverage_matches = query
        .coverage_class
        .is_none_or(|coverage_class| request.provider_policy.coverage_class == coverage_class);
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        request
            .requested_coverage_amount
            .currency
            .eq_ignore_ascii_case(currency)
    });

    quote_request_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_claim_workflow_matches_query(
    claim: &SignedLiabilityClaimPackage,
    query: &LiabilityClaimWorkflowQuery,
) -> bool {
    let claim_body = &claim.body;
    let provider_policy = &claim_body
        .bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .provider_policy;
    let claim_id_matches = query
        .claim_id
        .as_deref()
        .is_none_or(|claim_id| claim_body.claim_id == claim_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| provider_policy.provider_id == provider_id);
    let subject_matches = query.agent_subject.as_deref().is_none_or(|subject| {
        claim_body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key
            == subject
    });
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let policy_number_matches = query
        .policy_number
        .as_deref()
        .is_none_or(|policy_number| claim_body.bound_coverage.body.policy_number == policy_number);

    claim_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && policy_number_matches
}

pub(crate) fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}
