use super::*;

pub(super) fn validate_cumulative_request(
    request: &BudgetCumulativeApprovalRequest,
) -> Result<(), BudgetStoreError> {
    request.account_key.validate()?;
    if request.operation_id.is_empty() {
        return Err(BudgetStoreError::Invariant(
            "cumulative approval operation_id must not be empty".to_string(),
        ));
    }
    let currency = request.account_key.currency.as_str();
    if request.authority_threshold.currency != currency
        || request.effective_threshold.currency != currency
        || request.requested_authorized.currency != currency
    {
        return Err(BudgetStoreError::Invariant(
            "cumulative approval amounts must use the account currency".to_string(),
        ));
    }
    if request.effective_threshold.units > request.authority_threshold.units {
        return Err(BudgetStoreError::Invariant(
            "effective cumulative threshold exceeds authority threshold".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_stored_composite_binding(
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    event_id: &str,
    admission: &BudgetAdmissionBinding,
    quotas: &[BudgetInvocationQuota],
    cumulative: Option<&BudgetCumulativeApprovalRequest>,
) -> Result<(), BudgetStoreError> {
    BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index,
        max_invocations: None,
        invocation_quotas: quotas.to_vec(),
        cumulative_approval: cumulative.cloned(),
        admission_binding: Some(admission.clone()),
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some(hold_id.to_string()),
        event_id: Some(event_id.to_string()),
        authority: None,
    }
    .validate()
}
