fn contribute_metric(
    metric: Option<f64>,
    weight: f64,
    weighted_sum: &mut f64,
    effective_weight_sum: &mut f64,
) {
    if let Some(value) = metric {
        *weighted_sum += weight * clamp01(value);
        *effective_weight_sum += weight;
    }
}

fn receipt_subject_key(
    receipt: &ChioReceipt,
    capability_map: &BTreeMap<&str, &CapabilityLineageRecord>,
) -> Option<String> {
    receipt_attribution(receipt)
        .map(|metadata| metadata.subject_key)
        .or_else(|| {
            capability_map
                .get(receipt.capability_id.as_str())
                .map(|record| record.subject_key.clone())
        })
}

fn receipt_attribution(receipt: &ChioReceipt) -> Option<ReceiptAttributionMetadata> {
    let metadata = receipt.metadata.as_ref()?;
    let attribution = metadata.get("attribution")?;
    serde_json::from_value(attribution.clone()).ok()
}

fn weighted_average(values: &[(f64, f64)]) -> f64 {
    let total_weight = values.iter().map(|(_, weight)| weight).sum::<f64>();
    if total_weight == 0.0 {
        0.0
    } else {
        values
            .iter()
            .map(|(value, weight)| value * weight)
            .sum::<f64>()
            / total_weight
    }
}

fn decay_weight(now: u64, timestamp: u64, half_life_days: u32) -> f64 {
    if half_life_days == 0 {
        return 1.0;
    }
    let age_seconds = now.saturating_sub(timestamp) as f64;
    let half_life_seconds = half_life_days as f64 * SECONDS_PER_DAY as f64;
    2f64.powf(-age_seconds / half_life_seconds)
}

fn scope_reduced(parent: &ChioScope, child: &ChioScope) -> bool {
    if child
        .grants
        .iter()
        .any(|child_grant| parent_grant_for(child_grant, parent).is_none())
    {
        return false;
    }

    if child.grants.len() < parent.grants.len()
        || child.resource_grants.len() < parent.resource_grants.len()
        || child.prompt_grants.len() < parent.prompt_grants.len()
    {
        return true;
    }

    child.grants.iter().any(|child_grant| {
        parent_grant_for(child_grant, parent)
            .map(|parent_grant| grant_scope_reduced(parent_grant, child_grant))
            .unwrap_or(false)
    })
}

fn budget_reduced(parent: &ChioScope, child: &ChioScope) -> bool {
    child.grants.iter().any(|child_grant| {
        parent_grant_for(child_grant, parent)
            .map(|parent_grant| {
                invocation_limit_reduced(parent_grant, child_grant)
                    || monetary_limit_reduced(parent_grant, child_grant)
            })
            .unwrap_or(false)
    })
}

fn parent_grant_for<'a>(child: &ToolGrant, parent: &'a ChioScope) -> Option<&'a ToolGrant> {
    parent
        .grants
        .iter()
        .find(|grant| {
            grant.server_id == child.server_id
                && grant.tool_name == child.tool_name
                && child.is_subset_of(grant)
        })
        .or_else(|| parent.grants.iter().find(|grant| child.is_subset_of(grant)))
}

fn grant_scope_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    if child
        .operations
        .iter()
        .any(|operation| !parent.operations.contains(operation))
    {
        return false;
    }

    child.operations.len() < parent.operations.len()
        || child.constraints.len() > parent.constraints.len()
        || child
            .constraints
            .iter()
            .any(|constraint| !parent.constraints.contains(constraint))
        || invocation_limit_reduced(parent, child)
        || monetary_limit_reduced(parent, child)
}

fn invocation_limit_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    match (parent.max_invocations, child.max_invocations) {
        (Some(parent_max), Some(child_max)) => child_max < parent_max,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn monetary_limit_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    monetary_cap_reduced(
        parent.max_cost_per_invocation.as_ref(),
        child.max_cost_per_invocation.as_ref(),
    ) || monetary_cap_reduced(
        parent.max_total_cost.as_ref(),
        child.max_total_cost.as_ref(),
    )
}

fn monetary_cap_reduced(
    parent: Option<&chio_core::capability::scope::MonetaryAmount>,
    child: Option<&chio_core::capability::scope::MonetaryAmount>,
) -> bool {
    match (parent, child) {
        (Some(parent_amount), Some(child_amount)) => {
            parent_amount.currency == child_amount.currency
                && child_amount.units < parent_amount.units
        }
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => false,
    }
}

fn bool_to_score(value: bool) -> f64 {
    if value {
        1.0
    } else {
        0.0
    }
}

fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

