/// Compute the local reputation scorecard for one agent.
#[must_use]
pub fn compute_local_scorecard(
    subject_key: &str,
    now: u64,
    corpus: &LocalReputationCorpus,
    config: &ReputationConfig,
) -> LocalReputationScorecard {
    let capability_map: BTreeMap<&str, &CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .map(|record| (record.capability_id.as_str(), record))
        .collect();

    let subject_receipts: Vec<&ChioReceipt> = corpus
        .receipts
        .iter()
        .filter(|receipt| {
            receipt_subject_key(receipt, &capability_map).as_deref() == Some(subject_key)
        })
        .collect();

    let subject_capabilities: Vec<&CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .filter(|record| record.subject_key == subject_key)
        .collect();

    let delegations_issued: Vec<&CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .filter(|record| record.issuer_key == subject_key && record.parent_capability_id.is_some())
        .collect();

    let boundary_pressure = compute_boundary_pressure(&subject_receipts, now, config);
    let resource_stewardship =
        compute_resource_stewardship(&subject_capabilities, &corpus.budget_usage, config);
    let least_privilege =
        compute_least_privilege(&subject_capabilities, &subject_receipts, now, config);
    let history_depth = compute_history_depth(&subject_receipts, config);
    let specialization = compute_specialization(&subject_receipts, now, config);
    let delegation_hygiene =
        compute_delegation_hygiene(&delegations_issued, &capability_map, now, config);
    let reliability = compute_reliability(&subject_receipts, now, config);
    let incident_correlation = compute_incident_correlation(subject_key, now, corpus, config);

    let mut weighted_sum = 0.0;
    let mut effective_weight_sum = 0.0;

    contribute_metric(
        boundary_pressure
            .deny_ratio
            .as_option()
            .map(|value| 1.0 - value),
        config.weights.boundary_pressure,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        resource_stewardship.fit_score.as_option(),
        config.weights.resource_stewardship,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        least_privilege.score.as_option(),
        config.weights.least_privilege,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        history_depth.score.as_option(),
        config.weights.history_depth,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        specialization
            .score
            .as_option()
            .map(|value| value.min(clamp01(config.diversity_cap))),
        config.weights.tool_diversity,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        delegation_hygiene.score.as_option(),
        config.weights.delegation_hygiene,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        reliability.score.as_option(),
        config.weights.reliability,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        incident_correlation.score.as_option(),
        config.weights.incident_correlation,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );

    let composite_score = if effective_weight_sum > 0.0 {
        MetricValue::known(weighted_sum / effective_weight_sum)
    } else {
        MetricValue::Unknown
    };

    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: now,
        boundary_pressure,
        resource_stewardship,
        least_privilege,
        history_depth,
        specialization,
        delegation_hygiene,
        reliability,
        incident_correlation,
        composite_score,
        effective_weight_sum,
    }
}

fn compute_boundary_pressure(
    receipts: &[&ChioReceipt],
    now: u64,
    config: &ReputationConfig,
) -> BoundaryPressureMetrics {
    if receipts.is_empty() {
        return BoundaryPressureMetrics {
            deny_ratio: MetricValue::Unknown,
            policies_observed: 0,
            receipts_observed: 0,
        };
    }

    let mut by_policy: BTreeMap<&str, (f64, f64)> = BTreeMap::new();
    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        let entry = by_policy
            .entry(receipt.policy_hash.as_str())
            .or_insert((0.0, 0.0));
        if matches!(receipt.decision, Decision::Deny { .. }) {
            entry.0 += weight;
        }
        entry.1 += weight;
    }

    let deny_ratio = by_policy
        .values()
        .map(|(denied, total)| if *total > 0.0 { denied / total } else { 0.0 })
        .sum::<f64>()
        / by_policy.len() as f64;

    BoundaryPressureMetrics {
        deny_ratio: MetricValue::known(deny_ratio),
        policies_observed: by_policy.len(),
        receipts_observed: receipts.len(),
    }
}

fn compute_resource_stewardship(
    capabilities: &[&CapabilityLineageRecord],
    budget_usage: &[BudgetUsageRecord],
    config: &ReputationConfig,
) -> ResourceStewardshipMetrics {
    let usage_index: BTreeMap<(&str, u32), &BudgetUsageRecord> = budget_usage
        .iter()
        .map(|record| ((record.capability_id.as_str(), record.grant_index), record))
        .collect();

    let mut utilizations = Vec::new();

    for capability in capabilities {
        for (grant_index, grant) in capability.scope.grants.iter().enumerate() {
            if let Some(max_invocations) = grant.max_invocations {
                if max_invocations == 0 {
                    continue;
                }
                let actual = usage_index
                    .get(&(capability.capability_id.as_str(), grant_index as u32))
                    .map(|record| record.invocation_count)
                    .unwrap_or(0);
                utilizations.push((actual as f64 / max_invocations as f64).min(1.0));
            }
        }
    }

    if utilizations.is_empty() {
        return ResourceStewardshipMetrics {
            average_utilization: MetricValue::Unknown,
            fit_score: MetricValue::Unknown,
            capped_grants_observed: 0,
        };
    }

    let average_utilization = utilizations.iter().sum::<f64>() / utilizations.len() as f64;
    let fit_score = 1.0 - (average_utilization - clamp01(config.target_utilization)).abs();

    ResourceStewardshipMetrics {
        average_utilization: MetricValue::known(average_utilization),
        fit_score: MetricValue::known(fit_score),
        capped_grants_observed: utilizations.len(),
    }
}

fn compute_least_privilege(
    capabilities: &[&CapabilityLineageRecord],
    receipts: &[&ChioReceipt],
    now: u64,
    config: &ReputationConfig,
) -> LeastPrivilegeMetrics {
    let mut weighted_scores = Vec::new();

    for capability in capabilities {
        let grants = &capability.scope.grants;
        if grants.is_empty() {
            continue;
        }

        let used_tools: BTreeSet<(&str, &str)> = receipts
            .iter()
            .filter(|receipt| {
                receipt.capability_id == capability.capability_id && receipt.is_allowed()
            })
            .map(|receipt| (receipt.tool_server.as_str(), receipt.tool_name.as_str()))
            .collect();

        let base = used_tools.len() as f64 / grants.len() as f64;
        let constrained_ratio = grants
            .iter()
            .filter(|grant| !grant.constraints.is_empty())
            .count() as f64
            / grants.len() as f64;
        let non_delegate_ratio = grants
            .iter()
            .filter(|grant| !grant.operations.contains(&Operation::Delegate))
            .count() as f64
            / grants.len() as f64;

        let constraint_factor = 0.5 + 0.5 * constrained_ratio;
        let operation_factor = 0.5 + 0.5 * non_delegate_ratio;
        let score = clamp01(base * constraint_factor * operation_factor);
        let weight = decay_weight(
            now,
            capability.issued_at,
            config.temporal_decay_half_life_days,
        );
        weighted_scores.push((score, weight));
    }

    if weighted_scores.is_empty() {
        return LeastPrivilegeMetrics {
            score: MetricValue::Unknown,
            capabilities_observed: 0,
        };
    }

    LeastPrivilegeMetrics {
        score: MetricValue::known(weighted_average(&weighted_scores)),
        capabilities_observed: weighted_scores.len(),
    }
}
