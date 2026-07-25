use super::*;

type MarkerRow = (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<bool>,
    Option<bool>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<bool>,
    Option<i64>,
    Option<String>,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
);

impl SqliteBudgetStore {
    pub(crate) fn load_projected_mutation_event(
        transaction: &Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        let Some(event) = Self::load_mutation_event(transaction, event_id)? else {
            return Ok(None);
        };
        project_mutation_event(transaction, event).map(Some)
    }
}

fn project_mutation_event(
    transaction: &Transaction<'_>,
    mut event: BudgetMutationRecord,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let row: MarkerRow = transaction.query_row(
        r#"
        SELECT projection_kind, operation_id, revocation_set_digest,
               expected_quota_count, expected_artifact_count,
               has_cumulative_approval, has_revocation_commit,
               authorization_outcome, invocation_state_before,
               invocation_state_after, monetary_state_before,
               monetary_state_after, cumulative_approval_set_digest,
               supplemental_verifier_id, supplemental_verifier_config_digest,
               supplemental_expires_at, invocation_quotas_explicit,
               trusted_time, expected_cumulative_state,
               EXISTS(SELECT 1 FROM budget_event_revocation_members
                      WHERE event_id = parent.event_id),
               EXISTS(SELECT 1 FROM budget_event_authorization_artifacts
                      WHERE event_id = parent.event_id),
               EXISTS(SELECT 1 FROM budget_event_quota_members
                      WHERE event_id = parent.event_id),
               EXISTS(SELECT 1 FROM budget_event_cumulative_approval
                      WHERE event_id = parent.event_id),
               EXISTS(SELECT 1 FROM budget_event_revocation_commits
                      WHERE event_id = parent.event_id),
               supplemental_artifact_digest IS NOT NULL
        FROM budget_mutation_events AS parent WHERE event_id = ?1
        "#,
        params![&event.event_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
                row.get(15)?,
                row.get(16)?,
                row.get(17)?,
                row.get(18)?,
                row.get(19)?,
                row.get(20)?,
                row.get(21)?,
                row.get(22)?,
                row.get(23)?,
                row.get(24)?,
            ))
        },
    )?;

    if row.0 == "legacy" {
        let has_structured_metadata = row.1.is_some()
            || row.2.is_some()
            || row.3.is_some()
            || row.4.is_some()
            || row.5.is_some()
            || row.6.is_some()
            || row.12.is_some()
            || row.13.is_some()
            || row.14.is_some()
            || row.15.is_some()
            || row.16.is_some()
            || row.17.is_some()
            || row.18.is_some()
            || row.19
            || row.20
            || row.21
            || row.22
            || row.23
            || row.24;
        if has_structured_metadata {
            return Err(BudgetStoreError::Invariant(format!(
                "legacy budget event `{}` contains composite projection state",
                event.event_id
            )));
        }
        validate_legacy_event_lifecycle(&event)?;
        return Ok(event);
    }
    if row.0 != "composite_v1" {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{}` has unknown projection discriminator `{}`",
            event.event_id, row.0
        )));
    }

    let contract = load_event_projection_contract(transaction, &event.event_id)?;
    event.admission_binding = Some(load_event_admission(transaction, &event.event_id)?);
    event.authorization_outcome = row
        .7
        .as_deref()
        .map(budget_authorization_outcome)
        .transpose()?;
    let valid_outcome = match event.kind {
        BudgetMutationKind::ReserveInvocation | BudgetMutationKind::AuthorizeExposure => {
            event.authorization_outcome.is_some()
        }
        BudgetMutationKind::AuthorizeCumulativeApproval => {
            event.authorization_outcome == Some(BudgetAuthorizationOutcome::Authorized)
        }
        BudgetMutationKind::CaptureInvocation
        | BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::ReleaseExposure
        | BudgetMutationKind::ReconcileSpend
        | BudgetMutationKind::CaptureSpend => event.authorization_outcome.is_none(),
        _ => false,
    };
    if !valid_outcome {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget event `{}` has an invalid authorization outcome",
            event.event_id
        )));
    }
    event.invocation_state_before = required_invocation_state(&event.event_id, row.8.as_deref())?;
    event.invocation_state_after = required_invocation_state(&event.event_id, row.9.as_deref())?;
    event.monetary_state_before = required_monetary_state(&event.event_id, row.10.as_deref())?;
    event.monetary_state_after = required_monetary_state(&event.event_id, row.11.as_deref())?;
    event.cumulative_approval_set_digest = row.12;

    let (quota_usages, quota_mutations) = load_quota_projection(
        transaction,
        &event.event_id,
        contract.expected_quota_count,
        event.authorization_outcome == Some(BudgetAuthorizationOutcome::Denied),
    )?;
    event.invocation_quota_usages = quota_usages;
    let reports_reservation_mutation = matches!(
        event.kind,
        BudgetMutationKind::ReserveInvocation
            | BudgetMutationKind::AuthorizeExposure
            | BudgetMutationKind::CaptureInvocation
            | BudgetMutationKind::ReverseInvocation
            | BudgetMutationKind::ReverseExposure
            | BudgetMutationKind::AuthorizeCumulativeApproval
    );
    if reports_reservation_mutation {
        event.invocation_quota_mutations = quota_mutations;
    }

    let cumulative = load_cumulative_projection(transaction, &event.event_id)?;
    if contract.has_cumulative_approval != cumulative.is_some() {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget event `{}` lost cumulative approval projection",
            event.event_id
        )));
    }
    if event.authorization_outcome != Some(BudgetAuthorizationOutcome::Denied) {
        if let Some((usage, mutation)) = cumulative {
            event.cumulative_approval = Some(usage);
            if reports_reservation_mutation {
                event.cumulative_approval_mutation = Some(mutation);
            }
        }
    }
    let admission = event.admission_binding.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget event `{}` lost admission binding",
            event.event_id
        ))
    })?;
    let cumulative_request = load_event_cumulative_request(transaction, &event.event_id)?;
    validate_stored_composite_binding(
        &event.capability_id,
        usize::try_from(event.grant_index)
            .map_err(|_| BudgetStoreError::Invariant("invalid event grant_index".to_string()))?,
        event.hold_id.as_deref().unwrap_or(""),
        &event.event_id,
        admission,
        &event
            .invocation_quota_usages
            .iter()
            .map(|usage| usage.quota.clone())
            .collect::<Vec<_>>(),
        cumulative_request.as_ref(),
    )?;
    Ok(event)
}

fn required_invocation_state(
    event_id: &str,
    value: Option<&str>,
) -> Result<BudgetInvocationState, BudgetStoreError> {
    budget_invocation_state(value.ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget event `{event_id}` lost invocation state"
        ))
    })?)
}

fn required_monetary_state(
    event_id: &str,
    value: Option<&str>,
) -> Result<BudgetMonetaryState, BudgetStoreError> {
    budget_monetary_state(value.ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget event `{event_id}` lost monetary state"
        ))
    })?)
}

fn load_quota_projection(
    transaction: &Transaction<'_>,
    event_id: &str,
    expected_count: usize,
    allow_zero_maximum: bool,
) -> Result<
    (
        Vec<BudgetInvocationQuotaUsage>,
        Vec<BudgetInvocationQuotaMutation>,
    ),
    BudgetStoreError,
> {
    let mut statement = transaction.prepare(
        r#"
        SELECT profile, owner_id, grant_index, max_invocations,
               reserved_before, captured_before, reserved_after, captured_after
        FROM budget_event_quota_members WHERE event_id = ?1
        ORDER BY CASE profile
            WHEN 'chio.grant-invocation.v1' THEN 0
            WHEN 'chio.aggregate-capability-invocation.v1' THEN 1
            WHEN 'chio.aggregate-family-invocation.v1' THEN 2
            WHEN 'chio.broker-capability-execution.v1' THEN 3
            ELSE 99 END,
            owner_id, grant_index
        "#,
    )?;
    let rows = statement.query_map(params![event_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
        ))
    })?;
    let mut usages = Vec::new();
    let mut mutations = Vec::new();
    for row in rows {
        let row = row?;
        let maximum = u32::try_from(row.3)
            .map_err(|_| BudgetStoreError::Invariant("invalid quota maximum".to_string()))?;
        let quota = BudgetInvocationQuota {
            key: quota_key(&row.0, row.1, row.2)?,
            max_invocations: maximum,
        };
        let counts = [row.4, row.5, row.6, row.7]
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    BudgetStoreError::Invariant("invalid quota projection count".to_string())
                })
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        if (!allow_zero_maximum && maximum == 0)
            || counts[0]
                .checked_add(counts[1])
                .is_none_or(|sum| sum > maximum)
            || counts[2]
                .checked_add(counts[3])
                .is_none_or(|sum| sum > maximum)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget event `{event_id}` contains invalid quota bounds"
            )));
        }
        usages.push(BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations: counts[2],
            captured_invocations: counts[3],
        });
        mutations.push(BudgetInvocationQuotaMutation {
            quota,
            reserved_invocations_before: counts[0],
            captured_invocations_before: counts[1],
            reserved_invocations_after: counts[2],
            captured_invocations_after: counts[3],
        });
    }
    require_expected_count(event_id, "quota", expected_count, usages.len())?;
    Ok((usages, mutations))
}

fn load_cumulative_projection(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<
    Option<(
        BudgetCumulativeApprovalUsage,
        BudgetCumulativeApprovalMutation,
    )>,
    BudgetStoreError,
> {
    let Some(request) = load_event_cumulative_request(transaction, event_id)? else {
        return Ok(None);
    };
    type StateRow = (Option<String>, String, i64, i64, i64, i64, i64, i64);
    let row: StateRow = transaction.query_row(
        r#"
        SELECT state_before, state_after,
               reserved_authorized_before, captured_authorized_before,
               reserved_authorized_after, captured_authorized_after,
               version_before, version_after
        FROM budget_event_cumulative_approval WHERE event_id = ?1
        "#,
        params![event_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let state_before = row.0.as_deref().map(cumulative_state).transpose()?;
    let state_after = cumulative_state(&row.1)?;
    let values = [row.2, row.3, row.4, row.5, row.6, row.7]
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                BudgetStoreError::Invariant("negative cumulative approval projection".to_string())
            })
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let currency = request.account_key.currency.clone();
    let account_key = request.account_key.clone();
    let amount = |units| MonetaryAmount {
        units,
        currency: currency.clone(),
    };
    Ok(Some((
        BudgetCumulativeApprovalUsage {
            operation_id: request.operation_id.clone(),
            account_key: request.account_key.clone(),
            authority_threshold: request.authority_threshold.clone(),
            effective_threshold: request.effective_threshold.clone(),
            requested_authorized: request.requested_authorized.clone(),
            reserved_authorized_after: amount(values[2]),
            captured_authorized_after: amount(values[3]),
            state: state_after,
            version: values[5],
        },
        BudgetCumulativeApprovalMutation {
            operation_id: request.operation_id,
            account_key,
            state_before,
            state_after,
            reserved_authorized_before: amount(values[0]),
            captured_authorized_before: amount(values[1]),
            reserved_authorized_after: amount(values[2]),
            captured_authorized_after: amount(values[3]),
            version_before: values[4],
            version_after: values[5],
        },
    )))
}
