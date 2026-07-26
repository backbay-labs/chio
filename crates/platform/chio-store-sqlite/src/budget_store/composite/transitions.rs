use super::*;
use rusqlite::{params, OptionalExtension, Transaction};

mod approval;
mod capture;
pub(crate) use capture::AdmissionCaptureBinding;
mod terminal;

struct CumulativeSnapshot<'a> {
    request: &'a BudgetCumulativeApprovalRequest,
    state: BudgetCumulativeApprovalState,
    account: &'a CumulativeAccount,
}

type LoadedCumulativeSnapshot = (
    BudgetCumulativeApprovalRequest,
    BudgetCumulativeApprovalState,
    CumulativeAccount,
    Option<String>,
);

pub(super) fn cumulative_state_text(state: BudgetCumulativeApprovalState) -> &'static str {
    match state {
        BudgetCumulativeApprovalState::PendingApproval => "pending_approval",
        BudgetCumulativeApprovalState::Authorized => "authorized",
        BudgetCumulativeApprovalState::Captured => "captured",
        BudgetCumulativeApprovalState::ReversedBeforeDispatch => "reversed_before_dispatch",
    }
}

pub(super) fn cumulative_state(
    value: &str,
) -> Result<BudgetCumulativeApprovalState, BudgetStoreError> {
    match value {
        "pending_approval" => Ok(BudgetCumulativeApprovalState::PendingApproval),
        "authorized" => Ok(BudgetCumulativeApprovalState::Authorized),
        "captured" => Ok(BudgetCumulativeApprovalState::Captured),
        "reversed_before_dispatch" => Ok(BudgetCumulativeApprovalState::ReversedBeforeDispatch),
        _ => Err(BudgetStoreError::Invariant(format!(
            "unknown cumulative approval state `{value}`"
        ))),
    }
}

pub(super) fn captured_authorization_decision(
    store: &SqliteBudgetStore,
    transaction: &Transaction<'_>,
    hold: &StructuredHold,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let event_id = transaction
        .query_row(
            r#"
            SELECT event_id FROM budget_mutation_events
            WHERE hold_id = ?1 AND kind = ?2
            ORDER BY event_seq DESC LIMIT 1
            "#,
            params![
                &hold.hold_id,
                BudgetMutationKind::CaptureInvocation.as_str()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "captured budget hold `{}` lost its capture event",
                hold.hold_id
            ))
        })?;
    let event =
        SqliteBudgetStore::load_mutation_event(transaction, &event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("captured budget event `{event_id}` disappeared"))
        })?;
    Ok(BudgetAuthorizeHoldDecision::AlreadyCaptured(
        transition_decision_from_event(store, transaction, event)?,
    ))
}

impl SqliteBudgetStore {
    pub(crate) fn is_structured_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let marker = transaction
            .query_row(
                r#"
            SELECT projection_kind, operation_id, revocation_set_digest,
                   expected_quota_count, expected_artifact_count,
                   has_cumulative_approval, has_revocation_commit,
                   expected_revocation_count, trusted_capture_time,
                   EXISTS(SELECT 1 FROM budget_hold_revocation_members
                          WHERE hold_id = parent.hold_id),
                   EXISTS(SELECT 1 FROM budget_hold_quota_members
                          WHERE hold_id = parent.hold_id),
                   EXISTS(SELECT 1 FROM budget_hold_authorization_artifacts
                          WHERE hold_id = parent.hold_id),
                   EXISTS(SELECT 1 FROM budget_cumulative_approval_operations
                          WHERE hold_id = parent.hold_id),
                   EXISTS(SELECT 1 FROM budget_hold_revocation_commits
                          WHERE hold_id = parent.hold_id)
            FROM budget_authorization_holds AS parent WHERE hold_id = ?1
            "#,
                params![hold_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<bool>>(5)?,
                        row.get::<_, Option<bool>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, bool>(9)?,
                        row.get::<_, bool>(10)?,
                        row.get::<_, bool>(11)?,
                        row.get::<_, bool>(12)?,
                        row.get::<_, bool>(13)?,
                    ))
                },
            )
            .optional()?;
        let structured = match marker {
            None => false,
            Some(marker) if marker.0 == "composite_v1" => {
                if load_structured_hold(&transaction, hold_id)?.is_none() {
                    return Err(BudgetStoreError::Invariant(format!(
                        "composite budget hold `{hold_id}` lost its durable projection"
                    )));
                }
                true
            }
            Some(marker)
                if marker.0 == "legacy"
                    && marker.1.is_none()
                    && marker.2.is_none()
                    && marker.3.is_none()
                    && marker.4.is_none()
                    && marker.5.is_none()
                    && marker.6.is_none()
                    && marker.7.is_none()
                    && marker.8.is_none()
                    && !marker.9
                    && !marker.10
                    && !marker.11
                    && !marker.12
                    && !marker.13 =>
            {
                false
            }
            Some(_) => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` has an inconsistent projection discriminator"
                )));
            }
        };
        transaction.rollback()?;
        Ok(structured)
    }
}

fn load_event_strings(
    transaction: &Transaction<'_>,
    sql: &str,
    event_id: &str,
) -> Result<Vec<String>, BudgetStoreError> {
    let mut statement = transaction.prepare(sql)?;
    let values = statement
        .query_map(params![event_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(values)
}

pub(super) fn load_event_admission(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<BudgetAdmissionBinding, BudgetStoreError> {
    let contract = load_event_projection_contract(transaction, event_id)?;
    let row = transaction.query_row(
        r#"
        SELECT supplemental_verifier_id, supplemental_verifier_config_digest,
               supplemental_artifact_digest, supplemental_expires_at
        FROM budget_mutation_events WHERE event_id = ?1
        "#,
        params![event_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    let revocation_ids = load_event_strings(
        transaction,
        r#"
        SELECT capability_id FROM budget_event_revocation_members
        WHERE event_id = ?1 ORDER BY member_index
        "#,
        event_id,
    )?;
    require_expected_count(
        event_id,
        "revocation",
        contract.expected_revocation_count,
        revocation_ids.len(),
    )?;
    let revocation_set = CanonicalRevocationSet::from_canonical_parts(
        revocation_ids,
        contract.revocation_set_digest,
    )
    .map_err(|error| {
        BudgetStoreError::Invariant(format!("stored revocation set is invalid: {error}"))
    })?;
    let authorization_artifact_digests = load_event_strings(
        transaction,
        r#"
        SELECT artifact_digest FROM budget_event_authorization_artifacts
        WHERE event_id = ?1 ORDER BY artifact_index
        "#,
        event_id,
    )?;
    require_expected_count(
        event_id,
        "authorization artifact",
        contract.expected_artifact_count,
        authorization_artifact_digests.len(),
    )?;
    let revocation_commit = load_event_revocation_commit(transaction, event_id)?;
    if contract.has_revocation_commit != revocation_commit.is_some() {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget event `{event_id}` lost revocation commit projection"
        )));
    }
    let admission = BudgetAdmissionBinding {
        operation_id: contract.operation_id,
        revocation_set,
        authorization_artifact_digests,
        last_observed_revocation: revocation_commit,
        supplemental_verifier_id: row.0,
        supplemental_verifier_config_digest: row.1,
        supplemental_authorization_artifact_digest: row.2,
        supplemental_authorization_expires_at: row
            .3
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    BudgetStoreError::Invariant("negative supplemental expiration".to_string())
                })
            })
            .transpose()?,
    };
    admission.validate()?;
    Ok(admission)
}

#[allow(clippy::too_many_arguments)]
fn write_transition_projection(
    transaction: &Transaction<'_>,
    event_id: &str,
    hold: &StructuredHold,
    authorization_outcome: Option<BudgetAuthorizationOutcome>,
    invocation_before: BudgetInvocationState,
    invocation_after: BudgetInvocationState,
    monetary_before: BudgetMonetaryState,
    monetary_after: BudgetMonetaryState,
    quota_before: &[QuotaState],
    quota_after: &[QuotaState],
    cumulative_before: Option<CumulativeSnapshot<'_>>,
    cumulative_after: Option<CumulativeSnapshot<'_>>,
    approval_set_digest: Option<&str>,
    trusted_time: Option<u64>,
    expected_cumulative_state: Option<BudgetCumulativeApprovalState>,
) -> Result<(), BudgetStoreError> {
    let admission = &hold.admission;
    if quota_before.len() != quota_after.len() {
        return Err(BudgetStoreError::Invariant(
            "budget transition quota snapshots have different lengths".to_string(),
        ));
    }
    if cumulative_before.is_some() != cumulative_after.is_some() {
        return Err(BudgetStoreError::Invariant(
            "budget transition cumulative projection changed participation".to_string(),
        ));
    }
    transaction.execute(
        r#"
        UPDATE budget_mutation_events
        SET projection_kind = 'composite_v1',
            operation_id = ?2,
            revocation_set_digest = ?3,
            expected_quota_count = ?4,
            expected_artifact_count = ?5,
            has_cumulative_approval = ?6,
            has_revocation_commit = ?7,
            authorization_outcome = ?8,
            invocation_state_before = ?9,
            invocation_state_after = ?10,
            monetary_state_before = ?11,
            monetary_state_after = ?12,
            cumulative_approval_set_digest = ?13,
            supplemental_verifier_id = ?14,
            supplemental_verifier_config_digest = ?15,
            supplemental_artifact_digest = ?16,
            supplemental_expires_at = ?17,
            trusted_time = ?18,
            expected_cumulative_state = ?19,
            expected_revocation_count = ?20
        WHERE event_id = ?1
        "#,
        params![
            event_id,
            &admission.operation_id,
            admission.revocation_set.digest(),
            i64::try_from(quota_before.len()).map_err(|_| {
                BudgetStoreError::Invariant("quota count exceeds sqlite range".to_string())
            })?,
            i64::try_from(admission.authorization_artifact_digests.len()).map_err(|_| {
                BudgetStoreError::Invariant("artifact count exceeds sqlite range".to_string())
            })?,
            cumulative_before.is_some(),
            admission.last_observed_revocation.is_some(),
            authorization_outcome.map(budget_authorization_outcome_text),
            budget_invocation_state_text(invocation_before),
            budget_invocation_state_text(invocation_after),
            budget_monetary_state_text(monetary_before),
            budget_monetary_state_text(monetary_after),
            approval_set_digest,
            admission.supplemental_verifier_id.as_deref(),
            admission.supplemental_verifier_config_digest.as_deref(),
            admission
                .supplemental_authorization_artifact_digest
                .as_deref(),
            optional_budget_u64_to_sqlite(
                admission.supplemental_authorization_expires_at,
                "supplemental_expires_at",
            )?,
            optional_budget_u64_to_sqlite(trusted_time, "trusted_time")?,
            expected_cumulative_state.map(cumulative_state_text),
            i64::try_from(admission.revocation_set.ids().len()).map_err(|_| {
                BudgetStoreError::Invariant("revocation count exceeds sqlite range".to_string())
            })?,
        ],
    )?;
    for (index, capability_id) in admission.revocation_set.ids().iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_event_revocation_members (
                event_id, member_index, capability_id
            ) VALUES (?1, ?2, ?3)
            "#,
            params![event_id, index as i64, capability_id],
        )?;
    }
    for (index, digest) in admission.authorization_artifact_digests.iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_event_authorization_artifacts (
                event_id, artifact_index, artifact_digest
            ) VALUES (?1, ?2, ?3)
            "#,
            params![event_id, index as i64, digest],
        )?;
    }
    write_event_revocation_commit(
        transaction,
        event_id,
        admission.last_observed_revocation.as_ref(),
    )?;
    for (before, after) in quota_before.iter().zip(quota_after) {
        if before.quota != after.quota {
            return Err(BudgetStoreError::Invariant(
                "budget transition quota snapshot identity changed".to_string(),
            ));
        }
        transaction.execute(
            r#"
            INSERT INTO budget_event_quota_members (
                event_id, profile, owner_id, grant_index, max_invocations,
                reserved_before, captured_before, reserved_after, captured_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                event_id,
                before.quota.key.profile.as_str(),
                &before.quota.key.owner_id,
                quota_index(&before.quota.key)?,
                i64::from(before.maximum),
                i64::from(before.reserved),
                i64::from(before.captured),
                i64::from(after.reserved),
                i64::from(after.captured),
            ],
        )?;
    }
    match (cumulative_before, cumulative_after) {
        (None, None) => {}
        (Some(before), Some(after)) if before.request == after.request => {
            transaction.execute(
                r#"
                INSERT INTO budget_event_cumulative_approval (
                    event_id, operation_id, authority_id, owner_id,
                    approval_budget_id, approval_budget_epoch, root_grant_hash,
                    delegation_root_id, root_binding_digest, currency,
                    authority_threshold_units, effective_threshold_units,
                    requested_authorized_units, state_before, state_after,
                    reserved_authorized_before, captured_authorized_before,
                    reserved_authorized_after, captured_authorized_after,
                    version_before, version_after
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                )
                "#,
                params![
                    event_id,
                    &before.request.operation_id,
                    &before.request.account_key.authority_id,
                    &before.request.account_key.owner_id,
                    &before.request.account_key.approval_budget_id,
                    budget_u64_to_sqlite(
                        before.request.account_key.approval_budget_epoch,
                        "approval_budget_epoch",
                    )?,
                    &before.request.account_key.root_grant_hash,
                    before.request.account_key.delegation_root_id.as_deref(),
                    before.request.account_key.root_binding_digest.as_deref(),
                    &before.request.account_key.currency,
                    budget_u64_to_sqlite(
                        before.request.authority_threshold.units,
                        "authority_threshold_units",
                    )?,
                    budget_u64_to_sqlite(
                        before.request.effective_threshold.units,
                        "effective_threshold_units",
                    )?,
                    budget_u64_to_sqlite(
                        before.request.requested_authorized.units,
                        "requested_authorized_units",
                    )?,
                    cumulative_state_text(before.state),
                    cumulative_state_text(after.state),
                    budget_u64_to_sqlite(before.account.reserved, "reserved_authorized_before",)?,
                    budget_u64_to_sqlite(before.account.captured, "captured_authorized_before",)?,
                    budget_u64_to_sqlite(after.account.reserved, "reserved_authorized_after",)?,
                    budget_u64_to_sqlite(after.account.captured, "captured_authorized_after",)?,
                    budget_u64_to_sqlite(before.account.version, "version_before")?,
                    budget_u64_to_sqlite(after.account.version, "version_after")?,
                ],
            )?;
        }
        _ => {
            return Err(BudgetStoreError::Invariant(
                "budget transition cumulative snapshot identity changed".to_string(),
            ));
        }
    }
    Ok(())
}

fn transition_decision_from_event(
    store: &SqliteBudgetStore,
    transaction: &Transaction<'_>,
    event: BudgetMutationRecord,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let contract = load_event_projection_contract(transaction, &event.event_id)?;
    let row = transaction.query_row(
        r#"
        SELECT invocation_state_after, monetary_state_after
        FROM budget_mutation_events WHERE event_id = ?1
        "#,
        params![&event.event_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        },
    )?;
    let cumulative_request = load_event_cumulative_request(transaction, &event.event_id)?;
    let cumulative_state = load_event_cumulative_state(transaction, &event.event_id)?;
    let cumulative_after = load_event_cumulative_after(transaction, &event.event_id)?;
    let cumulative_complete =
        cumulative_request.is_some() && cumulative_state.is_some() && cumulative_after.is_some();
    let cumulative_absent =
        cumulative_request.is_none() && cumulative_state.is_none() && cumulative_after.is_none();
    if (contract.has_cumulative_approval && !cumulative_complete)
        || (!contract.has_cumulative_approval && !cumulative_absent)
    {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget event `{}` lost cumulative approval projection",
            event.event_id
        )));
    }
    let quota_after = load_event_quota_after(transaction, &event.event_id)?;
    require_expected_count(
        &event.event_id,
        "quota",
        contract.expected_quota_count,
        quota_after.len(),
    )?;
    let admission = load_event_admission(transaction, &event.event_id)?;
    validate_stored_composite_binding(
        &event.capability_id,
        usize::try_from(event.grant_index)
            .map_err(|_| BudgetStoreError::Invariant("invalid event grant_index".to_string()))?,
        event.hold_id.as_deref().unwrap_or(""),
        &event.event_id,
        &admission,
        &quota_after
            .iter()
            .map(|state| state.quota.clone())
            .collect::<Vec<_>>(),
        cumulative_request.as_ref(),
    )?;
    let cumulative_approval = cumulative_request
        .zip(cumulative_state)
        .zip(cumulative_after)
        .map(|((request, state), account)| cumulative_usage(&request, state, &account));
    let invocation_state = budget_invocation_state(row.0.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget event `{}` lost invocation state",
            event.event_id
        ))
    })?)?;
    let monetary_state = budget_monetary_state(row.1.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "composite budget event `{}` lost monetary state",
            event.event_id
        ))
    })?)?;
    Ok(BudgetHoldMutationDecision {
        hold_id: event.hold_id,
        admission_binding: Some(admission),
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?,
        invocation_count_after: event.invocation_count_after,
        invocation_quota_usages: quota_after.iter().map(QuotaState::usage).collect(),
        cumulative_approval,
        invocation_state,
        monetary_state,
        metadata: BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: Some(event.event_seq),
            event_id: Some(event.event_id),
            recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
        },
    })
}

fn load_quota_states(
    transaction: &Transaction<'_>,
    hold: &StructuredHold,
) -> Result<Vec<QuotaState>, BudgetStoreError> {
    hold.quotas
        .iter()
        .map(|quota| {
            let state = load_quota_state(transaction, &quota.key)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget hold `{}` lost quota `{}`",
                    hold.hold_id, quota.key.owner_id
                ))
            })?;
            if state.maximum != quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` quota maximum changed",
                    hold.hold_id
                )));
            }
            Ok(state)
        })
        .collect()
}

fn load_cumulative_snapshot(
    transaction: &Transaction<'_>,
    hold: &StructuredHold,
) -> Result<Option<LoadedCumulativeSnapshot>, BudgetStoreError> {
    hold.cumulative
        .as_ref()
        .map(|(request, state, digest)| {
            Ok((
                request.clone(),
                *state,
                load_or_validate_cumulative(transaction, request)?,
                digest.clone(),
            ))
        })
        .transpose()
}

fn validate_transition_identity(
    store: &SqliteBudgetStore,
    transaction: &Transaction<'_>,
    hold: &StructuredHold,
    capability_id: &str,
    grant_index: usize,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    if hold.capability_id != capability_id || hold.grant_index != grant_index {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{}` changed capability identity",
            hold.hold_id
        )));
    }
    store.validate_persisted_authority(
        transaction,
        &hold.hold_id,
        hold.authority.as_ref(),
        authority,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replay_transition(
    store: &SqliteBudgetStore,
    transaction: &Transaction<'_>,
    event_id: &str,
    kind: BudgetMutationKind,
    hold_id: &str,
    capability_id: &str,
    grant_index: usize,
    exposure_units: Option<u64>,
    realized_spend_units: Option<u64>,
    authority: Option<&BudgetEventAuthority>,
    trusted_time: Option<u64>,
    expected_cumulative_state: Option<BudgetCumulativeApprovalState>,
) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
    let Some(event) = SqliteBudgetStore::load_mutation_event(transaction, event_id)? else {
        return Ok(None);
    };
    let extras = transaction.query_row(
        r#"
        SELECT trusted_time, expected_cumulative_state
        FROM budget_mutation_events WHERE event_id = ?1
        "#,
        params![event_id],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        },
    )?;
    let stored_trusted_time = extras
        .0
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| BudgetStoreError::Invariant("negative trusted time".to_string()))
        })
        .transpose()?;
    let stored_expected = extras.1.map(|value| cumulative_state(&value)).transpose()?;
    store.validate_persisted_authority(
        transaction,
        event_id,
        event.authority.as_ref(),
        authority,
    )?;
    if event.kind != kind
        || event.hold_id.as_deref() != Some(hold_id)
        || event.capability_id != capability_id
        || usize::try_from(event.grant_index).ok() != Some(grant_index)
        || exposure_units.is_some_and(|value| event.exposure_units != value)
        || realized_spend_units.is_some_and(|value| event.realized_spend_units != value)
        || (kind != BudgetMutationKind::CaptureInvocation || store.serving_owner.is_none())
            && stored_trusted_time != trusted_time
        || kind == BudgetMutationKind::CaptureInvocation
            && store.serving_owner.is_some()
            && stored_trusted_time.is_none()
        || stored_expected != expected_cumulative_state
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` was reused for a different mutation"
        )));
    }
    if latest_hold_event_seq(transaction, hold_id)? != Some(event.event_seq) {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` transition event was superseded"
        )));
    }
    transition_decision_from_event(store, transaction, event).map(Some)
}
