use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationStoreError, AdmissionOperationV1, AdmissionRecoveryLease,
};

pub(crate) struct AdmissionCaptureBinding<'a> {
    pub(crate) operation: &'a AdmissionOperationV1,
    pub(crate) recovery_lease: &'a AdmissionRecoveryLease,
    pub(crate) trusted_now_unix_ms: u64,
}

impl SqliteBudgetStore {
    pub(crate) fn capture_composite_invocation(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.capture_composite_invocation_inner(request, None)
            .map(|(decision, _)| decision)
    }

    pub(crate) fn capture_composite_invocation_and_commit_dispatch(
        &self,
        request: BudgetCaptureInvocationRequest,
        binding: AdmissionCaptureBinding<'_>,
    ) -> Result<(BudgetInvocationCaptureDecision, AdmissionOperationV1), BudgetStoreError> {
        let (decision, operation) =
            self.capture_composite_invocation_inner(request, Some(binding))?;
        let operation = operation.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "combined budget capture omitted its admission operation".to_owned(),
            )
        })?;
        Ok((decision, operation))
    }

    fn capture_composite_invocation_inner(
        &self,
        request: BudgetCaptureInvocationRequest,
        admission: Option<AdmissionCaptureBinding<'_>>,
    ) -> Result<
        (
            BudgetInvocationCaptureDecision,
            Option<AdmissionOperationV1>,
        ),
        BudgetStoreError,
    > {
        request.validate()?;
        validate_budget_grant_index(request.grant_index)?;
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        optional_budget_u64_to_sqlite(request.trusted_time, "trusted_time")?;
        if self.serving_owner.is_some() && request.trusted_time.is_some() {
            return Err(BudgetStoreError::Invariant(
                "joint budget callers cannot supply trusted capture time".to_string(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            &request.event_id,
            BudgetMutationKind::CaptureInvocation,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
            None,
            Some(0),
            request.authority.as_ref(),
            request.trusted_time,
            None,
        )? {
            let decision = BudgetInvocationCaptureDecision::AlreadyCaptured(decision);
            let operation = match admission {
                Some(binding) => {
                    let participant_digest = budget_projection_digest(
                        &transaction,
                        &request.event_id,
                        capture_commit_index(&decision)?,
                    )?;
                    Some(
                        crate::admission_operation_store::advance_budget_capture_tx(
                            &transaction,
                            self.serving_owner.as_deref().ok_or_else(|| {
                                BudgetStoreError::Invariant(
                                    "combined admission capture requires a serving owner"
                                        .to_owned(),
                                )
                            })?,
                            binding.operation,
                            binding.recovery_lease,
                            &participant_digest,
                            binding.trusted_now_unix_ms,
                        )
                        .map_err(|error| map_admission_error(self, error))?,
                    )
                }
                None => None,
            };
            if operation.is_some() {
                self.commit_joint_transaction(transaction)?;
                self.sync_joint_anchor(&connection)?;
            } else {
                transaction.rollback()?;
            }
            return Ok((decision, operation));
        }

        let hold = load_structured_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "unknown composite budget hold `{}`",
                request.hold_id
            ))
        })?;
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        let trusted_time = if self.serving_owner.is_some() {
            let value =
                transaction.query_row("SELECT unixepoch()", [], |row| row.get::<_, i64>(0))?;
            Some(u64::try_from(value).map_err(|_| {
                BudgetStoreError::Invariant("negative sqlite authority time".to_string())
            })?)
        } else {
            request.trusted_time
        };
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation reservations are not capturable",
                request.hold_id
            )));
        }
        if hold.authorized_exposure > 0
            && (hold.monetary_state != BudgetMonetaryState::Exposed || hold.remaining_exposure == 0)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no live monetary exposure",
                request.hold_id
            )));
        }
        if let Some(expires_at) = hold.admission.supplemental_authorization_expires_at {
            let trusted_time = trusted_time.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "supplemental invocation capture requires trusted time".to_string(),
                )
            })?;
            if expires_at > MAX_SUPPLEMENTAL_AUTHORIZATION_EXPIRES_AT_SECONDS {
                return Err(BudgetStoreError::Invariant(
                    "supplemental authorization expiry is not expressed in seconds".to_string(),
                ));
            }
            if trusted_time >= expires_at {
                return Err(BudgetStoreError::Invariant(
                    "supplemental authorization expired before invocation capture".to_string(),
                ));
            }
        }

        let quota_before = load_quota_states(&transaction, &hold)?;
        let mut quota_after = quota_before.clone();
        for state in &mut quota_after {
            if state.reserved == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` has an incomplete quota reservation",
                    request.hold_id
                )));
            }
            state.reserved -= 1;
            state.captured = state.captured.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation quota overflowed u32".to_string())
            })?;
            state.version = state.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation quota version overflowed u64".to_string())
            })?;
        }

        let cumulative_before = load_cumulative_snapshot(&transaction, &hold)?;
        let cumulative_after = cumulative_before
            .as_ref()
            .map(|(cumulative, state, account, digest)| {
                if *state != BudgetCumulativeApprovalState::Authorized {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{}` still requires cumulative approval",
                        request.hold_id
                    )));
                }
                if account.reserved < cumulative.requested_authorized.units {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval reservation is incomplete".to_string(),
                    ));
                }
                let mut account = account.clone();
                account.reserved -= cumulative.requested_authorized.units;
                account.captured = account
                    .captured
                    .checked_add(cumulative.requested_authorized.units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "captured cumulative approval overflowed u64".to_string(),
                        )
                    })?;
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                Ok::<_, BudgetStoreError>((
                    cumulative.clone(),
                    BudgetCumulativeApprovalState::Captured,
                    account,
                    digest.clone(),
                ))
            })
            .transpose()?;

        let usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        for state in &quota_after {
            write_quota_state(&transaction, state)?;
        }
        if let Some((cumulative, state, account, _)) = cumulative_after.as_ref() {
            write_cumulative_account(&transaction, account)?;
            let changed = transaction.execute(
                r#"
                UPDATE budget_cumulative_approval_operations
                SET state = ?2, account_version = ?3
                WHERE operation_id = ?1 AND hold_id = ?4 AND state = ?5
                "#,
                params![
                    &cumulative.operation_id,
                    cumulative_state_text(*state),
                    budget_u64_to_sqlite(account.version, "cumulative_account_version")?,
                    &request.hold_id,
                    cumulative_state_text(BudgetCumulativeApprovalState::Authorized),
                ],
            )?;
            if changed != 1 {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval capture compare-and-set failed".to_string(),
                ));
            }
        }
        let next_authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET invocation_captured = 1,
                invocation_state = 'captured',
                authorization_outcome = 'authorized',
                authority_id = ?2, lease_id = ?3, lease_epoch = ?4,
                trusted_capture_time = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'authorized'
            "#,
            params![
                &request.hold_id,
                next_authority.map(|value| value.authority_id.as_str()),
                next_authority.map(|value| value.lease_id.as_str()),
                next_authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                optional_budget_u64_to_sqlite(trusted_time, "trusted_capture_time")?,
                unix_now(),
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget invocation capture compare-and-set failed".to_string(),
            ));
        }
        let event = SqliteBudgetStore::append_mutation_event(
            &transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureInvocation,
            Some(true),
            event_seq,
            Some(usage.seq),
            hold.remaining_exposure,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            &transaction,
            &event.event_id,
            &hold,
            None,
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Captured,
            hold.monetary_state,
            hold.monetary_state,
            &quota_before,
            &quota_after,
            cumulative_before
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative_after
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                }),
            cumulative_after
                .as_ref()
                .and_then(|(_, _, _, digest)| digest.as_deref()),
            trusted_time,
            None,
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::CaptureInvocation,
            &request.event_id,
            event_seq,
        )?;
        let operation = match admission {
            Some(binding) => {
                let participant_digest =
                    budget_projection_digest(&transaction, &request.event_id, event_seq)?;
                Some(
                    crate::admission_operation_store::advance_budget_capture_tx(
                        &transaction,
                        self.serving_owner.as_deref().ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "combined admission capture requires a serving owner".to_owned(),
                            )
                        })?,
                        binding.operation,
                        binding.recovery_lease,
                        &participant_digest,
                        binding.trusted_now_unix_ms,
                    )
                    .map_err(|error| map_admission_error(self, error))?,
                )
            }
            None => None,
        };
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok((
            BudgetInvocationCaptureDecision::Captured(decision),
            operation,
        ))
    }
}

fn capture_commit_index(
    decision: &BudgetInvocationCaptureDecision,
) -> Result<u64, BudgetStoreError> {
    let mutation = match decision {
        BudgetInvocationCaptureDecision::Captured(mutation)
        | BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => mutation,
    };
    mutation.metadata.budget_commit_index.ok_or_else(|| {
        BudgetStoreError::Invariant("budget capture omitted its durable event sequence".to_owned())
    })
}

fn budget_projection_digest(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    event_seq: u64,
) -> Result<String, BudgetStoreError> {
    transaction
        .query_row(
            r#"
            SELECT projection_reference_digest
            FROM authority_global_commits
            WHERE projection_kind = 'budget' AND projection_key = ?1
              AND projection_sequence = ?2
            "#,
            params![
                event_id,
                budget_u64_to_sqlite(event_seq, "budget_event_sequence")?
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(Into::into)
}

fn map_admission_error(
    store: &SqliteBudgetStore,
    error: AdmissionOperationStoreError,
) -> BudgetStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => BudgetStoreError::Fenced {
            expected_epoch: store
                .serving_owner
                .as_ref()
                .map_or(0, |owner| owner.fence.owner_epoch),
            actual_epoch: None,
        },
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            BudgetStoreError::OutcomeUnknown(detail)
        }
        error => BudgetStoreError::Invariant(error.to_string()),
    }
}
