impl InMemoryBudgetStoreInner {
    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_expected_state(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reverse_charge_cost_with_expected_state(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        expected_cumulative_approval_state: Option<BudgetCumulativeApprovalState>,
    ) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(hold_id, event_id, "budget reversal")?;
        let request = BudgetMutationRequest::Reverse {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            cost_units,
            expected_cumulative_approval_state,
            authority: authority.cloned(),
        };
        self.reverse_charge_cost_with_mutation(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
            expected_cumulative_approval_state,
            request,
            BudgetMutationKind::ReverseExposure,
            false,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn reverse_charge_cost_with_mutation(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        expected_cumulative_approval_state: Option<BudgetCumulativeApprovalState>,
        request: BudgetMutationRequest,
        kind: BudgetMutationKind,
        cancels_captured_before_dispatch: bool,
    ) -> Result<(bool, u64, BudgetUsageRecord), BudgetStoreError> {
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            if let Some(hold_id) = hold_id {
                self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "reversal")?;
            } else {
                self.ensure_latest_usage_event(
                    capability_id,
                    grant_index,
                    existing.record.event_seq,
                    "reversal",
                )?;
            }
            return Ok((
                false,
                existing.record.event_seq,
                BudgetUsageRecord {
                    capability_id: existing.record.capability_id,
                    grant_index: existing.record.grant_index,
                    invocation_count: existing.record.invocation_count_after,
                    updated_at: existing.record.recorded_at,
                    seq: existing.record.usage_seq.unwrap_or(0),
                    total_cost_exposed: existing.record.total_cost_exposed_after,
                    total_cost_realized_spend: existing.record.total_cost_realized_spend_after,
                },
            ));
        }
        let hold_snapshot = hold_id
            .map(|hold_id| {
                self.validate_hold(hold_id, capability_id, grant_index)
                    .cloned()
            })
            .transpose()?;
        if let Some((hold_id, hold)) = hold_id.zip(hold_snapshot.as_ref()) {
            if hold.remaining_exposure_units != cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            let expected_state = if cancels_captured_before_dispatch {
                BudgetInvocationState::Captured
            } else {
                BudgetInvocationState::Authorized
            };
            if hold.invocation_state != expected_state {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` invocation state cannot be reversed"
                )));
            }
            if cancels_captured_before_dispatch && !hold.captured_cancellation_allowed {
                return Err(BudgetStoreError::Invariant(
                    "captured composite invocation reservations are terminal".to_string(),
                ));
            }
            if cost_units > 0 && hold.monetary_state != BudgetMonetaryState::Exposed {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary exposure is not reversible"
                )));
            }
            for quota in &hold.invocation_quotas {
                let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant("missing reserved invocation quota".to_string())
                })?;
                let reversible_invocations = if cancels_captured_before_dispatch {
                    state.captured_invocations
                } else {
                    state.reserved_invocations
                };
                if state.max_invocations != quota.max_invocations || reversible_invocations == 0 {
                    return Err(BudgetStoreError::Invariant(
                        "invocation quota reservation does not match its hold".to_string(),
                    ));
                }
            }
            if let Some(quota) = &hold.legacy_captured_invocation_quota {
                let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "missing captured legacy invocation quota".to_string(),
                    )
                })?;
                if state.max_invocations != quota.max_invocations || state.captured_invocations == 0
                {
                    return Err(BudgetStoreError::Invariant(
                        "legacy invocation quota does not match its hold".to_string(),
                    ));
                }
            }
            if let Some(participant) = &hold.cumulative_approval {
                if expected_cumulative_approval_state
                    .is_some_and(|expected| participant.state != expected)
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` cumulative approval state changed"
                    )));
                }
                if !(matches!(
                    participant.state,
                    BudgetCumulativeApprovalState::PendingApproval
                        | BudgetCumulativeApprovalState::Authorized
                ) || cancels_captured_before_dispatch
                    && participant.state == BudgetCumulativeApprovalState::Captured)
                {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval participant is terminal".to_string(),
                    ));
                }
                let account = self
                    .cumulative_approval_accounts
                    .get(&participant.request.account_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "missing cumulative approval account".to_string(),
                        )
                    })?;
                let reversible_authorized_units = if participant.state
                    == BudgetCumulativeApprovalState::Captured
                {
                    account.captured_authorized_units
                } else {
                    account.reserved_authorized_units
                };
                if reversible_authorized_units < participant.request.requested_authorized.units {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval reservation is incomplete".to_string(),
                    ));
                }
                account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval account version overflowed u64".to_string(),
                    )
                })?;
            } else if expected_cumulative_approval_state.is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` has no cumulative approval participant"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        } else if !cancels_captured_before_dispatch {
            if self.has_composite_history(capability_id, grant_index) {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse an unheld invocation after structured admission history"
                        .to_string(),
                ));
            }
            if self.holds.values().any(|hold| {
                hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && matches!(
                        hold.invocation_state,
                        BudgetInvocationState::Authorized | BudgetInvocationState::Captured
                    )
            }) {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse an unheld invocation while a live budget hold exists"
                        .to_string(),
                ));
            }
            let legacy_reversible = self
                .legacy_reversible_invocations
                .get(&(capability_id.to_string(), grant_index))
                .copied()
                .unwrap_or(0);
            if legacy_reversible == 0 {
                return Err(BudgetStoreError::Invariant(
                    "no reversible unheld invocation exists".to_string(),
                ));
            }
        }

        let affected_quotas = if let Some(hold) = &hold_snapshot {
            let mut quotas = hold.invocation_quotas.clone();
            if let Some(quota) = &hold.legacy_captured_invocation_quota {
                quotas.push(quota.clone());
            }
            quotas
        } else {
            let key = BudgetQuotaKey::grant(capability_id, grant_index_u32);
            self.invocation_quotas
                .get(&key)
                .map(|state| {
                    vec![BudgetInvocationQuota {
                        key,
                        max_invocations: state.max_invocations,
                    }]
                })
                .unwrap_or_default()
        };
        let invocation_quota_usages_before = self.invocation_quota_usages(&affected_quotas)?;
        let cumulative_before = hold_snapshot
            .as_ref()
            .and_then(|hold| hold.cumulative_approval.as_ref())
            .map(|participant| {
                self.cumulative_approval_accounts
                    .get(&participant.request.account_key)
                    .map(|account| {
                        (
                            account.reserved_authorized_units,
                            account.captured_authorized_units,
                            account.version,
                            participant.clone(),
                        )
                    })
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "cumulative approval account disappeared".to_string(),
                        )
                    })
            })
            .transpose()?;

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        for quota in &affected_quotas {
            let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                BudgetStoreError::Invariant("affected invocation quota is missing".to_string())
            })?;
            let captured_reversal = hold_snapshot
                .as_ref()
                .is_some_and(|hold| hold.legacy_captured_invocation_quota.as_ref() == Some(quota))
                || hold_snapshot.is_none()
                || cancels_captured_before_dispatch;
            let available = if captured_reversal {
                state.captured_invocations
            } else {
                state.reserved_invocations
            };
            if available == 0 {
                return Err(BudgetStoreError::Invariant(
                    "affected invocation quota has no reversible reservation".to_string(),
                ));
            }
        }
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge larger than total_cost_exposed".to_string(),
                ));
            }
            self.next_seq = next_seq;
            entry.invocation_count -= 1;
            entry.total_cost_exposed -= cost_units;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        let invocation_quota_usages;
        let invocation_quota_mutations;
        let mut cumulative_approval = None;
        let mut cumulative_approval_mutation = None;
        if let Some((hold_id, hold_snapshot)) = hold_id.zip(hold_snapshot.as_ref()) {
            for quota in &hold_snapshot.invocation_quotas {
                let state = self.invocation_quotas.get_mut(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "validated invocation quota disappeared".to_string(),
                    )
                })?;
                if cancels_captured_before_dispatch {
                    state.captured_invocations -= 1;
                } else {
                    state.reserved_invocations -= 1;
                }
            }
            if let Some(quota) = &hold_snapshot.legacy_captured_invocation_quota {
                if let Some(state) = self.invocation_quotas.get_mut(&quota.key) {
                    state.captured_invocations -= 1;
                }
            }
            if let Some(participant) = &hold_snapshot.cumulative_approval {
                let account = self
                    .cumulative_approval_accounts
                    .get_mut(&participant.request.account_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "validated cumulative approval account disappeared".to_string(),
                        )
                    })?;
                if participant.state == BudgetCumulativeApprovalState::Captured {
                    account.captured_authorized_units -=
                        participant.request.requested_authorized.units;
                } else {
                    account.reserved_authorized_units -=
                        participant.request.requested_authorized.units;
                }
                account.version += 1;
            }
            invocation_quota_usages = self.invocation_quota_usages(&affected_quotas)?;
            invocation_quota_mutations = Self::invocation_quota_mutations(
                &invocation_quota_usages_before,
                &invocation_quota_usages,
            )?;
            cumulative_approval = hold_snapshot
                .cumulative_approval
                .as_ref()
                .map(|participant| {
                    self.cumulative_approval_usage(
                        &participant.request,
                        BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    )
                })
                .transpose()?;
            cumulative_approval_mutation = cumulative_before
                .as_ref()
                .map(|(reserved, captured, version, participant)| {
                    self.cumulative_approval_mutation(
                        &participant.request,
                        Some(participant.state),
                        BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                        (*reserved, *captured, *version),
                    )
                })
                .transpose()?;
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during reverse_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units = 0;
            hold.invocation_state = BudgetInvocationState::Reversed;
            if cost_units > 0 {
                hold.monetary_state = BudgetMonetaryState::Reversed;
            }
            if let Some(participant) = hold.cumulative_approval.as_mut() {
                participant.state = BudgetCumulativeApprovalState::ReversedBeforeDispatch;
            }
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        } else {
            for quota in &affected_quotas {
                if let Some(state) = self.invocation_quotas.get_mut(&quota.key) {
                    state.captured_invocations -= 1;
                }
            }
            let legacy_reversible = self
                .legacy_reversible_invocations
                .get_mut(&(capability_id.to_string(), grant_index))
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "validated reversible invocation disappeared".to_string(),
                    )
                })?;
            *legacy_reversible -= 1;
            invocation_quota_usages = self.invocation_quota_usages(&affected_quotas)?;
            invocation_quota_mutations = Self::invocation_quota_mutations(
                &invocation_quota_usages_before,
                &invocation_quota_usages,
            )?;
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                admission_binding: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.admission_binding.clone()),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: if cancels_captured_before_dispatch || invocation_quota_usages.is_empty() {
                    kind
                } else {
                    BudgetMutationKind::ReverseInvocation
                },
                allowed: cancels_captured_before_dispatch.then_some(true),
                authorization_outcome: None,
                invocation_state_before: hold_snapshot
                    .as_ref()
                    .map_or(BudgetInvocationState::Authorized, |hold| {
                        hold.invocation_state
                    }),
                invocation_state_after: BudgetInvocationState::Reversed,
                monetary_state_before: hold_snapshot.as_ref().map_or(
                    if cost_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    |hold| hold.monetary_state,
                ),
                monetary_state_after: hold_snapshot.as_ref().map_or(
                    if cost_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Reversed
                    },
                    |hold| {
                        if cost_units == 0 {
                            hold.monetary_state
                        } else {
                            BudgetMonetaryState::Reversed
                        }
                    },
                ),
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages,
                invocation_quota_mutations,
                cumulative_approval,
                cumulative_approval_mutation,
                cumulative_approval_set_digest: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.cumulative_approval.as_ref())
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok((
            true,
            seq,
            BudgetUsageRecord {
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                invocation_count: invocation_count_after,
                updated_at: unix_now(),
                seq,
                total_cost_exposed: total_cost_exposed_after,
                total_cost_realized_spend: total_cost_realized_spend_after,
            },
        ))
    }

    fn cancel_captured_before_dispatch(
        &mut self,
        request: &BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<(bool, u64, BudgetUsageRecord), BudgetStoreError> {
        let cost_units = self
            .holds
            .get(&request.hold_id)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!("unknown budget hold `{}`", request.hold_id))
            })?
            .remaining_exposure_units;
        self.reverse_charge_cost_with_mutation(
            &request.capability_id,
            request.grant_index,
            cost_units,
            Some(&request.hold_id),
            Some(&request.event_id),
            request.authority.as_ref(),
            None,
            BudgetMutationRequest::CancelCapturedBeforeDispatch {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                hold_id: request.hold_id.clone(),
                authority: request.authority.clone(),
            },
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            true,
        )
    }

    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(hold_id, event_id, "budget release")?;
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if cost_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary release is not a state transition".to_string(),
            ));
        }
        let request = BudgetMutationRequest::Release {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            cost_units,
            authority: authority.cloned(),
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            if let Some(hold_id) = hold_id {
                let hold = self.validate_hold(hold_id, capability_id, grant_index)?;
                Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
                self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "release")?;
            } else {
                self.ensure_latest_usage_event(
                    capability_id,
                    grant_index,
                    existing.record.event_seq,
                    "release",
                )?;
            }
            return Ok(());
        }
        let hold_snapshot = hold_id
            .map(|hold_id| {
                self.validate_hold(hold_id, capability_id, grant_index)
                    .cloned()
            })
            .transpose()?;
        if let Some((hold_id, hold)) = hold_id.zip(hold_snapshot.as_ref()) {
            if hold.remaining_exposure_units < cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            if hold.monetary_state != BudgetMonetaryState::Exposed {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary exposure is not releasable"
                )));
            }
            if hold.invocation_state != BudgetInvocationState::Authorized {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` crossed the dispatch commitment fence"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        } else {
            if self.has_composite_history(capability_id, grant_index) {
                return Err(BudgetStoreError::Invariant(
                    "cannot release unheld exposure after structured admission history"
                        .to_string(),
                ));
            }
            if self.holds.values().any(|hold| {
                hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && matches!(
                        hold.invocation_state,
                        BudgetInvocationState::Authorized | BudgetInvocationState::Captured
                    )
            }) {
                return Err(BudgetStoreError::Invariant(
                    "cannot release unheld exposure while a live budget hold exists".to_string(),
                ));
            }
            if self
                .legacy_reversible_invocations
                .get(&(capability_id.to_string(), grant_index))
                .copied()
                .unwrap_or(0)
                == 0
            {
                return Err(BudgetStoreError::Invariant(
                    "no releasable unheld monetary invocation exists".to_string(),
                ));
            }
        }

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reduce charge larger than total_cost_exposed".to_string(),
                ));
            }

            let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
            })?;
            self.next_seq = next_seq;
            entry.total_cost_exposed -= cost_units;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during release_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units -= cost_units;
            if hold.remaining_exposure_units == 0 {
                hold.monetary_state = BudgetMonetaryState::Released;
            }
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                admission_binding: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.admission_binding.clone()),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                authorization_outcome: None,
                invocation_state_before: hold_snapshot
                    .as_ref()
                    .map_or(BudgetInvocationState::Absent, |hold| hold.invocation_state),
                invocation_state_after: hold_snapshot
                    .as_ref()
                    .map_or(BudgetInvocationState::Absent, |hold| hold.invocation_state),
                monetary_state_before: hold_snapshot
                    .as_ref()
                    .map_or(BudgetMonetaryState::Exposed, |hold| hold.monetary_state),
                monetary_state_after: hold_snapshot.as_ref().map_or(
                    BudgetMonetaryState::Released,
                    |hold| {
                        if hold.remaining_exposure_units == cost_units {
                            BudgetMonetaryState::Released
                        } else {
                            BudgetMonetaryState::Exposed
                        }
                    },
                ),
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages: hold_snapshot
                    .as_ref()
                    .map(|hold| self.invocation_quota_usages(&hold.invocation_quotas))
                    .transpose()?
                    .unwrap_or_default(),
                invocation_quota_mutations: Vec::new(),
                cumulative_approval: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.cumulative_approval.as_ref())
                    .map(|participant| {
                        self.cumulative_approval_usage(&participant.request, participant.state)
                    })
                    .transpose()?,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.cumulative_approval.as_ref())
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
    }

    fn settle_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
        )
    }

    fn settle_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_mutation(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
            BudgetMutationRequest::Reconcile {
                capability_id: capability_id.to_string(),
                grant_index,
                hold_id: hold_id.map(ToOwned::to_owned),
                exposed_cost_units,
                realized_cost_units,
                authority: authority.cloned(),
            },
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryState::Reconciled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_mutation(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        request: BudgetMutationRequest,
        mutation_kind: BudgetMutationKind,
        terminal_state: BudgetMonetaryState,
    ) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(hold_id, event_id, "budget settlement")?;
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        if exposed_cost_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary settlement is not a state transition".to_string(),
            ));
        }
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            if let Some(hold_id) = hold_id {
                let hold = self.validate_hold(hold_id, capability_id, grant_index)?;
                Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
                self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "settlement")?;
            } else {
                self.ensure_latest_usage_event(
                    capability_id,
                    grant_index,
                    existing.record.event_seq,
                    "settlement",
                )?;
            }
            return Ok(());
        }
        let hold_snapshot = hold_id
            .map(|hold_id| {
                self.validate_hold(hold_id, capability_id, grant_index)
                    .cloned()
            })
            .transpose()?;
        if let Some((hold_id, hold)) = hold_id.zip(hold_snapshot.as_ref()) {
            if hold.invocation_state != BudgetInvocationState::Captured {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` invocation is not dispatch-captured"
                )));
            }
            if hold.remaining_exposure_units != exposed_cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            if hold.monetary_state != BudgetMonetaryState::Exposed {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary exposure is not reconcilable"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        } else {
            if self.has_composite_history(capability_id, grant_index) {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle unheld exposure after structured admission history"
                        .to_string(),
                ));
            }
            if self.holds.values().any(|hold| {
                hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && matches!(
                        hold.invocation_state,
                        BudgetInvocationState::Authorized | BudgetInvocationState::Captured
                    )
            }) {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle unheld exposure while a live budget hold exists".to_string(),
                ));
            }
            if self
                .legacy_reversible_invocations
                .get(&(capability_id.to_string(), grant_index))
                .copied()
                .unwrap_or(0)
                == 0
            {
                return Err(BudgetStoreError::Invariant(
                    "no settleable unheld monetary invocation exists".to_string(),
                ));
            }
        }

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < exposed_cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle more exposure than total_cost_exposed".to_string(),
                ));
            }

            let next_realized_spend = entry
                .total_cost_realized_spend
                .checked_add(realized_cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_realized_spend + realized_cost_units overflowed u64"
                            .to_string(),
                    )
                })?;
            entry.total_cost_realized_spend = next_realized_spend;
            entry.total_cost_exposed -= exposed_cost_units;
            self.next_seq = next_seq;
            entry.updated_at = unix_now();
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during settle_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units = 0;
            hold.monetary_state = terminal_state;
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        } else if let Some(legacy_reversible) = self
            .legacy_reversible_invocations
            .get_mut(&(capability_id.to_string(), grant_index))
        {
            *legacy_reversible -= 1;
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                admission_binding: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.admission_binding.clone()),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: mutation_kind,
                allowed: None,
                authorization_outcome: None,
                invocation_state_before: hold_snapshot
                    .as_ref()
                    .map_or(BudgetInvocationState::Absent, |hold| hold.invocation_state),
                invocation_state_after: hold_snapshot
                    .as_ref()
                    .map_or(BudgetInvocationState::Absent, |hold| hold.invocation_state),
                monetary_state_before: hold_snapshot
                    .as_ref()
                    .map_or(BudgetMonetaryState::Exposed, |hold| hold.monetary_state),
                monetary_state_after: terminal_state,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: exposed_cost_units,
                realized_spend_units: realized_cost_units,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages: hold_snapshot
                    .as_ref()
                    .map(|hold| self.invocation_quota_usages(&hold.invocation_quotas))
                    .transpose()?
                    .unwrap_or_default(),
                invocation_quota_mutations: Vec::new(),
                cumulative_approval: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.cumulative_approval.as_ref())
                    .map(|participant| {
                        self.cumulative_approval_usage(&participant.request, participant.state)
                    })
                    .transpose()?,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: hold_snapshot
                    .as_ref()
                    .and_then(|hold| hold.cumulative_approval.as_ref())
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
    }

    fn capture_budget_hold(
        &mut self,
        request: &BudgetCaptureHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_mutation(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
            BudgetMutationRequest::CaptureMonetary(request.clone()),
            BudgetMutationKind::CaptureSpend,
            BudgetMonetaryState::Captured,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut records = self
            .counts
            .values()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.capability_id.cmp(&right.capability_id))
                .then_with(|| left.grant_index.cmp(&right.grant_index))
        });
        records.truncate(limit);
        Ok(records)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(self
            .counts
            .get(&(capability_id.to_string(), grant_index))
            .cloned())
    }

    fn get_invocation_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Option<BudgetInvocationQuotaUsage> {
        self.invocation_quotas
            .get(key)
            .map(|state| BudgetInvocationQuotaUsage {
                quota: BudgetInvocationQuota {
                    key: key.clone(),
                    max_invocations: state.max_invocations,
                },
                reserved_invocations: state.reserved_invocations,
                captured_invocations: state.captured_invocations,
            })
    }

    fn get_cumulative_approval_account_usage(
        &self,
        key: &BudgetCumulativeApprovalAccountKey,
    ) -> Option<BudgetCumulativeApprovalAccountUsage> {
        self.cumulative_approval_accounts.get(key).map(|account| {
            let amount = |units| chio_core::capability::scope::MonetaryAmount {
                units,
                currency: key.currency.clone(),
            };
            BudgetCumulativeApprovalAccountUsage {
                account_key: key.clone(),
                authority_threshold: amount(account.authority_threshold_units),
                reserved_authorized: amount(account.reserved_authorized_units),
                captured_authorized: amount(account.captured_authorized_units),
                version: account.version,
            }
        })
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let grant_index = grant_index
            .map(u32::try_from)
            .transpose()
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let mut events = self
            .events
            .iter()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .filter(|record| grant_index.is_none_or(|value| record.grant_index == value))
            .cloned()
            .collect::<Vec<_>>();
        events.truncate(limit);
        Ok(events)
    }
}
