impl InMemoryBudgetStoreInner {
    fn has_composite_history(&self, capability_id: &str, grant_index: usize) -> bool {
        self.events.iter().any(|event| {
            event.capability_id == capability_id
                && event.grant_index as usize == grant_index
                && event.admission_binding.is_some()
        })
    }

    fn ensure_latest_hold_event(
        &self,
        hold_id: &str,
        event_seq: u64,
        transition: &str,
    ) -> Result<(), BudgetStoreError> {
        if self
            .events
            .iter()
            .any(|event| event.hold_id.as_deref() == Some(hold_id) && event.event_seq > event_seq)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` {transition} event was superseded by a later transition"
            )));
        }
        Ok(())
    }

    fn ensure_latest_usage_event(
        &self,
        capability_id: &str,
        grant_index: usize,
        event_seq: u64,
        transition: &str,
    ) -> Result<(), BudgetStoreError> {
        let grant_index = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if self.events.iter().any(|event| {
            event.capability_id == capability_id
                && event.grant_index == grant_index
                && event.event_seq > event_seq
                && event.usage_seq.is_some()
        }) {
            return Err(BudgetStoreError::Invariant(format!(
                "unheld budget {transition} event was superseded by a later usage transition"
            )));
        }
        Ok(())
    }

    fn grant_quota_for_legacy_mutation(
        &self,
        capability_id: &str,
        grant_index: u32,
        current_invocation_count: u32,
        declared_maximum: Option<u32>,
    ) -> Result<Option<BudgetInvocationQuota>, BudgetStoreError> {
        let key = BudgetQuotaKey::grant(capability_id, grant_index);
        if let Some(existing) = self.invocation_quotas.get(&key) {
            if declared_maximum.is_some_and(|maximum| maximum != existing.max_invocations) {
                return Err(BudgetStoreError::Invariant(
                    "grant quota maximum changed".to_string(),
                ));
            }
            return Ok(Some(BudgetInvocationQuota {
                key,
                max_invocations: existing.max_invocations,
            }));
        }
        let Some(max_invocations) = declared_maximum else {
            return Ok(None);
        };
        if current_invocation_count != 0 {
            return Err(BudgetStoreError::Invariant(
                "cannot define a grant quota after untracked invocations".to_string(),
            ));
        }
        Ok(Some(BudgetInvocationQuota {
            key,
            max_invocations,
        }))
    }

    fn invocation_quota_usages(
        &self,
        quotas: &[BudgetInvocationQuota],
    ) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        quotas
            .iter()
            .map(|quota| {
                let (reserved_invocations, captured_invocations) = self
                    .invocation_quotas
                    .get(&quota.key)
                    .map_or((0, 0), |state| {
                        (state.reserved_invocations, state.captured_invocations)
                    });
                Ok(BudgetInvocationQuotaUsage {
                    quota: quota.clone(),
                    reserved_invocations,
                    captured_invocations,
                })
            })
            .collect()
    }

    fn invocation_quota_mutations(
        before: &[BudgetInvocationQuotaUsage],
        after: &[BudgetInvocationQuotaUsage],
    ) -> Result<Vec<BudgetInvocationQuotaMutation>, BudgetStoreError> {
        if before.len() != after.len()
            || before
                .iter()
                .zip(after)
                .any(|(before, after)| before.quota != after.quota)
        {
            return Err(BudgetStoreError::Invariant(
                "invocation quota mutation keys changed during transaction".to_string(),
            ));
        }
        Ok(before
            .iter()
            .zip(after)
            .map(|(before, after)| BudgetInvocationQuotaMutation {
                quota: after.quota.clone(),
                reserved_invocations_before: before.reserved_invocations,
                captured_invocations_before: before.captured_invocations,
                reserved_invocations_after: after.reserved_invocations,
                captured_invocations_after: after.captured_invocations,
            })
            .collect())
    }

    fn cumulative_approval_usage(
        &self,
        request: &BudgetCumulativeApprovalRequest,
        state: BudgetCumulativeApprovalState,
    ) -> Result<BudgetCumulativeApprovalUsage, BudgetStoreError> {
        let account = self
            .cumulative_approval_accounts
            .get(&request.account_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cumulative approval account disappeared while building result".to_string(),
                )
            })?;
        let currency = request.account_key.currency.clone();
        Ok(BudgetCumulativeApprovalUsage {
            operation_id: request.operation_id.clone(),
            account_key: request.account_key.clone(),
            authority_threshold: request.authority_threshold.clone(),
            effective_threshold: request.effective_threshold.clone(),
            requested_authorized: request.requested_authorized.clone(),
            reserved_authorized_after: chio_core::capability::scope::MonetaryAmount {
                units: account.reserved_authorized_units,
                currency: currency.clone(),
            },
            captured_authorized_after: chio_core::capability::scope::MonetaryAmount {
                units: account.captured_authorized_units,
                currency,
            },
            state,
            version: account.version,
        })
    }

    fn cumulative_approval_mutation(
        &self,
        request: &BudgetCumulativeApprovalRequest,
        state_before: Option<BudgetCumulativeApprovalState>,
        state_after: BudgetCumulativeApprovalState,
        before: (u64, u64, u64),
    ) -> Result<BudgetCumulativeApprovalMutation, BudgetStoreError> {
        let account = self
            .cumulative_approval_accounts
            .get(&request.account_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cumulative approval account disappeared".to_string())
            })?;
        let amount = |units| chio_core::capability::scope::MonetaryAmount {
            units,
            currency: request.account_key.currency.clone(),
        };
        Ok(BudgetCumulativeApprovalMutation {
            operation_id: request.operation_id.clone(),
            account_key: request.account_key.clone(),
            state_before,
            state_after,
            reserved_authorized_before: amount(before.0),
            captured_authorized_before: amount(before.1),
            reserved_authorized_after: amount(account.reserved_authorized_units),
            captured_authorized_after: amount(account.captured_authorized_units),
            version_before: before.2,
            version_after: account.version,
        })
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Option<BudgetCumulativeApprovalUsage> {
        self.events.iter().rev().find_map(|event| {
            event
                .cumulative_approval
                .as_ref()
                .filter(|usage| usage.operation_id == operation_id)
                .cloned()
        })
    }

    fn authorize_composite_budget_hold(
        &mut self,
        request: &BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let mut quotas = request.validate_composite()?;
        let legacy = request.admission_binding.is_none()
            && request.invocation_quotas.is_empty()
            && request.cumulative_approval.is_none();
        let mutation = BudgetMutationRequest::AuthorizeComposite(Box::new(request.clone()));
        if let Some(existing) = self.duplicate_mutation(request.event_id.as_deref(), &mutation)? {
            return Ok(existing.record);
        }
        if legacy && self.has_composite_history(&request.capability_id, request.grant_index) {
            return Err(BudgetStoreError::Invariant(
                "legacy budget authorization cannot bypass structured admission history"
                    .to_string(),
            ));
        }
        if let Some(hold_id) = request.hold_id.as_deref() {
            if let Some(existing) = self.hold_authorizations.get(hold_id) {
                let detail = if existing == &mutation {
                    "is missing its original event tombstone"
                } else {
                    "was reused for a different authorization"
                };
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` {detail}"
                )));
            }
        }
        if let Some(operation_id) = request
            .admission_binding
            .as_ref()
            .map(|binding| binding.operation_id.as_str())
        {
            if let Some(existing) = self.operation_authorizations.get(operation_id) {
                let detail = if existing == &mutation {
                    "is missing its original event tombstone"
                } else {
                    "was reused for a different authorization"
                };
                return Err(BudgetStoreError::Invariant(format!(
                    "budget operation `{operation_id}` {detail}"
                )));
            }
        }

        let grant_index = u32::try_from(request.grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let grant_quota_key = BudgetQuotaKey::grant(&request.capability_id, grant_index);
        if self.invocation_quotas.contains_key(&grant_quota_key)
            && !quotas.iter().any(|quota| quota.key == grant_quota_key)
        {
            if legacy {
                let maximum = self
                    .invocation_quotas
                    .get(&grant_quota_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "existing grant quota disappeared during authorization".to_string(),
                        )
                    })?
                    .max_invocations;
                quotas.push(BudgetInvocationQuota {
                    key: grant_quota_key,
                    max_invocations: maximum,
                });
            } else {
                return Err(BudgetStoreError::Invariant(
                    "budget authorization omitted the existing grant quota".to_string(),
                ));
            }
        }
        let primary_key = (request.capability_id.clone(), request.grant_index);
        let current = self
            .counts
            .get(&primary_key)
            .cloned()
            .unwrap_or_else(|| Self::default_usage_record(&request.capability_id, grant_index));
        let current_total = checked_committed_cost_units(
            current.total_cost_exposed,
            current.total_cost_realized_spend,
        )?;
        let next_total = current_total
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + requested exposure overflowed u64".to_string(),
                )
            })?;
        let mut allowed = request
            .max_cost_per_invocation
            .is_none_or(|maximum| request.requested_exposure_units <= maximum)
            && request
                .max_total_cost_units
                .is_none_or(|maximum| next_total <= maximum);

        for quota in &quotas {
            if let Some(existing) = self.invocation_quotas.get(&quota.key) {
                if existing.max_invocations != quota.max_invocations {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget quota `{}` maximum changed from {} to {}",
                        quota.key.owner_id, existing.max_invocations, quota.max_invocations
                    )));
                }
                let used = existing
                    .reserved_invocations
                    .checked_add(existing.captured_invocations)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved + captured quota count overflowed u32".to_string(),
                        )
                    })?;
                allowed &= used < quota.max_invocations;
            } else {
                if quota.key == BudgetQuotaKey::grant(&request.capability_id, grant_index)
                    && current.invocation_count != 0
                {
                    return Err(BudgetStoreError::Invariant(
                        "cannot define a grant quota after untracked invocations".to_string(),
                    ));
                }
                allowed &= quota.max_invocations > 0;
            }
        }

        let mut cumulative_before = None;
        let cumulative_state = if let Some(cumulative) = &request.cumulative_approval {
            let (reserved, captured, version) = self
                .cumulative_approval_accounts
                .get(&cumulative.account_key)
                .map_or(Ok((0, 0, 0)), |account| {
                    if account.authority_threshold_units != cumulative.authority_threshold.units {
                        return Err(BudgetStoreError::Invariant(
                            "cumulative approval authority threshold changed".to_string(),
                        ));
                    }
                    account.version.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "cumulative approval account version overflowed u64".to_string(),
                        )
                    })?;
                    Ok((
                        account.reserved_authorized_units,
                        account.captured_authorized_units,
                        account.version,
                    ))
                })?;
            cumulative_before = Some((reserved, captured, version));
            let prospective = reserved
                .checked_add(captured)
                .and_then(|used| used.checked_add(cumulative.requested_authorized.units))
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative authorized units overflowed u64".to_string(),
                    )
                })?;
            Some(if prospective >= cumulative.effective_threshold.units {
                BudgetCumulativeApprovalState::PendingApproval
            } else {
                BudgetCumulativeApprovalState::Authorized
            })
        } else {
            None
        };

        let next_invocation_count = current.invocation_count.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("invocation_count overflowed u32".to_string())
        })?;
        let next_exposure = current
            .total_cost_exposed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_exposed + requested exposure overflowed u64".to_string(),
                )
            })?;
        let next_legacy_reversible = if allowed && request.hold_id.is_none() {
            Some(
                self.legacy_reversible_invocations
                    .get(&primary_key)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "legacy reversible invocation count overflowed u32".to_string(),
                        )
                    })?,
            )
        } else {
            None
        };
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        self.next_seq = event_seq;
        let recorded_at = unix_now();
        let invocation_quota_usages_before = self.invocation_quota_usages(&quotas)?;

        if allowed {
            for quota in &quotas {
                self.invocation_quotas.entry(quota.key.clone()).or_insert(
                    BudgetInvocationQuotaState {
                        max_invocations: quota.max_invocations,
                        reserved_invocations: 0,
                        captured_invocations: 0,
                    },
                );
            }
            let entry = self
                .counts
                .entry(primary_key.clone())
                .or_insert_with(|| Self::default_usage_record(&request.capability_id, grant_index));
            entry.invocation_count = next_invocation_count;
            entry.total_cost_exposed = next_exposure;
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            if let Some(next_legacy_reversible) = next_legacy_reversible {
                self.legacy_reversible_invocations
                    .insert(primary_key.clone(), next_legacy_reversible);
            }

            for quota in &quotas {
                let quota_state = self.invocation_quotas.get_mut(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "validated invocation quota disappeared".to_string(),
                    )
                })?;
                quota_state.reserved_invocations = quota_state
                    .reserved_invocations
                    .checked_add(1)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved invocation quota count overflowed u32".to_string(),
                        )
                    })?;
            }

            let cumulative_approval = request
                .cumulative_approval
                .as_ref()
                .map(|cumulative| {
                    let account = self
                        .cumulative_approval_accounts
                        .entry(cumulative.account_key.clone())
                        .or_insert(BudgetCumulativeApprovalAccountState {
                            authority_threshold_units: cumulative.authority_threshold.units,
                            reserved_authorized_units: 0,
                            captured_authorized_units: 0,
                            version: 0,
                        });
                    let reserved_authorized_units = account
                        .reserved_authorized_units
                        .checked_add(cumulative.requested_authorized.units)
                        .ok_or_else(|| {
                            BudgetStoreError::Overflow(
                                "reserved cumulative authorized units overflowed u64".to_string(),
                            )
                        })?;
                    let version = account.version.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "cumulative approval account version overflowed u64".to_string(),
                        )
                    })?;
                    account.reserved_authorized_units = reserved_authorized_units;
                    account.version = version;
                    Ok::<_, BudgetStoreError>(BudgetCumulativeApprovalHoldState {
                        request: cumulative.clone(),
                        state: cumulative_state.ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "cumulative approval state missing".to_string(),
                            )
                        })?,
                        approval_set_digest: None,
                    })
                })
                .transpose()?;

            if let Some(hold_id) = request.hold_id.as_deref() {
                self.holds.insert(
                    hold_id.to_string(),
                    BudgetHoldState {
                        capability_id: request.capability_id.clone(),
                        grant_index: request.grant_index,
                        admission_binding: request.admission_binding.clone(),
                        authorized_exposure_units: request.requested_exposure_units,
                        remaining_exposure_units: request.requested_exposure_units,
                        invocation_state: BudgetInvocationState::Authorized,
                        invocation_quotas: quotas.clone(),
                        legacy_captured_invocation_quota: None,
                        captured_cancellation_allowed: request.cumulative_approval.is_some()
                            || (request.invocation_quotas.is_empty()
                                && request.admission_binding.is_none()),
                        cumulative_approval,
                        monetary_state: if request.requested_exposure_units == 0 {
                            BudgetMonetaryState::None
                        } else {
                            BudgetMonetaryState::Exposed
                        },
                        authority: request.authority.clone(),
                        reserved_until: None,
                        reserved_currency: None,
                        reserved_payment_reference: None,
                        reserved_envelope: ReservedHoldEnvelope::default(),
                    },
                );
            }
        }

        let invocation_quota_usages = self.invocation_quota_usages(&quotas)?;
        let invocation_quota_mutations = Self::invocation_quota_mutations(
            &invocation_quota_usages_before,
            &invocation_quota_usages,
        )?;
        let cumulative_approval = if allowed {
            request
                .cumulative_approval
                .as_ref()
                .zip(cumulative_state)
                .map(|(cumulative, state)| self.cumulative_approval_usage(cumulative, state))
                .transpose()?
        } else {
            None
        };
        let cumulative_approval_mutation = if allowed {
            request
                .cumulative_approval
                .as_ref()
                .zip(cumulative_state)
                .zip(cumulative_before)
                .map(
                    |((cumulative, state), (reserved_before, captured_before, version_before))| {
                        let after = self
                            .cumulative_approval_accounts
                            .get(&cumulative.account_key)
                            .ok_or_else(|| {
                                BudgetStoreError::Invariant(
                                    "cumulative approval account disappeared".to_string(),
                                )
                            })?;
                        let amount = |units| chio_core::capability::scope::MonetaryAmount {
                            units,
                            currency: cumulative.account_key.currency.clone(),
                        };
                        Ok::<_, BudgetStoreError>(BudgetCumulativeApprovalMutation {
                            operation_id: cumulative.operation_id.clone(),
                            account_key: cumulative.account_key.clone(),
                            state_before: None,
                            state_after: state,
                            reserved_authorized_before: amount(reserved_before),
                            captured_authorized_before: amount(captured_before),
                            reserved_authorized_after: amount(after.reserved_authorized_units),
                            captured_authorized_after: amount(after.captured_authorized_units),
                            version_before,
                            version_after: after.version,
                        })
                    },
                )
                .transpose()?
        } else {
            None
        };
        let record = BudgetMutationRecord {
            event_id: String::new(),
            hold_id: request.hold_id.clone(),
            admission_binding: request.admission_binding.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: if quotas.is_empty() && request.cumulative_approval.is_none() {
                BudgetMutationKind::AuthorizeExposure
            } else {
                BudgetMutationKind::ReserveInvocation
            },
            allowed: match (allowed, cumulative_state) {
                (false, _) => Some(false),
                (true, Some(BudgetCumulativeApprovalState::PendingApproval)) => None,
                (true, _) => Some(true),
            },
            authorization_outcome: Some(match (allowed, cumulative_state) {
                (false, _) => BudgetAuthorizationOutcome::Denied,
                (true, Some(BudgetCumulativeApprovalState::PendingApproval)) => {
                    BudgetAuthorizationOutcome::ApprovalRequired
                }
                (true, _) => BudgetAuthorizationOutcome::Authorized,
            }),
            invocation_state_before: BudgetInvocationState::Absent,
            invocation_state_after: if allowed {
                BudgetInvocationState::Authorized
            } else {
                BudgetInvocationState::Denied
            },
            monetary_state_before: BudgetMonetaryState::None,
            monetary_state_after: if allowed && request.requested_exposure_units > 0 {
                BudgetMonetaryState::Exposed
            } else {
                BudgetMonetaryState::None
            },
            recorded_at,
            event_seq,
            usage_seq: allowed.then_some(event_seq),
            exposure_units: request.requested_exposure_units,
            realized_spend_units: 0,
            max_invocations: request.max_invocations,
            max_cost_per_invocation: request.max_cost_per_invocation,
            max_total_cost_units: request.max_total_cost_units,
            invocation_count_after: if allowed {
                next_invocation_count
            } else {
                current.invocation_count
            },
            invocation_quota_usages,
            invocation_quota_mutations,
            cumulative_approval,
            cumulative_approval_mutation,
            cumulative_approval_set_digest: None,
            total_cost_exposed_after: if allowed {
                next_exposure
            } else {
                current.total_cost_exposed
            },
            total_cost_realized_spend_after: current.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        self.append_mutation(request.event_id.as_deref(), mutation.clone(), record);
        if allowed {
            if let Some(hold_id) = request.hold_id.as_deref() {
                self.hold_authorizations
                    .insert(hold_id.to_string(), mutation.clone());
            }
            if let Some(operation_id) = request
                .admission_binding
                .as_ref()
                .map(|binding| binding.operation_id.as_str())
            {
                self.operation_authorizations
                    .insert(operation_id.to_string(), mutation);
            }
        }
        self.events.last().cloned().ok_or_else(|| {
            BudgetStoreError::Invariant("authorization event disappeared after append".to_string())
        })
    }

    fn authorize_cumulative_approval(
        &mut self,
        request: &BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<(bool, BudgetMutationRecord), BudgetStoreError> {
        request.validate()?;
        let mutation =
            BudgetMutationRequest::AuthorizeCumulativeApproval(Box::new(request.clone()));
        if let Some(existing) = self.duplicate_mutation(Some(&request.event_id), &mutation)? {
            let hold = self.holds.get(&request.hold_id).ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "unknown cumulative approval hold `{}`",
                    request.hold_id
                ))
            })?;
            if hold.capability_id != request.capability_id
                || hold.grant_index != request.grant_index
                || hold.admission_binding.as_ref() != Some(&request.admission_binding)
            {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval replay changed the durable hold identity".to_string(),
                ));
            }
            Self::validate_hold_authority(
                &request.hold_id,
                hold.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            let participant = hold.cumulative_approval.as_ref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget hold has no cumulative approval participant".to_string(),
                )
            })?;
            if participant.request.operation_id != request.operation_id
                || participant.state != BudgetCumulativeApprovalState::Authorized
                || participant.approval_set_digest.as_deref()
                    != Some(request.approval_set_digest.as_str())
            {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval event was superseded by a later transition".to_string(),
                ));
            }
            self.ensure_latest_hold_event(
                &request.hold_id,
                existing.record.event_seq,
                "cumulative approval",
            )?;
            return Ok((false, existing.record));
        }
        let hold = self.holds.get(&request.hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "unknown cumulative approval hold `{}`",
                request.hold_id
            ))
        })?;
        if hold.capability_id != request.capability_id
            || hold.grant_index != request.grant_index
            || hold.admission_binding.as_ref() != Some(&request.admission_binding)
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval request changed the durable hold identity".to_string(),
            ));
        }
        Self::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if hold
            .admission_binding
            .as_ref()
            .is_none_or(|binding| binding.operation_id != request.operation_id)
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval operation does not match the admission binding".to_string(),
            ));
        }
        let participant = hold.cumulative_approval.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "budget hold has no cumulative approval participant".to_string(),
            )
        })?;
        if participant.request.operation_id != request.operation_id {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval operation does not own this participant".to_string(),
            ));
        }
        if participant.state != BudgetCumulativeApprovalState::PendingApproval
            || participant.approval_set_digest.is_some()
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval participant is not pending".to_string(),
            ));
        }

        let account_before = self
            .cumulative_approval_accounts
            .get(&participant.request.account_key)
            .map(|account| {
                (
                    account.reserved_authorized_units,
                    account.captured_authorized_units,
                    account.version,
                )
            })
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cumulative approval account disappeared".to_string())
            })?;
        account_before.2.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow(
                "cumulative approval account version overflowed u64".to_string(),
            )
        })?;
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        let usage = self
            .counts
            .get(&(hold.capability_id.clone(), hold.grant_index))
            .cloned()
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;
        let quota_usages_before = self.invocation_quota_usages(&hold.invocation_quotas)?;

        self.next_seq = event_seq;
        self.cumulative_approval_accounts
            .get_mut(&participant.request.account_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "validated cumulative approval account disappeared".to_string(),
                )
            })?
            .version += 1;
        let stored_participant = self
            .holds
            .get_mut(&request.hold_id)
            .and_then(|hold| hold.cumulative_approval.as_mut())
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "validated cumulative approval participant disappeared".to_string(),
                )
            })?;
        stored_participant.state = BudgetCumulativeApprovalState::Authorized;
        stored_participant.approval_set_digest = Some(request.approval_set_digest.clone());

        let quota_usages = self.invocation_quota_usages(&hold.invocation_quotas)?;
        let cumulative_approval = self.cumulative_approval_usage(
            &participant.request,
            BudgetCumulativeApprovalState::Authorized,
        )?;
        let record = BudgetMutationRecord {
            event_id: String::new(),
            hold_id: Some(request.hold_id.clone()),
            admission_binding: hold.admission_binding.clone(),
            capability_id: hold.capability_id,
            grant_index: u32::try_from(hold.grant_index).map_err(|_| {
                BudgetStoreError::Invariant("grant_index does not fit u32".to_string())
            })?,
            kind: BudgetMutationKind::AuthorizeCumulativeApproval,
            allowed: Some(true),
            authorization_outcome: Some(BudgetAuthorizationOutcome::Authorized),
            invocation_state_before: hold.invocation_state,
            invocation_state_after: hold.invocation_state,
            monetary_state_before: hold.monetary_state,
            monetary_state_after: hold.monetary_state,
            recorded_at: unix_now(),
            event_seq,
            usage_seq: None,
            exposure_units: 0,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: usage.invocation_count,
            invocation_quota_usages: quota_usages.clone(),
            invocation_quota_mutations: Self::invocation_quota_mutations(
                &quota_usages_before,
                &quota_usages,
            )?,
            cumulative_approval: Some(cumulative_approval),
            cumulative_approval_mutation: Some(self.cumulative_approval_mutation(
                &participant.request,
                Some(BudgetCumulativeApprovalState::PendingApproval),
                BudgetCumulativeApprovalState::Authorized,
                account_before,
            )?),
            cumulative_approval_set_digest: Some(request.approval_set_digest.clone()),
            total_cost_exposed_after: usage.total_cost_exposed,
            total_cost_realized_spend_after: usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        self.append_mutation(Some(&request.event_id), mutation, record);
        self.events
            .last()
            .cloned()
            .map(|record| (true, record))
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cumulative approval event disappeared after append".to_string(),
                )
            })
    }

    fn duplicate_mutation(
        &self,
        event_id: Option<&str>,
        request: &BudgetMutationRequest,
    ) -> Result<Option<RecordedBudgetMutation>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        if event_id.starts_with("local-budget-event-") {
            return Err(BudgetStoreError::Invariant(
                "explicit budget event_id uses the reserved local event namespace".to_string(),
            ));
        }
        let Some(existing) = self.explicit_events.get(event_id) else {
            return Ok(None);
        };
        if &existing.request != request {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing.clone()))
    }

    fn append_mutation(
        &mut self,
        explicit_event_id: Option<&str>,
        request: BudgetMutationRequest,
        mut record: BudgetMutationRecord,
    ) {
        let event_id = explicit_event_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("local-budget-event-{}", record.event_seq));
        record.event_id = event_id.clone();
        self.events.push(record.clone());
        if explicit_event_id.is_some() {
            self.explicit_events
                .insert(event_id, RecordedBudgetMutation { request, record });
        }
    }

    fn validate_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<&BudgetHoldState, BudgetStoreError> {
        let hold = self.holds.get(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        Ok(hold)
    }

    fn validate_hold_authority(
        hold_id: &str,
        current: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match (current, requested) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` was created without authority lease metadata"
            ))),
            (Some(_), None) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` requires authority lease metadata"
            ))),
            (Some(current), Some(requested)) => {
                if current.authority_id != requested.authority_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority_id does not match the open lease"
                    )));
                }
                if requested.lease_id != current.lease_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` lease_id does not match the open lease epoch"
                    )));
                }
                if requested.lease_epoch < current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch regressed"
                    )));
                }
                if requested.lease_epoch > current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch advanced beyond the open lease"
                    )));
                }
                Ok(Some(requested.clone()))
            }
        }
    }

    fn default_usage_record(capability_id: &str, grant_index: u32) -> BudgetUsageRecord {
        BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_exposed: 0,
            total_cost_realized_spend: 0,
        }
    }
}
