impl InMemoryBudgetStoreInner {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let request = BudgetMutationRequest::Increment {
            capability_id: capability_id.to_string(),
            grant_index,
            max_invocations,
        };
        let key = (capability_id.to_string(), grant_index);
        let current = self
            .counts
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Self::default_usage_record(capability_id, grant_index_u32));
        let quota = self.grant_quota_for_legacy_mutation(
            capability_id,
            grant_index_u32,
            current.invocation_count,
            max_invocations,
        )?;
        let mut allowed = true;
        if let Some(quota) = &quota {
            if let Some(existing) = self.invocation_quotas.get(&quota.key) {
                if existing.max_invocations != quota.max_invocations {
                    return Err(BudgetStoreError::Invariant(
                        "grant quota maximum changed".to_string(),
                    ));
                }
                let used = existing
                    .reserved_invocations
                    .checked_add(existing.captured_invocations)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved + captured quota count overflowed u32".to_string(),
                        )
                    })?;
                allowed = used < quota.max_invocations;
            } else {
                allowed = quota.max_invocations > 0;
            }
        }
        if self.has_composite_history(capability_id, grant_index) {
            return Err(BudgetStoreError::Invariant(
                "legacy invocation admission cannot bypass composite budget history".to_string(),
            ));
        }
        let invocation_quota_usages_before = quota
            .as_ref()
            .map(|quota| self.invocation_quota_usages(std::slice::from_ref(quota)))
            .transpose()?
            .unwrap_or_default();
        let recorded_at = unix_now();
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        let next_invocation_count = if allowed {
            current.invocation_count.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation_count overflowed u32".to_string())
            })?
        } else {
            current.invocation_count
        };
        let quota_update = if allowed {
            quota
                .as_ref()
                .map(|quota| {
                    let next_captured = self
                        .invocation_quotas
                        .get(&quota.key)
                        .map_or(0, |state| state.captured_invocations)
                        .checked_add(1)
                        .ok_or_else(|| {
                            BudgetStoreError::Overflow(
                                "captured invocation quota overflowed u32".to_string(),
                            )
                        })?;
                    Ok::<_, BudgetStoreError>((quota.clone(), next_captured))
                })
                .transpose()?
        } else {
            None
        };
        let legacy_reversible_after = if allowed {
            self.legacy_reversible_invocations
                .get(&(capability_id.to_string(), grant_index))
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "legacy reversible invocation count overflowed u32".to_string(),
                    )
                })?
        } else {
            0
        };
        self.next_seq = event_seq;
        let usage_seq = if allowed {
            let entry = self
                .counts
                .entry(key)
                .or_insert_with(|| Self::default_usage_record(capability_id, grant_index_u32));
            entry.invocation_count = next_invocation_count;
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            if let Some((quota, next_captured_invocations)) = quota_update {
                let state = self.invocation_quotas.entry(quota.key.clone()).or_insert(
                    BudgetInvocationQuotaState {
                        max_invocations: quota.max_invocations,
                        reserved_invocations: 0,
                        captured_invocations: 0,
                    },
                );
                state.captured_invocations = next_captured_invocations;
            }
            self.legacy_reversible_invocations.insert(
                (capability_id.to_string(), grant_index),
                legacy_reversible_after,
            );
            Some(event_seq)
        } else {
            None
        };
        let invocation_quota_usages = quota
            .as_ref()
            .map(|quota| self.invocation_quota_usages(std::slice::from_ref(quota)))
            .transpose()?
            .unwrap_or_default();
        let invocation_quota_mutations = Self::invocation_quota_mutations(
            &invocation_quota_usages_before,
            &invocation_quota_usages,
        )?;
        self.append_mutation(
            None,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: None,
                admission_binding: None,
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::IncrementInvocation,
                allowed: Some(allowed),
                authorization_outcome: Some(if allowed {
                    BudgetAuthorizationOutcome::Authorized
                } else {
                    BudgetAuthorizationOutcome::Denied
                }),
                invocation_state_before: BudgetInvocationState::Absent,
                invocation_state_after: if allowed {
                    BudgetInvocationState::Captured
                } else {
                    BudgetInvocationState::Denied
                },
                monetary_state_before: BudgetMonetaryState::None,
                monetary_state_after: BudgetMonetaryState::None,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units: 0,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: if allowed {
                    next_invocation_count
                } else {
                    current.invocation_count
                },
                invocation_quota_usages,
                invocation_quota_mutations,
                cumulative_approval: None,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: None,
                total_cost_exposed_after: current.total_cost_exposed,
                total_cost_realized_spend_after: current.total_cost_realized_spend,
                authority: None,
            },
        );
        Ok(allowed)
    }

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        validate_optional_budget_identity(hold_id, event_id, "budget authorization")?;
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let request = BudgetMutationRequest::Authorize {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            cost_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            authority: authority.cloned(),
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            if let Some(hold_id) = hold_id {
                self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "authorization")?;
            } else {
                self.ensure_latest_usage_event(
                    capability_id,
                    grant_index,
                    existing.record.event_seq,
                    "authorization",
                )?;
            }
            return Ok(existing.record.allowed.unwrap_or(false));
        }

        let key = (capability_id.to_string(), grant_index);
        let current = self
            .counts
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Self::default_usage_record(capability_id, grant_index_u32));
        let quota = self.grant_quota_for_legacy_mutation(
            capability_id,
            grant_index_u32,
            current.invocation_count,
            max_invocations,
        )?;
        let invocation_quota_usages_before = quota
            .as_ref()
            .map(|quota| self.invocation_quota_usages(std::slice::from_ref(quota)))
            .transpose()?
            .unwrap_or_default();

        let mut allowed = true;
        if let Some(quota) = &quota {
            if let Some(existing) = self.invocation_quotas.get(&quota.key) {
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
                allowed &= quota.max_invocations > 0;
            }
        }
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        let current_total = checked_committed_cost_units(
            current.total_cost_exposed,
            current.total_cost_realized_spend,
        )?;
        let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
            BudgetStoreError::Overflow(
                "authorized exposure + cost_units overflowed u64".to_string(),
            )
        })?;
        if let Some(max_total) = max_total_cost_units {
            if new_total > max_total {
                allowed = false;
            }
        }
        if self.has_composite_history(capability_id, grant_index) {
            return Err(BudgetStoreError::Invariant(
                "legacy budget admission cannot bypass composite budget history".to_string(),
            ));
        }

        let recorded_at = unix_now();
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        let next_invocation_count = allowed
            .then(|| {
                current.invocation_count.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow("invocation_count overflowed u32".to_string())
                })
            })
            .transpose()?;
        let next_exposure = allowed
            .then(|| {
                current
                    .total_cost_exposed
                    .checked_add(cost_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "total_cost_exposed + cost_units overflowed u64".to_string(),
                        )
                    })
            })
            .transpose()?;
        let next_quota_captured = if allowed {
            quota
                .as_ref()
                .map(|quota| {
                    self.invocation_quotas
                        .get(&quota.key)
                        .map_or(0, |state| state.captured_invocations)
                        .checked_add(1)
                        .ok_or_else(|| {
                            BudgetStoreError::Overflow(
                                "captured invocation quota overflowed u32".to_string(),
                            )
                        })
                })
                .transpose()?
        } else {
            None
        };
        let next_legacy_reversible = if allowed && hold_id.is_none() {
            Some(
                self.legacy_reversible_invocations
                    .get(&(capability_id.to_string(), grant_index))
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
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            usage_seq,
        );

        if allowed {
            if let Some(hold_id) = hold_id {
                if self.holds.contains_key(hold_id) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` already exists"
                    )));
                }
            }
            let checked_invocation_count = next_invocation_count.ok_or_else(|| {
                BudgetStoreError::Invariant("missing checked invocation count".to_string())
            })?;
            let checked_exposure = next_exposure.ok_or_else(|| {
                BudgetStoreError::Invariant("missing checked exposure".to_string())
            })?;
            let checked_quota_captured = if quota.is_some() {
                Some(next_quota_captured.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "missing checked captured invocation count".to_string(),
                    )
                })?)
            } else {
                None
            };
            self.next_seq = event_seq;
            let entry = self
                .counts
                .entry(key.clone())
                .or_insert_with(|| Self::default_usage_record(capability_id, grant_index_u32));
            entry.invocation_count = checked_invocation_count;
            entry.total_cost_exposed = checked_exposure;
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            if let Some(quota) = &quota {
                let state = self.invocation_quotas.entry(quota.key.clone()).or_insert(
                    BudgetInvocationQuotaState {
                        max_invocations: quota.max_invocations,
                        reserved_invocations: 0,
                        captured_invocations: 0,
                    },
                );
                if let Some(checked_quota_captured) = checked_quota_captured {
                    state.captured_invocations = checked_quota_captured;
                }
            }
            if let Some(next_legacy_reversible) = next_legacy_reversible {
                self.legacy_reversible_invocations.insert(
                    (capability_id.to_string(), grant_index),
                    next_legacy_reversible,
                );
            }
            if let Some(hold_id) = hold_id {
                self.holds.insert(
                    hold_id.to_string(),
                    BudgetHoldState {
                        capability_id: capability_id.to_string(),
                        grant_index,
                        admission_binding: None,
                        authorized_exposure_units: cost_units,
                        remaining_exposure_units: cost_units,
                        invocation_state: BudgetInvocationState::Authorized,
                        invocation_quotas: Vec::new(),
                        legacy_captured_invocation_quota: quota.clone(),
                        captured_cancellation_allowed: true,
                        cumulative_approval: None,
                        monetary_state: if cost_units == 0 {
                            BudgetMonetaryState::None
                        } else {
                            BudgetMonetaryState::Exposed
                        },
                        authority: authority.cloned(),
                        reserved_until: None,
                        reserved_currency: None,
                        reserved_payment_reference: None,
                        reserved_envelope: ReservedHoldEnvelope::default(),
                    },
                );
            }
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            usage_seq = Some(event_seq);
        } else {
            self.next_seq = event_seq;
            invocation_count_after = current.invocation_count;
            total_cost_exposed_after = current.total_cost_exposed;
            total_cost_realized_spend_after = current.total_cost_realized_spend;
            usage_seq = None;
        }

        let invocation_quota_usages = quota
            .as_ref()
            .map(|quota| self.invocation_quota_usages(std::slice::from_ref(quota)))
            .transpose()?
            .unwrap_or_default();
        let invocation_quota_mutations = Self::invocation_quota_mutations(
            &invocation_quota_usages_before,
            &invocation_quota_usages,
        )?;

        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                admission_binding: None,
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::AuthorizeExposure,
                allowed: Some(allowed),
                authorization_outcome: Some(if allowed {
                    BudgetAuthorizationOutcome::Authorized
                } else {
                    BudgetAuthorizationOutcome::Denied
                }),
                invocation_state_before: BudgetInvocationState::Absent,
                invocation_state_after: if allowed {
                    BudgetInvocationState::Authorized
                } else {
                    BudgetInvocationState::Denied
                },
                monetary_state_before: BudgetMonetaryState::None,
                monetary_state_after: if allowed && cost_units > 0 {
                    BudgetMonetaryState::Exposed
                } else {
                    BudgetMonetaryState::None
                },
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                invocation_count_after,
                invocation_quota_usages,
                invocation_quota_mutations,
                cumulative_approval: None,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: None,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );

        Ok(allowed)
    }

    fn capture_invocation_reservations(
        &mut self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<(bool, u64, String, BudgetUsageRecord), BudgetStoreError> {
        let grant_index = u32::try_from(request.grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let mutation = BudgetMutationRequest::CaptureInvocation {
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: request.hold_id.clone(),
            trusted_time: request.trusted_time,
            authority: request.authority.clone(),
        };
        if let Some(existing) = self.duplicate_mutation(Some(&request.event_id), &mutation)? {
            let hold = self.validate_hold(
                &request.hold_id,
                &request.capability_id,
                request.grant_index,
            )?;
            Self::validate_hold_authority(
                &request.hold_id,
                hold.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            if hold.invocation_state != BudgetInvocationState::Captured {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` capture event was superseded by a terminal transition",
                    request.hold_id
                )));
            }
            return Ok((
                false,
                existing.record.event_seq,
                existing.record.event_id,
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

        let hold = self
            .validate_hold(
                &request.hold_id,
                &request.capability_id,
                request.grant_index,
            )?
            .clone();
        Self::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if hold.authorized_exposure_units > 0
            && (hold.monetary_state != BudgetMonetaryState::Exposed
                || hold.remaining_exposure_units == 0)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no live monetary exposure for invocation capture",
                request.hold_id
            )));
        }
        if let Some(expires_at) = hold
            .admission_binding
            .as_ref()
            .and_then(|binding| binding.supplemental_authorization_expires_at)
        {
            let trusted_time = request.trusted_time.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "supplemental invocation capture requires trusted time".to_string(),
                )
            })?;
            if trusted_time >= expires_at {
                return Err(BudgetStoreError::Invariant(
                    "supplemental authorization expired before invocation capture".to_string(),
                ));
            }
        }
        if hold.invocation_state == BudgetInvocationState::Captured {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation reservations were already captured by another event",
                request.hold_id
            )));
        }
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation reservations are terminal",
                request.hold_id
            )));
        }
        if hold
            .cumulative_approval
            .as_ref()
            .is_some_and(|participant| {
                participant.state == BudgetCumulativeApprovalState::PendingApproval
            })
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` still requires cumulative approval",
                request.hold_id
            )));
        }

        let quota_usages_before = self.invocation_quota_usages(&hold.invocation_quotas)?;
        for quota in &hold.invocation_quotas {
            let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing reserved invocation quota".to_string())
            })?;
            if state.max_invocations != quota.max_invocations || state.reserved_invocations == 0 {
                return Err(BudgetStoreError::Invariant(
                    "invocation quota reservation does not match its hold".to_string(),
                ));
            }
            state.captured_invocations.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation quota overflowed u32".to_string())
            })?;
        }
        let cumulative_before = if let Some(participant) = &hold.cumulative_approval {
            if participant.state != BudgetCumulativeApprovalState::Authorized {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval participant is not authorized".to_string(),
                ));
            }
            let account = self
                .cumulative_approval_accounts
                .get(&participant.request.account_key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant("missing cumulative approval account".to_string())
                })?;
            if account.reserved_authorized_units < participant.request.requested_authorized.units {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval reservation is incomplete".to_string(),
                ));
            }
            account
                .captured_authorized_units
                .checked_add(participant.request.requested_authorized.units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "captured cumulative authorized units overflowed u64".to_string(),
                    )
                })?;
            account.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "cumulative approval account version overflowed u64".to_string(),
                )
            })?;
            Some((
                account.reserved_authorized_units,
                account.captured_authorized_units,
                account.version,
                participant.clone(),
            ))
        } else {
            None
        };

        let key = (request.capability_id.clone(), request.grant_index);
        let usage =
            self.counts.get(&key).cloned().ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        self.next_seq = event_seq;
        for quota in &hold.invocation_quotas {
            let state = self.invocation_quotas.get_mut(&quota.key).ok_or_else(|| {
                BudgetStoreError::Invariant("validated invocation quota disappeared".to_string())
            })?;
            state.reserved_invocations -= 1;
            state.captured_invocations += 1;
        }
        if let Some(participant) = &hold.cumulative_approval {
            let account = self
                .cumulative_approval_accounts
                .get_mut(&participant.request.account_key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "validated cumulative approval account disappeared".to_string(),
                    )
                })?;
            account.reserved_authorized_units -= participant.request.requested_authorized.units;
            account.captured_authorized_units += participant.request.requested_authorized.units;
            account.version += 1;
        }
        let quota_usages = self.invocation_quota_usages(&hold.invocation_quotas)?;
        let quota_mutations =
            Self::invocation_quota_mutations(&quota_usages_before, &quota_usages)?;
        let cumulative_approval = hold
            .cumulative_approval
            .as_ref()
            .map(|participant| {
                self.cumulative_approval_usage(
                    &participant.request,
                    BudgetCumulativeApprovalState::Captured,
                )
            })
            .transpose()?;
        let cumulative_approval_mutation = cumulative_before
            .as_ref()
            .map(
                |(reserved_before, captured_before, version_before, participant)| {
                    let account = self
                        .cumulative_approval_accounts
                        .get(&participant.request.account_key)
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "cumulative approval account disappeared".to_string(),
                            )
                        })?;
                    let amount = |units| chio_core::capability::scope::MonetaryAmount {
                        units,
                        currency: participant.request.account_key.currency.clone(),
                    };
                    Ok::<_, BudgetStoreError>(BudgetCumulativeApprovalMutation {
                        operation_id: participant.request.operation_id.clone(),
                        account_key: participant.request.account_key.clone(),
                        state_before: Some(BudgetCumulativeApprovalState::Authorized),
                        state_after: BudgetCumulativeApprovalState::Captured,
                        reserved_authorized_before: amount(*reserved_before),
                        captured_authorized_before: amount(*captured_before),
                        reserved_authorized_after: amount(account.reserved_authorized_units),
                        captured_authorized_after: amount(account.captured_authorized_units),
                        version_before: *version_before,
                        version_after: account.version,
                    })
                },
            )
            .transpose()?;
        let stored_hold = self.holds.get_mut(&request.hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant("validated budget hold missing".to_string())
        })?;
        stored_hold.invocation_state = BudgetInvocationState::Captured;
        if let Some(participant) = stored_hold.cumulative_approval.as_mut() {
            participant.state = BudgetCumulativeApprovalState::Captured;
        }
        self.append_mutation(
            Some(&request.event_id),
            mutation,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: Some(request.hold_id.clone()),
                admission_binding: hold.admission_binding.clone(),
                capability_id: request.capability_id.clone(),
                grant_index,
                kind: BudgetMutationKind::CaptureInvocation,
                allowed: Some(true),
                authorization_outcome: None,
                invocation_state_before: BudgetInvocationState::Authorized,
                invocation_state_after: BudgetInvocationState::Captured,
                monetary_state_before: hold.monetary_state,
                monetary_state_after: hold.monetary_state,
                recorded_at: unix_now(),
                event_seq,
                usage_seq: Some(usage.seq),
                exposure_units: hold.remaining_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: usage.invocation_count,
                invocation_quota_usages: quota_usages,
                invocation_quota_mutations: quota_mutations,
                cumulative_approval,
                cumulative_approval_mutation,
                cumulative_approval_set_digest: hold
                    .cumulative_approval
                    .as_ref()
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after: usage.total_cost_exposed,
                total_cost_realized_spend_after: usage.total_cost_realized_spend,
                authority: request.authority.clone(),
            },
        );
        Ok((true, event_seq, request.event_id.clone(), usage))
    }
}
