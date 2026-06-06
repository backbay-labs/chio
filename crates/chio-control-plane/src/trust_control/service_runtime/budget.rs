use super::client::build_client;
use super::errors::into_budget_store_error;
use super::*;

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        cached_usage: Mutex::new(HashMap::new()),
    }))
}

impl BudgetStore for RemoteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(response.budget_authority.as_ref(), None),
                    response.invocation_count,
                    None,
                    None,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_charge_cost_with_ids(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reconcile_budget_spend(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reconcile_budget_spend_with_ids(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let response = self
            .client
            .try_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        let metadata = self.remote_budget_commit_metadata(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            request.event_id.clone(),
        );
        if response.allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: usage.committed_cost_units()?,
                    invocation_count_after: usage.invocation_count,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after: usage.committed_cost_units()?,
                invocation_count_after: usage.invocation_count,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reverse_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.reversed_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reduce_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.released_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reconcile_budget_spend_with_ids(
                &request.capability_id,
                request.grant_index,
                request.exposed_cost_units,
                request.realized_spend_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map(|response| {
                let usages: Vec<_> = response
                    .usages
                    .into_iter()
                    .map(|usage| BudgetUsageRecord {
                        capability_id: usage.capability_id,
                        grant_index: usage.grant_index,
                        invocation_count: usage.invocation_count,
                        updated_at: usage.updated_at,
                        seq: usage.seq.unwrap_or(0),
                        total_cost_exposed: usage.total_cost_exposed,
                        total_cost_realized_spend: usage.total_cost_realized_spend,
                    })
                    .collect();
                self.replace_cached_usages(capability_id, &usages);
                usages
            })
            .map_err(into_budget_store_error)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        if let Some(cached) = self.cached_usage(capability_id, grant_index) {
            return Ok(Some(cached));
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index as u32)
            })
    }
}

impl RemoteBudgetStore {
    fn cache_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (capability_id.to_string(), grant_index as u32);
        let updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        match (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        ) {
            (None, None, None) => {
                cached_usage.remove(&key);
            }
            _ => {
                let entry = cached_usage
                    .entry(key)
                    .or_insert_with(|| BudgetUsageRecord {
                        capability_id: capability_id.to_string(),
                        grant_index: grant_index as u32,
                        invocation_count: 0,
                        updated_at,
                        seq: seq.unwrap_or(0),
                        total_cost_exposed: 0,
                        total_cost_realized_spend: 0,
                    });
                if let Some(seq) = seq {
                    entry.seq = seq;
                }
                if let Some(invocation_count) = invocation_count {
                    entry.invocation_count = invocation_count;
                }
                if let Some(total_cost_exposed) = total_cost_exposed {
                    entry.total_cost_exposed = total_cost_exposed;
                }
                if let Some(total_cost_realized_spend) = total_cost_realized_spend {
                    entry.total_cost_realized_spend = total_cost_realized_spend;
                }
                entry.updated_at = updated_at;
            }
        }
    }

    fn cached_usage(&self, capability_id: &str, grant_index: usize) -> Option<BudgetUsageRecord> {
        match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
        .get(&(capability_id.to_string(), grant_index as u32))
        .cloned()
    }

    fn replace_cached_usages(&self, capability_id: Option<&str>, usages: &[BudgetUsageRecord]) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(capability_id) = capability_id {
            cached_usage
                .retain(|(cached_capability_id, _), _| cached_capability_id != capability_id);
        } else {
            cached_usage.clear();
        }

        for usage in usages {
            cached_usage.insert(
                (usage.capability_id.clone(), usage.grant_index),
                usage.clone(),
            );
        }
    }

    fn cached_usage_or_default(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> BudgetUsageRecord {
        self.cached_usage(capability_id, grant_index)
            .unwrap_or_else(|| BudgetUsageRecord {
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                invocation_count: 0,
                updated_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as i64)
                    .unwrap_or(0),
                seq: 0,
                total_cost_exposed: 0,
                total_cost_realized_spend: 0,
            })
    }

    fn remote_budget_commit_metadata(
        &self,
        authority: Option<&BudgetAuthorityMetadataView>,
        commit: Option<&BudgetWriteCommitView>,
        fallback_authority: Option<&BudgetEventAuthority>,
        event_id: Option<String>,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: remote_budget_event_authority(authority, commit)
                .or_else(|| fallback_authority.cloned()),
            guarantee_level: remote_budget_guarantee_level(authority, commit),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: response_budget_commit_index(authority, commit),
            event_id,
        }
    }
}

fn response_budget_commit_index(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<u64> {
    commit
        .map(|commit| commit.commit_index)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index))
}

fn remote_budget_event_authority(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<BudgetEventAuthority> {
    authority
        .map(|authority| BudgetEventAuthority {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        })
        .or_else(|| {
            commit.map(|commit| BudgetEventAuthority {
                authority_id: commit.authority_id.clone(),
                lease_id: commit.lease_id.clone(),
                lease_epoch: commit.lease_epoch,
            })
        })
}

fn remote_budget_guarantee_level(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> BudgetGuaranteeLevel {
    match authority.map(|authority| authority.guarantee_level.as_str()) {
        Some("single_node_atomic") => BudgetGuaranteeLevel::SingleNodeAtomic,
        Some("ha_quorum_commit") | Some("ha_linearizable") => BudgetGuaranteeLevel::HaLinearizable,
        Some("partition_escrowed") => BudgetGuaranteeLevel::PartitionEscrowed,
        Some("ha_leader_visible") | Some("advisory_posthoc") => {
            BudgetGuaranteeLevel::AdvisoryPosthoc
        }
        Some(_) => {
            if commit.is_some_and(|commit| commit.quorum_committed) {
                BudgetGuaranteeLevel::HaLinearizable
            } else {
                BudgetGuaranteeLevel::AdvisoryPosthoc
            }
        }
        None => {
            if commit.is_some_and(|commit| commit.quorum_committed) {
                BudgetGuaranteeLevel::HaLinearizable
            } else {
                BudgetGuaranteeLevel::SingleNodeAtomic
            }
        }
    }
}
