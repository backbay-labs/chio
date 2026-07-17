use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    budget_commit_metadata, checked_committed_cost_units, AuthorizedBudgetHold,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureHoldDecision,
    BudgetCaptureHoldRequest, BudgetEventAuthority, BudgetHoldMutationDecision, BudgetMutationKind,
    BudgetMutationRecord, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReleaseHoldDecision, BudgetReleaseHoldRequest, BudgetReverseHoldDecision,
    BudgetReverseHoldRequest, BudgetStore, BudgetStoreError, BudgetUsageRecord, DeniedBudgetHold,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetHoldDisposition {
    Open,
    Released,
    Reversed,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetHoldState {
    capability_id: String,
    grant_index: usize,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    invocation_count_debited: bool,
    disposition: BudgetHoldDisposition,
    authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetMutationRequest {
    Increment {
        capability_id: String,
        grant_index: usize,
        max_invocations: Option<u32>,
    },
    Authorize {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    },
    Reverse {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
    },
    Release {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        cost_units: u64,
    },
    Reconcile {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        authority: Option<BudgetEventAuthority>,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    },
}

#[derive(Debug, Clone)]
struct RecordedBudgetMutation {
    request: BudgetMutationRequest,
    record: BudgetMutationRecord,
}

pub struct InMemoryBudgetStore {
    inner: Mutex<InMemoryBudgetStoreInner>,
}

impl Default for InMemoryBudgetStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(InMemoryBudgetStoreInner::default()),
        }
    }
}

impl InMemoryBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, InMemoryBudgetStoreInner>, BudgetStoreError> {
        self.inner.lock().map_err(|_| {
            BudgetStoreError::Invariant("in-memory budget store lock poisoned".to_string())
        })
    }
}

#[derive(Default)]
struct InMemoryBudgetStoreInner {
    counts: HashMap<(String, usize), BudgetUsageRecord>,
    events: Vec<BudgetMutationRecord>,
    explicit_events: HashMap<String, RecordedBudgetMutation>,
    holds: HashMap<String, BudgetHoldState>,
    next_seq: u64,
    next_event_ordinal: u64,
}

impl InMemoryBudgetStoreInner {
    fn next_event_id(&mut self) -> String {
        self.next_event_ordinal = self.next_event_ordinal.saturating_add(1);
        format!("local-budget-event-{}", self.next_event_ordinal)
    }

    fn duplicate_mutation(
        &self,
        event_id: Option<&str>,
        request: &BudgetMutationRequest,
    ) -> Result<Option<RecordedBudgetMutation>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
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
            .unwrap_or_else(|| self.next_event_id());
        record.event_id = event_id.clone();
        self.events.push(record.clone());
        if explicit_event_id.is_some() {
            self.explicit_events
                .insert(event_id, RecordedBudgetMutation { request, record });
        }
    }

    fn validate_open_hold(
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
        if hold.disposition != BudgetHoldDisposition::Open {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is no longer open"
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

    fn default_usage_record(capability_id: &str, grant_index: usize) -> BudgetUsageRecord {
        BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_exposed: 0,
            total_cost_realized_spend: 0,
        }
    }
}

impl InMemoryBudgetStoreInner {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
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
            .unwrap_or_else(|| Self::default_usage_record(capability_id, grant_index));
        let allowed = max_invocations.is_none_or(|max| current.invocation_count < max);
        let recorded_at = unix_now();
        let event_seq = self.next_seq.saturating_add(1);
        self.next_seq = event_seq;
        let usage_seq = if allowed {
            let entry = self
                .counts
                .entry(key)
                .or_insert_with(|| Self::default_usage_record(capability_id, grant_index));
            entry.invocation_count = current.invocation_count.saturating_add(1);
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            Some(event_seq)
        } else {
            None
        };
        self.append_mutation(
            None,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: None,
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                kind: BudgetMutationKind::IncrementInvocation,
                allowed: Some(allowed),
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units: 0,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: if allowed {
                    current.invocation_count.saturating_add(1)
                } else {
                    current.invocation_count
                },
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
        let request = BudgetMutationRequest::Authorize {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            return Ok(existing.record.allowed.unwrap_or(false));
        }

        let key = (capability_id.to_string(), grant_index);
        let current = self
            .counts
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Self::default_usage_record(capability_id, grant_index));

        let mut allowed = true;
        if let Some(max) = max_invocations {
            if current.invocation_count >= max {
                allowed = false;
            }
        }
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        if let Some(max_total) = max_total_cost_units {
            let current_total = checked_committed_cost_units(
                current.total_cost_exposed,
                current.total_cost_realized_spend,
            )?;
            let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                allowed = false;
            }
        }

        let recorded_at = unix_now();
        let (invocation_count_after, total_cost_exposed_after, total_cost_realized_spend_after);
        let event_seq;
        let mut usage_seq = None;

        if allowed {
            if let Some(hold_id) = hold_id {
                if self.holds.contains_key(hold_id) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` already exists"
                    )));
                }
            }
            let new_total_cost_exposed = current
                .total_cost_exposed
                .checked_add(cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            event_seq = self.next_seq.saturating_add(1);
            self.next_seq = event_seq;
            let entry = self
                .counts
                .entry(key)
                .or_insert_with(|| Self::default_usage_record(capability_id, grant_index));
            entry.invocation_count = current.invocation_count.saturating_add(1);
            entry.total_cost_exposed = new_total_cost_exposed;
            entry.updated_at = recorded_at;
            entry.seq = event_seq;
            if let Some(hold_id) = hold_id {
                self.holds.insert(
                    hold_id.to_string(),
                    BudgetHoldState {
                        capability_id: capability_id.to_string(),
                        grant_index,
                        authorized_exposure_units: cost_units,
                        remaining_exposure_units: cost_units,
                        invocation_count_debited: true,
                        disposition: BudgetHoldDisposition::Open,
                        authority: authority.cloned(),
                    },
                );
            }
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            usage_seq = Some(event_seq);
        } else {
            event_seq = self.next_seq.saturating_add(1);
            self.next_seq = event_seq;
            invocation_count_after = current.invocation_count;
            total_cost_exposed_after = current.total_cost_exposed;
            total_cost_realized_spend_after = current.total_cost_realized_spend;
        }

        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                kind: BudgetMutationKind::AuthorizeExposure,
                allowed: Some(allowed),
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );

        Ok(allowed)
    }

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
        let request = BudgetMutationRequest::Reverse {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
        };
        if self.duplicate_mutation(event_id, &request)?.is_some() {
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
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
            let next_seq = self.next_seq.saturating_add(1);
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
        if let Some(hold_id) = hold_id {
            let Some(hold) = self.holds.get_mut(hold_id) else {
                return Err(BudgetStoreError::Invariant(
                    "validated hold missing during reverse_charge_cost".to_string(),
                ));
            };
            hold.remaining_exposure_units = 0;
            hold.disposition = BudgetHoldDisposition::Reversed;
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                kind: BudgetMutationKind::ReverseExposure,
                allowed: None,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
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
        let request = BudgetMutationRequest::Release {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            cost_units,
        };
        if self.duplicate_mutation(event_id, &request)?.is_some() {
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units < cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
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

            let next_seq = self.next_seq.saturating_add(1);
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
                hold.disposition = BudgetHoldDisposition::Released;
            }
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
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
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        let request = BudgetMutationRequest::Reconcile {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.map(ToOwned::to_owned),
            authority: authority.cloned(),
            exposed_cost_units,
            realized_cost_units,
        };
        if self.duplicate_mutation(event_id, &request)?.is_some() {
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = self.validate_open_hold(hold_id, capability_id, grant_index)?;
            if hold.remaining_exposure_units != exposed_cost_units {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
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

            entry.total_cost_realized_spend = entry
                .total_cost_realized_spend
                .checked_add(realized_cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_realized_spend + realized_cost_units overflowed u64"
                            .to_string(),
                    )
                })?;
            entry.total_cost_exposed -= exposed_cost_units;

            let next_seq = self.next_seq.saturating_add(1);
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
            hold.disposition = BudgetHoldDisposition::Reconciled;
            hold.authority = authority.cloned().or_else(|| hold.authority.clone());
        }
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: hold_id.map(ToOwned::to_owned),
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                kind: BudgetMutationKind::ReconcileSpend,
                allowed: None,
                recorded_at: unix_now(),
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: exposed_cost_units,
                realized_spend_units: realized_cost_units,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
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

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let mut events = self
            .events
            .iter()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .filter(|record| grant_index.is_none_or(|value| record.grant_index == value as u32))
            .cloned()
            .collect::<Vec<_>>();
        events.truncate(limit);
        Ok(events)
    }
}

impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?
            .try_increment(capability_id, grant_index, max_invocations)
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
        self.lock_inner()?.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
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
        self.lock_inner()?.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
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
        self.lock_inner()?.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.reverse_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.reduce_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
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
        self.lock_inner()?.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        self.lock_inner()?
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.payment_journal.is_some() {
            // The in-memory store cannot journal the money path durably, and
            // a silently dropped journal row would leave a rail movement
            // unrecoverable after a crash. Deny rather than proceed.
            return Err(BudgetStoreError::Invariant(
                "payment journal is not supported by this budget store".to_string(),
            ));
        }
        let mut inner = self.lock_inner()?;
        let allowed = inner.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = inner.get_usage(&request.capability_id, request.grant_index)?;
        let committed_cost_units_after = usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()?
            .unwrap_or(0);
        let invocation_count_after = usage.as_ref().map_or(0, |usage| usage.invocation_count);
        let metadata = budget_commit_metadata(
            self,
            request.authority,
            allowed
                .then(|| usage.as_ref().map(|usage| usage.seq))
                .flatten(),
            request.event_id,
        );

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        inner.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = inner.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        inner.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = inner.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        inner.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = inner.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        self.reconcile_budget_hold(request)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
