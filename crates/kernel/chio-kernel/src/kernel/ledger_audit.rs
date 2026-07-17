use std::collections::HashMap;

use chio_log_redact::redacted;
use tracing::debug;

use crate::budget_store::{BudgetGuaranteeLevel, BudgetMutationKind};

use super::ChioKernel;

/// Debug-only replay of the reservation law.
///
/// Reservation law (normative text in `chio-kernel/src/budget_store.rs`):
/// 1. Partition: reserved amount equals committed plus released plus retained
///    plus outstanding at every reachable state, and outstanding is nonnegative.
/// 2. Terminal uniqueness: a terminal admission has no outstanding amount and
///    exactly one terminal classification.
/// 3. Child splits: admitted sibling shares never exceed the parent share, and
///    every child independently obeys clauses 1 and 2.
///
/// The bounded lifecycle model, scalar transition, journal replay, and
/// stateful store sequence tests independently enforce this partition.
/// Agreement across those surfaces is required because none observes every
/// production side effect.
///
/// `JournalState` has no retained column because `BudgetMutationKind` has no
/// retain mutation. This replay covers monetary reserve, commit, release, and
/// outstanding amounts only. It does not establish retained monetary holds or
/// crash recovery. `debug_assert_runtime_reservations_retained` separately
/// validates runtime lease IDs and their retention marker in receipt metadata.
/// Events without hold IDs are conserved as one anonymous pool; they do not
/// establish per-hold identity. Kernel reverse and reconcile call sites require
/// their named hold to reach exactly one terminal mutation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct JournalState {
    invocations: u64,
    reserved_total: u64,
    outstanding: u64,
    committed: u64,
    released: u64,
}

impl JournalState {
    fn apply(
        self,
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        exposure: u64,
        realized: u64,
    ) -> Result<Self, &'static str> {
        let mut next = self;
        match kind {
            BudgetMutationKind::IncrementInvocation => {
                if allowed == Some(true) {
                    next.invocations = next
                        .invocations
                        .checked_add(1)
                        .ok_or("invocation count overflow")?;
                }
            }
            BudgetMutationKind::AuthorizeExposure => {
                if allowed == Some(true) {
                    next.invocations = next
                        .invocations
                        .checked_add(1)
                        .ok_or("invocation count overflow")?;
                    next.outstanding = next
                        .outstanding
                        .checked_add(exposure)
                        .ok_or("outstanding exposure overflow")?;
                    next.reserved_total = next
                        .reserved_total
                        .checked_add(exposure)
                        .ok_or("reserved total overflow")?;
                }
            }
            BudgetMutationKind::ReverseExposure | BudgetMutationKind::ExpireHold => {
                next.invocations = next
                    .invocations
                    .checked_sub(1)
                    .ok_or("reversal without an invocation")?;
                next.outstanding = next
                    .outstanding
                    .checked_sub(exposure)
                    .ok_or("reversal exceeds outstanding exposure")?;
                next.released = next
                    .released
                    .checked_add(exposure)
                    .ok_or("released exposure overflow")?;
            }
            BudgetMutationKind::ReleaseExposure => {
                next.outstanding = next
                    .outstanding
                    .checked_sub(exposure)
                    .ok_or("release exceeds outstanding exposure")?;
                next.released = next
                    .released
                    .checked_add(exposure)
                    .ok_or("released exposure overflow")?;
            }
            BudgetMutationKind::ReconcileSpend => {
                if realized > exposure {
                    return Err("realized spend exceeds reconciled exposure");
                }
                next.outstanding = next
                    .outstanding
                    .checked_sub(exposure)
                    .ok_or("reconciliation exceeds outstanding exposure")?;
                next.committed = next
                    .committed
                    .checked_add(realized)
                    .ok_or("committed spend overflow")?;
                next.released = next
                    .released
                    .checked_add(exposure - realized)
                    .ok_or("released reconciliation remainder overflow")?;
            }
        }
        Ok(next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HoldState {
    remaining: u64,
    terminal: bool,
}

fn apply_hold_event(
    holds: &mut HashMap<String, HoldState>,
    unnamed_outstanding: &mut u64,
    event_id: &str,
    hold_id: Option<&str>,
    kind: BudgetMutationKind,
    allowed: Option<bool>,
    exposure: u64,
) -> Result<(), String> {
    let Some(hold_id) = hold_id else {
        match kind {
            BudgetMutationKind::AuthorizeExposure if allowed == Some(true) => {
                *unnamed_outstanding = unnamed_outstanding
                    .checked_add(exposure)
                    .ok_or_else(|| format!("event {event_id} overflowed unnamed holds"))?;
            }
            BudgetMutationKind::ReverseExposure
            | BudgetMutationKind::ReleaseExposure
            | BudgetMutationKind::ReconcileSpend
            | BudgetMutationKind::ExpireHold => {
                *unnamed_outstanding =
                    unnamed_outstanding.checked_sub(exposure).ok_or_else(|| {
                        format!("event {event_id} disposed exposure without a matching hold id")
                    })?;
            }
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {}
        }
        return Ok(());
    };
    match kind {
        BudgetMutationKind::AuthorizeExposure if allowed == Some(true) => {
            if holds
                .insert(
                    hold_id.to_string(),
                    HoldState {
                        remaining: exposure,
                        terminal: false,
                    },
                )
                .is_some()
            {
                return Err(format!(
                    "event {event_id} authorized duplicate hold {hold_id}"
                ));
            }
        }
        BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::ReleaseExposure
        | BudgetMutationKind::ReconcileSpend
        | BudgetMutationKind::ExpireHold => {
            let hold = holds
                .get_mut(hold_id)
                .ok_or_else(|| format!("event {event_id} mutated unknown hold {hold_id}"))?;
            if hold.terminal {
                return Err(format!(
                    "event {event_id} applied a second terminal mutation to hold {hold_id}"
                ));
            }
            hold.remaining = hold
                .remaining
                .checked_sub(exposure)
                .ok_or_else(|| format!("event {event_id} over-disposed hold {hold_id}"))?;
            if kind != BudgetMutationKind::ReleaseExposure || hold.remaining == 0 {
                if hold.remaining != 0 {
                    return Err(format!(
                        "event {event_id} terminally disposed only part of hold {hold_id}"
                    ));
                }
                hold.terminal = true;
            }
        }
        BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {}
    }
    Ok(())
}

impl ChioKernel {
    pub(crate) fn debug_assert_reservation_conservation(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) {
        self.debug_assert_reservation_conservation_inner(capability_id, grant_index, None);
    }

    pub(crate) fn debug_assert_terminal_reservation_conservation(
        &self,
        capability_id: &str,
        grant_index: usize,
        hold_id: &str,
    ) {
        self.debug_assert_reservation_conservation_inner(capability_id, grant_index, Some(hold_id));
    }

    fn debug_assert_reservation_conservation_inner(
        &self,
        capability_id: &str,
        grant_index: usize,
        terminal_hold_id: Option<&str>,
    ) {
        if self.budget_store.budget_guarantee_level() != BudgetGuaranteeLevel::SingleNodeAtomic {
            debug!(
                capability_id,
                grant_index, "reservation audit skipped for a non-single-node budget backend"
            );
            return;
        }
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let events = match self.budget_store.list_mutation_events(
            i64::MAX as usize,
            Some(capability_id),
            Some(grant_index),
        ) {
            Ok(events) => events,
            Err(error) => {
                debug!(
                    capability_id,
                    grant_index,
                    reason = %redacted!(&error),
                    "reservation audit skipped because the journal is unavailable"
                );
                return;
            }
        };

        let mut state = JournalState::default();
        let mut holds = HashMap::new();
        let mut unnamed_outstanding = 0u64;
        for event in events {
            if let Err(reason) = apply_hold_event(
                &mut holds,
                &mut unnamed_outstanding,
                &event.event_id,
                event.hold_id.as_deref(),
                event.kind,
                event.allowed,
                event.exposure_units,
            ) {
                panic!("reservation hold history violated uniqueness: {reason}");
            }
            let next = match state.apply(
                event.kind,
                event.allowed,
                event.exposure_units,
                event.realized_spend_units,
            ) {
                Ok(next) => next,
                Err(reason) => panic!(
                    "reservation journal violated conservation at event {}: {}",
                    event.event_id, reason
                ),
            };
            debug_assert_eq!(
                next.invocations,
                u64::from(event.invocation_count_after),
                "reservation journal invocation snapshot drift at event {}",
                event.event_id
            );
            debug_assert_eq!(
                u128::from(next.reserved_total),
                u128::from(next.outstanding)
                    + u128::from(next.committed)
                    + u128::from(next.released),
                "reservation partition drift at event {}",
                event.event_id
            );
            let named_outstanding = holds
                .values()
                .map(|hold| u128::from(hold.remaining))
                .sum::<u128>();
            debug_assert_eq!(
                u128::from(next.outstanding),
                named_outstanding + u128::from(unnamed_outstanding),
                "reservation hold identities drifted at event {}",
                event.event_id
            );
            debug_assert_eq!(
                next.outstanding, event.total_cost_exposed_after,
                "reservation journal exposure snapshot drift at event {}",
                event.event_id
            );
            debug_assert_eq!(
                next.committed, event.total_cost_realized_spend_after,
                "reservation journal spend snapshot drift at event {}",
                event.event_id
            );
            state = next;
        }

        let usage = match self.budget_store.get_usage(capability_id, grant_index) {
            Ok(usage) => usage,
            Err(error) => {
                debug!(
                    capability_id,
                    grant_index,
                    reason = %redacted!(&error),
                    "reservation audit skipped because the usage row is unavailable"
                );
                return;
            }
        };
        match usage {
            Some(usage) => {
                debug_assert_eq!(state.invocations, u64::from(usage.invocation_count));
                debug_assert_eq!(state.outstanding, usage.total_cost_exposed);
                debug_assert_eq!(state.committed, usage.total_cost_realized_spend);
            }
            None => debug_assert_eq!(state, JournalState::default()),
        }
        if let Some(hold_id) = terminal_hold_id {
            debug_assert!(
                holds
                    .get(hold_id)
                    .is_some_and(|hold| hold.terminal && hold.remaining == 0),
                "reservation hold {hold_id} did not reach exactly one terminal mutation"
            );
        }
    }

    pub(crate) fn debug_assert_runtime_reservations_retained(
        &self,
        metadata: Option<&serde_json::Value>,
    ) {
        let Some(runtime) = metadata
            .and_then(|value| value.get("chio_runtime"))
            .and_then(serde_json::Value::as_object)
        else {
            return;
        };
        let pairs = [
            (
                "reserved_destructive_lease_id",
                "retained_destructive_lease_id",
            ),
            (
                "reserved_treaty_continuation_id",
                "retained_treaty_continuation_id",
            ),
            (
                "reserved_swarm_continuation_id",
                "retained_swarm_continuation_id",
            ),
        ];
        let mut had_reservation = false;
        for (reserved_key, retained_key) in pairs {
            let reserved = runtime
                .get(reserved_key)
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty());
            if let Some(reserved) = reserved {
                had_reservation = true;
                debug_assert_eq!(
                    runtime
                        .get(retained_key)
                        .and_then(serde_json::Value::as_str),
                    Some(reserved),
                    "retained runtime reservation does not match its admitted id"
                );
            } else {
                debug_assert!(
                    runtime.get(retained_key).is_none(),
                    "runtime metadata retained an id that was not reserved"
                );
            }
        }
        debug_assert_eq!(
            runtime
                .get("reservations_retained_fail_closed")
                .and_then(serde_json::Value::as_bool),
            had_reservation.then_some(true),
            "runtime reservation retention marker drifted from retained ids"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_release_is_rejected_by_the_replay() {
        let result = JournalState::default().apply(BudgetMutationKind::ReleaseExposure, None, 1, 0);
        assert_eq!(result, Err("release exceeds outstanding exposure"));
    }

    #[test]
    fn reconcile_tracks_outstanding_and_committed_amounts() {
        let authorized = JournalState::default()
            .apply(BudgetMutationKind::AuthorizeExposure, Some(true), 8, 0)
            .unwrap_or_else(|error| panic!("authorize replay failed: {error}"));
        let reconciled = authorized
            .apply(BudgetMutationKind::ReconcileSpend, None, 8, 5)
            .unwrap_or_else(|error| panic!("reconcile replay failed: {error}"));
        assert_eq!(
            reconciled,
            JournalState {
                invocations: 1,
                reserved_total: 8,
                outstanding: 0,
                committed: 5,
                released: 3,
            }
        );
    }

    #[test]
    fn expired_hold_releases_exposure_and_invocation() {
        let authorized = JournalState::default()
            .apply(BudgetMutationKind::AuthorizeExposure, Some(true), 8, 0)
            .unwrap_or_else(|error| panic!("authorize replay failed: {error}"));
        let expired = authorized
            .apply(BudgetMutationKind::ExpireHold, Some(true), 8, 0)
            .unwrap_or_else(|error| panic!("expiry replay failed: {error}"));
        assert_eq!(
            expired,
            JournalState {
                invocations: 0,
                reserved_total: 8,
                outstanding: 0,
                committed: 0,
                released: 8,
            }
        );
    }

    #[test]
    fn named_hold_cannot_be_disposed_without_its_identity() {
        let mut holds = HashMap::new();
        let mut unnamed_outstanding = 0;
        apply_hold_event(
            &mut holds,
            &mut unnamed_outstanding,
            "authorize",
            Some("hold-1"),
            BudgetMutationKind::AuthorizeExposure,
            Some(true),
            8,
        )
        .unwrap_or_else(|error| panic!("named authorization failed: {error}"));

        let result = apply_hold_event(
            &mut holds,
            &mut unnamed_outstanding,
            "release-without-id",
            None,
            BudgetMutationKind::ReleaseExposure,
            None,
            8,
        );
        assert_eq!(
            result,
            Err(
                "event release-without-id disposed exposure without a matching hold id".to_string()
            )
        );
    }
}
