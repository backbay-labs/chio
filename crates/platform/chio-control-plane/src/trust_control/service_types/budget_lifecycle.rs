use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetAuthorizationOutcomeView {
    Authorized,
    ApprovalRequired,
    Denied,
}

impl From<BudgetAuthorizationOutcome> for BudgetAuthorizationOutcomeView {
    fn from(value: BudgetAuthorizationOutcome) -> Self {
        match value {
            BudgetAuthorizationOutcome::Authorized => Self::Authorized,
            BudgetAuthorizationOutcome::ApprovalRequired => Self::ApprovalRequired,
            BudgetAuthorizationOutcome::Denied => Self::Denied,
        }
    }
}

impl From<BudgetAuthorizationOutcomeView> for BudgetAuthorizationOutcome {
    fn from(value: BudgetAuthorizationOutcomeView) -> Self {
        match value {
            BudgetAuthorizationOutcomeView::Authorized => Self::Authorized,
            BudgetAuthorizationOutcomeView::ApprovalRequired => Self::ApprovalRequired,
            BudgetAuthorizationOutcomeView::Denied => Self::Denied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetInvocationStateView {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

impl From<BudgetInvocationState> for BudgetInvocationStateView {
    fn from(value: BudgetInvocationState) -> Self {
        match value {
            BudgetInvocationState::Absent => Self::Absent,
            BudgetInvocationState::Authorized => Self::Authorized,
            BudgetInvocationState::Captured => Self::Captured,
            BudgetInvocationState::Reversed => Self::Reversed,
            BudgetInvocationState::Denied => Self::Denied,
        }
    }
}

impl From<BudgetInvocationStateView> for BudgetInvocationState {
    fn from(value: BudgetInvocationStateView) -> Self {
        match value {
            BudgetInvocationStateView::Absent => Self::Absent,
            BudgetInvocationStateView::Authorized => Self::Authorized,
            BudgetInvocationStateView::Captured => Self::Captured,
            BudgetInvocationStateView::Reversed => Self::Reversed,
            BudgetInvocationStateView::Denied => Self::Denied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetMonetaryStateView {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

impl From<BudgetMonetaryState> for BudgetMonetaryStateView {
    fn from(value: BudgetMonetaryState) -> Self {
        match value {
            BudgetMonetaryState::None => Self::None,
            BudgetMonetaryState::Exposed => Self::Exposed,
            BudgetMonetaryState::Released => Self::Released,
            BudgetMonetaryState::Reconciled => Self::Reconciled,
            BudgetMonetaryState::Captured => Self::Captured,
            BudgetMonetaryState::Reversed => Self::Reversed,
        }
    }
}

impl From<BudgetMonetaryStateView> for BudgetMonetaryState {
    fn from(value: BudgetMonetaryStateView) -> Self {
        match value {
            BudgetMonetaryStateView::None => Self::None,
            BudgetMonetaryStateView::Exposed => Self::Exposed,
            BudgetMonetaryStateView::Released => Self::Released,
            BudgetMonetaryStateView::Reconciled => Self::Reconciled,
            BudgetMonetaryStateView::Captured => Self::Captured,
            BudgetMonetaryStateView::Reversed => Self::Reversed,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetMutationLifecycleView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_outcome: Option<BudgetAuthorizationOutcomeView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_state_before: Option<BudgetInvocationStateView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_state_after: Option<BudgetInvocationStateView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    monetary_state_before: Option<BudgetMonetaryStateView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    monetary_state_after: Option<BudgetMonetaryStateView>,
}

#[derive(Debug)]
pub(crate) struct ResolvedBudgetMutationLifecycle {
    pub(crate) authorization_outcome: Option<BudgetAuthorizationOutcome>,
    pub(crate) invocation_state_before: BudgetInvocationState,
    pub(crate) invocation_state_after: BudgetInvocationState,
    pub(crate) monetary_state_before: BudgetMonetaryState,
    pub(crate) monetary_state_after: BudgetMonetaryState,
}

impl BudgetMutationLifecycleView {
    pub(crate) fn from_record(record: &BudgetMutationRecord) -> Self {
        Self {
            authorization_outcome: record.authorization_outcome.map(Into::into),
            invocation_state_before: Some(record.invocation_state_before.into()),
            invocation_state_after: Some(record.invocation_state_after.into()),
            monetary_state_before: Some(record.monetary_state_before.into()),
            monetary_state_after: Some(record.monetary_state_after.into()),
        }
    }

    pub(crate) fn resolve(
        &self,
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        has_hold: bool,
        exposure_units: u64,
        realized_spend_units: u64,
    ) -> Result<ResolvedBudgetMutationLifecycle, String> {
        let authorization_outcome = expected_authorization_outcome(kind, allowed)?;
        let (expected_invocation_before, expected_invocation_after) =
            expected_invocation_transition(kind, allowed, has_hold);
        let invocation_state_before = self
            .invocation_state_before
            .map(Into::into)
            .unwrap_or(expected_invocation_before);
        let invocation_state_after = self
            .invocation_state_after
            .map(Into::into)
            .unwrap_or(expected_invocation_after);

        let supplied_monetary_before = self.monetary_state_before.map(Into::into);
        let supplied_monetary_after = self.monetary_state_after.map(Into::into);
        let (monetary_state_before, monetary_state_after) = match kind {
            BudgetMutationKind::AuthorizeCumulativeApproval => {
                let state = supplied_monetary_before
                    .or(supplied_monetary_after)
                    .ok_or_else(|| ambiguous_legacy_lifecycle(kind, "monetary state"))?;
                (
                    supplied_monetary_before.unwrap_or(state),
                    supplied_monetary_after.unwrap_or(state),
                )
            }
            BudgetMutationKind::ReleaseExposure if has_hold => (
                supplied_monetary_before.unwrap_or(BudgetMonetaryState::Exposed),
                supplied_monetary_after
                    .ok_or_else(|| ambiguous_legacy_lifecycle(kind, "monetary state after"))?,
            ),
            _ => {
                let (before, after) = expected_monetary_transition(kind, allowed, exposure_units)?;
                (
                    supplied_monetary_before.unwrap_or(before),
                    supplied_monetary_after.unwrap_or(after),
                )
            }
        };

        let resolved = ResolvedBudgetMutationLifecycle {
            authorization_outcome: self
                .authorization_outcome
                .map(Into::into)
                .or(authorization_outcome),
            invocation_state_before,
            invocation_state_after,
            monetary_state_before,
            monetary_state_after,
        };
        validate_transition(
            &resolved,
            kind,
            allowed,
            authorization_outcome,
            expected_invocation_before,
            expected_invocation_after,
            has_hold,
            exposure_units,
            realized_spend_units,
        )?;
        Ok(resolved)
    }
}

fn expected_authorization_outcome(
    kind: BudgetMutationKind,
    allowed: Option<bool>,
) -> Result<Option<BudgetAuthorizationOutcome>, String> {
    let outcome = match kind {
        BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {
            match allowed {
                Some(true) => BudgetAuthorizationOutcome::Authorized,
                Some(false) => BudgetAuthorizationOutcome::Denied,
                None => return Err(invalid_lifecycle(kind)),
            }
        }
        BudgetMutationKind::ReserveInvocation => match allowed {
            Some(true) => BudgetAuthorizationOutcome::Authorized,
            Some(false) => BudgetAuthorizationOutcome::Denied,
            None => BudgetAuthorizationOutcome::ApprovalRequired,
        },
        BudgetMutationKind::AuthorizeCumulativeApproval if allowed == Some(true) => {
            BudgetAuthorizationOutcome::Authorized
        }
        BudgetMutationKind::CaptureInvocation if allowed == Some(true) => return Ok(None),
        BudgetMutationKind::CancelCapturedBeforeDispatch if allowed == Some(true) => {
            return Ok(None)
        }
        BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::ReleaseExposure
        | BudgetMutationKind::ReconcileSpend
        | BudgetMutationKind::CaptureSpend
            if allowed.is_none() =>
        {
            return Ok(None)
        }
        _ => return Err(invalid_lifecycle(kind)),
    };
    Ok(Some(outcome))
}

fn expected_invocation_transition(
    kind: BudgetMutationKind,
    allowed: Option<bool>,
    has_hold: bool,
) -> (BudgetInvocationState, BudgetInvocationState) {
    match kind {
        BudgetMutationKind::IncrementInvocation => (
            BudgetInvocationState::Absent,
            if allowed == Some(true) {
                BudgetInvocationState::Captured
            } else {
                BudgetInvocationState::Denied
            },
        ),
        BudgetMutationKind::ReserveInvocation | BudgetMutationKind::AuthorizeExposure => (
            BudgetInvocationState::Absent,
            if allowed == Some(false) {
                BudgetInvocationState::Denied
            } else {
                BudgetInvocationState::Authorized
            },
        ),
        BudgetMutationKind::CaptureInvocation => (
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Captured,
        ),
        BudgetMutationKind::AuthorizeCumulativeApproval => (
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Authorized,
        ),
        BudgetMutationKind::ReverseInvocation | BudgetMutationKind::ReverseExposure => (
            BudgetInvocationState::Authorized,
            BudgetInvocationState::Reversed,
        ),
        BudgetMutationKind::CancelCapturedBeforeDispatch => (
            BudgetInvocationState::Captured,
            BudgetInvocationState::Reversed,
        ),
        BudgetMutationKind::ReleaseExposure => {
            let state = if has_hold {
                BudgetInvocationState::Authorized
            } else {
                BudgetInvocationState::Absent
            };
            (state, state)
        }
        BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureSpend => {
            let state = if has_hold {
                BudgetInvocationState::Captured
            } else {
                BudgetInvocationState::Absent
            };
            (state, state)
        }
    }
}

fn expected_monetary_transition(
    kind: BudgetMutationKind,
    allowed: Option<bool>,
    exposure_units: u64,
) -> Result<(BudgetMonetaryState, BudgetMonetaryState), String> {
    let has_exposure = exposure_units > 0;
    let transition = match kind {
        BudgetMutationKind::IncrementInvocation => {
            (BudgetMonetaryState::None, BudgetMonetaryState::None)
        }
        BudgetMutationKind::ReserveInvocation | BudgetMutationKind::AuthorizeExposure => (
            BudgetMonetaryState::None,
            if allowed != Some(false) && has_exposure {
                BudgetMonetaryState::Exposed
            } else {
                BudgetMonetaryState::None
            },
        ),
        BudgetMutationKind::CaptureInvocation => {
            let state = if has_exposure {
                BudgetMonetaryState::Exposed
            } else {
                BudgetMonetaryState::None
            };
            (state, state)
        }
        BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::CancelCapturedBeforeDispatch
        | BudgetMutationKind::ReverseExposure => (
            if has_exposure {
                BudgetMonetaryState::Exposed
            } else {
                BudgetMonetaryState::None
            },
            if has_exposure {
                BudgetMonetaryState::Reversed
            } else {
                BudgetMonetaryState::None
            },
        ),
        BudgetMutationKind::ReleaseExposure => {
            (BudgetMonetaryState::Exposed, BudgetMonetaryState::Released)
        }
        BudgetMutationKind::ReconcileSpend => (
            BudgetMonetaryState::Exposed,
            BudgetMonetaryState::Reconciled,
        ),
        BudgetMutationKind::CaptureSpend => {
            (BudgetMonetaryState::Exposed, BudgetMonetaryState::Captured)
        }
        BudgetMutationKind::AuthorizeCumulativeApproval => {
            return Err(ambiguous_legacy_lifecycle(kind, "monetary state"));
        }
    };
    Ok(transition)
}

#[allow(clippy::too_many_arguments)]
fn validate_transition(
    lifecycle: &ResolvedBudgetMutationLifecycle,
    kind: BudgetMutationKind,
    allowed: Option<bool>,
    expected_authorization_outcome: Option<BudgetAuthorizationOutcome>,
    expected_invocation_before: BudgetInvocationState,
    expected_invocation_after: BudgetInvocationState,
    has_hold: bool,
    exposure_units: u64,
    realized_spend_units: u64,
) -> Result<(), String> {
    let amounts_valid = match kind {
        BudgetMutationKind::IncrementInvocation
        | BudgetMutationKind::AuthorizeCumulativeApproval => {
            exposure_units == 0 && realized_spend_units == 0
        }
        BudgetMutationKind::ReserveInvocation
        | BudgetMutationKind::AuthorizeExposure
        | BudgetMutationKind::CaptureInvocation
        | BudgetMutationKind::ReverseInvocation
        | BudgetMutationKind::CancelCapturedBeforeDispatch
        | BudgetMutationKind::ReverseExposure
        | BudgetMutationKind::ReleaseExposure => realized_spend_units == 0,
        BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureSpend => {
            exposure_units > 0 && realized_spend_units <= exposure_units
        }
    };
    let monetary_valid = match kind {
        BudgetMutationKind::AuthorizeCumulativeApproval => {
            lifecycle.monetary_state_before == lifecycle.monetary_state_after
                && matches!(
                    lifecycle.monetary_state_before,
                    BudgetMonetaryState::None | BudgetMonetaryState::Exposed
                )
        }
        BudgetMutationKind::ReleaseExposure if has_hold => {
            lifecycle.monetary_state_before == BudgetMonetaryState::Exposed
                && matches!(
                    lifecycle.monetary_state_after,
                    BudgetMonetaryState::Exposed | BudgetMonetaryState::Released
                )
        }
        _ => {
            let expected = expected_monetary_transition(kind, allowed, exposure_units)?;
            (
                lifecycle.monetary_state_before,
                lifecycle.monetary_state_after,
            ) == expected
        }
    };
    if lifecycle.authorization_outcome != expected_authorization_outcome
        || lifecycle.invocation_state_before != expected_invocation_before
        || lifecycle.invocation_state_after != expected_invocation_after
        || !monetary_valid
        || !amounts_valid
    {
        return Err(invalid_lifecycle(kind));
    }
    Ok(())
}

fn invalid_lifecycle(kind: BudgetMutationKind) -> String {
    format!(
        "budget mutation `{}` has an invalid lifecycle transition",
        kind.as_str()
    )
}

fn ambiguous_legacy_lifecycle(kind: BudgetMutationKind, field: &str) -> String {
    format!(
        "legacy budget mutation `{}` omitted ambiguous {field}",
        kind.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_control::cluster::{
        budget_mutation_event_view, budget_mutation_record_from_view,
    };
    use chio_test_support::prelude::*;

    #[derive(Clone, Copy)]
    struct LifecycleCase {
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        authorization_outcome: Option<BudgetAuthorizationOutcome>,
        invocation_before: BudgetInvocationState,
        invocation_after: BudgetInvocationState,
        monetary_before: BudgetMonetaryState,
        monetary_after: BudgetMonetaryState,
        has_hold: bool,
        exposure_units: u64,
        realized_spend_units: u64,
    }

    fn lifecycle_cases() -> [LifecycleCase; 11] {
        use BudgetAuthorizationOutcome::{ApprovalRequired, Authorized, Denied};
        use BudgetInvocationState::{
            Absent, Authorized as InvocationAuthorized, Captured, Denied as InvocationDenied,
            Reversed,
        };
        use BudgetMonetaryState::{
            Captured as SpendCaptured, Exposed, None as NoMoney, Reconciled, Released,
            Reversed as MoneyReversed,
        };
        [
            LifecycleCase {
                kind: BudgetMutationKind::IncrementInvocation,
                allowed: Some(true),
                authorization_outcome: Some(Authorized),
                invocation_before: Absent,
                invocation_after: Captured,
                monetary_before: NoMoney,
                monetary_after: NoMoney,
                has_hold: false,
                exposure_units: 0,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::ReserveInvocation,
                allowed: None,
                authorization_outcome: Some(ApprovalRequired),
                invocation_before: Absent,
                invocation_after: InvocationAuthorized,
                monetary_before: NoMoney,
                monetary_after: Exposed,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::AuthorizeExposure,
                allowed: Some(false),
                authorization_outcome: Some(Denied),
                invocation_before: Absent,
                invocation_after: InvocationDenied,
                monetary_before: NoMoney,
                monetary_after: NoMoney,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::CaptureInvocation,
                allowed: Some(true),
                authorization_outcome: None,
                invocation_before: InvocationAuthorized,
                invocation_after: Captured,
                monetary_before: Exposed,
                monetary_after: Exposed,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::AuthorizeCumulativeApproval,
                allowed: Some(true),
                authorization_outcome: Some(Authorized),
                invocation_before: InvocationAuthorized,
                invocation_after: InvocationAuthorized,
                monetary_before: Exposed,
                monetary_after: Exposed,
                has_hold: true,
                exposure_units: 0,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::ReverseInvocation,
                allowed: None,
                authorization_outcome: None,
                invocation_before: InvocationAuthorized,
                invocation_after: Reversed,
                monetary_before: Exposed,
                monetary_after: MoneyReversed,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::CancelCapturedBeforeDispatch,
                allowed: Some(true),
                authorization_outcome: None,
                invocation_before: Captured,
                invocation_after: Reversed,
                monetary_before: Exposed,
                monetary_after: MoneyReversed,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::ReverseExposure,
                allowed: None,
                authorization_outcome: None,
                invocation_before: InvocationAuthorized,
                invocation_after: Reversed,
                monetary_before: Exposed,
                monetary_after: MoneyReversed,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                authorization_outcome: None,
                invocation_before: InvocationAuthorized,
                invocation_after: InvocationAuthorized,
                monetary_before: Exposed,
                monetary_after: Released,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 0,
            },
            LifecycleCase {
                kind: BudgetMutationKind::ReconcileSpend,
                allowed: None,
                authorization_outcome: None,
                invocation_before: Captured,
                invocation_after: Captured,
                monetary_before: Exposed,
                monetary_after: Reconciled,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 7,
            },
            LifecycleCase {
                kind: BudgetMutationKind::CaptureSpend,
                allowed: None,
                authorization_outcome: None,
                invocation_before: Captured,
                invocation_after: Captured,
                monetary_before: Exposed,
                monetary_after: SpendCaptured,
                has_hold: true,
                exposure_units: 10,
                realized_spend_units: 7,
            },
        ]
    }

    fn mutation_record(case: LifecycleCase, event_seq: u64) -> BudgetMutationRecord {
        BudgetMutationRecord {
            event_id: format!("event-{event_seq}"),
            hold_id: case.has_hold.then(|| format!("hold-{event_seq}")),
            admission_binding: None,
            capability_id: "capability".to_string(),
            grant_index: 0,
            kind: case.kind,
            allowed: case.allowed,
            authorization_outcome: case.authorization_outcome,
            invocation_state_before: case.invocation_before,
            invocation_state_after: case.invocation_after,
            monetary_state_before: case.monetary_before,
            monetary_state_after: case.monetary_after,
            recorded_at: 10,
            event_seq,
            usage_seq: Some(event_seq),
            exposure_units: case.exposure_units,
            realized_spend_units: case.realized_spend_units,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            invocation_quota_usages: Vec::new(),
            invocation_quota_mutations: Vec::new(),
            cumulative_approval: None,
            cumulative_approval_mutation: None,
            cumulative_approval_set_digest: None,
            total_cost_exposed_after: 0,
            total_cost_realized_spend_after: case.realized_spend_units,
            authority: None,
        }
    }

    fn assert_lifecycle_equal(expected: &BudgetMutationRecord, actual: &BudgetMutationRecord) {
        assert_eq!(actual.kind, expected.kind);
        assert_eq!(actual.allowed, expected.allowed);
        assert_eq!(actual.authorization_outcome, expected.authorization_outcome);
        assert_eq!(
            actual.invocation_state_before,
            expected.invocation_state_before
        );
        assert_eq!(
            actual.invocation_state_after,
            expected.invocation_state_after
        );
        assert_eq!(actual.monetary_state_before, expected.monetary_state_before);
        assert_eq!(actual.monetary_state_after, expected.monetary_state_after);
    }

    #[test]
    fn every_mutation_kind_round_trips_complete_lifecycle() {
        for (index, case) in lifecycle_cases().into_iter().enumerate() {
            let original = mutation_record(case, u64::try_from(index + 1).test_unwrap());
            let view = budget_mutation_event_view(original.clone()).test_unwrap();
            let round_trip = budget_mutation_record_from_view(&view).test_unwrap();
            assert_lifecycle_equal(&original, &round_trip);
        }
    }

    #[test]
    fn delta_and_snapshot_envelopes_preserve_lifecycle_fields() {
        let original = mutation_record(lifecycle_cases()[9], 1);
        let view = budget_mutation_event_view(original.clone()).test_unwrap();
        let delta = BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events: vec![view.clone()],
            abandoned_seqs: Vec::new(),
        };
        let delta: BudgetDeltaResponse =
            serde_json::from_value(serde_json::to_value(delta).test_unwrap()).test_unwrap();
        let from_delta = budget_mutation_record_from_view(&delta.mutation_events[0]).test_unwrap();
        assert_lifecycle_equal(&original, &from_delta);

        let snapshot = ClusterStateSnapshotResponse {
            generated_at: 1,
            election_term: 0,
            replication: ClusterReplicationHeadsView::default(),
            authority_lease: None,
            authority: None,
            revocations: Vec::new(),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            lineage: Vec::new(),
            budgets: Vec::new(),
            budget_usage_history_anchors: Vec::new(),
            budget_anchor_provenance: None,
            budget_mutation_events: vec![view],
            budget_abandoned_seq_ranges: Vec::new(),
            budget_origin_ack_heads: Vec::new(),
        };
        let snapshot: ClusterStateSnapshotResponse =
            serde_json::from_value(serde_json::to_value(snapshot).test_unwrap()).test_unwrap();
        let from_snapshot =
            budget_mutation_record_from_view(&snapshot.budget_mutation_events[0]).test_unwrap();
        assert_lifecycle_equal(&original, &from_snapshot);
    }

    #[test]
    fn composite_projection_state_is_refused_rather_than_exported() {
        // `capture_invocation` is absent from the store-side unsupported-kind list, so
        // a lossy export of one is accepted by peers and silently strips the composite
        // state instead of failing the import.
        let mut record = mutation_record(lifecycle_cases()[9], 1);
        record.kind = BudgetMutationKind::CaptureInvocation;
        record.cumulative_approval_set_digest = Some("approval-set-digest".to_string());
        match budget_mutation_event_view(record) {
            Ok(_) => panic!("composite projection state must not lower into a cluster view"),
            Err(error) => assert!(error.to_string().contains("composite projection state")),
        }
    }

    #[test]
    fn old_authorization_event_derives_only_deterministic_lifecycle() {
        let lifecycle = BudgetMutationLifecycleView::default()
            .resolve(
                BudgetMutationKind::AuthorizeExposure,
                Some(true),
                true,
                25,
                0,
            )
            .test_unwrap();
        assert_eq!(
            lifecycle.authorization_outcome,
            Some(BudgetAuthorizationOutcome::Authorized)
        );
        assert_eq!(
            lifecycle.invocation_state_before,
            BudgetInvocationState::Absent
        );
        assert_eq!(
            lifecycle.invocation_state_after,
            BudgetInvocationState::Authorized
        );
        assert_eq!(lifecycle.monetary_state_before, BudgetMonetaryState::None);
        assert_eq!(lifecycle.monetary_state_after, BudgetMonetaryState::Exposed);
    }

    #[test]
    fn old_peer_omissions_resolve_for_every_unambiguous_kind() {
        for case in lifecycle_cases().into_iter().filter(|case| {
            !matches!(
                case.kind,
                BudgetMutationKind::AuthorizeCumulativeApproval
                    | BudgetMutationKind::ReleaseExposure
            )
        }) {
            let lifecycle = BudgetMutationLifecycleView::default()
                .resolve(
                    case.kind,
                    case.allowed,
                    case.has_hold,
                    case.exposure_units,
                    case.realized_spend_units,
                )
                .test_unwrap();
            assert_eq!(lifecycle.authorization_outcome, case.authorization_outcome);
            assert_eq!(lifecycle.invocation_state_before, case.invocation_before);
            assert_eq!(lifecycle.invocation_state_after, case.invocation_after);
            assert_eq!(lifecycle.monetary_state_before, case.monetary_before);
            assert_eq!(lifecycle.monetary_state_after, case.monetary_after);
        }
    }

    #[test]
    fn old_partial_held_release_fails_closed_without_terminal_state() {
        let error = BudgetMutationLifecycleView::default()
            .resolve(BudgetMutationKind::ReleaseExposure, None, true, 25, 0)
            .test_unwrap_err();
        assert!(error.contains("omitted ambiguous monetary state after"));
    }

    #[test]
    fn supplied_lifecycle_must_match_mutation_kind() {
        let lifecycle = BudgetMutationLifecycleView {
            authorization_outcome: Some(BudgetAuthorizationOutcomeView::Authorized),
            invocation_state_before: Some(BudgetInvocationStateView::Absent),
            invocation_state_after: Some(BudgetInvocationStateView::Captured),
            monetary_state_before: Some(BudgetMonetaryStateView::None),
            monetary_state_after: Some(BudgetMonetaryStateView::Exposed),
        };
        let error = lifecycle
            .resolve(
                BudgetMutationKind::AuthorizeExposure,
                Some(true),
                true,
                25,
                0,
            )
            .test_unwrap_err();
        assert!(error.contains("invalid lifecycle transition"));
    }

    #[test]
    fn terminal_mutation_rejects_injected_authorization_outcome() {
        let lifecycle = BudgetMutationLifecycleView {
            authorization_outcome: Some(BudgetAuthorizationOutcomeView::Authorized),
            invocation_state_before: Some(BudgetInvocationStateView::Captured),
            invocation_state_after: Some(BudgetInvocationStateView::Captured),
            monetary_state_before: Some(BudgetMonetaryStateView::Exposed),
            monetary_state_after: Some(BudgetMonetaryStateView::Reconciled),
        };
        let error = lifecycle
            .resolve(BudgetMutationKind::ReconcileSpend, None, true, 25, 20)
            .test_unwrap_err();
        assert!(error.contains("invalid lifecycle transition"));
    }

    #[test]
    fn current_peer_emits_complete_typed_lifecycle_fields() {
        let lifecycle = BudgetMutationLifecycleView {
            authorization_outcome: Some(BudgetAuthorizationOutcomeView::Authorized),
            invocation_state_before: Some(BudgetInvocationStateView::Absent),
            invocation_state_after: Some(BudgetInvocationStateView::Authorized),
            monetary_state_before: Some(BudgetMonetaryStateView::None),
            monetary_state_after: Some(BudgetMonetaryStateView::Exposed),
        };
        let value = serde_json::to_value(lifecycle).test_unwrap();
        assert_eq!(value["authorizationOutcome"], "authorized");
        assert_eq!(value["invocationStateBefore"], "absent");
        assert_eq!(value["invocationStateAfter"], "authorized");
        assert_eq!(value["monetaryStateBefore"], "none");
        assert_eq!(value["monetaryStateAfter"], "exposed");
    }
}
