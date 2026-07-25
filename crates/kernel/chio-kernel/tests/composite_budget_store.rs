#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::budget_store::{
    ApprovalRequiredBudgetHold, AuthorizedBudgetHold, BudgetAdmissionBinding,
    BudgetAuthorizeCumulativeApprovalRequest, BudgetAuthorizeHoldDecision,
    BudgetAuthorizeHoldRequest, BudgetCancelCapturedBeforeDispatchRequest,
    BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetCumulativeApprovalAccountKey,
    BudgetCumulativeApprovalAuthorizationDecision, BudgetCumulativeApprovalRequest,
    BudgetCumulativeApprovalState, BudgetEventAuthority, BudgetGuaranteeLevel,
    BudgetHoldMutationDecision, BudgetInvocationCaptureDecision, BudgetInvocationQuota,
    BudgetInvocationQuotaUsage, BudgetInvocationState, BudgetMonetaryState, BudgetMutationKind,
    BudgetQuotaKey, BudgetQuotaProfile, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest, DeniedBudgetHold, RevocationCommitMetadata,
    MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{BudgetStore, BudgetStoreError, InMemoryBudgetStore};

#[path = "composite_budget_store/concurrency_and_properties.rs"]
mod concurrency_and_properties;

const CAPABILITY_ID: &str = "cap-composite-test";
const GRANT_INDEX: usize = 0;
const APPROVAL_SET_DIGEST: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIFFERENT_APPROVAL_SET_DIGEST: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn quota(
    profile: BudgetQuotaProfile,
    owner_id: impl Into<String>,
    max_invocations: u32,
) -> BudgetInvocationQuota {
    BudgetInvocationQuota {
        key: BudgetQuotaKey {
            profile,
            owner_id: owner_id.into(),
            grant_index: None,
        },
        max_invocations,
    }
}

fn grant_quota(max_invocations: u32) -> BudgetInvocationQuota {
    BudgetInvocationQuota {
        key: BudgetQuotaKey::grant(CAPABILITY_ID, GRANT_INDEX as u32),
        max_invocations,
    }
}

fn canonical_quotas(mut quotas: Vec<BudgetInvocationQuota>) -> Vec<BudgetInvocationQuota> {
    quotas.sort_by(|left, right| left.key.cmp(&right.key));
    quotas
}

fn three_quotas(max_invocations: u32) -> Vec<BudgetInvocationQuota> {
    canonical_quotas(vec![
        grant_quota(max_invocations),
        quota(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "aggregate:capability",
            max_invocations,
        ),
        quota(
            BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
            "broker:capability",
            max_invocations,
        ),
    ])
}

fn admission_binding(
    operation_id: &str,
    capability_id: &str,
    has_supplemental_quota: bool,
) -> BudgetAdmissionBinding {
    let supplemental_revocation_ids = if has_supplemental_quota {
        vec![format!("supplemental-revocation:{operation_id}")]
    } else {
        Vec::new()
    };
    let supplemental_artifact_digest = has_supplemental_quota.then(|| "a".repeat(64));
    BudgetAdmissionBinding {
        operation_id: operation_id.to_string(),
        revocation_set: CanonicalRevocationSet::canonicalize(
            std::iter::once(capability_id.to_string())
                .chain(supplemental_revocation_ids)
                .collect(),
        )
        .expect("build canonical revocation set"),
        authorization_artifact_digests: supplemental_artifact_digest.iter().cloned().collect(),
        last_observed_revocation: has_supplemental_quota.then(|| RevocationCommitMetadata {
            authority: BudgetEventAuthority {
                authority_id: "authority:test".to_string(),
                lease_id: "lease:test".to_string(),
                lease_epoch: 1,
            },
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            commit_index: 1,
        }),
        supplemental_verifier_id: has_supplemental_quota.then(|| "verifier:test".to_string()),
        supplemental_verifier_config_digest: has_supplemental_quota.then(|| "b".repeat(64)),
        supplemental_authorization_artifact_digest: supplemental_artifact_digest,
        supplemental_authorization_expires_at: has_supplemental_quota.then_some(1_000),
    }
}

fn authorize_request(
    operation_id: &str,
    quotas: Vec<BudgetInvocationQuota>,
    requested_exposure_units: u64,
) -> BudgetAuthorizeHoldRequest {
    let has_supplemental_quota = quotas.iter().any(|quota| {
        quota.key.profile == BudgetQuotaProfile::SupplementalBrokerCapabilityExecution
    });
    BudgetAuthorizeHoldRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        max_invocations: None,
        invocation_quotas: quotas,
        cumulative_approval: None,
        admission_binding: Some(admission_binding(
            operation_id,
            CAPABILITY_ID,
            has_supplemental_quota,
        )),
        requested_exposure_units,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some(format!("hold:{operation_id}")),
        event_id: Some(format!("event:{operation_id}:authorize")),
        authority: None,
    }
}

#[test]
fn composite_authorization_requires_leaf_revocation_coverage() {
    let mut request =
        authorize_request("operation-missing-leaf-revocation", vec![grant_quota(1)], 0);
    request
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .revocation_set =
        CanonicalRevocationSet::canonicalize(vec!["different-capability".to_string()])
            .expect("canonical revocation set");

    assert!(matches!(
        request.validate(),
        Err(BudgetStoreError::Invariant(_))
    ));
}

fn cumulative_account() -> BudgetCumulativeApprovalAccountKey {
    BudgetCumulativeApprovalAccountKey {
        authority_id: "authority:test".to_string(),
        owner_id: "family:test".to_string(),
        approval_budget_id: "approval-budget:test".to_string(),
        approval_budget_epoch: 7,
        root_grant_hash: "root-grant-hash:test".to_string(),
        delegation_root_id: Some("root-capability:test".to_string()),
        root_binding_digest: Some("root-binding-digest:test".to_string()),
        currency: "USD".to_string(),
    }
}

fn money(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn cumulative_request(
    operation_id: &str,
    account_key: BudgetCumulativeApprovalAccountKey,
    authority_threshold: u64,
    effective_threshold: u64,
    requested_authorized: u64,
) -> BudgetAuthorizeHoldRequest {
    let mut request = authorize_request(operation_id, Vec::new(), 0);
    request.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
        operation_id: operation_id.to_string(),
        account_key,
        authority_threshold: money(authority_threshold),
        effective_threshold: money(effective_threshold),
        requested_authorized: money(requested_authorized),
    });
    request
}

fn expect_authorized(decision: BudgetAuthorizeHoldDecision) -> AuthorizedBudgetHold {
    match decision {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
        other => panic!("expected authorized hold, got {other:?}"),
    }
}

fn expect_denied(decision: BudgetAuthorizeHoldDecision) -> DeniedBudgetHold {
    match decision {
        BudgetAuthorizeHoldDecision::Denied(denied) => denied,
        other => panic!("expected denied hold, got {other:?}"),
    }
}

fn expect_approval_required(decision: BudgetAuthorizeHoldDecision) -> ApprovalRequiredBudgetHold {
    match decision {
        BudgetAuthorizeHoldDecision::ApprovalRequired(required) => required,
        other => panic!("expected approval-required hold, got {other:?}"),
    }
}

fn quota_usage(store: &InMemoryBudgetStore, key: &BudgetQuotaKey) -> BudgetInvocationQuotaUsage {
    store
        .get_invocation_quota_usage(key)
        .expect("query invocation quota")
        .expect("invocation quota should exist")
}

fn assert_usage(usage: &BudgetInvocationQuotaUsage, reserved: u32, captured: u32) {
    assert_eq!(usage.reserved_invocations, reserved);
    assert_eq!(usage.captured_invocations, captured);
}

fn captured_zero_exposure_hold(operation_id: &str) -> (InMemoryBudgetStore, BudgetQuotaKey) {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(operation_id, vec![quota.clone()], 0))
            .expect("authorize zero-exposure hold"),
    );
    assert!(matches!(
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: format!("hold:{operation_id}"),
            event_id: format!("event:{operation_id}:capture-invocation"),
            trusted_time: None,
            authority: None,
        }),
        Ok(BudgetInvocationCaptureDecision::Captured(_))
    ));
    (store, quota.key)
}

fn assert_zero_terminal_mutation(
    operation_id: &str,
    mutate: impl FnOnce(&InMemoryBudgetStore) -> Result<BudgetHoldMutationDecision, BudgetStoreError>,
) {
    let (store, key) = captured_zero_exposure_hold(operation_id);
    let usage_before = store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("query usage before terminal mutation");
    assert!(matches!(
        mutate(&store),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query usage after terminal mutation"),
        usage_before
    );
    assert_usage(&quota_usage(&store, &key), 0, 1);
}

#[test]
fn composite_authorization_reserves_and_captures_every_quota() {
    let store = InMemoryBudgetStore::new();
    let quotas = three_quotas(3);
    let authorized = expect_authorized(
        store
            .authorize_budget_hold(authorize_request("reserve-all", quotas.clone(), 100))
            .expect("authorize composite hold"),
    );

    assert_eq!(authorized.invocation_quota_usages.len(), quotas.len());
    for usage in &authorized.invocation_quota_usages {
        assert_usage(usage, 1, 0);
    }
    assert_eq!(authorized.authorized_exposure_units, 100);
    assert_eq!(authorized.committed_cost_units_after, 100);

    let capture = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:reserve-all".to_string(),
            event_id: "event:reserve-all:capture".to_string(),
            trusted_time: Some(100),
            authority: None,
        })
        .expect("capture composite invocation reservations");
    let captured = match capture {
        BudgetInvocationCaptureDecision::Captured(captured) => captured,
        other => panic!("expected fresh capture, got {other:?}"),
    };
    for usage in &captured.invocation_quota_usages {
        assert_usage(usage, 0, 1);
    }
    assert_eq!(captured.exposure_units, 100);
    assert_eq!(captured.monetary_state, BudgetMonetaryState::Exposed);
    assert_eq!(captured.committed_cost_units_after, 100);

    let reconciled = store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold:reserve-all".to_string()),
            event_id: Some("event:reserve-all:reconcile".to_string()),
            authority: None,
        })
        .expect("reconcile captured composite hold");
    assert_eq!(reconciled.committed_cost_units_after, 75);
    for usage in &reconciled.invocation_quota_usages {
        assert_usage(usage, 0, 1);
    }
    for quota in quotas {
        assert_usage(&quota_usage(&store, &quota.key), 0, 1);
    }
}

#[test]
fn supplemental_capture_rechecks_exclusive_artifact_expiry() {
    let store = InMemoryBudgetStore::new();
    let quotas = three_quotas(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("expired-capture", quotas.clone(), 0))
            .expect("authorize supplemental composite hold"),
    );

    let capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:expired-capture".to_string(),
        event_id: "event:expired-capture:capture".to_string(),
        trusted_time: Some(1_000),
        authority: None,
    });
    assert!(matches!(capture, Err(BudgetStoreError::Invariant(_))));
    for quota in quotas {
        assert_usage(&quota_usage(&store, &quota.key), 1, 0);
    }
}

#[test]
fn supplemental_capture_missing_time_can_retry_without_state_change() {
    let store = InMemoryBudgetStore::new();
    let quotas = three_quotas(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("missing-time-capture", quotas.clone(), 0))
            .expect("authorize supplemental composite hold"),
    );

    let mut capture = BudgetCaptureInvocationRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:missing-time-capture".to_string(),
        event_id: "event:missing-time-capture:capture".to_string(),
        trusted_time: None,
        authority: None,
    };
    assert!(matches!(
        store.capture_invocation_reservations(capture.clone()),
        Err(BudgetStoreError::Invariant(_))
    ));
    for quota in &quotas {
        assert_usage(&quota_usage(&store, &quota.key), 1, 0);
    }

    capture.trusted_time = Some(999);
    assert!(matches!(
        store.capture_invocation_reservations(capture),
        Ok(BudgetInvocationCaptureDecision::Captured(_))
    ));
    for quota in quotas {
        assert_usage(&quota_usage(&store, &quota.key), 0, 1);
    }
}

#[test]
fn legacy_increment_reverse_restores_grant_quota_and_allows_retry() {
    let store = InMemoryBudgetStore::new();
    let key = BudgetQuotaKey::grant(CAPABILITY_ID, GRANT_INDEX as u32);

    assert!(store
        .try_increment(CAPABILITY_ID, GRANT_INDEX, Some(1))
        .expect("increment within grant quota"));
    assert_usage(&quota_usage(&store, &key), 0, 1);

    store
        .reverse_charge_cost(CAPABILITY_ID, GRANT_INDEX, 0)
        .expect("reverse legacy zero-cost invocation");
    assert_usage(&quota_usage(&store, &key), 0, 0);

    assert!(store
        .try_increment(CAPABILITY_ID, GRANT_INDEX, None)
        .expect("retry within existing grant quota"));
    assert_usage(&quota_usage(&store, &key), 0, 1);
}

#[test]
fn denied_legacy_calls_do_not_define_quota_maxima() {
    let increment_store = InMemoryBudgetStore::new();
    let key = BudgetQuotaKey::grant(CAPABILITY_ID, GRANT_INDEX as u32);
    assert!(!increment_store
        .try_increment(CAPABILITY_ID, GRANT_INDEX, Some(0))
        .expect("deny zero-maximum increment"));
    assert!(increment_store
        .get_invocation_quota_usage(&key)
        .expect("query denied increment quota")
        .is_none());
    assert!(increment_store
        .try_increment(CAPABILITY_ID, GRANT_INDEX, Some(1))
        .expect("define quota after denied increment"));

    let charge_store = InMemoryBudgetStore::new();
    assert!(!charge_store
        .try_charge_cost(CAPABILITY_ID, GRANT_INDEX, Some(0), 0, None, None)
        .expect("deny zero-maximum charge"));
    assert!(charge_store
        .get_invocation_quota_usage(&key)
        .expect("query denied charge quota")
        .is_none());
    assert!(charge_store
        .try_charge_cost(CAPABILITY_ID, GRANT_INDEX, Some(1), 0, None, None)
        .expect("define quota after denied charge"));
}

#[test]
fn raw_legacy_mutations_reject_invalid_and_reserved_identities() {
    let store = InMemoryBudgetStore::new();
    assert!(matches!(
        store.try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            None,
            10,
            None,
            None,
            Some("hold:partial-id"),
            None,
        ),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        store.try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            None,
            10,
            None,
            None,
            None,
            Some(""),
        ),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("query invalid authorization usage")
        .is_none());

    assert!(store
        .try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 10, None, None)
        .expect("create unheld legacy exposure"));
    assert!(matches!(
        store.reverse_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            10,
            Some("hold:partial-reverse"),
            None,
        ),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        store.reduce_charge_cost_with_ids(CAPABILITY_ID, GRANT_INDEX, 1, None, Some(""),),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        store.settle_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            10,
            5,
            Some("hold:partial-settle"),
            None,
        ),
        Err(BudgetStoreError::Invariant(_))
    ));

    assert!(matches!(
        store.try_charge_cost_with_ids(
            "cap-reserved-event",
            GRANT_INDEX,
            None,
            0,
            None,
            None,
            None,
            Some("local-budget-event-99"),
        ),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn unstructured_rich_authorization_remains_reversible() {
    let store = InMemoryBudgetStore::new();
    let request = BudgetAuthorizeHoldRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 25,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: None,
        event_id: None,
        authority: None,
    };
    expect_authorized(
        store
            .authorize_budget_hold(request.clone())
            .expect("authorize unstructured rich request"),
    );
    let reversed = store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            reversed_exposure_units: 25,
            hold_id: None,
            event_id: None,
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .expect("reverse unstructured rich request");
    assert_eq!(reversed.committed_cost_units_after, 0);
    assert_eq!(reversed.invocation_count_after, 0);

    let event_store = InMemoryBudgetStore::new();
    let mut authorization = request;
    authorization.event_id = Some("event:unstructured-rich:authorize".to_string());
    expect_authorized(
        event_store
            .authorize_budget_hold(authorization.clone())
            .expect("authorize event-only unstructured request"),
    );
    event_store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            reversed_exposure_units: 25,
            hold_id: None,
            event_id: Some("event:unstructured-rich:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .expect("reverse event-only unstructured request");
    assert!(matches!(
        event_store.authorize_budget_hold(authorization),
        Err(BudgetStoreError::Invariant(_))
    ));

    let raw_store = InMemoryBudgetStore::new();
    assert!(raw_store
        .try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            None,
            25,
            None,
            None,
            None,
            Some("event:unstructured-raw:authorize"),
        )
        .expect("authorize raw event-only request"));
    raw_store
        .reverse_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            25,
            None,
            Some("event:unstructured-raw:reverse"),
        )
        .expect("reverse raw event-only request");
    assert!(matches!(
        raw_store.try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            None,
            25,
            None,
            None,
            None,
            Some("event:unstructured-raw:authorize"),
        ),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn legacy_charge_cannot_bypass_or_redefine_structured_grant_maximum() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "structured-grant-max",
                vec![quota.clone()],
                0,
            ))
            .expect("authorize structured grant quota"),
    );

    assert!(matches!(
        store.try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 0, None, None),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        store.try_charge_cost(CAPABILITY_ID, GRANT_INDEX, Some(2), 0, None, None),
        Err(BudgetStoreError::Invariant(_))
    ));
    let usage = quota_usage(&store, &quota.key);
    assert_eq!(usage.quota.max_invocations, 1);
    assert_usage(&usage, 1, 0);
}

#[test]
fn legacy_admission_cannot_skip_a_live_composite_quota() {
    let store = InMemoryBudgetStore::new();
    let quotas = canonical_quotas(vec![
        grant_quota(2),
        quota(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "aggregate:legacy-bypass",
            2,
        ),
    ]);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("legacy-bypass", quotas.clone(), 0))
            .expect("authorize composite hold"),
    );
    assert!(matches!(
        store.try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 0, None, None),
        Err(BudgetStoreError::Invariant(_))
    ));
    for quota in quotas {
        assert_usage(&quota_usage(&store, &quota.key), 1, 0);
    }
}

#[test]
fn composite_admission_cannot_omit_an_existing_grant_quota() {
    let store = InMemoryBudgetStore::new();
    let grant = grant_quota(2);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "grant-quota-owner",
                vec![grant.clone()],
                0,
            ))
            .expect("authorize grant quota"),
    );

    let aggregate = quota(
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        "aggregate:grant-quota-omission",
        2,
    );
    assert!(matches!(
        store.authorize_budget_hold(authorize_request(
            "grant-quota-omission",
            vec![aggregate.clone()],
            0,
        )),
        Err(BudgetStoreError::Invariant(_))
    ));

    assert_usage(&quota_usage(&store, &grant.key), 1, 0);
    assert!(store
        .get_invocation_quota_usage(&aggregate.key)
        .expect("query omitted admission quota")
        .is_none());
    assert_eq!(
        store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query grant usage")
            .expect("grant usage")
            .invocation_count,
        1
    );
}

#[test]
fn direct_legacy_authorization_inherits_legacy_quota_and_rejects_structured_history() {
    let legacy_store = InMemoryBudgetStore::new();
    assert!(legacy_store
        .try_charge_cost(CAPABILITY_ID, GRANT_INDEX, Some(2), 0, None, None)
        .expect("define legacy quota"));
    let mut legacy = authorize_request("legacy-quota-inheritance", Vec::new(), 0);
    legacy.admission_binding = None;
    expect_authorized(
        legacy_store
            .authorize_budget_hold(legacy)
            .expect("inherit existing legacy grant quota"),
    );
    assert_usage(&quota_usage(&legacy_store, &grant_quota(2).key), 1, 1);

    let structured_store = InMemoryBudgetStore::new();
    expect_authorized(
        structured_store
            .authorize_budget_hold(authorize_request(
                "structured-history-owner",
                vec![quota(
                    BudgetQuotaProfile::AggregateCapabilityInvocation,
                    "aggregate:direct-legacy-bypass",
                    2,
                )],
                0,
            ))
            .expect("authorize structured history"),
    );
    let mut bypass = authorize_request("direct-legacy-bypass", Vec::new(), 0);
    bypass.admission_binding = None;
    assert!(matches!(
        structured_store.authorize_budget_hold(bypass),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        structured_store.try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 1, Some(0), None,),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        structured_store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query structured usage")
            .expect("structured usage")
            .invocation_count,
        1
    );
}

#[test]
fn unheld_legacy_terminals_cannot_mutate_after_structured_history() {
    let prepared_store = || {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 10, None, None)
            .expect("create legacy reversible charge"));
        expect_authorized(
            store
                .authorize_budget_hold(authorize_request(
                    "structured-terminal-boundary",
                    vec![quota(
                        BudgetQuotaProfile::AggregateCapabilityInvocation,
                        "aggregate:terminal-boundary",
                        1,
                    )],
                    0,
                ))
                .expect("authorize structured boundary"),
        );
        store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                reversed_exposure_units: 0,
                hold_id: Some("hold:structured-terminal-boundary".to_string()),
                event_id: Some("event:structured-terminal-boundary:reverse".to_string()),
                expected_cumulative_approval_state: None,
                authority: None,
            })
            .expect("terminalize structured hold");
        store
    };

    assert!(matches!(
        prepared_store().reverse_charge_cost(CAPABILITY_ID, GRANT_INDEX, 10),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        prepared_store().reduce_charge_cost(CAPABILITY_ID, GRANT_INDEX, 10),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(matches!(
        prepared_store().settle_charge_cost(CAPABILITY_ID, GRANT_INDEX, 10, 5),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn legacy_admission_cannot_bypass_denied_or_reversed_composite_history() {
    let denied_store = InMemoryBudgetStore::new();
    let mut denied_request = authorize_request(
        "legacy-after-denial",
        vec![quota(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "aggregate:legacy-after-denial",
            1,
        )],
        1,
    );
    denied_request.max_total_cost_units = Some(0);
    expect_denied(
        denied_store
            .authorize_budget_hold(denied_request)
            .expect("record denied composite authorization"),
    );
    assert!(matches!(
        denied_store.try_increment(CAPABILITY_ID, GRANT_INDEX, None),
        Err(BudgetStoreError::Invariant(_))
    ));

    let reversed_store = InMemoryBudgetStore::new();
    expect_authorized(
        reversed_store
            .authorize_budget_hold(authorize_request(
                "legacy-after-reverse",
                vec![quota(
                    BudgetQuotaProfile::AggregateCapabilityInvocation,
                    "aggregate:legacy-after-reverse",
                    1,
                )],
                0,
            ))
            .expect("authorize composite hold before reversal"),
    );
    reversed_store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            reversed_exposure_units: 0,
            hold_id: Some("hold:legacy-after-reverse".to_string()),
            event_id: Some("event:legacy-after-reverse:terminal".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .expect("reverse composite hold");
    assert!(matches!(
        reversed_store.try_charge_cost(CAPABILITY_ID, GRANT_INDEX, None, 0, None, None),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn no_hold_legacy_mutations_cannot_touch_live_composite_hold() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "no-hold-mutation",
                vec![quota.clone()],
                25,
            ))
            .expect("authorize live composite hold"),
    );
    let usage_before = store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("query usage")
        .expect("authorized usage");
    let quota_before = quota_usage(&store, &quota.key);

    assert!(matches!(
        store.reverse_charge_cost(CAPABILITY_ID, GRANT_INDEX, 25),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query usage after reverse"),
        Some(usage_before.clone())
    );
    assert_eq!(quota_usage(&store, &quota.key), quota_before);

    assert!(matches!(
        store.reduce_charge_cost(CAPABILITY_ID, GRANT_INDEX, 25),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query usage after release"),
        Some(usage_before.clone())
    );
    assert_eq!(quota_usage(&store, &quota.key), quota_before);

    assert!(matches!(
        store.settle_charge_cost(CAPABILITY_ID, GRANT_INDEX, 25, 10),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query usage after reconcile"),
        Some(usage_before)
    );
    assert_eq!(quota_usage(&store, &quota.key), quota_before);
}

#[test]
fn held_monetary_settlement_requires_dispatch_capture_without_poisoning_state() {
    for monetary_capture in [false, true] {
        let operation_id = if monetary_capture {
            "capture-dispatch-fence"
        } else {
            "reconcile-dispatch-fence"
        };
        let store = InMemoryBudgetStore::new();
        let quota = grant_quota(1);
        expect_authorized(
            store
                .authorize_budget_hold(authorize_request(operation_id, vec![quota.clone()], 25))
                .expect("authorize held settlement"),
        );
        let usage_before = store
            .get_usage(CAPABILITY_ID, GRANT_INDEX)
            .expect("query usage before rejected settlement")
            .expect("authorized usage");
        let event_id = format!("event:{operation_id}:settle");

        let rejected = if monetary_capture {
            store.capture_budget_hold(BudgetCaptureHoldRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                exposed_cost_units: 25,
                realized_spend_units: 10,
                hold_id: Some(format!("hold:{operation_id}")),
                event_id: Some(event_id.clone()),
                authority: None,
            })
        } else {
            store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                exposed_cost_units: 25,
                realized_spend_units: 10,
                hold_id: Some(format!("hold:{operation_id}")),
                event_id: Some(event_id.clone()),
                authority: None,
            })
        };
        assert!(matches!(
            rejected,
            Err(BudgetStoreError::Invariant(reason)) if reason.contains("not dispatch-captured")
        ));
        assert_eq!(
            store
                .get_usage(CAPABILITY_ID, GRANT_INDEX)
                .expect("query usage after rejected settlement"),
            Some(usage_before)
        );
        assert_usage(&quota_usage(&store, &quota.key), 1, 0);

        assert!(matches!(
            store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                hold_id: format!("hold:{operation_id}"),
                event_id: format!("event:{operation_id}:capture-invocation"),
                trusted_time: None,
                authority: None,
            }),
            Ok(BudgetInvocationCaptureDecision::Captured(_))
        ));
        let settled = if monetary_capture {
            store
                .capture_budget_hold(BudgetCaptureHoldRequest {
                    capability_id: CAPABILITY_ID.to_string(),
                    grant_index: GRANT_INDEX,
                    exposed_cost_units: 25,
                    realized_spend_units: 10,
                    hold_id: Some(format!("hold:{operation_id}")),
                    event_id: Some(event_id),
                    authority: None,
                })
                .expect("capture monetary spend after dispatch capture")
        } else {
            store
                .reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: CAPABILITY_ID.to_string(),
                    grant_index: GRANT_INDEX,
                    exposed_cost_units: 25,
                    realized_spend_units: 10,
                    hold_id: Some(format!("hold:{operation_id}")),
                    event_id: Some(event_id),
                    authority: None,
                })
                .expect("reconcile spend after dispatch capture")
        };
        assert_eq!(settled.invocation_state, BudgetInvocationState::Captured);
        assert_eq!(
            settled.monetary_state,
            if monetary_capture {
                BudgetMonetaryState::Captured
            } else {
                BudgetMonetaryState::Reconciled
            }
        );
        assert_usage(&quota_usage(&store, &quota.key), 0, 1);
    }
}

#[test]
fn zero_unit_monetary_mutations_cannot_cross_captured_composite_fence() {
    assert_zero_terminal_mutation("zero-release", |store| {
        store.release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            released_exposure_units: 0,
            hold_id: Some("hold:zero-release".to_string()),
            event_id: Some("event:zero-release:release".to_string()),
            authority: None,
        })
    });

    assert_zero_terminal_mutation("zero-reconcile", |store| {
        store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            exposed_cost_units: 0,
            realized_spend_units: 0,
            hold_id: Some("hold:zero-reconcile".to_string()),
            event_id: Some("event:zero-reconcile:reconcile".to_string()),
            authority: None,
        })
    });

    assert_zero_terminal_mutation("zero-capture", |store| {
        store.capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            exposed_cost_units: 0,
            realized_spend_units: 0,
            hold_id: Some("hold:zero-capture".to_string()),
            event_id: Some("event:zero-capture:capture-money".to_string()),
            authority: None,
        })
    });
}

#[test]
fn exhausted_member_denies_without_reserving_other_quotas_or_exposure() {
    let store = InMemoryBudgetStore::new();
    let exhausted = quota(
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        "aggregate:shared-exhausted",
        1,
    );
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "exhaust-shared",
                vec![exhausted.clone()],
                0,
            ))
            .expect("exhaust shared quota"),
    );

    let private = quota(
        BudgetQuotaProfile::AggregateFamilyInvocation,
        "family:private",
        1,
    );
    let broker = quota(
        BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
        "broker:private",
        1,
    );
    let attempted = canonical_quotas(vec![exhausted.clone(), private.clone(), broker.clone()]);
    let denied = expect_denied(
        store
            .authorize_budget_hold(authorize_request("denied-composite", attempted, 90))
            .expect("evaluate denied composite hold"),
    );

    assert_eq!(denied.invocation_quota_usages.len(), 3);
    let exhausted_usage = denied
        .invocation_quota_usages
        .iter()
        .find(|usage| usage.quota.key == exhausted.key)
        .expect("exhausted quota usage");
    let private_usage = denied
        .invocation_quota_usages
        .iter()
        .find(|usage| usage.quota.key == private.key)
        .expect("private quota usage");
    let broker_usage = denied
        .invocation_quota_usages
        .iter()
        .find(|usage| usage.quota.key == broker.key)
        .expect("broker quota usage");
    assert_usage(exhausted_usage, 1, 0);
    assert_usage(private_usage, 0, 0);
    assert_usage(broker_usage, 0, 0);
    assert!(store
        .get_invocation_quota_usage(&private.key)
        .expect("query private quota after denial")
        .is_none());
    assert!(store
        .get_invocation_quota_usage(&broker.key)
        .expect("query broker quota after denial")
        .is_none());

    let monetary = store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("query monetary usage")
        .expect("first authorization created monetary usage");
    assert_eq!(monetary.invocation_count, 1);
    assert_eq!(monetary.total_cost_exposed, 0);

    let private_with_new_maximum = quota(
        BudgetQuotaProfile::AggregateFamilyInvocation,
        "family:private",
        2,
    );
    let mut retry = authorize_request(
        "denied-composite",
        vec![private_with_new_maximum.clone()],
        0,
    );
    retry.event_id = Some("event:denied-composite:retry".to_string());
    expect_authorized(
        store
            .authorize_budget_hold(retry)
            .expect("denied hold and operation identifiers remain reusable"),
    );
    assert_usage(&quota_usage(&store, &private_with_new_maximum.key), 1, 0);
}

#[test]
fn exact_authorization_replay_is_stable_and_identifier_reuse_fails_closed() {
    let store = InMemoryBudgetStore::new();
    let request = authorize_request("replay", three_quotas(2), 10);
    let first = store
        .authorize_budget_hold(request.clone())
        .expect("first authorization");
    let replay = store
        .authorize_budget_hold(request.clone())
        .expect("exact replay");
    assert_eq!(replay, first);

    let mut changed_event_payload = request.clone();
    changed_event_payload.invocation_quotas[0].max_invocations = 3;
    assert!(matches!(
        store.authorize_budget_hold(changed_event_payload),
        Err(BudgetStoreError::Invariant(_))
    ));

    let mut reused_hold = request;
    reused_hold.event_id = Some("event:replay:different".to_string());
    assert!(matches!(
        store.authorize_budget_hold(reused_hold),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn capture_and_terminal_authorization_replay_require_exact_events() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    let authorization = authorize_request("capture-replay", vec![quota.clone()], 0);
    expect_authorized(
        store
            .authorize_budget_hold(authorization.clone())
            .expect("authorize capture replay hold"),
    );
    let capture = BudgetCaptureInvocationRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:capture-replay".to_string(),
        event_id: "event:capture-replay:capture".to_string(),
        trusted_time: None,
        authority: None,
    };
    let first = match store
        .capture_invocation_reservations(capture.clone())
        .expect("capture invocation")
    {
        BudgetInvocationCaptureDecision::Captured(mutation) => mutation,
        other => panic!("expected fresh capture, got {other:?}"),
    };
    let replay = match store
        .capture_invocation_reservations(capture.clone())
        .expect("replay exact capture")
    {
        BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => mutation,
        other => panic!("expected already-captured replay, got {other:?}"),
    };
    assert_eq!(replay, first);

    let mut different_event = capture;
    different_event.event_id = "event:capture-replay:different".to_string();
    assert!(matches!(
        store.capture_invocation_reservations(different_event),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_usage(&quota_usage(&store, &quota.key), 0, 1);

    let terminal = store
        .authorize_budget_hold(authorization)
        .expect("replay authorization after capture");
    let BudgetAuthorizeHoldDecision::AlreadyCaptured(mutation) = terminal else {
        panic!("expected terminal authorization replay, got {terminal:?}");
    };
    assert_eq!(mutation.invocation_state, BudgetInvocationState::Captured);
    assert_usage(&mutation.invocation_quota_usages[0], 0, 1);
}

#[test]
fn authorization_replay_fails_after_release_or_approval_attachment() {
    let store = InMemoryBudgetStore::new();
    let authorization = authorize_request("authorization-after-release", vec![grant_quota(2)], 50);
    expect_authorized(
        store
            .authorize_budget_hold(authorization.clone())
            .expect("authorize releasable hold"),
    );
    store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            released_exposure_units: 10,
            hold_id: Some("hold:authorization-after-release".to_string()),
            event_id: Some("event:authorization-after-release:release".to_string()),
            authority: None,
        })
        .expect("partially release hold");
    assert!(matches!(
        store.authorize_budget_hold(authorization),
        Err(BudgetStoreError::Invariant(_))
    ));

    let store = InMemoryBudgetStore::new();
    let cumulative = cumulative_request(
        "authorization-after-approval",
        cumulative_account(),
        100,
        100,
        100,
    );
    expect_approval_required(
        store
            .authorize_budget_hold(cumulative.clone())
            .expect("authorize pending cumulative hold"),
    );
    store
        .authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            operation_id: "authorization-after-approval".to_string(),
            hold_id: "hold:authorization-after-approval".to_string(),
            admission_binding: admission_binding(
                "authorization-after-approval",
                CAPABILITY_ID,
                false,
            ),
            approval_set_digest: APPROVAL_SET_DIGEST.to_string(),
            event_id: "event:authorization-after-approval:approval".to_string(),
            authority: None,
        })
        .expect("attach cumulative approval");
    assert!(matches!(
        store.authorize_budget_hold(cumulative),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn capture_event_identity_includes_trusted_time() {
    let store = InMemoryBudgetStore::new();
    let quotas = three_quotas(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("capture-time-identity", quotas, 0))
            .expect("authorize supplemental hold"),
    );
    let mut capture = BudgetCaptureInvocationRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:capture-time-identity".to_string(),
        event_id: "event:capture-time-identity:capture".to_string(),
        trusted_time: Some(999),
        authority: None,
    };
    assert!(matches!(
        store.capture_invocation_reservations(capture.clone()),
        Ok(BudgetInvocationCaptureDecision::Captured(_))
    ));
    capture.trusted_time = Some(998);
    assert!(matches!(
        store.capture_invocation_reservations(capture),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn partially_released_legacy_capture_cancels_remaining_exposure() {
    let store = InMemoryBudgetStore::new();
    let key = BudgetQuotaKey::grant(CAPABILITY_ID, GRANT_INDEX as u32);
    assert!(store
        .try_charge_cost_with_ids(
            CAPABILITY_ID,
            GRANT_INDEX,
            Some(1),
            100,
            Some(100),
            Some(100),
            Some("hold:partial-cancel"),
            Some("event:partial-cancel:authorize"),
        )
        .expect("authorize legacy hold"));
    let release = BudgetReleaseHoldRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        released_exposure_units: 40,
        hold_id: Some("hold:partial-cancel".to_string()),
        event_id: Some("event:partial-cancel:release".to_string()),
        authority: None,
    };
    store
        .release_budget_hold(release.clone())
        .expect("partially release legacy hold");
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:partial-cancel".to_string(),
            event_id: "event:partial-cancel:capture".to_string(),
            trusted_time: None,
            authority: None,
        })
        .expect("capture legacy invocation");
    assert!(matches!(
        store.release_budget_hold(release),
        Err(BudgetStoreError::Invariant(_))
    ));
    let cancellation = BudgetCancelCapturedBeforeDispatchRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:partial-cancel".to_string(),
        event_id: "event:partial-cancel:cancel".to_string(),
        authority: None,
    };
    let cancelled = match store
        .cancel_captured_before_dispatch(cancellation.clone())
        .expect("cancel captured legacy invocation")
    {
        BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(cancelled) => cancelled,
        other => panic!("expected fresh cancellation, got {other:?}"),
    };
    assert_eq!(cancelled.exposure_units, 60);
    assert_eq!(cancelled.invocation_count_after, 0);
    assert_eq!(cancelled.committed_cost_units_after, 0);
    assert_usage(&quota_usage(&store, &key), 0, 0);

    let replayed = match store
        .cancel_captured_before_dispatch(cancellation)
        .expect("replay exact cancellation")
    {
        BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(replayed) => replayed,
        other => panic!("expected cancellation replay, got {other:?}"),
    };
    assert_eq!(replayed, cancelled);
}

#[test]
fn authority_mismatch_does_not_consume_capture_event_or_reservation() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    let correct_authority = BudgetEventAuthority {
        authority_id: "authority:correct".to_string(),
        lease_id: "lease:correct".to_string(),
        lease_epoch: 7,
    };
    let mut authorization = authorize_request("authority-fence", vec![quota.clone()], 0);
    authorization.authority = Some(correct_authority.clone());
    expect_authorized(
        store
            .authorize_budget_hold(authorization)
            .expect("authorize authority-bound hold"),
    );

    let mut capture = BudgetCaptureInvocationRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        hold_id: "hold:authority-fence".to_string(),
        event_id: "event:authority-fence:capture".to_string(),
        trusted_time: None,
        authority: Some(BudgetEventAuthority {
            authority_id: "authority:wrong".to_string(),
            ..correct_authority.clone()
        }),
    };
    assert!(matches!(
        store.capture_invocation_reservations(capture.clone()),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_usage(&quota_usage(&store, &quota.key), 1, 0);

    capture.authority = Some(correct_authority);
    assert!(matches!(
        store.capture_invocation_reservations(capture),
        Ok(BudgetInvocationCaptureDecision::Captured(_))
    ));
    assert_usage(&quota_usage(&store, &quota.key), 0, 1);
}

#[test]
fn operation_id_cannot_move_to_a_different_hold_or_event() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(2);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("operation-owner", vec![quota.clone()], 0))
            .expect("authorize operation owner"),
    );

    let mut reused = authorize_request("operation-reuser", vec![quota.clone()], 0);
    reused
        .admission_binding
        .as_mut()
        .expect("admission binding")
        .operation_id = "operation-owner".to_string();
    assert!(matches!(
        store.authorize_budget_hold(reused),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_usage(&quota_usage(&store, &quota.key), 1, 0);
}

#[test]
fn malformed_quota_sets_are_rejected_before_state_changes() {
    let store = InMemoryBudgetStore::new();
    let duplicate = quota(
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        "aggregate:duplicate",
        2,
    );
    let request = authorize_request("duplicate", vec![duplicate.clone(), duplicate.clone()], 0);
    assert!(matches!(
        store.authorize_budget_hold(request),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(store
        .get_invocation_quota_usage(&duplicate.key)
        .expect("query duplicate key")
        .is_none());

    let low = quota(
        BudgetQuotaProfile::AggregateCapabilityInvocation,
        "aggregate:a",
        2,
    );
    let high = quota(BudgetQuotaProfile::AggregateFamilyInvocation, "family:z", 2);
    let unsorted = authorize_request("unsorted", vec![high.clone(), low.clone()], 0);
    assert!(matches!(
        store.authorize_budget_hold(unsorted),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert!(store
        .get_invocation_quota_usage(&low.key)
        .expect("query low key")
        .is_none());
    assert!(store
        .get_invocation_quota_usage(&high.key)
        .expect("query high key")
        .is_none());

    let too_many = (0..=MAX_INVOCATION_QUOTAS_PER_ADMISSION)
        .map(|index| {
            quota(
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                format!("aggregate:{index:02}"),
                2,
            )
        })
        .collect();
    assert!(matches!(
        store.authorize_budget_hold(authorize_request("too-many", too_many, 0)),
        Err(BudgetStoreError::Invariant(_))
    ));
}

#[test]
fn quota_maximum_is_immutable_and_failed_change_does_not_mutate_usage() {
    let store = InMemoryBudgetStore::new();
    let key = BudgetQuotaKey {
        profile: BudgetQuotaProfile::AggregateFamilyInvocation,
        owner_id: "family:immutable-max".to_string(),
        grant_index: None,
    };
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "immutable-first",
                vec![BudgetInvocationQuota {
                    key: key.clone(),
                    max_invocations: 2,
                }],
                0,
            ))
            .expect("authorize immutable quota"),
    );

    let changed = authorize_request(
        "immutable-changed",
        vec![BudgetInvocationQuota {
            key: key.clone(),
            max_invocations: 3,
        }],
        0,
    );
    assert!(matches!(
        store.authorize_budget_hold(changed),
        Err(BudgetStoreError::Invariant(_))
    ));
    let usage = quota_usage(&store, &key);
    assert_eq!(usage.quota.max_invocations, 2);
    assert_usage(&usage, 1, 0);
}

#[test]
fn reversing_composite_hold_restores_every_reservation_and_exposure() {
    let store = InMemoryBudgetStore::new();
    let quotas = three_quotas(1);
    let authorization = authorize_request("reverse", quotas.clone(), 50);
    expect_authorized(
        store
            .authorize_budget_hold(authorization.clone())
            .expect("authorize hold for reverse"),
    );

    let reversed = store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            reversed_exposure_units: 50,
            hold_id: Some("hold:reverse".to_string()),
            event_id: Some("event:reverse:terminal".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .expect("reverse composite hold");
    assert_eq!(reversed.committed_cost_units_after, 0);
    for usage in &reversed.invocation_quota_usages {
        assert_usage(usage, 0, 0);
    }
    for quota in &quotas {
        assert_usage(&quota_usage(&store, &quota.key), 0, 0);
    }
    assert!(matches!(
        store.authorize_budget_hold(authorization),
        Err(BudgetStoreError::Invariant(_))
    ));

    expect_authorized(
        store
            .authorize_budget_hold(authorize_request("reuse-after-reverse", quotas, 50))
            .expect("re-authorize after reverse"),
    );
}

#[test]
fn cumulative_threshold_boundary_requires_approval_before_capture() {
    let store = InMemoryBudgetStore::new();
    let account = cumulative_account();
    let first = expect_authorized(
        store
            .authorize_budget_hold(cumulative_request(
                "cumulative-first",
                account.clone(),
                100,
                100,
                60,
            ))
            .expect("authorize first cumulative participant"),
    );
    assert_eq!(
        first.cumulative_approval.as_ref().map(|usage| usage.state),
        Some(BudgetCumulativeApprovalState::Authorized)
    );

    let pending = expect_approval_required(
        store
            .authorize_budget_hold(cumulative_request(
                "cumulative-boundary",
                account.clone(),
                100,
                100,
                40,
            ))
            .expect("reserve boundary cumulative participant"),
    );
    assert_eq!(
        pending.cumulative_approval.state,
        BudgetCumulativeApprovalState::PendingApproval
    );
    assert_eq!(
        pending.cumulative_approval.reserved_authorized_after.units,
        100
    );
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("cumulative-boundary")
            .expect("query pending cumulative operation"),
        Some(pending.cumulative_approval.clone())
    );
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("missing-operation")
            .expect("query missing cumulative operation"),
        None
    );

    let capture_before_approval =
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:cumulative-boundary".to_string(),
            event_id: "event:cumulative-boundary:capture-before-approval".to_string(),
            trusted_time: None,
            authority: None,
        });
    assert!(matches!(
        capture_before_approval,
        Err(BudgetStoreError::Invariant(_))
    ));

    let approval_request = BudgetAuthorizeCumulativeApprovalRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        operation_id: "cumulative-boundary".to_string(),
        hold_id: "hold:cumulative-boundary".to_string(),
        admission_binding: admission_binding("cumulative-boundary", CAPABILITY_ID, false),
        approval_set_digest: APPROVAL_SET_DIGEST.to_string(),
        event_id: "event:cumulative-boundary:approval".to_string(),
        authority: None,
    };
    let approval = store
        .authorize_cumulative_approval(approval_request.clone())
        .expect("attach cumulative approval");
    let approved = match approval {
        BudgetCumulativeApprovalAuthorizationDecision::Authorized(approved) => approved,
        other => panic!("expected fresh cumulative approval, got {other:?}"),
    };
    assert_eq!(
        approved
            .cumulative_approval
            .as_ref()
            .map(|usage| usage.state),
        Some(BudgetCumulativeApprovalState::Authorized)
    );

    let replay = store
        .authorize_cumulative_approval(approval_request.clone())
        .expect("replay exact cumulative approval");
    let replayed = match replay {
        BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(replayed) => replayed,
        other => panic!("expected already-authorized replay, got {other:?}"),
    };
    assert_eq!(replayed, approved);
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("cumulative-boundary")
            .expect("query approved cumulative operation"),
        approved.cumulative_approval.clone()
    );
    let account_before_mismatch = store
        .get_cumulative_approval_account_usage(&account)
        .expect("query cumulative account")
        .expect("cumulative account exists");

    let mut mismatched_digest = approval_request.clone();
    mismatched_digest.approval_set_digest = DIFFERENT_APPROVAL_SET_DIGEST.to_string();
    assert!(matches!(
        store.authorize_cumulative_approval(mismatched_digest),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_eq!(
        store
            .get_cumulative_approval_account_usage(&account)
            .expect("query cumulative account after mismatch"),
        Some(account_before_mismatch)
    );

    let capture = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:cumulative-boundary".to_string(),
            event_id: "event:cumulative-boundary:capture".to_string(),
            trusted_time: None,
            authority: None,
        })
        .expect("capture approved cumulative participant");
    let captured = match capture {
        BudgetInvocationCaptureDecision::Captured(captured) => captured,
        other => panic!("expected cumulative capture, got {other:?}"),
    };
    assert_eq!(
        captured
            .cumulative_approval
            .as_ref()
            .map(|usage| usage.state),
        Some(BudgetCumulativeApprovalState::Captured)
    );
    assert_eq!(
        store
            .get_cumulative_approval_operation_usage("cumulative-boundary")
            .expect("query captured cumulative operation"),
        captured.cumulative_approval.clone()
    );
    assert!(matches!(
        store.authorize_cumulative_approval(approval_request),
        Err(BudgetStoreError::Invariant(_))
    ));
    let capture_event = store
        .list_mutation_events(10, Some(CAPABILITY_ID), Some(GRANT_INDEX))
        .expect("list cumulative capture events")
        .into_iter()
        .find(|event| event.event_id == "event:cumulative-boundary:capture")
        .expect("cumulative capture event");
    assert_eq!(
        capture_event.cumulative_approval_set_digest.as_deref(),
        Some(APPROVAL_SET_DIGEST)
    );
    let authorize_event = store
        .list_mutation_events(10, Some(CAPABILITY_ID), Some(GRANT_INDEX))
        .expect("list cumulative authorization events")
        .into_iter()
        .find(|event| event.event_id == "event:cumulative-boundary:authorize")
        .expect("cumulative authorization event");
    assert_eq!(authorize_event.kind, BudgetMutationKind::ReserveInvocation);

    let cancellation = store
        .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:cumulative-boundary".to_string(),
            event_id: "event:cumulative-boundary:cancel".to_string(),
            authority: None,
        })
        .expect("cancel captured cumulative participant");
    let cancelled = match cancellation {
        BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(cancelled) => cancelled,
        other => panic!("expected cumulative cancellation, got {other:?}"),
    };
    assert_eq!(
        cancelled
            .cumulative_approval
            .as_ref()
            .map(|usage| usage.state),
        Some(BudgetCumulativeApprovalState::ReversedBeforeDispatch)
    );
    let account_after_cancel = store
        .get_cumulative_approval_account_usage(&account)
        .expect("query cumulative account after cancellation")
        .expect("cumulative account exists");
    assert_eq!(account_after_cancel.reserved_authorized.units, 60);
    assert_eq!(account_after_cancel.captured_authorized.units, 0);
}

#[test]
fn pending_approval_timeout_and_attachment_have_one_cas_winner() {
    let store = Arc::new(InMemoryBudgetStore::new());
    let account = cumulative_account();
    expect_approval_required(
        store
            .authorize_budget_hold(cumulative_request(
                "approval-timeout-race",
                account.clone(),
                100,
                100,
                100,
            ))
            .expect("reserve pending cumulative participant"),
    );

    let barrier = Arc::new(Barrier::new(3));
    let approval_store = Arc::clone(&store);
    let approval_barrier = Arc::clone(&barrier);
    let approval = thread::spawn(move || {
        approval_barrier.wait();
        approval_store
            .authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                operation_id: "approval-timeout-race".to_string(),
                hold_id: "hold:approval-timeout-race".to_string(),
                admission_binding: admission_binding("approval-timeout-race", CAPABILITY_ID, false),
                approval_set_digest: APPROVAL_SET_DIGEST.to_string(),
                event_id: "event:approval-timeout-race:approval".to_string(),
                authority: None,
            })
            .is_ok()
    });
    let timeout_store = Arc::clone(&store);
    let timeout_barrier = Arc::clone(&barrier);
    let timeout = thread::spawn(move || {
        timeout_barrier.wait();
        timeout_store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: CAPABILITY_ID.to_string(),
                grant_index: GRANT_INDEX,
                reversed_exposure_units: 0,
                hold_id: Some("hold:approval-timeout-race".to_string()),
                event_id: Some("event:approval-timeout-race:timeout".to_string()),
                expected_cumulative_approval_state: Some(
                    BudgetCumulativeApprovalState::PendingApproval,
                ),
                authority: None,
            })
            .is_ok()
    });
    barrier.wait();

    let approval_won = approval.join().expect("approval thread");
    let timeout_won = timeout.join().expect("timeout thread");
    assert_ne!(approval_won, timeout_won);

    let account = store
        .get_cumulative_approval_account_usage(&account)
        .expect("query cumulative account")
        .expect("cumulative account exists");
    assert_eq!(
        account.reserved_authorized.units,
        u64::from(approval_won) * 100
    );
}

#[test]
fn zero_exposure_invocation_reverse_preserves_released_monetary_state() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "orthogonal-reverse",
                vec![quota.clone()],
                50,
            ))
            .expect("authorize orthogonal hold"),
    );
    let released = store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            released_exposure_units: 50,
            hold_id: Some("hold:orthogonal-reverse".to_string()),
            event_id: Some("event:orthogonal-reverse:release".to_string()),
            authority: None,
        })
        .expect("release monetary exposure");
    assert_eq!(released.monetary_state, BudgetMonetaryState::Released);

    let reversed = store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            reversed_exposure_units: 0,
            hold_id: Some("hold:orthogonal-reverse".to_string()),
            event_id: Some("event:orthogonal-reverse:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        })
        .expect("reverse invocation reservation");
    assert_eq!(reversed.invocation_state, BudgetInvocationState::Reversed);
    assert_eq!(reversed.monetary_state, BudgetMonetaryState::Released);
    assert_usage(&quota_usage(&store, &quota.key), 0, 0);
}

#[test]
fn fully_released_monetary_hold_cannot_capture_invocation() {
    let store = InMemoryBudgetStore::new();
    let quota = grant_quota(1);
    expect_authorized(
        store
            .authorize_budget_hold(authorize_request(
                "release-before-capture",
                vec![quota.clone()],
                50,
            ))
            .expect("authorize releasable hold"),
    );
    store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            released_exposure_units: 50,
            hold_id: Some("hold:release-before-capture".to_string()),
            event_id: Some("event:release-before-capture:release".to_string()),
            authority: None,
        })
        .expect("release full exposure before capture");

    assert!(matches!(
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: CAPABILITY_ID.to_string(),
            grant_index: GRANT_INDEX,
            hold_id: "hold:release-before-capture".to_string(),
            event_id: "event:release-before-capture:capture".to_string(),
            trusted_time: None,
            authority: None,
        }),
        Err(BudgetStoreError::Invariant(_))
    ));
    assert_usage(&quota_usage(&store, &quota.key), 1, 0);
    let usage = store
        .get_usage(CAPABILITY_ID, GRANT_INDEX)
        .expect("query released usage")
        .expect("released usage exists");
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.invocation_count, 1);
}

#[test]
fn family_siblings_share_authority_account_but_keep_effective_thresholds() {
    let store = InMemoryBudgetStore::new();
    let account = cumulative_account();
    let narrow = expect_authorized(
        store
            .authorize_budget_hold(cumulative_request(
                "family-narrow",
                account.clone(),
                100,
                50,
                40,
            ))
            .expect("authorize narrow family participant"),
    );
    let wider = expect_authorized(
        store
            .authorize_budget_hold(cumulative_request(
                "family-wider",
                account.clone(),
                100,
                100,
                50,
            ))
            .expect("authorize wider family participant"),
    );
    assert_eq!(
        narrow
            .cumulative_approval
            .as_ref()
            .expect("narrow cumulative usage")
            .effective_threshold
            .units,
        50
    );
    assert_eq!(
        wider
            .cumulative_approval
            .as_ref()
            .expect("wider cumulative usage")
            .effective_threshold
            .units,
        100
    );

    let boundary = expect_approval_required(
        store
            .authorize_budget_hold(cumulative_request("family-boundary", account, 100, 100, 10))
            .expect("reserve family boundary participant"),
    );
    assert_eq!(
        boundary.cumulative_approval.reserved_authorized_after.units,
        100
    );
}
