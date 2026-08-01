use super::*;

#[test]
fn recovery_claims_are_bounded_fenced_and_time_monotonic() {
    let fixture = fixture();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-a",
        "capability-recovery-a",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-b",
        "capability-recovery-b",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .expect("begin");
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    fixture
        .store
        .claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-active"),
            now,
            now + 1_000,
            &fixture.fence,
        )
        .expect("claim");
    let recoverable = fixture
        .store
        .list_recoverable(now, 10)
        .expect("recoverable");
    assert_eq!(recoverable, vec![second.clone()]);
    assert_eq!(
        fixture
            .store
            .list_recoverable(now + 1_000, 10)
            .expect("expired claim scan")
            .len(),
        2
    );
    assert!(matches!(
        fixture.store.list_recoverable(now, 257),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));

    let mut forged = fixture.fence.clone();
    forged.owner_epoch += 1;
    assert!(matches!(
        fixture.store.claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-forged"),
            now,
            now + 1_000,
            &forged,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(matches!(
        fixture.store.claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "worker-old-time"),
            1,
            now + 1_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn recovery_claims_advance_a_full_batch_without_hiding_later_operations() {
    let fixture = fixture();
    let begun_at = now_ms();
    for index in 0..257 {
        let request_id = format!("request-recovery-page-{index:03}");
        let capability_id = format!("capability-recovery-page-{index:03}");
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            &request_id,
            &capability_id,
        );
        fixture
            .store
            .begin(&operation, &fixture.fence, begun_at)
            .expect("begin paged recovery operation");
    }
    let trusted_now = begun_at + 1;
    let first = fixture
        .store
        .list_recoverable(trusted_now, 256)
        .expect("first recovery page");
    assert_eq!(first.len(), 256);
    for operation in &first {
        fixture
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &identifier("claimant_id", "paged-recovery-worker"),
                trusted_now,
                trusted_now + 1_000,
                &fixture.fence,
            )
            .expect("claim first-page recovery operation");
    }
    let second = fixture
        .store
        .list_recoverable(trusted_now, 256)
        .expect("second recovery page");
    assert_eq!(second.len(), 1);
    assert!(first.iter().all(|operation| {
        operation.binding().operation_id() != second[0].binding().operation_id()
    }));
}

#[test]
fn recovery_claim_retry_returns_the_persisted_lease_when_expiry_changes() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-retry",
        "capability-recovery-retry",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let claimant = identifier("claimant_id", "worker-retry");
    let first = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 1,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("first claim");
    let retried = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 2,
            begun_at + 20_000,
            &fixture.fence,
        )
        .expect("retry claim");

    assert_eq!(retried, first);
    let claim_commits: i64 = fixture
        .store
        .connection()
        .expect("connection")
        .query_row(
            "SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind = 'recovery_claim'",
            [],
            |row| row.get(0),
        )
        .expect("claim commits");
    assert_eq!(claim_commits, 1);
}

#[test]
fn qualified_recovery_rechecks_history_version_fence_and_expiry() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-qualified-recovery",
        "capability-qualified-recovery",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    let expires_at = now + 100;
    let lease = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", "qualified-worker"),
            now,
            expires_at,
            &fixture.fence,
        )
        .expect("qualified claim");
    fixture
        .store
        .revalidate_recovery_claim(&operation, lease.untrusted_claim(), now + 1, &fixture.fence)
        .expect("exact durable claim must revalidate");

    let forged =
        |coordinator_lease_id: &str, claimed_version: u64, store_fence: StoreMutationFence| {
            UntrustedAdmissionRecoveryClaim::new(
                operation.binding().operation_id().clone(),
                identifier("claimant_id", "qualified-worker"),
                identifier("coordinator_lease_id", coordinator_lease_id),
                operation.coordinator_lease_epoch(),
                claimed_version,
                expires_at,
                store_fence,
            )
            .expect("forged raw claim remains structurally valid")
        };
    let wrong_history = forged(
        "different-coordinator-lease",
        operation.version(),
        fixture.fence.clone(),
    );
    assert!(matches!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            &wrong_history,
            now + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let wrong_version = forged(
        lease.coordinator_lease_id().as_str(),
        operation.version() + 1,
        fixture.fence.clone(),
    );
    assert!(matches!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            &wrong_version,
            now + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let mut stale_fence = fixture.fence.clone();
    stale_fence.lease_id = "stale-serving-lease".to_string();
    let wrong_fence = forged(
        lease.coordinator_lease_id().as_str(),
        operation.version(),
        stale_fence,
    );
    assert!(matches!(
        fixture
            .store
            .revalidate_recovery_claim(&operation, &wrong_fence, now + 1, &fixture.fence,),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_eq!(
        fixture.store.revalidate_recovery_claim(
            &operation,
            lease.untrusted_claim(),
            expires_at,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::LeaseExpired
        ))
    );
}

#[test]
fn recovery_claim_rolls_forward_only_for_the_same_claimant() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-recovery-roll-forward",
        "capability-recovery-roll-forward",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let claimant = identifier("claimant_id", "worker-owner");
    let first = fixture
        .store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &claimant,
            begun_at + 1,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("first claim");
    let updated = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                first,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-recovery-roll-forward",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at + 2,
        )
        .expect("advance operation")
        .into_operation();

    assert!(matches!(
        fixture.store.claim_recovery(
            updated.binding().operation_id(),
            2,
            &identifier("claimant_id", "worker-other"),
            begun_at + 3,
            begun_at + 20_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let rolled_forward = fixture
        .store
        .claim_recovery(
            updated.binding().operation_id(),
            2,
            &claimant,
            begun_at + 3,
            begun_at + 20_000,
            &fixture.fence,
        )
        .expect("roll claim forward");
    assert_eq!(rolled_forward.claimed_version(), 2);
    assert_eq!(rolled_forward.expires_at_unix_ms(), begun_at + 20_000);
}

#[test]
fn trusted_time_high_water_rejects_regression_across_operations() {
    let fixture = fixture();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-a",
        "capability-time-a",
    );
    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-b",
        "capability-time-b",
    );
    let third = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-time-c",
        "capability-time-c",
    );
    let begun_at = now_ms();
    assert!(matches!(
        fixture.store.begin(&first, &fixture.fence, 0),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture
            .store
            .begin(&first, &fixture.fence, MAX_TRUSTED_UNIX_MS + 1),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture
            .store
            .begin(&first, &fixture.fence, MAX_TRUSTED_UNIX_MS),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .expect("first begin");
    assert!(matches!(
        fixture.store.claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "long-lease-worker"),
            begun_at + 1,
            begun_at + 1 + MAX_RECOVERY_LEASE_DURATION_MS + 1,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture.store.claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "zero-time-worker"),
            0,
            begun_at + 10_000,
            &fixture.fence,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .claim_recovery(
            first.binding().operation_id(),
            1,
            &identifier("claimant_id", "time-worker-a"),
            begun_at + 2,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("advance time high-water");
    assert!(matches!(
        fixture.store.begin(&second, &fixture.fence, begun_at + 1),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(fixture
        .store
        .load_by_operation_id(second.binding().operation_id())
        .expect("load")
        .is_none());
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at + 2)
        .expect("non-regressing begin");
    let lease = fixture
        .store
        .claim_recovery(
            second.binding().operation_id(),
            1,
            &identifier("claimant_id", "time-worker-b"),
            begun_at + 3,
            begun_at + 10_000,
            &fixture.fence,
        )
        .expect("second claim");
    assert!(matches!(
        fixture.store.compare_and_swap(
            &command(
                &second,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-time",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            0,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .compare_and_swap(
            &command(
                &second,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-time",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at + 4,
        )
        .expect("advance high-water by CAS");
    assert!(matches!(
        fixture.store.begin(&third, &fixture.fence, begun_at + 3),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn scoped_runtime_clock_qualifies_deterministic_admission_time() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-fixed-runtime-time",
        "capability-fixed-runtime-time",
    );
    let fixed_now_unix_ms = 1_700_000_001_000;
    let _scope = chio_kernel::scope_fixed_runtime_for_current_thread(
        fixed_now_unix_ms / 1_000,
        std::iter::empty(),
    );

    fixture
        .store
        .begin(&operation, &fixture.fence, fixed_now_unix_ms)
        .expect("fixed runtime clock");
}
