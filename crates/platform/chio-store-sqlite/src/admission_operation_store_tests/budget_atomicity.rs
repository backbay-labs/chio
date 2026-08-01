use super::*;

#[test]
fn combined_budget_authorization_payment_journal_and_operation_commit_are_atomic() {
    let fixture = fixture();
    let begun_at = now_ms();
    let mut operation = prepared_payment_operation(
        &fixture.fence,
        "request-combined-authorization",
        "capability-combined-authorization",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin combined authorization operation");
    let broker_lease = claim(
        &fixture,
        &operation,
        "combined-authorization-worker",
        begun_at + 1,
    );
    operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                broker_lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-combined-authorization",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at + 2,
        )
        .expect("register combined authorization attempt")
        .into_operation();

    let hold_id = "hold-combined-authorization";
    let event_id = "authorize-combined-admission";
    let authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let request = BudgetAuthorizeHoldRequest {
        capability_id: "capability-combined-authorization".to_owned(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![
                "capability-combined-authorization".to_owned(),
            ])
            .expect("canonical revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 125,
        max_cost_per_invocation: Some(125),
        max_total_cost_units: Some(125),
        hold_id: Some(hold_id.to_owned()),
        event_id: Some(event_id.to_owned()),
        authority: Some(authority),
    };
    let journal = PaymentJournalRecord {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        journal_version: 1,
        request_namespace_digest: operation
            .binding()
            .request_namespace_digest()
            .as_str()
            .to_owned(),
        request_id: operation.binding().request_id().as_str().to_owned(),
        capability_id: operation.binding().capability_id().as_str().to_owned(),
        grant_index: 0,
        hold_id: Some(hold_id.to_owned()),
        rail: "acp".to_owned(),
        rail_mode: PaymentRailMode::ReversibleHold,
        authorization_id: None,
        transaction_id: None,
        amount_units: 125,
        settle_action: None,
        settle_amount_units: None,
        release_authority: None,
        currency: "USD".to_owned(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: begun_at + 3,
    };
    let authorization_lease = claim(
        &fixture,
        &operation,
        "combined-authorization-worker",
        begun_at + 3,
    );

    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_combined_authorization_admission_commit
                BEFORE INSERT ON admission_operation_commits
                WHEN NEW.mutation_kind = 'compare_and_swap'
                 AND NEW.participant_digest IS NOT NULL
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected combined authorization rollback');
                END;
                "#,
            )
            .expect("install combined authorization failure");
    }
    assert!(fixture
        .store
        .authorize_budget_and_commit_admission(
            &operation,
            &authorization_lease,
            request.clone(),
            Some(journal.clone()),
            None,
            &fixture.fence,
            begun_at + 4,
        )
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_combined_authorization_admission_commit")
            .expect("remove combined authorization failure");
        let (holds, journals, events): (i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = ?1),
                    (SELECT COUNT(*) FROM payment_journal WHERE operation_id = ?2),
                    (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = ?3)
                "#,
                params![
                    hold_id,
                    operation.binding().operation_id().as_str(),
                    event_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("rolled-back combined authorization state");
        assert_eq!((holds, journals, events), (0, 0, 0));
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load rolled-back operation")
            .expect("operation exists")
            .state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );

    let (decision, authorized) = fixture
        .store
        .authorize_budget_and_commit_admission(
            &operation,
            &authorization_lease,
            request.clone(),
            Some(journal.clone()),
            None,
            &fixture.fence,
            begun_at + 4,
        )
        .expect("commit combined authorization");
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert_eq!(
        authorized.state(),
        AdmissionOperationState::BudgetAuthorized
    );
    assert_eq!(
        authorized.budget_hold_id().map(AdmissionIdentifier::as_str),
        Some(hold_id)
    );

    let replayed = fixture
        .store
        .authorize_budget_and_commit_admission(
            &operation,
            &authorization_lease,
            request.clone(),
            Some(journal.clone()),
            None,
            &fixture.fence,
            begun_at + 4,
        )
        .expect("replay combined authorization");
    assert_eq!(replayed.1, authorized);
    let resumed_lease = claim(
        &fixture,
        &authorized,
        "combined-authorization-worker",
        begun_at + 5,
    );
    let resumed = fixture
        .store
        .authorize_budget_and_commit_admission(
            &authorized,
            &resumed_lease,
            request.clone(),
            Some(journal.clone()),
            None,
            &fixture.fence,
            begun_at + 6,
        )
        .expect("resume combined authorization from committed operation");
    assert_eq!(resumed.1, authorized);
    let held = fixture
        .store
        .advance_payment_journal(chio_kernel::AdmissionPaymentJournalAdvance {
            operation: &authorized,
            recovery_lease: &resumed_lease,
            expected: &journal,
            transition: &PaymentJournalTransition::AuthorizationHeld {
                authorization_id: "authorization-combined".to_owned(),
            },
            release_evidence: None,
            active_fence: &fixture.fence,
            trusted_now_unix_ms: begun_at + 7,
        })
        .expect("advance payment authorization");
    assert_eq!(held.state, PaymentJournalState::Authorized);
    assert_eq!(held.journal_version, 2);
    let post_transition_replay = fixture
        .store
        .authorize_budget_and_commit_admission(
            &authorized,
            &resumed_lease,
            request,
            Some(journal.clone()),
            None,
            &fixture.fence,
            begun_at + 8,
        )
        .expect("replay combined authorization after payment transition");
    assert_eq!(post_transition_replay.1, authorized);
    assert_eq!(
        fixture
            .store
            .advance_payment_journal(chio_kernel::AdmissionPaymentJournalAdvance {
                operation: &authorized,
                recovery_lease: &resumed_lease,
                expected: &journal,
                transition: &PaymentJournalTransition::AuthorizationHeld {
                    authorization_id: "authorization-combined".to_owned(),
                },
                release_evidence: None,
                active_fence: &fixture.fence,
                trusted_now_unix_ms: begun_at + 7,
            })
            .expect("replay payment authorization"),
        held
    );
    let connection = Connection::open(&fixture.database).expect("open independent connection");
    let (holds, journals, events, participant_commits, payment_commits): (i64, i64, i64, i64, i64) =
        connection
            .query_row(
                r#"
            SELECT
                (SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = ?1),
                (SELECT COUNT(*) FROM payment_journal WHERE operation_id = ?2),
                (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = ?3),
                (SELECT COUNT(*) FROM admission_operation_commits
                 WHERE operation_id = ?2 AND participant_digest IS NOT NULL),
                (SELECT COUNT(*) FROM authority_global_commits
                 WHERE projection_kind = 'payment' AND projection_key = ?2)
            "#,
                params![
                    hold_id,
                    operation.binding().operation_id().as_str(),
                    event_id
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("combined authorization commit counts");
    assert_eq!(
        (
            holds,
            journals,
            events,
            participant_commits,
            payment_commits
        ),
        (1, 1, 1, 1, 2)
    );
    drop(connection);

    let mut dispatching = authorized.clone();
    for (offset, state) in [
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
    ]
    .into_iter()
    .enumerate()
    {
        let at = begun_at + 9 + u64::try_from(offset).expect("dispatch transition index") * 2;
        let lease = if offset == 0 {
            resumed_lease.clone()
        } else {
            claim(&fixture, &dispatching, "combined-authorization-worker", at)
        };
        dispatching = fixture
            .store
            .compare_and_swap(
                &command(&dispatching, lease, Vec::new(), state, None),
                at + 1,
            )
            .expect("advance payment operation to capture pending")
            .into_operation();
    }
    let settlement_authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let capture_lease = claim(
        &fixture,
        &dispatching,
        "combined-authorization-worker",
        begun_at + 13,
    );
    let (_, dispatched) = fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &dispatching,
            &capture_lease,
            BudgetCaptureInvocationRequest {
                capability_id: operation.binding().capability_id().as_str().to_owned(),
                grant_index: 0,
                hold_id: hold_id.to_owned(),
                event_id: "capture-combined-settlement".to_owned(),
                trusted_time: None,
                authority: Some(settlement_authority.clone()),
            },
            &fixture.fence,
            begun_at + 14,
        )
        .expect("capture payment operation before settlement");
    let settlement_lease = claim(
        &fixture,
        &dispatched,
        "combined-authorization-worker",
        begun_at + 15,
    );
    let transition = PaymentJournalTransition::BeginCapture { amount_units: 75 };
    let reconcile = BudgetReconcileHoldRequest {
        capability_id: operation.binding().capability_id().as_str().to_owned(),
        grant_index: 0,
        exposed_cost_units: 125,
        realized_spend_units: 75,
        hold_id: Some(hold_id.to_owned()),
        event_id: Some(format!("{hold_id}:reconcile")),
        authority: Some(settlement_authority),
    };
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_combined_payment_settlement
                AFTER UPDATE OF state ON payment_journal
                WHEN NEW.state = 'settling'
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected combined settlement rollback');
                END;
                "#,
            )
            .expect("install combined settlement failure");
    }
    assert!(fixture
        .store
        .begin_payment_settlement(AdmissionPaymentSettlementBegin {
            operation: &dispatched,
            recovery_lease: &settlement_lease,
            expected: &held,
            transition: Some(&transition),
            release_evidence: None,
            budget_reconcile: reconcile.clone(),
            active_fence: &fixture.fence,
            trusted_now_unix_ms: begun_at + 16,
        })
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_combined_payment_settlement")
            .expect("remove combined settlement failure");
        let (budget_state, payment_state, events): (String, String, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT monetary_state FROM budget_authorization_holds WHERE hold_id = ?1),
                    (SELECT state FROM payment_journal WHERE operation_id = ?2),
                    (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = ?3)
                "#,
                params![
                    hold_id,
                    operation.binding().operation_id().as_str(),
                    reconcile.event_id.as_deref()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("rolled-back combined settlement state");
        assert_eq!(
            (budget_state.as_str(), payment_state.as_str(), events),
            ("exposed", "authorized", 0)
        );
    }
    let settlement = fixture
        .store
        .begin_payment_settlement(AdmissionPaymentSettlementBegin {
            operation: &dispatched,
            recovery_lease: &settlement_lease,
            expected: &held,
            transition: Some(&transition),
            release_evidence: None,
            budget_reconcile: reconcile.clone(),
            active_fence: &fixture.fence,
            trusted_now_unix_ms: begun_at + 16,
        })
        .expect("commit combined payment settlement");
    assert_eq!(settlement.journal.state, PaymentJournalState::Settling);
    assert_eq!(settlement.budget.realized_spend_units, 75);
    assert!(!settlement.budget_already_reconciled);
    let replayed_settlement = fixture
        .store
        .begin_payment_settlement(AdmissionPaymentSettlementBegin {
            operation: &dispatched,
            recovery_lease: &settlement_lease,
            expected: &settlement.journal,
            transition: None,
            release_evidence: None,
            budget_reconcile: reconcile,
            active_fence: &fixture.fence,
            trusted_now_unix_ms: begun_at + 17,
        })
        .expect("replay combined payment settlement");
    assert_eq!(replayed_settlement.journal, settlement.journal);
    assert!(replayed_settlement.budget_already_reconciled);

    let connection = Connection::open(&fixture.database).expect("open tamper connection");
    connection
        .execute(
            "UPDATE payment_journal SET authorization_id = 'authorization-tampered' WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
        )
        .expect("tamper payment journal");
    drop(connection);
    assert!(fixture
        .store
        .load_payment_journal(operation.binding().operation_id().as_str(), &fixture.fence)
        .is_err());
}

#[test]
fn combined_budget_capture_and_dispatch_commit_is_atomic_and_exactly_replayable() {
    let fixture = fixture();
    let begun_at = now_ms();
    let mut operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-combined-capture",
        "capability-combined-capture",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin combined capture operation");
    let hold_id = "hold-combined-capture";
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation,
                "attempt-combined-capture",
            ))],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                hold_id,
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
    ];
    for (index, (state, attachments)) in transitions.into_iter().enumerate() {
        let at = begun_at + 1 + u64::try_from(index).expect("transition index") * 2;
        let lease = claim(&fixture, &operation, "combined-capture-worker", at);
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, lease, attachments, state, None),
                at + 1,
            )
            .expect("advance combined capture operation")
            .into_operation();
    }
    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);

    let authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let budget = fixture.authority.budget_store();
    assert!(matches!(
        budget
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "capability-combined-capture".to_owned(),
                grant_index: 0,
                max_invocations: Some(1),
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: Some(BudgetAdmissionBinding {
                    operation_id: operation.binding().operation_id().as_str().to_owned(),
                    revocation_set: CanonicalRevocationSet::canonicalize(vec![
                        "capability-combined-capture".to_owned(),
                    ])
                    .expect("canonical revocation set"),
                    authorization_artifact_digests: vec!["a".repeat(64)],
                    last_observed_revocation: None,
                    supplemental_verifier_id: None,
                    supplemental_verifier_config_digest: None,
                    supplemental_authorization_artifact_digest: None,
                    supplemental_authorization_expires_at: None,
                }),
                requested_exposure_units: 10,
                max_cost_per_invocation: Some(10),
                max_total_cost_units: Some(10),
                hold_id: Some(hold_id.to_owned()),
                event_id: Some("authorize-combined-capture".to_owned()),
                authority: Some(authority.clone()),
            })
            .expect("authorize combined capture hold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let capture = BudgetCaptureInvocationRequest {
        capability_id: "capability-combined-capture".to_owned(),
        grant_index: 0,
        hold_id: hold_id.to_owned(),
        event_id: "capture-combined-capture".to_owned(),
        trusted_time: None,
        authority: Some(authority),
    };
    let capture_at = begun_at + 20;
    let lease = claim(&fixture, &operation, "combined-capture-worker", capture_at);
    let head_before = {
        let connection = fixture.store.connection().expect("connection");
        connection
            .query_row(
                "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("global head before capture")
    };
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_combined_capture_admission_commit
                BEFORE INSERT ON admission_operation_commits
                WHEN NEW.mutation_kind = 'compare_and_swap'
                 AND NEW.participant_digest IS NOT NULL
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected combined capture rollback');
                END;
                "#,
            )
            .expect("install combined capture failure");
    }
    assert!(fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &operation,
            &lease,
            capture.clone(),
            &fixture.fence,
            capture_at + 1,
        )
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_combined_capture_admission_commit")
            .expect("remove combined capture failure");
        let (state, capture_events, global_head): (String, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT invocation_state FROM budget_authorization_holds
                     WHERE hold_id = ?1),
                    (SELECT COUNT(*) FROM budget_mutation_events
                     WHERE event_id = ?2),
                    (SELECT head_sequence FROM authority_global_commit_meta
                     WHERE singleton = 1)
                "#,
                params![hold_id, &capture.event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("state after rolled-back combined capture");
        assert_eq!(state, "authorized");
        assert_eq!(capture_events, 0);
        assert_eq!(global_head, head_before);
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load rolled-back operation")
            .expect("rolled-back operation exists")
            .state(),
        AdmissionOperationState::CapturePending
    );

    let (capture_decision, dispatched) = fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &operation,
            &lease,
            capture.clone(),
            &fixture.fence,
            capture_at + 1,
        )
        .expect("commit combined capture");
    assert!(matches!(
        capture_decision,
        BudgetInvocationCaptureDecision::Captured(_)
    ));
    assert_eq!(
        dispatched.state(),
        AdmissionOperationState::DispatchCommitted
    );
    let (replay_decision, replayed) = fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &operation,
            &lease,
            capture.clone(),
            &fixture.fence,
            capture_at + 1,
        )
        .expect("replay exact combined capture");
    assert!(matches!(
        replay_decision,
        BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    assert_eq!(replayed, dispatched);
    let connection = fixture.store.connection().expect("connection");
    let (capture_events, participant_commits, global_head): (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = ?1),
                (SELECT COUNT(*) FROM admission_operation_commits
                 WHERE operation_id = ?2 AND participant_digest IS NOT NULL),
                (SELECT head_sequence FROM authority_global_commit_meta
                 WHERE singleton = 1)
            "#,
            params![
                &capture.event_id,
                operation.binding().operation_id().as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("combined capture commit counts");
    assert_eq!(capture_events, 1);
    assert_eq!(participant_commits, 1);
    assert_eq!(global_head, head_before + 2);
}
