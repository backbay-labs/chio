use super::*;

#[test]
fn sqlite_legacy_event_only_authorization_replays_once_with_invocation_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-legacy-event-replay");
    let store = SqliteBudgetStore::open(&path)?;
    for _ in 0..2 {
        assert!(store.try_charge_cost_with_ids_and_authority(
            "cap-legacy-event",
            0,
            Some(1),
            10,
            Some(10),
            Some(10),
            None,
            Some("legacy-authorize-event"),
            None,
        )?);
    }
    let usage = store
        .get_usage("cap-legacy-event", 0)?
        .ok_or_else(|| std::io::Error::other("legacy event usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 10, 0);
    let events = store.list_mutation_events(10, Some("cap-legacy-event"), Some(0))?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "legacy-authorize-event");

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_invocation_count_overflow_is_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-invocation-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    store.connection()?.execute(
        r#"
        INSERT INTO capability_grant_budgets (
            capability_id, grant_index, invocation_count, updated_at, seq,
            total_cost_exposed, total_cost_realized_spend
        ) VALUES (?1, 0, ?2, 0, 0, 0, 0)
        "#,
        params!["cap-invocation-overflow", i64::from(u32::MAX)],
    )?;
    let result = store.try_increment_with_event_id(
        "cap-invocation-overflow",
        0,
        None,
        Some("invocation-overflow"),
    );
    assert!(result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("invocation count overflowed")));
    assert_eq!(store.max_mutation_event_seq()?, 0);
    let usage = store
        .get_usage("cap-invocation-overflow", 0)?
        .ok_or_else(|| std::io::Error::other("overflow usage missing"))?;
    assert_eq!(usage.invocation_count, u32::MAX);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_oversized_grant_index_fails_before_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(grant_index) = usize::try_from(u64::from(u32::MAX) + 1) else {
        return Ok(());
    };
    let path = unique_db_path("chio-budget-grant-index-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    let results = [
        store.try_increment_with_event_id(
            "cap-grant-overflow",
            grant_index,
            None,
            Some("grant-overflow:increment"),
        ),
        store.try_charge_cost_with_ids(
            "cap-grant-overflow",
            grant_index,
            None,
            1,
            None,
            None,
            None,
            Some("grant-overflow:authorize"),
        ),
    ];
    for result in results {
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("grant_index exceeds u32 range")));
    }
    assert!(store
        .get_usage("cap-grant-overflow", grant_index)
        .as_ref()
        .is_err_and(|error| error.to_string().contains("grant_index exceeds u32 range")));
    assert!(store
        .list_mutation_events(10, Some("cap-grant-overflow"), Some(grant_index))
        .as_ref()
        .is_err_and(|error| error.to_string().contains("grant_index exceeds u32 range")));
    assert_eq!(store.max_mutation_event_seq()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn independent_plain_opens_reject_composite_authorization_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-composite-durable");
    let first = SqliteBudgetStore::open(&path)?;
    let second = SqliteBudgetStore::open(&path)?;
    let request = BudgetAuthorizeHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: vec![chio_kernel::budget_store::BudgetInvocationQuota {
            key: chio_kernel::budget_store::BudgetQuotaKey::grant("cap-composite", 0),
            max_invocations: 1,
        }],
        cumulative_approval: None,
        admission_binding: Some(chio_kernel::budget_store::BudgetAdmissionBinding {
            operation_id: "op-composite".to_string(),
            revocation_set: chio_kernel::supplemental_quota::CanonicalRevocationSet::canonicalize(
                vec!["cap-composite".to_string()],
            )?,
            authorization_artifact_digests: Vec::new(),
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:authorize".to_string()),
        authority: None,
    };
    for store in [&first, &second] {
        let error = store
            .authorize_budget_hold(request.clone())
            .expect_err("plain sqlite open must not own structured authority");
        assert!(error
            .to_string()
            .contains("require a provisioned serving owner"));
        assert_eq!(store.max_mutation_event_seq()?, 0);
        assert!(store.get_usage("cap-composite", 0)?.is_none());
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_rejects_unsupported_imported_mutation_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-composite-import-unsupported");
    let store = SqliteBudgetStore::open(&path)?;
    let mut event = ack_head_event(1, "event-composite", "http://origin");
    event.kind = BudgetMutationKind::ReserveInvocation;

    let error = match store.import_mutation_record(&event) {
        Ok(()) => return Err(std::io::Error::other("sqlite imported composite mutation").into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("uses state unsupported by the sqlite budget store"));
    assert_eq!(store.max_mutation_event_seq()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_rejects_unrepresentable_authorization_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-authorization-sqlite-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    let error = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-overflow".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: u64::MAX,
            max_cost_per_invocation: Some(u64::MAX),
            max_total_cost_units: Some(u64::MAX),
            hold_id: Some("hold-overflow".to_string()),
            event_id: Some("hold-overflow:authorize".to_string()),
            authority: None,
        })
        .expect_err("unrepresentable monetary values must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert!(store.get_usage("cap-overflow", 0)?.is_none());
    assert_eq!(store.max_mutation_event_seq()?, 0);

    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    assert!(SqliteBudgetStore::load_hold(&transaction, "hold-overflow")?.is_none());
    transaction.rollback()?;
    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_rolls_back_snapshot_when_event_exceeds_integer_range(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-import-sqlite-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    let usage = usage_record("cap-import-overflow", 0, 1, 1, 1, 10, 0);
    let mut event = ack_head_event(2, "event-import-overflow", "budget-primary");
    event.exposure_units = u64::MAX;

    let error = store
        .import_snapshot_records(std::slice::from_ref(&usage), &[event])
        .expect_err("unrepresentable imported values must roll back the snapshot");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert!(store.get_usage("cap-import-overflow", 0)?.is_none());
    assert_eq!(store.max_mutation_event_seq()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_capture_overflow_rolls_back_hold_transition(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-capture-sqlite-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_charge_cost_with_ids(
        "cap-capture-overflow",
        0,
        Some(1),
        10,
        Some(10),
        Some(10),
        Some("hold-capture-overflow"),
        Some("hold-capture-overflow:authorize"),
    )?);
    {
        let connection = store.connection()?;
        connection.execute(
            "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
            params![i64::MAX],
        )?;
    }

    let error = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-capture-overflow".to_string(),
            grant_index: 0,
            hold_id: "hold-capture-overflow".to_string(),
            event_id: "hold-capture-overflow:capture".to_string(),
            trusted_time: None,
            authority: None,
        })
        .expect_err("unrepresentable capture sequence must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert_eq!(store.max_mutation_event_seq()?, 1);
    let usage = store
        .get_usage("cap-capture-overflow", 0)?
        .ok_or_else(|| std::io::Error::other("capture usage disappeared"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 10, 0);

    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let hold = SqliteBudgetStore::load_hold(&transaction, "hold-capture-overflow")?
        .ok_or_else(|| std::io::Error::other("capture hold disappeared"))?;
    assert!(!hold.invocation_captured);
    transaction.rollback()?;
    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_migrates_invocation_captured_column(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-invocation-captured-migration");
    {
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            r#"
                CREATE TABLE capability_grant_budgets (
                    capability_id TEXT NOT NULL,
                    grant_index INTEGER NOT NULL,
                    invocation_count INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    seq INTEGER NOT NULL DEFAULT 0,
                    total_cost_exposed INTEGER NOT NULL DEFAULT 0,
                    total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (capability_id, grant_index)
                );
                CREATE TABLE budget_authorization_holds (
                    hold_id TEXT PRIMARY KEY,
                    capability_id TEXT NOT NULL,
                    grant_index INTEGER NOT NULL,
                    authorized_exposure_units INTEGER NOT NULL,
                    remaining_exposure_units INTEGER NOT NULL,
                    invocation_count_debited INTEGER NOT NULL,
                    disposition TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                INSERT INTO budget_authorization_holds (
                    hold_id,
                    capability_id,
                    grant_index,
                    authorized_exposure_units,
                    remaining_exposure_units,
                    invocation_count_debited,
                    disposition,
                    created_at,
                    updated_at
                ) VALUES
                    ('hold-legacy-open', 'cap-legacy', 0, 100, 100, 1, 'open', 1, 1),
                    ('hold-legacy-terminal', 'cap-legacy', 1, 100, 0, 1, 'reconciled', 1, 1);
                INSERT INTO capability_grant_budgets (
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                ) VALUES ('cap-legacy', 0, 1, 1, 1, 100, 0);
                "#,
        )?;
    }

    let store = SqliteBudgetStore::open(&path)?;
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let open = SqliteBudgetStore::load_hold(&transaction, "hold-legacy-open")?
        .ok_or_else(|| std::io::Error::other("migrated open budget hold missing"))?;
    assert!(open.invocation_captured);
    let terminal = SqliteBudgetStore::load_hold(&transaction, "hold-legacy-terminal")?
        .ok_or_else(|| std::io::Error::other("migrated terminal budget hold missing"))?;
    assert!(!terminal.invocation_captured);
    transaction.rollback()?;
    drop(connection);

    assert!(store
        .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-legacy".to_string(),
            grant_index: 0,
            hold_id: "hold-legacy-open".to_string(),
            event_id: "hold-legacy-open:cancel-captured-before-dispatch".to_string(),
            authority: None,
        })
        .is_err());
    let usage = store
        .get_usage("cap-legacy", 0)?
        .ok_or_else(|| std::io::Error::other("migrated legacy usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(usage.total_cost_realized_spend, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_v1_existing_capture_column_quarantines_open_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-v1-existing-capture-column");
    drop(SqliteBudgetStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute(
        r#"
        INSERT INTO capability_grant_budgets (
            capability_id, grant_index, invocation_count, updated_at, seq,
            total_cost_exposed, total_cost_realized_spend
        ) VALUES ('cap-v1-captured', 0, 1, 1, 1, 25, 0)
        "#,
        [],
    )?;
    connection.execute(
        r#"
        INSERT INTO budget_authorization_holds (
            hold_id, capability_id, grant_index, authorized_exposure_units,
            remaining_exposure_units, invocation_count_debited,
            invocation_captured, disposition, created_at, updated_at
        ) VALUES ('hold-v1-captured', 'cap-v1-captured', 0, 25, 25, 1, 0, 'open', 1, 1)
        "#,
        [],
    )?;
    crate::stamp_schema_version(&connection, "budget", 1)?;
    drop(connection);

    let store = SqliteBudgetStore::open(&path)?;
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let hold = SqliteBudgetStore::load_hold(&transaction, "hold-v1-captured")?
        .ok_or_else(|| std::io::Error::other("migrated hold missing"))?;
    assert!(hold.invocation_captured);
    transaction.rollback()?;
    drop(connection);
    assert!(store
        .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-v1-captured".to_string(),
            grant_index: 0,
            hold_id: "hold-v1-captured".to_string(),
            event_id: "hold-v1-captured:authorize:rollback:1".to_string(),
            authority: None,
        })
        .is_err());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn rollback_shaped_unrelated_event_cannot_reopen_budget_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-fake-rollback-fence");
    let store = SqliteBudgetStore::open(&path)?;
    let request = BudgetAuthorizeHoldRequest {
        capability_id: "cap-fake-rollback".to_string(),
        grant_index: 0,
        max_invocations: Some(10),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1000),
        hold_id: Some("hold-fake-rollback".to_string()),
        event_id: Some("hold-fake-rollback:authorize".to_string()),
        authority: None,
    };
    let authorized = match store.authorize_budget_hold(request.clone())? {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
        other => {
            return Err(std::io::Error::other(format!(
                "initial authorization was not allowed: {other:?}"
            ))
            .into())
        }
    };
    let authorize_seq = authorized
        .metadata
        .budget_commit_index
        .ok_or_else(|| std::io::Error::other("authorize generation missing"))?;
    let fake_fence = format!("hold-fake-rollback:authorize:rollback:{authorize_seq}");
    assert!(store.try_increment_with_event_id(
        "cap-fake-rollback",
        0,
        Some(10),
        Some(&fake_fence),
    )?);
    store.reverse_charge_cost_with_ids(
        "cap-fake-rollback",
        0,
        100,
        Some("hold-fake-rollback"),
        Some("hold-fake-rollback:unrelated-reverse"),
    )?;

    assert!(store.authorize_budget_hold(request).is_err());
    let usage = store
        .get_usage("cap-fake-rollback", 0)?
        .ok_or_else(|| std::io::Error::other("fake rollback usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 0);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn compensated_kernel_budget_holds_require_fresh_request_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-nonce-preflight-terminal");
    let store = SqliteBudgetStore::open(&path)?;
    for (prefix, capability_id) in [
        ("nonce-preflight-budget-hold", "cap-preflight"),
        ("budget-hold", "cap-executable"),
    ] {
        let hold_id = format!("{prefix}:req-1:{capability_id}:0");
        let event_id = format!("{hold_id}:authorize:attempt-1");
        assert!(store.try_charge_cost_with_ids(
            capability_id,
            0,
            Some(1),
            0,
            None,
            None,
            Some(&hold_id),
            Some(&event_id),
        )?);
        let authorize_seq = store
            .list_mutation_events(10, Some(capability_id), Some(0))?
            .into_iter()
            .find(|event| event.event_id == event_id)
            .ok_or_else(|| std::io::Error::other("kernel budget authorization missing"))?
            .event_seq;
        store.reverse_charge_cost_with_ids(
            capability_id,
            0,
            0,
            Some(&hold_id),
            Some(&format!("{event_id}:rollback:{authorize_seq}")),
        )?;

        let terminal_seq = store.max_mutation_event_seq()?;
        let next_event_id = format!("{hold_id}:authorize:attempt-2");
        for (retry_event_id, expected_error) in [
            (event_id.as_str(), "cannot be reopened"),
            (
                next_event_id.as_str(),
                "exists without the requested authorization event",
            ),
        ] {
            let retry = store.try_charge_cost_with_ids(
                capability_id,
                0,
                Some(1),
                0,
                None,
                None,
                Some(&hold_id),
                Some(retry_event_id),
            );
            assert!(
                retry
                    .as_ref()
                    .is_err_and(|error| error.to_string().contains(expected_error)),
                "unexpected retry result: {retry:?}"
            );
            assert_eq!(store.max_mutation_event_seq()?, terminal_seq);
        }

        let fresh_hold_id = format!("{prefix}:req-2:{capability_id}:0");
        assert!(store.try_charge_cost_with_ids(
            capability_id,
            0,
            Some(1),
            0,
            None,
            None,
            Some(&fresh_hold_id),
            Some(&format!("{fresh_hold_id}:authorize")),
        )?);
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_rich_reverse_supports_kernel_cleanup_with_durable_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-rich-kernel-reverse");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "nonce-preflight-budget-hold:req-1:cap-preflight:0";
    store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-preflight".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some(hold_id.to_string()),
        event_id: Some(format!("{hold_id}:authorize")),
        authority: None,
    })?;
    let request = BudgetReverseHoldRequest {
        capability_id: "cap-preflight".to_string(),
        grant_index: 0,
        reversed_exposure_units: 0,
        hold_id: Some(hold_id.to_string()),
        event_id: Some(format!("{hold_id}:rollback")),
        expected_cumulative_approval_state: None,
        authority: None,
    };
    let event_seq_before = store.max_mutation_event_seq()?;
    let mut fenced = request.clone();
    fenced.expected_cumulative_approval_state =
        Some(chio_kernel::budget_store::BudgetCumulativeApprovalState::PendingApproval);
    assert!(store
        .reverse_budget_hold(fenced)
        .as_ref()
        .is_err_and(|error| error
            .to_string()
            .contains("cumulative approval state fencing")));
    assert_eq!(store.max_mutation_event_seq()?, event_seq_before);

    let reversed = store.reverse_budget_hold(request.clone())?;
    assert_eq!(reversed.hold_id.as_deref(), Some(hold_id));
    assert_eq!(reversed.exposure_units, 0);
    assert_eq!(reversed.committed_cost_units_after, 0);
    assert_eq!(reversed.invocation_count_after, 0);
    assert_eq!(reversed.invocation_state, BudgetInvocationState::Reversed);
    assert_eq!(reversed.monetary_state, BudgetMonetaryState::None);
    assert_eq!(
        reversed.metadata.event_id.as_deref(),
        Some("nonce-preflight-budget-hold:req-1:cap-preflight:0:rollback")
    );
    assert_eq!(store.reverse_budget_hold(request)?, reversed);
    let usage = store
        .get_usage("cap-preflight", 0)?
        .ok_or_else(|| std::io::Error::other("kernel cleanup usage missing"))?;
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 0, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_live_hold_blocks_unheld_legacy_mutations_without_state_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-live-hold-generic-fence");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-live-generic-fence";
    assert!(store.try_charge_cost_with_ids(
        "cap-live-generic-fence",
        0,
        Some(1),
        100,
        Some(100),
        Some(100),
        Some(hold_id),
        Some("hold-live-generic-fence:authorize"),
    )?);
    let event_seq = store.max_mutation_event_seq()?;

    let mutations = [
        store.reverse_charge_cost_with_ids(
            "cap-live-generic-fence",
            0,
            100,
            None,
            Some("generic-reverse"),
        ),
        store.reduce_charge_cost_with_ids(
            "cap-live-generic-fence",
            0,
            100,
            None,
            Some("generic-release"),
        ),
        store.settle_charge_cost_with_ids(
            "cap-live-generic-fence",
            0,
            100,
            75,
            None,
            Some("generic-reconcile"),
        ),
    ];
    for mutation in mutations {
        assert!(mutation.as_ref().is_err_and(|error| error
            .to_string()
            .contains("live budget hold blocks generic")));
    }
    assert_eq!(store.max_mutation_event_seq()?, event_seq);
    let usage = store
        .get_usage("cap-live-generic-fence", 0)?
        .ok_or_else(|| std::io::Error::other("live hold usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)?
        .ok_or_else(|| std::io::Error::other("live hold missing"))?;
    assert_eq!(hold.disposition, HoldDisposition::Open);
    assert_eq!(hold.remaining_exposure_units, 100);
    assert!(hold.invocation_count_debited);
    assert!(!hold.invocation_captured);
    transaction.rollback()?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_rejects_future_budget_schema_version(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-future-schema");
    drop(SqliteBudgetStore::open(&path)?);
    let connection = Connection::open(&path)?;
    crate::stamp_schema_version(
        &connection,
        "budget",
        BUDGET_STORE_SUPPORTED_SCHEMA_VERSION + 1,
    )?;
    drop(connection);

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => return Err(std::io::Error::other("future budget schema was accepted").into()),
        Err(error) => error,
    };
    assert!(error.to_string().contains(&format!(
        "newer than this binary supports ({BUDGET_STORE_SUPPORTED_SCHEMA_VERSION})"
    )));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_rejects_capture_schema_stamp_without_column(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-capture-schema-mismatch");
    drop(SqliteBudgetStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute(
        "ALTER TABLE budget_authorization_holds DROP COLUMN invocation_captured",
        [],
    )?;
    drop(connection);

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => return Err(std::io::Error::other("capture schema mismatch was accepted").into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("declares invocation capture support but the column is missing"));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_budget_store_upsert_usage_keeps_newer_seq_state() {
    let path = unique_db_path("chio-budget-upsert");
    let store = SqliteBudgetStore::open(&path).unwrap();
    install_usage_anchor(&store, &usage_record("cap-1", 0, 3, 10, 3, 300, 0));
    let error = store
        .upsert_usage(&usage_record("cap-1", 0, 2, 9, 2, 200, 0))
        .expect_err("stale usage snapshot must be rejected");
    assert!(error.to_string().contains("anchor"));

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 3);
    assert_usage_totals(&records[0], 300, 0);
    assert_eq!(records[0].seq, 3);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
    let path = unique_db_path("chio-budget-seq-delta");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    let first = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(first.len(), 1);
    let first_seq = first[0].seq;

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].invocation_count, 3);
    assert!(delta[0].seq > first_seq);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
    let path = unique_db_path("chio-budget-seq-floor");
    let store = SqliteBudgetStore::open(&path).unwrap();

    install_usage_anchor(&store, &usage_record("cap-1", 0, 3, 10, 42, 0, 0));
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 4);
    assert_eq!(records[0].seq, 43);

    let _ = fs::remove_file(path);
}

// --- try_charge_cost tests ---

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
    let path = unique_db_path("chio-charge-cost-ok");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 100 units, cap is 200 per invocation, total cap is 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-per-inv");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 500 units > max_cost_per_invocation of 200
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);

    // Nothing should have been charged
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert!(records.is_empty() || records[0].invocation_count == 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-total");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // First charge 900 of 1000 budget
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    // Second charge of 200 would exceed the total cap of 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 900, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_atomic_increment_sqlite() {
    let path = unique_db_path("chio-charge-cost-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
        .unwrap());
    assert!(store
        .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
        .unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 2);
    assert_usage_totals(&records[0], 250, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_usage_record_includes_split_cost_state() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 42, None, None)
        .unwrap());
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 42, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
    let path = unique_db_path("chio-reverse-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_sqlite() {
    let path = unique_db_path("chio-reduce-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_sqlite() {
    let path = unique_db_path("chio-settle-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_sqlite() {
    let path = unique_db_path("chio-charge-cost-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_capture_invocation_is_atomic_idempotent_and_persistent_sqlite(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-capture-invocation");
    let hold_id = "hold-cap-capture-0";
    let authorize_event_id = "hold-cap-capture-0:authorize";
    let capture_event_id = "hold-cap-capture-0:capture-invocation";
    let authority = authority("budget-primary", "lease-7", 7);

    {
        let store = SqliteBudgetStore::open(&path)?;
        assert!(store.try_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            Some(1),
            100,
            Some(100),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&authority),
        )?);
        let request = BudgetCaptureInvocationRequest {
            capability_id: "cap-capture".to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: capture_event_id.to_string(),
            trusted_time: None,
            authority: Some(authority.clone()),
        };
        let BudgetInvocationCaptureDecision::Captured(captured) =
            store.capture_invocation_reservations(request.clone())?
        else {
            return Err(std::io::Error::other("new invocation capture was replayed").into());
        };
        assert_eq!(captured.exposure_units, 100);
        assert_eq!(captured.monetary_state, BudgetMonetaryState::Exposed);
        let BudgetInvocationCaptureDecision::AlreadyCaptured(replayed) =
            store.capture_invocation_reservations(request)?
        else {
            return Err(std::io::Error::other("invocation capture replay was recaptured").into());
        };
        assert_eq!(replayed.exposure_units, 100);
        assert_eq!(replayed.monetary_state, BudgetMonetaryState::Exposed);
        let different_event =
            match store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-capture".to_string(),
                grant_index: 0,
                hold_id: hold_id.to_string(),
                event_id: "hold-cap-capture-0:different-capture".to_string(),
                trusted_time: None,
                authority: Some(authority.clone()),
            }) {
                Ok(_) => {
                    return Err(
                        std::io::Error::other("different event recaptured invocation").into(),
                    )
                }
                Err(error) => error,
            };
        assert!(different_event.to_string().contains("different event"));

        let usage = store
            .get_usage("cap-capture", 0)?
            .ok_or_else(|| std::io::Error::other("captured budget usage missing"))?;
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);
        assert!(!store.try_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            Some(1),
            100,
            Some(100),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&authority),
        )?);
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-capture",
                0,
                Some(1),
                100,
                Some(100),
                Some(1000),
                Some(hold_id),
                Some("hold-cap-capture-0:fresh-authorize"),
                Some(&authority),
            )
            .is_err());
        let events = store.list_mutation_events(10, Some("cap-capture"), Some(0))?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_id, capture_event_id);
        assert_eq!(events[1].kind, BudgetMutationKind::CaptureInvocation);
        assert_eq!(events[1].exposure_units, 100);
        assert_eq!(events[1].invocation_count_after, 1);
        assert_eq!(events[1].total_cost_exposed_after, 100);
    }

    let reopened = SqliteBudgetStore::open(&path)?;
    let request = BudgetCaptureInvocationRequest {
        capability_id: "cap-capture".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: capture_event_id.to_string(),
        trusted_time: None,
        authority: Some(authority.clone()),
    };
    assert!(matches!(
        reopened.capture_invocation_reservations(request)?,
        BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    let mut connection = reopened.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    assert!(
        SqliteBudgetStore::load_hold(&transaction, hold_id)?
            .ok_or_else(|| std::io::Error::other("reopened captured hold missing"))?
            .invocation_captured
    );
    transaction.rollback()?;
    drop(connection);

    assert!(reopened
        .reverse_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            100,
            Some(hold_id),
            Some("hold-cap-capture-0:reverse"),
            Some(&authority),
        )
        .is_err());
    assert!(reopened
        .reduce_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            100,
            Some(hold_id),
            Some("hold-cap-capture-0:release"),
            Some(&authority),
        )
        .is_err());
    assert!(reopened
        .reverse_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            100,
            None,
            Some("hold-cap-capture-0:generic-reverse"),
            None,
        )
        .is_err());
    assert!(reopened
        .reduce_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            100,
            None,
            Some("hold-cap-capture-0:generic-release"),
            None,
        )
        .is_err());
    let retained = reopened
        .get_usage("cap-capture", 0)?
        .ok_or_else(|| std::io::Error::other("retained captured usage missing"))?;
    assert_eq!(retained.invocation_count, 1);
    assert_usage_totals(&retained, 100, 0);

    let authorize_generation = reopened
        .list_mutation_events(20, Some("cap-capture"), Some(0))?
        .into_iter()
        .find(|event| event.event_id == authorize_event_id)
        .ok_or_else(|| std::io::Error::other("authorize generation missing"))?
        .event_seq;
    let compensation = BudgetCancelCapturedBeforeDispatchRequest {
        capability_id: "cap-capture".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: format!("{authorize_event_id}:rollback:{authorize_generation}"),
        authority: Some(authority.clone()),
    };
    assert!(matches!(
        reopened.cancel_captured_before_dispatch(compensation.clone())?,
        BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(_)
    ));
    assert!(matches!(
        reopened.cancel_captured_before_dispatch(compensation)?,
        BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(_)
    ));
    let stale_capture =
        match reopened.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-capture".to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: capture_event_id.to_string(),
            trusted_time: None,
            authority: Some(authority.clone()),
        }) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "cancelled invocation capture replayed as current",
                )
                .into())
            }
            Err(error) => error,
        };
    assert!(stale_capture.to_string().contains("no longer current"));
    let usage = reopened
        .get_usage("cap-capture", 0)?
        .ok_or_else(|| std::io::Error::other("compensated captured usage missing"))?;
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 0, 0);
    let retry = reopened
        .try_charge_cost_with_ids_and_authority(
            "cap-capture",
            0,
            Some(1),
            100,
            Some(100),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&authority),
        )
        .expect_err("a compensated hold must remain terminal");
    assert!(retry.to_string().contains("cannot be reopened"));

    let fresh_hold_id = "hold-cap-capture-1";
    assert!(reopened.try_charge_cost_with_ids_and_authority(
        "cap-capture",
        0,
        Some(1),
        100,
        Some(100),
        Some(1000),
        Some(fresh_hold_id),
        Some("hold-cap-capture-1:authorize"),
        Some(&authority),
    )?);
    let mut connection = reopened.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let hold = SqliteBudgetStore::load_hold(&transaction, fresh_hold_id)?
        .ok_or_else(|| std::io::Error::other("fresh replacement hold missing"))?;
    assert!(!hold.invocation_captured);
    assert_eq!(hold.disposition, HoldDisposition::Open);
    transaction.rollback()?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn budget_store_import_reconstructs_captured_before_dispatch_cancellation_sqlite(
) -> Result<(), Box<dyn std::error::Error>> {
    let source_path = unique_db_path("chio-capture-import-source");
    let target_path = unique_db_path("chio-capture-import-target");
    let hold_id = "hold-cap-capture-import-0";
    let authority = authority("budget-primary", "lease-9", 9);
    let source = SqliteBudgetStore::open(&source_path)?;
    assert!(source.try_charge_cost_with_ids_and_authority(
        "cap-capture-import",
        0,
        Some(2),
        100,
        Some(100),
        Some(1000),
        Some(hold_id),
        Some("hold-cap-capture-import-0:authorize"),
        Some(&authority),
    )?);
    source.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-capture-import".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: "hold-cap-capture-import-0:capture-invocation".to_string(),
        trusted_time: None,
        authority: Some(authority.clone()),
    })?;
    source.cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
        capability_id: "cap-capture-import".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: "hold-cap-capture-import-0:compensate-no-effect".to_string(),
        authority: Some(authority.clone()),
    })?;

    let usages = source.list_all_usages()?;
    let events = source.list_mutation_events_after_seq(10, 0)?;
    for (kind, suffix, expected_error) in [
        (
            BudgetMutationKind::CaptureInvocation,
            "capture",
            "does not match invocation capture exposure",
        ),
        (
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            "cancellation",
            "counters do not follow the durable usage chain",
        ),
    ] {
        let malformed_path = unique_db_path(&format!("chio-capture-import-{suffix}-mismatch"));
        let malformed_target = SqliteBudgetStore::open(&malformed_path)?;
        let mut malformed_events = events.clone();
        malformed_events
            .iter_mut()
            .find(|event| event.kind == kind)
            .ok_or_else(|| std::io::Error::other("import event missing"))?
            .exposure_units = 99;
        let error = match malformed_target.import_snapshot_records(&usages, &malformed_events) {
            Ok(()) => {
                return Err(std::io::Error::other(
                    "malformed capture lifecycle import was accepted",
                )
                .into())
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected_error),
            "unexpected {suffix} import error: {error}"
        );
        assert_eq!(malformed_target.max_mutation_event_seq()?, 0);
        let _ = fs::remove_file(malformed_path);
    }
    let target = SqliteBudgetStore::open(&target_path)?;
    target.import_snapshot_records(&usages, &events)?;

    let usage = target
        .get_usage("cap-capture-import", 0)?
        .ok_or_else(|| std::io::Error::other("imported captured usage missing"))?;
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 0, 0);
    let mut connection = target.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)?
        .ok_or_else(|| std::io::Error::other("imported captured hold missing"))?;
    assert!(!hold.invocation_captured);
    assert_eq!(hold.disposition, HoldDisposition::Reversed);
    transaction.rollback()?;

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
    Ok(())
}

#[test]
fn sqlite_captured_reconciled_hold_rejects_legacy_mutations_without_hold_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-captured-reconciled-no-hold-id");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-captured-reconciled";
    assert!(store.try_charge_cost_with_ids(
        "cap-captured-reconciled",
        0,
        Some(1),
        100,
        Some(100),
        Some(100),
        Some(hold_id),
        Some("hold-captured-reconciled:authorize"),
    )?);
    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-captured-reconciled".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: "hold-captured-reconciled:capture-invocation".to_string(),
        trusted_time: None,
        authority: None,
    })?;
    let reconciled = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
        capability_id: "cap-captured-reconciled".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 100,
        hold_id: Some(hold_id.to_string()),
        event_id: Some("hold-captured-reconciled:reconcile".to_string()),
        authority: None,
    })?;
    assert_eq!(reconciled.invocation_state, BudgetInvocationState::Captured);
    assert_eq!(reconciled.monetary_state, BudgetMonetaryState::Reconciled);

    assert!(store
        .reverse_charge_cost_with_ids(
            "cap-captured-reconciled",
            0,
            0,
            None,
            Some("captured-reconciled:generic-reverse"),
        )
        .is_err());
    assert!(store
        .reduce_charge_cost_with_ids(
            "cap-captured-reconciled",
            0,
            0,
            None,
            Some("captured-reconciled:generic-release"),
        )
        .is_err());
    assert!(store
        .settle_charge_cost_with_ids(
            "cap-captured-reconciled",
            0,
            0,
            0,
            None,
            Some("captured-reconciled:generic-reconcile"),
        )
        .is_err());
    let usage = store
        .get_usage("cap-captured-reconciled", 0)?
        .ok_or_else(|| std::io::Error::other("captured reconciled usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 100);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn historical_captured_hold_does_not_block_fresh_specific_hold_cleanup(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-historical-capture-fresh-cleanup");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_charge_cost_with_ids(
        "cap-cross-hold",
        0,
        Some(10),
        100,
        Some(100),
        Some(1000),
        Some("hold-old-captured"),
        Some("hold-old-captured:authorize"),
    )?);
    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-cross-hold".to_string(),
        grant_index: 0,
        hold_id: "hold-old-captured".to_string(),
        event_id: "hold-old-captured:capture-invocation".to_string(),
        trusted_time: None,
        authority: None,
    })?;
    store.reconcile_budget_hold(BudgetReconcileHoldRequest {
        capability_id: "cap-cross-hold".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 100,
        hold_id: Some("hold-old-captured".to_string()),
        event_id: Some("hold-old-captured:reconcile".to_string()),
        authority: None,
    })?;

    for (hold_id, event_suffix, release) in [
        ("hold-fresh-reverse", "reverse", false),
        ("hold-fresh-release", "release", true),
    ] {
        assert!(store.try_charge_cost_with_ids(
            "cap-cross-hold",
            0,
            Some(10),
            50,
            Some(100),
            Some(1000),
            Some(hold_id),
            Some(&format!("{hold_id}:authorize")),
        )?);
        if release {
            let released = store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: "cap-cross-hold".to_string(),
                grant_index: 0,
                released_exposure_units: 50,
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:{event_suffix}")),
                authority: None,
            })?;
            assert_eq!(released.invocation_state, BudgetInvocationState::Authorized);
            assert_eq!(released.monetary_state, BudgetMonetaryState::Released);
        } else {
            store.reverse_charge_cost_with_ids(
                "cap-cross-hold",
                0,
                50,
                Some(hold_id),
                Some(&format!("{hold_id}:{event_suffix}")),
            )?;
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_partial_release_replay_preserves_event_time_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-partial-release-event-time");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-partial-release";
    assert!(store.try_charge_cost_with_ids(
        "cap-partial-release",
        0,
        Some(1),
        100,
        Some(100),
        Some(100),
        Some(hold_id),
        Some("hold-partial-release:authorize"),
    )?);
    let request = BudgetReleaseHoldRequest {
        capability_id: "cap-partial-release".to_string(),
        grant_index: 0,
        released_exposure_units: 40,
        hold_id: Some(hold_id.to_string()),
        event_id: Some("hold-partial-release:release".to_string()),
        authority: None,
    };
    let released = store.release_budget_hold(request.clone())?;
    assert_eq!(released.invocation_state, BudgetInvocationState::Authorized);
    assert_eq!(released.monetary_state, BudgetMonetaryState::Exposed);

    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-partial-release".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: "hold-partial-release:capture".to_string(),
        trusted_time: None,
        authority: None,
    })?;
    let replayed = store.release_budget_hold(request)?;
    assert_eq!(replayed.invocation_state, BudgetInvocationState::Authorized);
    assert_eq!(replayed.monetary_state, BudgetMonetaryState::Exposed);
    let usage = store
        .get_usage("cap-partial-release", 0)?
        .ok_or_else(|| std::io::Error::other("partial release usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 60, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_captured_before_dispatch_cancellation_rejects_partial_exposure(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-captured-cancel-partial-exposure");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-captured-cancel-partial";
    assert!(store.try_charge_cost_with_ids(
        "cap-captured-cancel-partial",
        0,
        Some(1),
        100,
        Some(100),
        Some(100),
        Some(hold_id),
        Some("hold-captured-cancel-partial:authorize"),
    )?);
    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-captured-cancel-partial".to_string(),
        grant_index: 0,
        hold_id: hold_id.to_string(),
        event_id: "hold-captured-cancel-partial:capture-invocation".to_string(),
        trusted_time: None,
        authority: None,
    })?;
    {
        let connection = store.connection()?;
        connection.execute(
            "UPDATE budget_authorization_holds SET remaining_exposure_units = 50 WHERE hold_id = ?1",
            params![hold_id],
        )?;
    }

    assert!(store
        .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-captured-cancel-partial".to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: "hold-captured-cancel-partial:cancel-captured-before-dispatch".to_string(),
            authority: None,
        })
        .is_err());
    let usage = store
        .get_usage("cap-captured-cancel-partial", 0)?
        .ok_or_else(|| std::io::Error::other("partial captured usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);
    let _ = fs::remove_file(path);
    Ok(())
}
