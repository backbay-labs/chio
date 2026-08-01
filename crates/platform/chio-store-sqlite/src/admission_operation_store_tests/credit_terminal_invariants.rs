use chio_core::canonical::canonical_json_bytes;
use chio_credit::obligation::CreditExposureReservationRecordV1;
use chio_kernel::admission_operation::{
    verified_pre_dispatch_compensation_projection,
    verified_released_pre_dispatch_compensation_projection_for_test,
};

use super::*;

fn authorized_credit_operation(
    fixture: &Fixture,
    authorities: &CreditAuthorityFixture,
    suffix: &str,
    begun_at_unix_ms: u64,
) -> CreditAuthorizationTestResult<(AdmissionOperationV1, CreditExposureReservationRequest)> {
    let operation = broker_registered_credit_operation(
        fixture,
        &format!("request-credit-terminal-{suffix}"),
        begun_at_unix_ms,
    )?;
    let request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        &format!("nonce-credit-terminal-{suffix}"),
        SOURCE_VERSION,
        begun_at_unix_ms + 3,
    )?;
    provision_account(fixture, &request, begun_at_unix_ms + 3)?;
    let recovery = claim(
        fixture,
        &operation,
        "sqlite-credit-authorizer",
        begun_at_unix_ms + 4,
    );
    let (decision, operation) = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &recovery,
        budget_authorization_request(fixture, &operation, &format!("terminal-{suffix}")),
        None,
        Some(request.clone()),
        &fixture.fence,
        begun_at_unix_ms + 5,
    )?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    Ok((operation, request))
}

fn assert_invariant(error: AdmissionOperationStoreError, expected: &str) {
    assert!(
        matches!(
            &error,
            AdmissionOperationStoreError::Invariant(detail) if detail.contains(expected)
        ),
        "unexpected admission invariant error: {error:?}"
    );
}

#[test]
fn startup_rejects_credit_account_without_reservation_history() -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = broker_registered_credit_operation(&fixture, "credit-empty-history", now)?;
    let request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-empty-history",
        SOURCE_VERSION,
        now + 3,
    )?;
    provision_account(&fixture, &request, now + 3)?;

    let connection = fixture.store.connection()?;
    let error = verify_admission_operation_invariants(&connection)
        .expect_err("an account without immutable history must fail verification");
    assert_invariant(
        error,
        "credit exposure account has no immutable reservation history",
    );
    drop(connection);

    let Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(database, lock_root),
        Err(SqliteServingOwnerError::Invalid(detail))
            if detail.contains("credit exposure account has no immutable reservation history")
    ));
    drop(temp);
    Ok(())
}

#[test]
fn non_credit_operation_rejects_persisted_credit_reservation() -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-non-credit-orphan",
        CAPABILITY_ID,
    );
    fixture.store.begin(&operation, &fixture.fence, now)?;
    let request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-non-credit-orphan",
        SOURCE_VERSION,
        now + 1,
    )?;
    provision_account(&fixture, &request, now + 1)?;
    let reservation = CreditExposureReservationRecordV1::prepare_reserved(
        &request,
        SOURCE_VERSION + 1,
        SOURCE_VERSION + 1,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    crate::admission_operation_store::reserve_credit_exposure_tx(
        &transaction,
        &reservation,
        &fixture.fence,
        now + 2,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    drop(connection);

    let error = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())
        .expect_err("non-credit operation must reject persisted credit state");
    assert_invariant(
        error,
        "non-credit admission operation has credit exposure state",
    );
    Ok(())
}

#[test]
fn credit_operation_rejects_missing_reservation_row() -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let (operation, _) = authorized_credit_operation(&fixture, &authorities, "missing", now)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER credit_exposure_reservations_no_delete")?;
    assert_eq!(
        connection.execute(
            "DELETE FROM credit_exposure_reservations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
        )?,
        1
    );
    drop(connection);

    let error = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())
        .expect_err("credit operation must retain its reservation row");
    assert_invariant(
        error,
        "credit admission operation lost its persisted reservation",
    );
    Ok(())
}

#[test]
fn credit_operation_rejects_mismatched_reservation_row() -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let (operation, _) = authorized_credit_operation(&fixture, &authorities, "mismatch", now)?;
    let replacement_request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-terminal-replacement",
        SOURCE_VERSION,
        now + 3,
    )?;
    let replacement = CreditExposureReservationRecordV1::prepare_reserved(
        &replacement_request,
        SOURCE_VERSION + 1,
        SOURCE_VERSION + 1,
    )?;
    let replacement_json = canonical_json_bytes(&replacement)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER credit_exposure_reservations_immutable")?;
    assert_eq!(
        connection.execute(
            r#"
            UPDATE credit_exposure_reservations
            SET reservation_digest = ?1, action_nonce = ?2, reservation_json = ?3
            WHERE operation_id = ?4
            "#,
            params![
                replacement.reservation_digest(),
                replacement.action_nonce(),
                replacement_json,
                operation.binding().operation_id().as_str(),
            ],
        )?,
        1
    );
    drop(connection);

    let error = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())
        .expect_err("credit operation must reject a substituted reservation");
    assert_invariant(
        error,
        "credit admission operation reservation digest differs from storage",
    );
    Ok(())
}

#[test]
fn acquired_credit_rejects_unproven_compensation_before_store_mutation(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let (operation, _) = authorized_credit_operation(&fixture, &authorities, "compensate", now)?;
    let before_account = account_state(&fixture)?;
    let before_reservation = fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .ok_or("credit reservation missing before compensation")?;
    let recovery = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 6);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: now + 7,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    assert!(matches!(
        verified_pre_dispatch_compensation_projection(&operation, context),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    assert_eq!(account_state(&fixture)?, before_account);
    assert_eq!(
        fixture
            .store
            .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
            .ok_or("credit reservation disappeared after compensation rejection")?,
        before_reservation
    );
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("credit operation disappeared after compensation rejection")?,
        operation
    );
    let counts = fixture.store.connection()?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_operation_terminal_projections WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM admission_operation_terminal_records WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM credit_exposure_terminal_transitions WHERE operation_id = ?1)
        "#,
        [operation.binding().operation_id().as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    assert_eq!(counts, (0, 0, 0));
    Ok(())
}

#[test]
fn verified_predispatch_projection_releases_reserved_credit_atomically(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let (operation, _) = authorized_credit_operation(&fixture, &authorities, "release", now)?;
    let recovery = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 6);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: now + 7,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    let projection = verified_released_pre_dispatch_compensation_projection_for_test(
        &operation,
        context,
        serde_json::json!({"policy": "sqlite-credit-release-v1"}),
    )?;
    let terminal = fixture.store.commit_terminal_projection(&projection)?;

    assert_eq!(
        terminal.state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let released = fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .ok_or("released credit reservation disappeared")?;
    assert_eq!(
        released.state(),
        CreditExposureReservationStateV1::ReleasedBeforeDispatch
    );
    assert_eq!(account_state(&fixture)?, (1, 0, 0, 9, 9));
    Ok(())
}

#[test]
fn outcome_unknown_credit_transition_is_exactly_bound_to_projection(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let (mut operation, _) = authorized_credit_operation(&fixture, &authorities, "unknown", now)?;
    let transitions = [
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
        (
            AdmissionOperationState::Finalizing,
            vec![AdmissionAttachment::ToolOutcomeId(digest(
                "tool_outcome_id",
                '9',
            ))],
        ),
    ];
    for (index, (next_state, attachments)) in transitions.into_iter().enumerate() {
        let at = now + 6 + u64::try_from(index)? * 2;
        let recovery = claim(&fixture, &operation, "sqlite-credit-authorizer", at);
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, recovery, attachments, next_state, None),
                at + 1,
            )?
            .into_operation();
    }
    let projection = unknown_projection_for_claimant(
        &fixture,
        &operation,
        "credit-outcome-unknown-incident",
        '8',
        now + 20,
        "sqlite-credit-authorizer",
    );
    fixture.store.commit_terminal_projection(&projection)?;
    let reservation = fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .ok_or("outcome-unknown credit reservation missing")?;
    assert_eq!(
        reservation.state(),
        CreditExposureReservationStateV1::OutcomeUnknown
    );
    assert_eq!(
        account_state(&fixture)?,
        (1, 0, i64::try_from(EXPOSURE_UNITS)?, 9, 9)
    );

    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER credit_exposure_terminal_transitions_immutable")?;
    assert_eq!(
        connection.execute(
            "UPDATE credit_exposure_terminal_transitions SET projection_digest = ?1 WHERE operation_id = ?2",
            params![
                "f".repeat(64),
                operation.binding().operation_id().as_str(),
            ],
        )?,
        1
    );
    drop(connection);
    let error = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())
        .expect_err("credit transition must retain its exact projection digest");
    assert_invariant(error, "credit exposure terminal replay conflicts");
    Ok(())
}
