use super::*;

fn seed_credit_account(
    transaction: &rusqlite::Transaction<'_>,
    fixture: &Fixture,
    updated_at_unix_ms: u64,
) -> rusqlite::Result<()> {
    transaction.execute(
        r#"
        INSERT INTO credit_exposure_accounts (
            debtor_id, scope_digest, currency, open_units, reserved_units,
            effective_ceiling_units, authority_configuration_digest,
            authority_set_digest, authority_evidence_digest,
            authority_expires_at_unix_seconds, account_version, resource_fence,
            updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, 'USD', 0, 0, 2000, ?3, ?4, ?5, ?6, 7, 7, ?7, ?8, ?9, ?10)
        "#,
        params![
            "did:chio:credit-debtor",
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            1_800_000_000_i64,
            i64::try_from(updated_at_unix_ms).expect("trusted time fits SQLite"),
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
        ],
    )?;
    Ok(())
}

fn seed_credit_reservation(
    transaction: &rusqlite::Transaction<'_>,
    fixture: &Fixture,
    operation_id: &str,
    reserved_at_unix_ms: u64,
) -> rusqlite::Result<()> {
    transaction.execute(
        r#"
        INSERT INTO credit_exposure_reservations (
            operation_id, reservation_digest, debtor_id, scope_digest, currency,
            action_nonce, amount_units, source_account_version,
            source_resource_fence, reserved_account_version,
            reserved_resource_fence, reservation_json, reserved_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, ?4, 'USD', ?5, 1000, 7, 7, 8, 8, X'01', ?6, ?7, ?8, ?9)
        "#,
        params![
            operation_id,
            "5".repeat(64),
            "did:chio:credit-debtor",
            "1".repeat(64),
            "credit-action-nonce",
            i64::try_from(reserved_at_unix_ms).expect("trusted time fits SQLite"),
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
        ],
    )?;
    transaction.execute(
        r#"
        UPDATE credit_exposure_accounts
        SET reserved_units = 1000, account_version = 8, resource_fence = 8,
            updated_at_unix_ms = ?1
        WHERE debtor_id = ?2 AND scope_digest = ?3 AND currency = 'USD'
        "#,
        params![
            i64::try_from(reserved_at_unix_ms).expect("trusted time fits SQLite"),
            "did:chio:credit-debtor",
            "1".repeat(64),
        ],
    )?;
    Ok(())
}

#[test]
fn credit_exposure_account_rejects_stale_fences_non_linear_updates_and_delete() {
    let fixture = fixture();
    let now = now_ms();
    let mut connection = fixture.store.connection().expect("connection");
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))
        .expect("begin fenced write");
    seed_credit_account(&transaction, &fixture, now).expect("seed credit account");
    assert!(transaction
        .execute(
            r#"
            UPDATE credit_exposure_accounts
            SET account_version = 9, resource_fence = 9, updated_at_unix_ms = ?1
            WHERE debtor_id = ?2 AND scope_digest = ?3 AND currency = 'USD'
            "#,
            params![
                i64::try_from(now + 1).expect("trusted time fits SQLite"),
                "did:chio:credit-debtor",
                "1".repeat(64),
            ],
        )
        .is_err());
    assert!(transaction
        .execute(
            r#"
            INSERT INTO credit_exposure_accounts (
                debtor_id, scope_digest, currency, open_units, reserved_units,
                effective_ceiling_units, authority_configuration_digest,
                authority_set_digest, authority_evidence_digest,
                authority_expires_at_unix_seconds, account_version, resource_fence,
                updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, 'USD', 0, 0, 1, ?3, ?4, ?5, 1, 1, 1, ?6, ?7, ?8, ?9)
            "#,
            params![
                "did:chio:other-debtor",
                "6".repeat(64),
                "7".repeat(64),
                "8".repeat(64),
                "9".repeat(64),
                i64::try_from(now).expect("trusted time fits SQLite"),
                &fixture.fence.store_uuid,
                "stale-serving-lease",
                i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
            ],
        )
        .is_err());
    assert!(transaction
        .execute(
            "DELETE FROM credit_exposure_accounts WHERE debtor_id = ?1",
            ["did:chio:credit-debtor"],
        )
        .is_err());
}

#[test]
fn credit_exposure_terminal_rejects_projection_state_obligation_and_nonce_forgery() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "credit-exposure-request",
        "credit-exposure-capability",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now)
        .expect("begin credit operation");
    let other = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "credit-exposure-other-request",
        "credit-exposure-capability",
    );
    fixture
        .store
        .begin(&other, &fixture.fence, now + 1)
        .expect("begin other credit operation");
    let operation_id = operation.binding().operation_id().as_str();
    let mut connection = fixture.store.connection().expect("connection");
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))
        .expect("begin fenced write");
    seed_credit_account(&transaction, &fixture, now + 1).expect("seed credit account");
    seed_credit_reservation(&transaction, &fixture, operation_id, now + 2)
        .expect("seed credit reservation");
    let transition = |terminal_state: &str,
                      admission_terminal_state: &str,
                      projection_digest: &str,
                      obligation_id: Option<&str>| {
        transaction.execute(
            r#"
            INSERT INTO credit_exposure_terminal_transitions (
                operation_id, reservation_digest, terminal_state,
                admission_terminal_state, projection_digest, obligation_id,
                account_version, resource_fence, transition_json,
                transitioned_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 9, 9, X'02', ?7, ?8, ?9, ?10)
            "#,
            params![
                operation_id,
                "5".repeat(64),
                terminal_state,
                admission_terminal_state,
                projection_digest,
                obligation_id,
                i64::try_from(now + 3).expect("trusted time fits SQLite"),
                &fixture.fence.store_uuid,
                &fixture.fence.lease_id,
                i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
            ],
        )
    };
    assert!(transition(
        "outcome_unknown",
        "outcome_unknown_after_dispatch",
        &"a".repeat(64),
        None,
    )
    .is_err());
    let projection_digest = "a".repeat(64);
    transaction
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_projections (
                operation_id, source_operation_version, terminal_operation_version,
                terminal_state, projection_body_digest, projection_digest,
                projection_json, manifest_json, record_count, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, 1, 2, 'outcome_unknown_after_dispatch', ?2, ?3,
                      X'01', X'01', 1, ?4, ?5, ?6, ?7)
            "#,
            params![
                operation_id,
                "b".repeat(64),
                &projection_digest,
                i64::try_from(now + 3).expect("trusted time fits SQLite"),
                &fixture.fence.store_uuid,
                &fixture.fence.lease_id,
                i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
            ],
        )
        .expect("insert admission terminal projection");
    assert!(transition(
        "released_before_dispatch",
        "outcome_unknown_after_dispatch",
        &projection_digest,
        None,
    )
    .is_err());
    assert!(transition(
        "committed",
        "outcome_unknown_after_dispatch",
        &projection_digest,
        Some(&"c".repeat(64)),
    )
    .is_err());
    assert!(transaction
        .execute(
            r#"
            INSERT INTO credit_exposure_reservations (
                operation_id, reservation_digest, debtor_id, scope_digest, currency,
                action_nonce, amount_units, source_account_version,
                source_resource_fence, reserved_account_version,
                reserved_resource_fence, reservation_json, reserved_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, 'USD', ?5, 1, 8, 8, 9, 9, X'03', ?6, ?7, ?8, ?9)
            "#,
            params![
                other.binding().operation_id().as_str(),
                "d".repeat(64),
                "did:chio:credit-debtor",
                "1".repeat(64),
                "credit-action-nonce",
                i64::try_from(now + 3).expect("trusted time fits SQLite"),
                &fixture.fence.store_uuid,
                &fixture.fence.lease_id,
                i64::try_from(fixture.fence.owner_epoch).expect("owner epoch fits SQLite"),
            ],
        )
        .is_err());
    transition(
        "outcome_unknown",
        "outcome_unknown_after_dispatch",
        &projection_digest,
        None,
    )
    .expect("insert exact outcome-unknown transition");
    assert!(transaction
        .execute(
            "DELETE FROM credit_exposure_terminal_transitions WHERE operation_id = ?1",
            [operation_id],
        )
        .is_err());
}
