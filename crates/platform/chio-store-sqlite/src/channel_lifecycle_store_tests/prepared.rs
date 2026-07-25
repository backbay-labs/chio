use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicEffectTargetV1,
    EconomicRequestBindingV1,
};
use chio_kernel::admission_operation::{
    expected_dispatch_committed_version, AdmissionAttachment, AdmissionOperationCommand,
    AdmissionOperationState, ProviderAttemptBindingV1, QualifiedAdmissionOperationStoreExt,
};
use chio_settle::channel::{
    derive_channel_reservation_id, ChannelAssetBindingV1, ChannelEscrowReferenceV1,
    ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1, ChannelLifecycleStatusV1,
    ChannelLifecycleViewV1, ChannelOpenBodyV1, ChannelOpenIntentBodyV1,
    ChannelPreparedReservationV1, ChannelReservationBodyV1, ChannelServiceBindingV1,
    ChannelSignatureV1, ChannelStateBodyV1, RetainedChannelStateV1, SignedChannelOpenIntentV1,
    SignedChannelOpenV1, SignedChannelStateV1, VerifiedChannelPreparedReservationV1,
    CHANNEL_ASSET_BINDING_SCHEMA, CHANNEL_ESCROW_RESERVATION_SCHEMA, CHANNEL_LIFECYCLE_SCHEMA,
    CHANNEL_OPEN_INTENT_SCHEMA, CHANNEL_OPEN_SCHEMA, CHANNEL_PREPARED_RESERVATION_SCHEMA,
    CHANNEL_RESERVATION_SCHEMA,
};

use super::*;

fn evm_hash(label: &str) -> String {
    format!("0x{}", digest(label))
}

fn prepared_plan(
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
) -> TestResult<ChannelPreparedReservationV1> {
    let observed_at_unix_ms = now_ms()?.saturating_sub(1_000);
    let channel_expiry_unix_ms = observed_at_unix_ms
        .checked_add(600_000)
        .ok_or("channel expiry overflowed")?;
    let payer_key = Keypair::from_seed(&[71; 32]);
    let payee_key = Keypair::from_seed(&[72; 32]);
    let asset_binding = ChannelAssetBindingV1 {
        schema: CHANNEL_ASSET_BINDING_SCHEMA.to_owned(),
        currency: "USD".to_owned(),
        protocol_minor_unit_decimals: 2,
        chain_id: "eip155:31337".to_owned(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        token_symbol: "USDC".to_owned(),
        token_decimals: 6,
        settlement_policy_digest: digest("settlement-policy"),
    };
    let escrow_reference = ChannelEscrowReferenceV1 {
        chain_id: asset_binding.chain_id.clone(),
        escrow_contract: "0x2222222222222222222222222222222222222222".to_owned(),
        escrow_id: evm_hash("escrow"),
    };
    let intent_body: ChannelOpenIntentBodyV1 = serde_json::from_value(serde_json::json!({
        "schema": CHANNEL_OPEN_INTENT_SCHEMA,
        "openIntentId": digest("open-intent"),
        "payerId": "payer",
        "payerKey": payer_key.public_key(),
        "payerKeyEpoch": 1,
        "payerRefundAddress": "0x3333333333333333333333333333333333333333",
        "payeeId": "payee",
        "payeeKey": payee_key.public_key(),
        "payeeKeyEpoch": 2,
        "payeeBeneficiaryAddress": "0x4444444444444444444444444444444444444444",
        "settlementAuthorityScopeId": "channel-settlement",
        "currency": "USD",
        "bound": { "units": 150, "currency": "USD" },
        "assetBinding": asset_binding.clone(),
        "boundTokenBaseUnits": "1500000",
        "channelExpiryUnixSecs": channel_expiry_unix_ms.div_ceil(1_000),
        "disputeTierUpperBoundUnits": 1_000,
        "disputeWindowSecs": 100,
        "requiredConfirmations": 12,
        "finalityMode": "l1_finalized",
        "fixedFinalityBroadcastMarginSecs": 50,
        "closeSubmissionCutoffUnixSecs": 1_950,
        "originalWeb3DispatchDigest": digest("web3-dispatch"),
        "escrowReference": escrow_reference.clone(),
        "fundingEvidenceDigest": digest("funding-evidence"),
        "originalOperator": "0x5555555555555555555555555555555555555555",
        "originalOperatorKeyHash": evm_hash("operator-key"),
        "participantSnapshotDigest": digest("participants"),
    }))?;
    let signed_open_intent = SignedChannelOpenIntentV1 {
        payer_signature: ChannelSignatureV1::sign(
            &intent_body,
            intent_body.payer_id.clone(),
            intent_body.payer_key_epoch,
            &payer_key,
        )?,
        payee_signature: ChannelSignatureV1::sign(
            &intent_body,
            intent_body.payee_id.clone(),
            intent_body.payee_key_epoch,
            &payee_key,
        )?,
        body: intent_body,
    };
    let channel_id = digest("channel");
    let initial_state = ChannelStateBodyV1::initial(
        channel_id.clone(),
        "USD".to_owned(),
        asset_binding.digest()?,
    )?;
    let open_body = ChannelOpenBodyV1 {
        schema: CHANNEL_OPEN_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        open_intent_digest: signed_open_intent.digest()?,
        funding_acknowledgement_digest: digest("funding-acknowledgement"),
        initial_state_digest: initial_state.digest()?,
        opened_at_unix_ms: 1_400,
    };
    let signed_open = SignedChannelOpenV1 {
        payer_signature: ChannelSignatureV1::sign(
            &open_body,
            signed_open_intent.body.payer_id.clone(),
            signed_open_intent.body.payer_key_epoch,
            &payer_key,
        )?,
        payee_signature: ChannelSignatureV1::sign(
            &open_body,
            signed_open_intent.body.payee_id.clone(),
            signed_open_intent.body.payee_key_epoch,
            &payee_key,
        )?,
        body: open_body,
    };
    let open_digest = signed_open.digest()?;
    let prior_state_digest = initial_state.digest()?;
    let request_id = operation.binding().request_id().as_str().to_owned();
    let service = ChannelServiceBindingV1 {
        request: EconomicRequestBindingV1 {
            request_namespace_digest: operation
                .binding()
                .request_namespace_digest()
                .as_str()
                .to_owned(),
            request_id: request_id.clone(),
            request_binding_digest: operation
                .binding()
                .request_binding_hash()
                .as_str()
                .to_owned(),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: expected_dispatch_committed_version(
                operation.binding().kind(),
                operation.binding().participant_requirements(),
                operation.version(),
            )?,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        },
        provider: EconomicEffectTargetV1 {
            target_id: "channel-provider".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("provider-qualification"),
        },
        action_digest: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
    };
    let reservation = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: derive_channel_reservation_id(
            &channel_id,
            &open_digest,
            &request_id,
            1,
            &prior_state_digest,
        )?,
        channel_id: channel_id.clone(),
        open_digest: open_digest.clone(),
        request_id: request_id.clone(),
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        next_sequence: 1,
        prior_state_digest: prior_state_digest.clone(),
        service_binding_digest: service.digest()?,
        receipt_authority_digest: digest("receipt-authority"),
        maximum_charge: MonetaryAmount {
            units: 40,
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: "400000".to_owned(),
        expires_at_unix_ms: observed_at_unix_ms
            .checked_add(300_000)
            .ok_or("reservation expiry overflowed")?,
        disposition_expected_version: 1,
        channel_state_expected_version: 1,
        lifecycle_fence: 2,
    };
    Ok(ChannelPreparedReservationV1 {
        schema: CHANNEL_PREPARED_RESERVATION_SCHEMA.to_owned(),
        signed_open_intent,
        signed_open,
        prior_state: RetainedChannelStateV1::Initial {
            body: Box::new(initial_state),
        },
        reservation,
        service,
        lifecycle: ChannelLifecycleViewV1 {
            schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
            channel_id: channel_id.clone(),
            status: ChannelLifecycleStatusV1::Open,
            latest_state_digest: prior_state_digest,
            latest_sequence: 0,
            state_version: 1,
            lifecycle_fence: 2,
            pending_close_body_digest: None,
            admitted_dispute_digest: None,
            live_reservation_id: None,
            operation_id: None,
        },
        escrow: ChannelEscrowReservationViewV1 {
            schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
            channel_id,
            open_digest,
            escrow_reference,
            status: ChannelEscrowReservationStatusV1::Open,
            version: 2,
            lifecycle_fence: 2,
            pending_close_body_digest: None,
        },
        channel_head_digest: digest("channel-head"),
        escrow_head_digest: digest("escrow-head"),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: 3,
        checkpoint_digest: digest("checkpoint"),
        observed_at_unix_ms,
    })
}

fn with_signed_remote_prior(
    mut plan: ChannelPreparedReservationV1,
) -> TestResult<ChannelPreparedReservationV1> {
    let RetainedChannelStateV1::Initial { body: initial } = &plan.prior_state else {
        return Err("prepared fixture did not contain an initial state".into());
    };
    let initial_digest = initial.digest()?;
    let body = ChannelStateBodyV1 {
        schema: initial.schema.clone(),
        channel_id: initial.channel_id.clone(),
        seq: 1,
        prev_state_digest: Some(initial_digest),
        cumulative_owed: MonetaryAmount {
            units: 1,
            currency: initial.cumulative_owed.currency.clone(),
        },
        receipt_id_root: digest("receipt-root"),
        receipt_count: 1,
        receipt_id: Some("receipt-1".to_owned()),
        receipt_digest: Some(digest("receipt")),
        receipt_authority_digest: Some(digest("receipt-authority")),
        obligation_atom_digest: Some(digest("obligation")),
        reservation_digest: Some(digest("signed-reservation")),
        actual_charge: Some(MonetaryAmount {
            units: 1,
            currency: initial.cumulative_owed.currency.clone(),
        }),
        cumulative_token_base_units: "10000".to_owned(),
        asset_binding_digest: initial.asset_binding_digest.clone(),
    };
    let payee_key = Keypair::from_seed(&[72; 32]);
    let state = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(
            &body,
            plan.signed_open_intent.body.payee_id.clone(),
            plan.signed_open_intent.body.payee_key_epoch,
            &payee_key,
        )?,
        body,
    };
    let prior_digest = state.digest()?;
    plan.reservation.next_sequence = 2;
    plan.reservation.prior_state_digest = prior_digest.clone();
    plan.reservation.reservation_id = derive_channel_reservation_id(
        &plan.reservation.channel_id,
        &plan.reservation.open_digest,
        &plan.reservation.request_id,
        plan.reservation.next_sequence,
        &prior_digest,
    )?;
    plan.lifecycle.latest_state_digest = prior_digest;
    plan.lifecycle.latest_sequence = 1;
    plan.prior_state = RetainedChannelStateV1::Signed {
        state: Box::new(state),
    };
    Ok(plan)
}

fn assert_verified_public_api(
    _begin: fn(
        &SqliteChannelLifecycleStore,
        &AdmissionOperationV1,
        &VerifiedChannelPreparedReservationV1,
        &StoreMutationFence,
        u64,
    ) -> Result<ChannelPreparedBeginResult, ChannelLifecycleStoreError>,
) {
}

fn created_prepared_record(
    fixture: &Fixture,
    request_id: &str,
) -> TestResult<ChannelPreparedAdmissionRecordV1> {
    let operation = prepared_operation(&fixture.fence, request_id)?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    match fixture.store.begin_channel_prepared_inner(
        &operation,
        &plan,
        &fixture.fence,
        now_ms()?,
    )? {
        ChannelPreparedBeginResult::Created(record) => Ok(record),
        _ => Err("channel prepared record was not created".into()),
    }
}

#[test]
fn generic_admission_begin_rejects_channel_operations() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "generic-channel-bypass")?;

    assert!(matches!(
        fixture
            .authority
            .admission_operation_store()
            .begin(&operation, &fixture.fence, now_ms()?,),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(operation.binding().operation_id())?
        .is_none());
    Ok(())
}

#[test]
fn typed_begin_decodes_and_round_trips_the_canonical_plan() -> TestResult {
    assert_verified_public_api(SqliteChannelLifecycleStore::begin_channel_prepared);
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "typed-begin")?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    let trusted_now = now_ms()?;
    let result = fixture.store.begin_channel_prepared_inner(
        &operation,
        &plan,
        &fixture.fence,
        trusted_now,
    )?;
    let ChannelPreparedBeginResult::Created(record) = result else {
        return Err("first channel prepared begin was not created".into());
    };
    assert_eq!(record.operation().binding(), operation.binding());
    assert_eq!(record.operation().version(), 1);
    assert_eq!(
        record
            .operation()
            .channel_reservation_proposal_digest()
            .map(|value| value.as_str()),
        Some(plan.reservation.proposal_digest()?.as_str())
    );
    assert_eq!(record.plan(), &plan);
    assert_eq!(record.plan_digest(), plan.digest()?);
    assert_eq!(record.store_fence(), &fixture.fence);
    assert_eq!(record.created_at_unix_ms(), trusted_now);
    let connection = fixture.store.connection()?;
    let stored_plan: Vec<u8> = connection.query_row(
        "SELECT plan_json FROM channel_prepared_admission_plans WHERE operation_id = ?1",
        [operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(stored_plan, canonical_json_bytes(&plan)?);
    drop(connection);
    fixture.store.verify_invariants()?;
    Ok(())
}

#[test]
fn exact_replay_returns_the_same_plan_without_a_second_commit() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "exact-replay")?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    let trusted_now = now_ms()?;
    fixture
        .store
        .begin_channel_prepared_inner(&operation, &plan, &fixture.fence, trusted_now)?;
    let replay = fixture.store.begin_channel_prepared_inner(
        &operation,
        &plan,
        &fixture.fence,
        trusted_now,
    )?;
    let ChannelPreparedBeginResult::ExactReplay(record) = replay else {
        return Err("exact channel prepared replay was not classified as exact".into());
    };
    assert_eq!(record.operation().binding(), operation.binding());
    assert_eq!(
        record
            .operation()
            .channel_reservation_proposal_digest()
            .map(|value| value.as_str()),
        Some(plan.reservation.proposal_digest()?.as_str())
    );
    assert_eq!(record.plan(), &plan);
    let connection = fixture.store.connection()?;
    let counts: (i64, i64, i64, i64, i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_operations),
            (SELECT COUNT(*) FROM admission_operation_commits),
            (SELECT COUNT(*) FROM channel_state_records),
            (SELECT COUNT(*) FROM channel_lifecycle_records),
            (SELECT COUNT(*) FROM channel_prepared_admission_plans),
            (SELECT COUNT(*) FROM authority_global_commits)
        "#,
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    assert_eq!(counts, (1, 1, 1, 1, 1, 2));
    Ok(())
}

#[test]
fn replay_with_a_conflicting_plan_is_rejected() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "conflicting-replay")?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    let trusted_now = now_ms()?;
    fixture
        .store
        .begin_channel_prepared_inner(&operation, &plan, &fixture.fence, trusted_now)?;
    let mut conflicting = plan;
    conflicting.reservation.receipt_authority_digest = digest("substituted-receipt-authority");
    let replay = fixture.store.begin_channel_prepared_inner(
        &operation,
        &conflicting,
        &fixture.fence,
        trusted_now,
    )?;
    assert!(matches!(
        replay,
        ChannelPreparedBeginResult::Conflict { existing_operation_id }
            if existing_operation_id == *operation.binding().operation_id()
    ));
    Ok(())
}

#[test]
fn injected_plan_failure_rolls_back_every_prepared_projection() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "rollback")?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            r#"
            CREATE TEMP TRIGGER fail_channel_prepared_begin
            BEFORE INSERT ON channel_prepared_admission_plans
            BEGIN
                SELECT RAISE(ROLLBACK, 'injected prepared plan failure');
            END;
            "#,
        )?;
    }
    assert!(fixture
        .store
        .begin_channel_prepared_inner(&operation, &plan, &fixture.fence, now_ms()?)
        .is_err());
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER fail_channel_prepared_begin")?;
    let counts: (i64, i64, i64, i64, i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_operations),
            (SELECT COUNT(*) FROM admission_operation_commits),
            (SELECT COUNT(*) FROM channel_state_records),
            (SELECT COUNT(*) FROM channel_lifecycle_records),
            (SELECT COUNT(*) FROM channel_prepared_admission_plans),
            (SELECT COUNT(*) FROM authority_global_commits)
        "#,
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    assert_eq!(counts, (0, 0, 0, 0, 0, 1));
    Ok(())
}

#[test]
fn stale_fence_cannot_begin_a_channel_prepared_plan() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "stale-fence")?;
    let plan = prepared_plan(&operation, &fixture.fence)?;
    let stale = StoreMutationFence {
        store_uuid: fixture.fence.store_uuid.clone(),
        lease_id: "stale-channel-lease".to_owned(),
        owner_epoch: fixture.fence.owner_epoch,
    };
    assert!(matches!(
        fixture
            .store
            .begin_channel_prepared_inner(&operation, &plan, &stale, now_ms()?),
        Err(ChannelLifecycleStoreError::Fenced)
    ));
    Ok(())
}

#[test]
fn trusted_time_must_be_inside_the_authenticated_plan_window() -> TestResult {
    for (request_id, at_expiry) in [("before-observation", false), ("at-expiry", true)] {
        let fixture = fixture()?;
        let operation = prepared_operation(&fixture.fence, request_id)?;
        let plan = prepared_plan(&operation, &fixture.fence)?;
        let trusted_now = if at_expiry {
            plan.reservation.expires_at_unix_ms
        } else {
            plan.observed_at_unix_ms.saturating_sub(1)
        };
        assert!(matches!(
            fixture.store.begin_channel_prepared_inner(
                &operation,
                &plan,
                &fixture.fence,
                trusted_now,
            ),
            Err(ChannelLifecycleStoreError::Invalid(_))
        ));
        let connection = fixture.store.connection()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0);
    }
    Ok(())
}

#[test]
fn signed_remote_prior_is_imported_without_a_local_producer() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "signed-remote-prior")?;
    let plan = with_signed_remote_prior(prepared_plan(&operation, &fixture.fence)?)?;
    fixture
        .store
        .begin_channel_prepared_inner(&operation, &plan, &fixture.fence, now_ms()?)?;
    let connection = fixture.store.connection()?;
    let stored: (String, Option<String>) = connection.query_row(
        "SELECT state_kind, operation_id FROM channel_state_records WHERE channel_id = ?1",
        [&plan.reservation.channel_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(stored, ("signed".to_owned(), None));
    Ok(())
}

#[test]
fn prepared_record_load_survives_serving_owner_takeover() -> TestResult {
    let fixture = fixture()?;
    let expected = created_prepared_record(&fixture, "load-after-takeover")?;
    let operation_id = expected.operation().binding().operation_id().clone();
    let transition_at = now_ms()?;
    let recovery = fixture
        .authority
        .admission_operation_store()
        .claim_recovery(
            &operation_id,
            expected.operation().version(),
            &identifier("claimant_id", "channel-load-recovery")?,
            transition_at,
            transition_at + 10_000,
            &fixture.fence,
        )?;
    let command = AdmissionOperationCommand::new(
        operation_id.clone(),
        expected.operation().version(),
        recovery,
        vec![AdmissionAttachment::BrokerAttempt(
            ProviderAttemptBindingV1 {
                operation_id: operation_id.as_str().to_owned(),
                attempt_id: "channel-load-attempt".to_owned(),
                transport_id: "channel-load-transport".to_owned(),
                transport_key_epoch: 1,
            },
        )],
        Some(AdmissionOperationState::BrokerAttemptRegistered),
        None,
        None,
    )?;
    let advanced = fixture
        .authority
        .admission_operation_store()
        .compare_and_swap(&command, transition_at + 1)?
        .into_operation();
    assert!(advanced.version() > 1);
    assert_eq!(
        advanced.channel_reservation_proposal_digest(),
        expected.operation().channel_reservation_proposal_digest()
    );
    let historical_fence = fixture.fence.clone();
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let active_fence = authority.mutation_fence();
    assert!(active_fence.owner_epoch > historical_fence.owner_epoch);
    let store = authority.channel_lifecycle_store();
    let loaded = store
        .load_channel_prepared(&operation_id)?
        .ok_or("prepared channel record was absent after takeover")?;
    assert_eq!(loaded.operation(), &advanced);
    assert_eq!(loaded.plan(), expected.plan());
    assert_eq!(loaded.plan_digest(), expected.plan_digest());
    assert_eq!(loaded.created_at_unix_ms(), expected.created_at_unix_ms());
    assert_eq!(loaded.store_fence(), &historical_fence);
    assert_eq!(
        &loaded.plan().service.admission_handoff.store_fence,
        &historical_fence
    );

    let missing = prepared_operation(&active_fence, "unknown-load")?;
    assert!(store
        .load_channel_prepared(missing.binding().operation_id())?
        .is_none());
    drop(_temp);
    Ok(())
}

#[test]
fn prepared_record_load_rejects_an_admission_without_its_plan() -> TestResult {
    let fixture = fixture()?;
    let operation = prepared_operation(&fixture.fence, "missing-plan")?;
    begin_operation(&fixture, &operation)?;
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(operation.binding().operation_id()),
        Err(ChannelLifecycleStoreError::NotFound)
    ));
    Ok(())
}

#[test]
fn prepared_record_load_rejects_a_mismatched_begin_participant() -> TestResult {
    let fixture = fixture()?;
    let record = created_prepared_record(&fixture, "mismatched-begin-participant")?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        let changed = connection.execute(
            r#"
            UPDATE admission_operation_commits
            SET participant_digest = ?1
            WHERE operation_id = ?2 AND mutation_kind = 'begin'
            "#,
            params![
                digest("forged-plan-participant"),
                record.operation().binding().operation_id().as_str(),
            ],
        )?;
        assert_eq!(changed, 1);
    }
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(record.operation().binding().operation_id()),
        Err(ChannelLifecycleStoreError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn prepared_record_load_rejects_mismatched_begin_fence_evidence() -> TestResult {
    let fixture = fixture()?;
    let record = created_prepared_record(&fixture, "mismatched-begin-fence")?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        let changed = connection.execute(
            r#"
            UPDATE admission_operation_commits
            SET store_lease_id = 'forged-historical-begin-lease'
            WHERE operation_id = ?1 AND mutation_kind = 'begin'
            "#,
            [record.operation().binding().operation_id().as_str()],
        )?;
        assert_eq!(changed, 1);
    }
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(record.operation().binding().operation_id()),
        Err(ChannelLifecycleStoreError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn prepared_record_load_rejects_multiple_begin_commits() -> TestResult {
    let fixture = fixture()?;
    let record = created_prepared_record(&fixture, "multiple-begin-commits")?;
    {
        let connection = fixture.store.connection()?;
        let inserted = connection.execute(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT
                (SELECT MAX(commit_sequence) + 1 FROM admission_operation_commits),
                operation_id, operation_version, 'begin', operation_digest, NULL,
                participant_digest, chain_digest, ?2, ?3, ?4, ?5, ?6
            FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = 'begin'
            "#,
            params![
                record.operation().binding().operation_id().as_str(),
                digest("forged-second-begin-chain"),
                &fixture.fence.store_uuid,
                &fixture.fence.lease_id,
                i64::try_from(fixture.fence.owner_epoch)?,
                i64::try_from(now_ms()?)?,
            ],
        )?;
        assert_eq!(inserted, 1);
    }
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(record.operation().binding().operation_id()),
        Err(ChannelLifecycleStoreError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn prepared_record_load_rejects_a_missing_begin_commit() -> TestResult {
    let fixture = fixture()?;
    let record = created_prepared_record(&fixture, "missing-begin-commit")?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_no_delete;")?;
        let deleted = connection.execute(
            "DELETE FROM admission_operation_commits WHERE operation_id = ?1 AND mutation_kind = 'begin'",
            [record.operation().binding().operation_id().as_str()],
        )?;
        assert_eq!(deleted, 1);
    }
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(record.operation().binding().operation_id()),
        Err(ChannelLifecycleStoreError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn prepared_record_load_rejects_external_authority_changes() -> TestResult {
    let fixture = fixture()?;
    let record = created_prepared_record(&fixture, "external-load-corruption")?;
    let outsider = rusqlite::Connection::open(&fixture.database)?;
    outsider.execute_batch("DROP TRIGGER channel_prepared_admission_plans_immutable;")?;
    outsider.execute(
        "UPDATE channel_prepared_admission_plans SET plan_digest = ?1 WHERE operation_id = ?2",
        params![
            digest("externally-forged-plan"),
            record.operation().binding().operation_id().as_str(),
        ],
    )?;
    drop(outsider);
    assert!(matches!(
        fixture
            .store
            .load_channel_prepared(record.operation().binding().operation_id()),
        Err(ChannelLifecycleStoreError::OutcomeUnknown(_))
    ));
    Ok(())
}

#[test]
fn first_prepared_commit_cannot_be_removed_by_snapshot_restore() -> TestResult {
    let fixture = fixture()?;
    let snapshot = fixture._temp.path().join("before-channel-prepared.db");
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    }
    fs::copy(&fixture.database, &snapshot)?;
    created_prepared_record(&fixture, "snapshot-rollback")?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let mut input = std::fs::File::open(snapshot)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&database)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display())));
    }
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
    drop(_temp);
    Ok(())
}
