use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1, ObligationSettlementLifecycleV1, ObligationSettlementStateV1,
};
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionCompletedProjection, AdmissionDispatchState,
    AdmissionReceiptMetadataV1, AdmissionReceiptSchema, ObligationProjection,
    VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve, returned_value,
};
use chio_kernel::tool_outcome::{SettlementDispositionV1, ToolOutcomeTerminalEvidenceV1};
use chio_settle::channel::{
    ChannelReservationBodyV1, ChannelSignatureV1, SignedChannelReservationV1,
    CHANNEL_RESERVATION_SCHEMA,
};
use rusqlite::params;

use super::*;

struct ObligationArtifact {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    obligation_json: Vec<u8>,
    channel_json: Vec<u8>,
}

struct PerCallArtifact {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    obligation_json: Vec<u8>,
}

fn obligation_artifact(
    at: u64,
    suffix: &str,
    economic_intent: &str,
    source_receipt_id: &str,
    source_receipt_digest: &str,
    units: u64,
) -> AnchoredTestResult<ObligationArtifact> {
    let payer = Keypair::from_seed(&[0x61; 32]);
    let authority = Keypair::from_seed(&[0x62; 32]);
    let channel_id = economic_digest(&format!("channel-{suffix}"));
    let reservation_id = economic_digest(&format!("reservation-{suffix}"));
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: reservation_id.clone(),
        channel_id: channel_id.clone(),
        open_digest: economic_digest(&format!("open-{suffix}")),
        request_id: format!("request-{suffix}"),
        operation_id: economic_digest(&format!("operation-{suffix}")),
        next_sequence: 1,
        prior_state_digest: economic_digest(&format!("prior-state-{suffix}")),
        service_binding_digest: economic_digest(&format!("service-binding-{suffix}")),
        receipt_authority_digest: economic_digest(&format!("receipt-authority-{suffix}")),
        maximum_charge: MonetaryAmount {
            units: units.max(1),
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: units.max(1).to_string(),
        expires_at_unix_ms: at + 60_000,
        disposition_expected_version: 1,
        channel_state_expected_version: 1,
        lifecycle_fence: 1,
    };
    let signed_reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "payer-1".to_owned(),
            1,
            &payer,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "authority-1".to_owned(),
            1,
            &authority,
        )?,
        body: reservation_body,
    };
    let reservation_digest = signed_reservation.digest()?;
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: economic_intent.to_owned(),
        source_receipt_id: source_receipt_id.to_owned(),
        source_receipt_digest: source_receipt_digest.to_owned(),
        debtor_id: "payer-1".to_owned(),
        original_creditor_id: "payee-1".to_owned(),
        original_settlement_destination_ref: "channel:payee-1".to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest("payee-1", "channel:payee-1")?,
        amount: MonetaryAmount {
            units,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: reservation_digest.clone(),
        created_at_unix_ms: at,
        due_at_unix_ms: at + 86_400_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id,
            reservation_id: reservation_id.clone(),
            authority_digest: reservation_digest.clone(),
        },
    )?;
    let atom_digest = atom.digest()?;
    let obligation_json = canonical_json_bytes(&serde_json::json!({
        "source": {
            "source_authority_digest": atom.pre_action_authority_digest(),
            "source_record_id": atom.obligation_id(),
            "source_record_digest": atom_digest,
            "source_recorded_at_unix_ms": atom.created_at_unix_ms(),
            "consumer_receipt_id": atom.source_receipt_id(),
            "consumer_receipt_digest": atom.source_receipt_digest()
        },
        "atom": atom,
        "disposition_record": disposition
    }))?;
    let channel_json = canonical_json_bytes(&serde_json::json!({
        "reservation_id": reservation_id,
        "reservation_digest": reservation_digest,
        "receipt_id": source_receipt_id,
        "receipt_digest": source_receipt_digest,
        "actual_charge": { "units": units, "currency": "USD" },
        "obligation_atom_id": atom.obligation_id(),
        "obligation_atom_digest": atom.digest()?,
        "signed_reservation": signed_reservation
    }))?;
    Ok(ObligationArtifact {
        atom,
        disposition,
        obligation_json,
        channel_json,
    })
}

fn per_call_artifact(at: u64, suffix: &str) -> AnchoredTestResult<PerCallArtifact> {
    let authority_digest = economic_digest(&format!("per-call-authority-{suffix}"));
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: economic_digest(&format!("per-call-intent-{suffix}")),
        source_receipt_id: format!("per-call-receipt-{suffix}"),
        source_receipt_digest: economic_digest(&format!("per-call-receipt-{suffix}")),
        debtor_id: "payer-1".to_owned(),
        original_creditor_id: "payee-1".to_owned(),
        original_settlement_destination_ref: "per-call:payee-1".to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            "payee-1",
            "per-call:payee-1",
        )?,
        amount: MonetaryAmount {
            units: 37,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: authority_digest,
        created_at_unix_ms: at,
        due_at_unix_ms: at + 86_400_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let obligation_json = canonical_json_bytes(&serde_json::json!({
        "source": {
            "source_authority_digest": atom.pre_action_authority_digest(),
            "source_record_id": atom.obligation_id(),
            "source_record_digest": atom.digest()?,
            "source_recorded_at_unix_ms": atom.created_at_unix_ms(),
            "consumer_receipt_id": atom.source_receipt_id(),
            "consumer_receipt_digest": atom.source_receipt_digest()
        },
        "atom": atom,
        "disposition_record": disposition
    }))?;
    Ok(PerCallArtifact {
        atom,
        disposition,
        obligation_json,
    })
}

fn operation(fixture: &Fixture, suffix: &str, at: u64) -> AnchoredTestResult<AdmissionOperationV1> {
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        &format!("obligation-request-{suffix}"),
        &format!("obligation-capability-{suffix}"),
    );
    fixture.store.begin(&operation, &fixture.fence, at)?;
    Ok(operation)
}

fn insert_local_projection(
    transaction: &rusqlite::Transaction<'_>,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
    at: u64,
) -> AnchoredTestResult {
    transaction.execute(
        r#"
        INSERT INTO admission_operation_terminal_projections (
            operation_id, source_operation_version, terminal_operation_version,
            terminal_state, projection_body_digest, projection_digest,
            projection_json, manifest_json, record_count, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, 'completed', ?4, ?5, X'01', X'01', 1, ?6, ?7, ?8, ?9)
        "#,
        params![
            operation.binding().operation_id().as_str(),
            i64::try_from(operation.version())?,
            i64::try_from(operation.version() + 1)?,
            economic_digest("projection-body"),
            economic_digest("projection-manifest"),
            i64::try_from(at)?,
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
        ],
    )?;
    Ok(())
}

fn commit_projection_with_obligation(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    artifact: &ObligationArtifact,
    at: u64,
) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, operation, &fixture.fence, at)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        Some(&artifact.channel_json),
        at,
        at,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

fn commit_per_call_projection(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    artifact: &PerCallArtifact,
    at: u64,
) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, operation, &fixture.fence, at)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        None,
        at,
        at,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

fn commit_valid_per_call_projection(
    fixture: &Fixture,
    suffix: &str,
    at: u64,
) -> AnchoredTestResult<(ObligationAtomV1, ObligationDispositionRecordV1)> {
    let action = ToolCallAction::from_parameters(serde_json::json!({}))?;
    let action_parameter_hash =
        AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?;
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        obligation: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "coordinator_authority_id",
            "local-test-authority",
        ))?,
        request_id: identifier("request_id", &format!("obligation-request-{suffix}")),
        capability_id: identifier("capability_id", &format!("obligation-capability-{suffix}")),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            digest("immutable_request_hash", 'b'),
            action_parameter_hash,
            requirements,
        )?,
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })?;
    let mut operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    fixture.store.begin(&operation, &fixture.fence, at)?;
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation,
                &format!("obligation-attempt-{suffix}"),
            ))],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                &format!("obligation-hold-{suffix}"),
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
    ];
    for (state, attachments) in transitions {
        let recovery = claim(fixture, &operation, suffix, at);
        operation = fixture
            .store
            .compare_and_swap(&command(&operation, recovery, attachments, state, None), at)?
            .into_operation();
    }

    let amount = MonetaryAmount {
        units: 37,
        currency: "USD".to_owned(),
    };
    let (_, returned) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({ "result": "ok" }),
        None,
    )?;
    let evaluation = prepared_evaluation(&operation, &returned, at)
        .and_then(|value| record_pure_step(&value))
        .and_then(|value| record_external_step(&value, at))?;
    let (evaluation, outcome) = resolve(
        &returned,
        &evaluation,
        SettlementDispositionV1::Capture {
            amount: amount.clone(),
        },
    )?;
    let recovery = claim(fixture, &operation, suffix, at);
    operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                recovery,
                vec![AdmissionAttachment::ToolOutcomeId(
                    outcome.outcome_id().clone(),
                )],
                AdmissionOperationState::Finalizing,
                None,
            ),
            at,
        )?
        .into_operation();
    let recovery = claim(fixture, &operation, suffix, at);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    let tool_outcome = ToolOutcomeTerminalEvidenceV1::from_records_for_test(
        &operation,
        &context,
        &outcome,
        &evaluation,
    )?;
    let content_hash = outcome
        .resolved_output_ref()
        .ok_or("resolved output is absent")?
        .0
        .digest()
        .clone();
    let metadata = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: operation
            .version()
            .checked_add(1)
            .ok_or("terminal operation version overflow")?,
        projected_state: AdmissionOperationState::Completed,
        projected_dispatch_state: AdmissionDispatchState::Terminal,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: AdmissionCompensationStatus::NotCompensated,
        tool_outcome_id: Some(outcome.outcome_id().clone()),
        tool_outcome_version: Some(outcome.version()),
    };
    let kernel = Keypair::from_seed(&[0x71; 32]);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("per-call-receipt-{suffix}"),
            timestamp: at / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: "tool-outcome-test-server".to_owned(),
            tool_name: "tool-outcome-test-tool".to_owned(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: content_hash.as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({ ADMISSION_RECEIPT_METADATA_KEY: metadata })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )?;
    let receipt = VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt,
        &kernel.public_key(),
        &Decision::Allow,
        "tool-outcome-test-server",
        "tool-outcome-test-tool",
        operation.binding().action_parameter_hash(),
        &content_hash,
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
        Some((outcome.outcome_id(), outcome.version())),
    )?;
    let source_authority_digest = AdmissionDigest::try_new(
        "per_call_authority_digest",
        economic_digest(&format!("per-call-authority-{suffix}")),
    )?;
    let due_at_unix_ms = at
        .checked_add(86_400_000)
        .ok_or("obligation due time overflow")?;
    let obligation = ObligationProjection::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("debtor_id", "payer-1"),
        identifier("original_creditor_id", "payee-1"),
        amount.clone(),
        due_at_unix_ms,
        ObligationDispositionV1::PerCall,
        source_authority_digest.clone(),
        outcome.outcome_id().clone(),
        outcome.version(),
    )?;
    let receipt_digest = chio_core::crypto::sha256_hex(&canonical_json_bytes(receipt.receipt())?);
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: operation
            .binding()
            .request_binding_hash()
            .as_str()
            .to_owned(),
        source_receipt_id: receipt.receipt().id.clone(),
        source_receipt_digest: receipt_digest,
        debtor_id: "payer-1".to_owned(),
        original_creditor_id: "payee-1".to_owned(),
        original_settlement_destination_ref: "settlement:payee-1".to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            "payee-1",
            "settlement:payee-1",
        )?,
        amount,
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: source_authority_digest.as_str().to_owned(),
        created_at_unix_ms: at,
        due_at_unix_ms,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    fixture
        .store
        .commit_terminal_projection(&AdmissionTerminalProjection::Completed(Box::new(
            AdmissionCompletedProjection {
                context,
                receipt,
                tool_outcome: Some(tool_outcome),
                payment_evidence: None,
                authorization: None,
                eligibility: None,
                observer_work: None,
                obligation: Some(obligation),
                channel_terminal: None,
            },
        )))?;
    Ok((atom, disposition))
}

fn shape_obligation_schema_as_v5(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        r#"
        DROP TABLE obligation_assignment_results;
        DROP TABLE factor_assignment_authority_sets;
        DROP TABLE credit_exposure_terminal_transitions;
        DROP TABLE credit_exposure_reservations;
        DROP TABLE credit_exposure_accounts;
        DROP TABLE obligation_heads;
        DROP TABLE obligation_head_commits;
        DROP TABLE obligation_settlement_lifecycle_records;
        DROP TRIGGER obligation_disposition_records_exact_lease;
        DROP TRIGGER obligation_disposition_records_immutable;
        DROP TRIGGER obligation_disposition_records_no_delete;
        DROP INDEX obligation_disposition_records_operation;
        ALTER TABLE obligation_disposition_records
            RENAME TO obligation_disposition_records_v6;
        CREATE TABLE obligation_disposition_records (
            obligation_id TEXT NOT NULL,
            version INTEGER NOT NULL CHECK (version > 0),
            lifecycle_fence INTEGER NOT NULL CHECK (lifecycle_fence = version),
            atom_digest TEXT NOT NULL,
            disposition_digest TEXT NOT NULL UNIQUE,
            operation_id TEXT NOT NULL,
            record_json BLOB NOT NULL,
            committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
            store_uuid TEXT NOT NULL,
            store_lease_id TEXT NOT NULL,
            store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
            PRIMARY KEY (obligation_id, version),
            FOREIGN KEY (obligation_id, atom_digest)
                REFERENCES obligation_atoms(obligation_id, atom_digest),
            FOREIGN KEY (operation_id)
                REFERENCES admission_operation_terminal_projections(operation_id),
            FOREIGN KEY (store_uuid, store_owner_epoch)
                REFERENCES chio_serving_leases(store_uuid, owner_epoch)
        );
        INSERT INTO obligation_disposition_records
        SELECT * FROM obligation_disposition_records_v6;
        DROP TABLE obligation_disposition_records_v6;
        CREATE INDEX obligation_disposition_records_operation
            ON obligation_disposition_records(operation_id, obligation_id, version);
        CREATE TRIGGER obligation_disposition_records_exact_lease
        BEFORE INSERT ON obligation_disposition_records BEGIN SELECT 1; END;
        CREATE TRIGGER obligation_disposition_records_immutable
        BEFORE UPDATE ON obligation_disposition_records BEGIN SELECT 1; END;
        CREATE TRIGGER obligation_disposition_records_no_delete
        BEFORE DELETE ON obligation_disposition_records BEGIN SELECT 1; END;
        UPDATE chio_store_schema_versions
        SET version = 5
        WHERE store_key = 'admission_operation';
        "#,
    )
}

#[test]
fn positive_channel_terminal_projection_persists_exact_obligation_atomically() -> AnchoredTestResult
{
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "positive", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "positive",
        &economic_digest("intent-positive"),
        "receipt-positive",
        &economic_digest("receipt-positive"),
        17,
    )?;
    commit_projection_with_obligation(&fixture, &operation, &artifact, at + 1)?;
    let stored = fixture
        .store
        .load_obligation(artifact.atom.obligation_id())?
        .ok_or("canonical obligation was not persisted")?;
    assert_eq!(stored.atom(), &artifact.atom);
    assert_eq!(stored.disposition(), &artifact.disposition);
    assert_eq!(
        stored.settlement_lifecycle(),
        &ObligationSettlementLifecycleV1::pending(&artifact.atom)?
    );
    assert_eq!(
        stored.settlement_lifecycle().state(),
        &ObligationSettlementStateV1::Pending
    );
    assert_eq!(stored.snapshot_version(), 1);
    assert_eq!(stored.resource_fence(), 1);
    let connection = fixture.store.connection()?;
    let (disposition_count, settlement_count, commit_count, head_count): (i64, i64, i64, i64) =
        connection.query_row(
            r#"
        SELECT
            (SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1),
            (SELECT COUNT(*) FROM obligation_settlement_lifecycle_records
             WHERE obligation_id = ?1),
            (SELECT COUNT(*) FROM obligation_head_commits WHERE obligation_id = ?1),
            (SELECT COUNT(*) FROM obligation_heads WHERE obligation_id = ?1)
        "#,
            [artifact.atom.obligation_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert_eq!(disposition_count, 2);
    assert_eq!(settlement_count, 1);
    assert_eq!(commit_count, 1);
    assert_eq!(head_count, 1);
    Ok(())
}

#[test]
fn zero_charge_channel_terminal_projection_creates_no_obligation() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "zero", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "zero",
        &economic_digest("intent-zero"),
        "receipt-zero",
        &economic_digest("receipt-zero"),
        1,
    )?;
    let channel: serde_json::Value = serde_json::from_slice(&artifact.channel_json)?;
    let mut channel = channel;
    channel["actual_charge"]["units"] = serde_json::json!(0);
    channel["obligation_atom_id"] = serde_json::Value::Null;
    channel["obligation_atom_digest"] = serde_json::Value::Null;
    let channel_json = canonical_json_bytes(&channel)?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        None,
        Some(&channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    let count: i64 = connection.query_row(
        r#"
        SELECT (SELECT COUNT(*) FROM obligation_atoms)
             + (SELECT COUNT(*) FROM obligation_disposition_records)
             + (SELECT COUNT(*) FROM obligation_settlement_lifecycle_records)
             + (SELECT COUNT(*) FROM obligation_head_commits)
             + (SELECT COUNT(*) FROM obligation_heads)
        "#,
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn exact_obligation_replay_is_idempotent() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "replay", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "replay",
        &economic_digest("intent-replay"),
        "receipt-replay",
        &economic_digest("receipt-replay"),
        23,
    )?;
    commit_projection_with_obligation(&fixture, &operation, &artifact, at + 1)?;
    let connection = fixture.store.connection()?;
    for _ in 0..2 {
        super::super::obligation::verify_obligation_projection(
            &connection,
            operation.binding().operation_id(),
            Some(&artifact.obligation_json),
            Some(&artifact.channel_json),
            at + 1,
            at + 1,
            &fixture.fence,
        )?;
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1",
        [artifact.atom.obligation_id()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn exact_replay_accepts_a_later_legal_disposition_successor() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let source_operation = operation(&fixture, "prefix-source", at)?;
    let artifact = per_call_artifact(at + 1, "prefix")?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &source_operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        source_operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        None,
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    drop(connection);

    let successor_operation = operation(&fixture, "prefix-successor", at + 2)?;
    let recovery = claim(&fixture, &successor_operation, "prefix-successor", at + 3);
    let participant_digest = economic_digest("prefix-successor-participant");
    let successor = artifact.disposition.advance(
        &artifact.atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-prefix".to_owned(),
            authority_digest: economic_digest("round-prefix-authority"),
        },
    )?;
    let settlement_lifecycle = ObligationSettlementLifecycleV1::pending(&artifact.atom)?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    append_participant_update_tx(
        &transaction,
        &fixture.store.serving_owner,
        &successor_operation,
        &recovery,
        &participant_digest,
        at + 4,
    )?;
    super::super::obligation::append_obligation_disposition_transition(
        &transaction,
        successor_operation.binding().operation_id(),
        &artifact.atom,
        &artifact.disposition,
        &successor,
        &settlement_lifecycle,
        1,
        1,
        &participant_digest,
        at + 4,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;

    super::super::obligation::verify_obligation_projection(
        &connection,
        source_operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        None,
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    let current = super::super::obligation::load_durable_obligation(
        &connection,
        artifact.atom.obligation_id(),
    )?
    .ok_or("canonical obligation disappeared after its successor")?;
    assert!(matches!(
        current.disposition().disposition(),
        ObligationDispositionV1::ClearingReserved { round_id } if round_id == "round-prefix"
    ));
    Ok(())
}

#[test]
fn obligation_lifecycle_and_head_survive_serving_owner_restart() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let (atom, disposition) = commit_valid_per_call_projection(&fixture, "restart", at)?;
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
    let stored = authority
        .admission_operation_store()
        .load_obligation(atom.obligation_id())?
        .ok_or("obligation disappeared across serving owner restart")?;
    assert_eq!(stored.atom(), &atom);
    assert_eq!(stored.disposition(), &disposition);
    assert_eq!(
        stored.settlement_lifecycle(),
        &ObligationSettlementLifecycleV1::pending(&atom)?
    );
    assert_eq!(stored.snapshot_version(), 1);
    assert_eq!(stored.resource_fence(), 1);
    drop(_temp);
    Ok(())
}

#[test]
fn empty_v5_migration_adds_lifecycle_state_without_backfill() -> AnchoredTestResult {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture();
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    shape_obligation_schema_as_v5(&connection)?;
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    let (version, lifecycles, commits, heads): (i64, i64, i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT version FROM chio_store_schema_versions
             WHERE store_key = 'admission_operation'),
            (SELECT COUNT(*) FROM obligation_settlement_lifecycle_records),
            (SELECT COUNT(*) FROM obligation_head_commits),
            (SELECT COUNT(*) FROM obligation_heads)
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert_eq!((lifecycles, commits, heads), (0, 0, 0));
    verify_admission_operation_invariants(&connection)?;
    drop(_temp);
    Ok(())
}

#[test]
fn populated_v5_migration_requires_authoritative_settlement_reconciliation() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "v5-migration", at)?;
    let artifact = per_call_artifact(at + 1, "v5-migration")?;
    let disposition_digest = artifact.disposition.digest(&artifact.atom)?;
    commit_per_call_projection(&fixture, &operation, &artifact, at + 1)?;
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

    let connection = Connection::open(&database)?;
    shape_obligation_schema_as_v5(&connection)?;
    drop(connection);

    let migration_error = match SqliteAuthorityStore::provision(&database, &lock_root) {
        Ok(()) => return Err("populated v5 migration unexpectedly succeeded".into()),
        Err(error) => error,
    };
    assert!(migration_error
        .to_string()
        .contains("offline authoritative settlement reconciliation"));

    let connection = Connection::open(&database)?;
    let (version, dispositions, digest, lifecycles, commits, heads): (
        i64,
        i64,
        String,
        i64,
        i64,
        i64,
    ) = connection.query_row(
        r#"
        SELECT
            (SELECT version FROM chio_store_schema_versions
             WHERE store_key = 'admission_operation'),
            (SELECT COUNT(*) FROM obligation_disposition_records
             WHERE obligation_id = ?1),
            (SELECT disposition_digest FROM obligation_disposition_records
             WHERE obligation_id = ?1 AND version = 1),
            (SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'obligation_settlement_lifecycle_records'),
            (SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'obligation_head_commits'),
            (SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'obligation_heads')
        "#,
        [artifact.atom.obligation_id()],
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
    assert_eq!(version, 5);
    assert_eq!(dispositions, 1);
    assert_eq!(digest, disposition_digest);
    assert_eq!(lifecycles, 0);
    assert_eq!(commits, 0);
    assert_eq!(heads, 0);
    drop(_temp);
    Ok(())
}

#[test]
fn obligation_load_rejects_a_head_that_does_not_bind_its_atom() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "corrupt-head", at)?;
    let artifact = per_call_artifact(at + 1, "corrupt-head")?;
    commit_per_call_projection(&fixture, &operation, &artifact, at + 1)?;
    let connection = fixture.store.connection()?;
    connection
        .execute_batch("DROP TRIGGER obligation_heads_versioned; PRAGMA foreign_keys = OFF;")?;
    connection.execute(
        "UPDATE obligation_heads SET atom_digest = ?1 WHERE obligation_id = ?2",
        params![
            economic_digest("corrupt-head-atom"),
            artifact.atom.obligation_id()
        ],
    )?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    assert!(super::super::obligation::load_durable_obligation(
        &connection,
        artifact.atom.obligation_id()
    )
    .is_err());
    Ok(())
}

#[test]
fn obligation_load_rejects_a_tampered_settlement_lifecycle_digest() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "corrupt-settlement", at)?;
    let artifact = per_call_artifact(at + 1, "corrupt-settlement")?;
    commit_per_call_projection(&fixture, &operation, &artifact, at + 1)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER obligation_settlement_lifecycle_records_immutable;")?;
    connection.execute(
        r#"
        UPDATE obligation_settlement_lifecycle_records
        SET lifecycle_digest = ?1
        WHERE obligation_id = ?2 AND version = 1
        "#,
        params![
            economic_digest("corrupt-settlement-digest"),
            artifact.atom.obligation_id()
        ],
    )?;
    assert!(super::super::obligation::load_durable_obligation(
        &connection,
        artifact.atom.obligation_id()
    )
    .is_err());
    Ok(())
}

#[test]
fn obligation_load_rejects_a_tampered_head_commit_preimage() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "corrupt-head-commit", at)?;
    let artifact = per_call_artifact(at + 1, "corrupt-head-commit")?;
    commit_per_call_projection(&fixture, &operation, &artifact, at + 1)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER obligation_head_commits_immutable;")?;
    connection.execute(
        r#"
        UPDATE obligation_head_commits
        SET previous_head_digest = ?1
        WHERE obligation_id = ?2 AND head_sequence = 1
        "#,
        params![
            economic_digest("corrupt-head-commit-predecessor"),
            artifact.atom.obligation_id()
        ],
    )?;
    assert!(super::super::obligation::load_durable_obligation(
        &connection,
        artifact.atom.obligation_id()
    )
    .is_err());
    Ok(())
}

#[test]
fn obligation_head_accepts_same_millisecond_serving_owner_rotation() -> AnchoredTestResult {
    let fixture = fixture();
    let committed_at = now_ms();
    let (atom, disposition) =
        commit_valid_per_call_projection(&fixture, "head-owner-rotation", committed_at)?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence: first_fence,
    } = fixture;
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let fixture = Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    };
    assert!(fixture.fence.owner_epoch > first_fence.owner_epoch);

    let successor_operation = operation(&fixture, "head-owner-successor", committed_at)?;
    let recovery = claim(
        &fixture,
        &successor_operation,
        "head-owner-successor",
        committed_at,
    );
    let participant_digest = economic_digest("head-owner-successor-participant");
    let successor = disposition.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-head-owner-rotation".to_owned(),
            authority_digest: economic_digest("round-head-owner-rotation-authority"),
        },
    )?;
    let settlement_lifecycle = ObligationSettlementLifecycleV1::pending(&atom)?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    append_participant_update_tx(
        &transaction,
        &fixture.store.serving_owner,
        &successor_operation,
        &recovery,
        &participant_digest,
        committed_at,
    )?;
    super::super::obligation::append_obligation_disposition_transition(
        &transaction,
        successor_operation.binding().operation_id(),
        &atom,
        &disposition,
        &successor,
        &settlement_lifecycle,
        1,
        1,
        &participant_digest,
        committed_at,
        &fixture.fence,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;

    let stored =
        super::super::obligation::load_durable_obligation(&connection, atom.obligation_id())?
            .ok_or("obligation disappeared after serving owner rotation")?;
    assert_eq!(stored.disposition(), &successor);
    assert_eq!(stored.snapshot_version(), 2);
    assert_eq!(stored.resource_fence(), 2);
    let commits = connection
        .prepare(
            r#"
            SELECT committed_at_unix_ms, store_owner_epoch
            FROM obligation_head_commits
            WHERE obligation_id = ?1
            ORDER BY head_sequence
            "#,
        )?
        .query_map([atom.obligation_id()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        commits,
        vec![
            (
                i64::try_from(committed_at)?,
                i64::try_from(first_fence.owner_epoch)?
            ),
            (
                i64::try_from(committed_at)?,
                i64::try_from(fixture.fence.owner_epoch)?
            ),
        ]
    );
    Ok(())
}

#[test]
fn conflicting_obligation_source_and_digest_are_rejected() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let source_receipt_digest = economic_digest("receipt-conflict");
    let first_operation = operation(&fixture, "conflict-first", at)?;
    let first = obligation_artifact(
        at + 1,
        "conflict-first",
        &economic_digest("intent-conflict-first"),
        "receipt-conflict",
        &source_receipt_digest,
        29,
    )?;
    commit_projection_with_obligation(&fixture, &first_operation, &first, at + 1)?;

    let second_operation = operation(&fixture, "conflict-second", at + 2)?;
    let second = obligation_artifact(
        at + 3,
        "conflict-second",
        &economic_digest("intent-conflict-second"),
        "receipt-conflict",
        &source_receipt_digest,
        29,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &second_operation, &fixture.fence, at + 3)?;
    assert!(super::super::obligation::insert_obligation_projection(
        &transaction,
        second_operation.binding().operation_id(),
        Some(&second.obligation_json),
        Some(&second.channel_json),
        at + 3,
        at + 3,
        &fixture.fence,
    )
    .is_err());
    transaction.rollback()?;

    let mut substituted: serde_json::Value = serde_json::from_slice(&first.obligation_json)?;
    substituted["source"]["source_record_digest"] =
        serde_json::json!(economic_digest("substituted-atom-digest"));
    let substituted = canonical_json_bytes(&substituted)?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    assert!(super::super::obligation::insert_obligation_projection(
        &transaction,
        first_operation.binding().operation_id(),
        Some(&substituted),
        Some(&first.channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )
    .is_err());
    transaction.rollback()?;
    Ok(())
}

#[test]
fn obligation_failure_rolls_back_local_terminal_and_obligation_state() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let operation = operation(&fixture, "rollback", at)?;
    let artifact = obligation_artifact(
        at + 1,
        "rollback",
        &economic_digest("intent-rollback"),
        "receipt-rollback",
        &economic_digest("receipt-rollback"),
        31,
    )?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    insert_local_projection(&transaction, &operation, &fixture.fence, at + 1)?;
    super::super::obligation::insert_obligation_projection(
        &transaction,
        operation.binding().operation_id(),
        Some(&artifact.obligation_json),
        Some(&artifact.channel_json),
        at + 1,
        at + 1,
        &fixture.fence,
    )?;
    transaction.rollback()?;
    let count: i64 = connection.query_row(
        r#"
        SELECT (SELECT COUNT(*) FROM admission_operation_terminal_projections WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_atoms WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_disposition_records WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_settlement_lifecycle_records
                WHERE operation_id = ?1)
             + (SELECT COUNT(*) FROM obligation_head_commits
                WHERE source_operation_id = ?1)
        "#,
        [operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
