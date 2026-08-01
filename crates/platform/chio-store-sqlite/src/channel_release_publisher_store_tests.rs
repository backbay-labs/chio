use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use chio_core::canonical::canonical_json_bytes;
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicFrostBindingV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicTerminalResultV1, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionDispatchState, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionRequestBindingV1,
    AdmissionTerminalReplay, AuthenticatedRequestNamespace, SideEffectClass,
};
use chio_settle::channel::{
    ChannelEscrowReferenceV1, ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1,
    ChannelLifecycleStatusV1, ChannelLifecycleViewV1, CHANNEL_ESCROW_RESERVATION_SCHEMA,
    CHANNEL_LIFECYCLE_SCHEMA,
};
use chio_settle::PreparedEvmCall;
use rusqlite::params;
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _temp: TempDir,
    _database: PathBuf,
    _lock_root: PathBuf,
    _authority: SqliteAuthorityStore,
    store: SqliteChannelReleasePublisherStore,
    fence: StoreMutationFence,
}

fn fixture() -> TestResult<Fixture> {
    let temp = tempfile::tempdir()?;
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure directory: {error}"));
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.channel_release_publisher_store();
    let fence = authority.mutation_fence();
    Ok(Fixture {
        _temp: temp,
        _database: database,
        _lock_root: lock_root,
        _authority: authority,
        store,
        fence,
    })
}

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn evm_hash(label: &str) -> String {
    format!("0x{}", digest(label))
}

fn candidate() -> TestResult<ChannelReleasePublisherCandidate> {
    let channel_id = digest("publisher-channel");
    let close_body_digest = digest("publisher-close-body");
    let publisher_fence = 8;
    let lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        status: ChannelLifecycleStatusV1::Closing,
        latest_state_digest: digest("publisher-final-state"),
        latest_sequence: 5,
        state_version: 4,
        lifecycle_fence: publisher_fence,
        pending_close_body_digest: Some(close_body_digest.clone()),
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        open_digest: digest("publisher-open"),
        escrow_reference: ChannelEscrowReferenceV1 {
            chain_id: "eip155:31337".to_owned(),
            escrow_contract: "0x1111111111111111111111111111111111111111".to_owned(),
            escrow_id: evm_hash("publisher-escrow"),
        },
        status: ChannelEscrowReservationStatusV1::Closing,
        version: 7,
        lifecycle_fence: publisher_fence,
        pending_close_body_digest: Some(close_body_digest.clone()),
    };
    let prepared_call = PreparedEvmCall {
        from_address: "0x2222222222222222222222222222222222222222".to_owned(),
        to_address: escrow.escrow_reference.escrow_contract.clone(),
        data: "0xdeadbeef".to_owned(),
        gas_limit: Some(250_000),
    };
    let prepared_call_json = canonical_json_bytes(&prepared_call)?;
    let authorization_json = canonical_json_bytes(&serde_json::json!({
        "channelId": channel_id,
        "escrowReference": escrow.escrow_reference,
        "openDigest": escrow.open_digest,
        "closeDigest": digest("publisher-close"),
        "closeBodyDigest": close_body_digest,
        "effectiveCloseDigest": digest("publisher-effective-close"),
        "finalStateDigest": lifecycle.latest_state_digest,
        "finalStateSequence": lifecycle.latest_sequence,
        "finalCumulativeOwed": { "units": 50, "currency": "USD" },
        "channelStateVersion": lifecycle.state_version - 1,
        "escrowReservationVersion": escrow.version - 1,
        "lifecycleFence": publisher_fence - 1,
        "boundTokenBaseUnits": "1500000",
        "expectedReleaseTokenBaseUnits": "500000",
        "expectedRefundTokenBaseUnits": "1000000",
        "assetBindingDigest": digest("publisher-asset-binding"),
        "originalWeb3DispatchDigest": digest("publisher-dispatch"),
        "originalOperator": "0x3333333333333333333333333333333333333333",
        "originalOperatorKeyHash": evm_hash("publisher-operator-key"),
        "payeeBeneficiaryAddress": prepared_call.from_address,
        "channelExpiryUnixMs": 40000,
        "disputeDeadlineUnixMs": 25000,
        "closeSubmissionCutoffUnixMs": 50000,
        "escrowDeadlineUnixMs": 60000,
        "publisherFence": publisher_fence,
        "authorizedAtUnixMs": 20000,
        "frost": {
            "authorizationSlotId": digest("publisher-frost-slot"),
            "authorizationId": digest("publisher-frost-authorization"),
            "actionDigest": digest("publisher-frost-action"),
            "signedEnvelopeDigest": digest("publisher-frost-envelope")
        },
        "frostScopeId": "publisher-settlement-scope",
        "frostResourceId": channel_id,
        "frostResourceVersion": lifecycle.state_version - 1,
        "frostResourceFence": publisher_fence - 1,
        "frostRosterDigest": digest("publisher-roster"),
        "frostKeyEpoch": 9,
        "frostIssuedAtUnixMs": 19000
    }))?;
    let authorization_digest = authorization_digest(&authorization_json);
    Ok(ChannelReleasePublisherCandidate {
        channel_id,
        chain_id: escrow.escrow_reference.chain_id.clone(),
        escrow_contract: escrow.escrow_reference.escrow_contract.clone(),
        escrow_id: escrow.escrow_reference.escrow_id.clone(),
        open_digest: escrow.open_digest.clone(),
        close_digest: digest("publisher-close"),
        close_body_digest,
        effective_close_digest: digest("publisher-effective-close"),
        final_state_digest: lifecycle.latest_state_digest.clone(),
        final_state_sequence: lifecycle.latest_sequence,
        source_channel_state_version: lifecycle.state_version - 1,
        source_escrow_reservation_version: escrow.version - 1,
        source_lifecycle_fence: publisher_fence - 1,
        source_checkpoint_sequence: 11,
        source_checkpoint_digest: digest("publisher-source-checkpoint"),
        source_channel_head_digest: digest("publisher-source-channel-head"),
        source_escrow_head_digest: digest("publisher-source-escrow-head"),
        closing_checkpoint_sequence: 12,
        closing_checkpoint_digest: digest("publisher-closing-checkpoint"),
        closing_channel_head_digest: digest("publisher-closing-channel-head"),
        closing_escrow_head_digest: digest("publisher-closing-escrow-head"),
        closing_channel_predecessor_digest: digest("publisher-source-channel-head"),
        closing_escrow_predecessor_digest: digest("publisher-source-escrow-head"),
        closing_lifecycle: lifecycle,
        closing_escrow: escrow,
        bound_token_base_units: "1500000".to_owned(),
        release_token_base_units: "500000".to_owned(),
        refund_token_base_units: "1000000".to_owned(),
        original_operator: "0x3333333333333333333333333333333333333333".to_owned(),
        original_operator_key_hash: evm_hash("publisher-operator-key"),
        beneficiary_address: prepared_call.from_address.clone(),
        asset_binding_digest: digest("publisher-asset-binding"),
        original_dispatch_digest: digest("publisher-dispatch"),
        close_submission_cutoff_unix_ms: 50_000,
        escrow_deadline_unix_ms: 60_000,
        publisher_fence,
        authorized_at_unix_ms: 20_000,
        frost_slot_id: digest("publisher-frost-slot"),
        frost_authorization_id: digest("publisher-frost-authorization"),
        frost_action_digest: digest("publisher-frost-action"),
        frost_envelope_digest: digest("publisher-frost-envelope"),
        frost_scope_id: "publisher-settlement-scope".to_owned(),
        frost_resource_id: digest("publisher-channel"),
        frost_resource_version: 3,
        frost_resource_fence: 7,
        frost_roster_digest: digest("publisher-roster"),
        frost_key_epoch: 9,
        frost_issued_at_unix_ms: 19_000,
        publication_root: digest("publisher-publication-root"),
        root_operation_id: digest("publisher-root-operation"),
        root_effect_slot_id: digest("publisher-root-effect-slot"),
        root_effect_scope_id: "publisher-settlement-scope".to_owned(),
        root_effect_kind: CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND.to_owned(),
        root_idempotency_key: digest("publisher-root-idempotency"),
        root_call_digest: digest("publisher-root-call"),
        root_resource_head_digest: digest("publisher-closing-escrow-head"),
        release_operation_id: digest("publisher-release-operation"),
        release_effect_slot_id: digest("publisher-release-effect-slot"),
        release_effect_scope_id: "publisher-settlement-scope".to_owned(),
        release_effect_kind: CHANNEL_RELEASE_BROADCAST_EFFECT_KIND.to_owned(),
        release_idempotency_key: digest("publisher-release-idempotency"),
        release_call_digest: sha256_hex(&prepared_call_json),
        release_resource_head_digest: digest("publisher-closing-escrow-head"),
        authorization_digest,
        authorization_json,
        prepared_call_digest: sha256_hex(&prepared_call_json),
        prepared_call_json,
    })
}

fn admission_digest(field: &'static str, value: &str) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(field, value.to_owned())?)
}

fn admission_identifier(field: &'static str, value: &str) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new(field, value.to_owned())?)
}

fn governed_operation(
    candidate: &ChannelReleasePublisherCandidate,
    label: &str,
    call_digest: &str,
    state: AdmissionOperationState,
    version: u64,
    fence: &StoreMutationFence,
) -> TestResult<AdmissionOperationV1> {
    let namespace = AuthenticatedRequestNamespace::for_local_system(admission_identifier(
        "coordinator_authority_id",
        "channel-release-publisher",
    )?)?;
    let request_binding = AdmissionRequestBindingV1::new_with_action_parameter_hash(
        admission_digest("immutable_request_hash", &candidate.authorization_digest)?,
        admission_digest("action_parameter_hash", call_digest)?,
        AdmissionParticipantRequirements::NONE,
    )?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace,
        request_id: admission_identifier("request_id", &format!("{label}-request"))?,
        capability_id: admission_identifier("capability_id", &format!("{label}-capability"))?,
        authorization_capability_hash: admission_digest(
            "authorization_capability_hash",
            &digest(&format!("{label}-authorization-capability")),
        )?,
        request_binding,
        policy_hash: admission_digest("policy_hash", &digest(&format!("{label}-policy")))?,
        effect_class: SideEffectClass::Monetary,
    })?;
    let prepared = AdmissionOperationV1::prepare(binding, fence.owner_epoch)?;
    let mut persisted = prepared.to_persisted();
    persisted.state = state;
    persisted.dispatch_state = AdmissionDispatchState::NotApplicable;
    persisted.version = version;
    if state == AdmissionOperationState::EconomicMutationApplied {
        persisted.terminal_replay = Some(AdmissionTerminalReplay::EconomicMutation {
            result_id: admission_identifier("result_id", &format!("{label}-result"))?,
            result_digest: admission_digest("result_digest", &digest(&format!("{label}-result")))?,
            projection_digest: admission_digest(
                "projection_digest",
                &digest(&format!("{label}-projection")),
            )?,
        });
    }
    Ok(AdmissionOperationV1::from_persisted(persisted)?)
}

fn effect_slot(
    candidate: &ChannelReleasePublisherCandidate,
    operation: &AdmissionOperationV1,
    effect_kind: &str,
    idempotency_key: &str,
    call_digest: &str,
    state: EconomicEffectStateV1,
    fence: &StoreMutationFence,
) -> TestResult<EconomicEffectSlotV1> {
    let result = EconomicContentV1::Inline {
        value: serde_json::json!({
            "schema": CHANNEL_ROOT_PUBLICATION_RESULT_SCHEMA,
            "publicationRoot": candidate.publication_root,
            "callDigest": candidate.root_call_digest,
            "transactionHash": format!("0x{}", "a".repeat(64)),
        }),
    };
    let terminal = (state == EconomicEffectStateV1::Completed).then(|| {
        Ok::<_, Box<dyn Error>>(EconomicEffectTerminalV1::Completed {
            result_id: "channel-root-publication-result".to_owned(),
            result_digest: result.digest()?,
            result,
        })
    });
    let terminal = terminal.transpose()?;
    let binding = operation.binding();
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "channel-release-anchor".to_owned(),
        namespace: "channel-release-namespace".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "channel_escrow_reservation".to_owned(),
            scope_id: candidate.frost_scope_id.clone(),
            resource_id: candidate.channel_id.clone(),
        },
        operation_id: binding.operation_id().as_str().to_owned(),
        effect_kind: effect_kind.to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: binding.request_namespace_digest().as_str().to_owned(),
            request_id: binding.request_id().as_str().to_owned(),
            request_binding_digest: binding.request_binding_hash().as_str().to_owned(),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: 3,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        },
        target: EconomicEffectTargetV1 {
            target_id: "channel-release-rail".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("channel-release-target-qualification"),
        },
        action_digest: candidate.frost_action_digest.clone(),
        parameters_digest: call_digest.to_owned(),
        resource_head_digest: candidate.closing_escrow_head_digest.clone(),
        frost: Some(EconomicFrostBindingV1 {
            authorization_slot_id: candidate.frost_slot_id.clone(),
            authorization_id: candidate.frost_authorization_id.clone(),
            action_digest: candidate.frost_action_digest.clone(),
            signed_envelope_digest: candidate.frost_envelope_digest.clone(),
        }),
        idempotency_key: idempotency_key.to_owned(),
        state,
        terminal,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
    Ok(slot)
}

fn effect_head(slot: &EconomicEffectSlotV1) -> TestResult<EconomicResourceHeadV1> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(slot)?,
    };
    let terminal_result = match slot.terminal.as_ref() {
        Some(EconomicEffectTerminalV1::Completed {
            result_id,
            result_digest,
            result,
        }) => Some(EconomicTerminalResultV1 {
            result_id: result_id.clone(),
            result_digest: result_digest.clone(),
            result: result.clone(),
        }),
        _ => None,
    };
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: slot.anchor_id.clone(),
        namespace: slot.namespace.clone(),
        resource_key: slot.resource_head_key(),
        head_version: 2,
        resource_version: 2,
        lifecycle_fence: slot.admission_handoff.lifecycle_fence,
        lifecycle_state: match slot.state {
            EconomicEffectStateV1::Completed => "completed",
            EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
            _ => "invalid",
        }
        .to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: slot.frost.clone(),
        terminal_result,
        trusted_clock_high_water: 30_000,
        predecessor_digest: Some(digest("effect-head-predecessor")),
    };
    head.validate()?;
    Ok(head)
}

fn qualified_execution_fixture(
    fence: &StoreMutationFence,
) -> TestResult<(
    ChannelReleasePublisherCandidate,
    AdmissionOperationV1,
    AdmissionOperationV1,
    EconomicResourceHeadV1,
    EconomicResourceHeadV1,
)> {
    let mut candidate = candidate()?;
    let root_operation = governed_operation(
        &candidate,
        "root-publication",
        &candidate.root_call_digest,
        AdmissionOperationState::EconomicMutationApplied,
        4,
        fence,
    )?;
    let release_operation = governed_operation(
        &candidate,
        "release-broadcast",
        &candidate.release_call_digest,
        AdmissionOperationState::MutationSubmitted,
        3,
        fence,
    )?;
    candidate.root_operation_id = root_operation.binding().operation_id().as_str().to_owned();
    candidate.release_operation_id = release_operation
        .binding()
        .operation_id()
        .as_str()
        .to_owned();
    let root_slot = effect_slot(
        &candidate,
        &root_operation,
        &candidate.root_effect_kind,
        &candidate.root_idempotency_key,
        &candidate.root_call_digest,
        EconomicEffectStateV1::Completed,
        fence,
    )?;
    let release_slot = effect_slot(
        &candidate,
        &release_operation,
        &candidate.release_effect_kind,
        &candidate.release_idempotency_key,
        &candidate.release_call_digest,
        EconomicEffectStateV1::DispatchCommitted,
        fence,
    )?;
    candidate.root_effect_slot_id = root_slot.slot_id.clone();
    candidate.release_effect_slot_id = release_slot.slot_id.clone();
    Ok((
        candidate,
        root_operation,
        release_operation,
        effect_head(&root_slot)?,
        effect_head(&release_slot)?,
    ))
}

fn append_fixture_admission_projection(
    fixture: &Fixture,
    transaction: &rusqlite::Transaction<'_>,
    candidate: &ChannelReleasePublisherCandidate,
    label: &str,
    recorded_at_unix_ms: u64,
) -> TestResult {
    let operation = governed_operation(
        candidate,
        label,
        &candidate.close_digest,
        AdmissionOperationState::Prepared,
        1,
        &fixture.fence,
    )?;
    let encoded = canonical_json_bytes(&operation.to_persisted())?;
    transaction.execute(
        r#"
        INSERT INTO admission_operations (
            operation_id, request_namespace_digest, request_id,
            operation_json, state, terminal, coordinator_lease_epoch,
            version, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, 'prepared', 0, ?5, 1, ?6, ?6)
        "#,
        params![
            operation.binding().operation_id().as_str(),
            operation.binding().request_namespace_digest().as_str(),
            operation.binding().request_id().as_str(),
            &encoded,
            i64::try_from(operation.coordinator_lease_epoch())?,
            i64::try_from(recorded_at_unix_ms)?,
        ],
    )?;
    crate::admission_operation_store::append_operation_commit_with_participant(
        transaction,
        &operation,
        &encoded,
        None,
        "begin",
        None,
        &fixture.store.serving_owner,
        recorded_at_unix_ms,
    )?;
    Ok(())
}

fn seed_closing_lifecycle(
    fixture: &Fixture,
    candidate: &ChannelReleasePublisherCandidate,
) -> TestResult {
    let lifecycle_json = canonical_json_bytes(&candidate.closing_lifecycle)?;
    let escrow_json = canonical_json_bytes(&candidate.closing_escrow)?;
    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    transaction.execute(
        r#"
        INSERT INTO channel_state_records (
            channel_id, sequence, state_kind, state_digest,
            checkpoint_sequence, checkpoint_digest, state_json, operation_id,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        ) VALUES (?1, ?2, 'signed', ?3, ?4, ?5, X'7b7d', NULL, ?6, ?7, ?8, 20000)
        "#,
        params![
            &candidate.channel_id,
            i64::try_from(candidate.final_state_sequence)?,
            &candidate.final_state_digest,
            i64::try_from(candidate.closing_checkpoint_sequence)?,
            &candidate.closing_checkpoint_digest,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO channel_lifecycle_records (
            channel_id, open_intent_digest, open_intent_json,
            open_digest, open_json, lifecycle_json, escrow_json,
            lifecycle_state, latest_state_digest, latest_sequence,
            state_version, lifecycle_fence, live_reservation_id, operation_id,
            channel_head_digest, escrow_head_digest,
            checkpoint_sequence, checkpoint_digest, record_version,
            store_uuid, store_lease_id, store_owner_epoch, updated_at_unix_ms
        ) VALUES (
            ?1, ?2, X'7b7d', ?3, X'7b7d', ?4, ?5,
            'closing', ?6, ?7, ?8, ?9, NULL, NULL, ?10, ?11, ?12, ?13, 2,
            ?14, ?15, ?16, 20000
        )
        "#,
        params![
            &candidate.channel_id,
            digest("publisher-open-intent"),
            &candidate.open_digest,
            lifecycle_json,
            escrow_json,
            &candidate.final_state_digest,
            i64::try_from(candidate.final_state_sequence)?,
            i64::try_from(candidate.closing_lifecycle.state_version)?,
            i64::try_from(candidate.publisher_fence)?,
            &candidate.closing_channel_head_digest,
            &candidate.closing_escrow_head_digest,
            i64::try_from(candidate.closing_checkpoint_sequence)?,
            &candidate.closing_checkpoint_digest,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    append_fixture_admission_projection(
        fixture,
        &transaction,
        candidate,
        "lifecycle-seed",
        20_000,
    )?;
    transaction.commit()?;
    fixture
        .store
        .serving_owner
        .sync_authority_anchor(&connection)?;
    Ok(())
}

#[test]
fn release_execution_requires_completed_root_and_distinct_submitted_release_slot() -> TestResult {
    let fixture = fixture()?;
    let (candidate, root_operation, release_operation, root_head, release_head) =
        qualified_execution_fixture(&fixture.fence)?;
    qualify_release_execution(
        &candidate,
        &root_operation,
        &release_operation,
        &root_head,
        &release_head,
        &fixture.fence,
    )?;
    let release_slot = economic_effect_slot_from_head(&release_head)?;
    candidate.verify_dispatch_slot(&release_slot)?;

    for mutation in ["slot", "call", "head", "frost", "handoff", "state"] {
        let mut substituted = release_slot.clone();
        match mutation {
            "slot" => substituted.slot_id = digest("substituted-release-slot"),
            "call" => substituted.parameters_digest = digest("substituted-release-call"),
            "head" => substituted.resource_head_digest = digest("substituted-release-head"),
            "frost" => {
                substituted
                    .frost
                    .as_mut()
                    .ok_or("release slot has no FROST binding")?
                    .signed_envelope_digest = digest("substituted-release-envelope");
            }
            "handoff" => {
                substituted.admission_handoff.state =
                    EconomicAdmissionHandoffStateV1::DispatchCommitted;
            }
            "state" => substituted.state = EconomicEffectStateV1::Ready,
            _ => return Err("unknown release slot mutation".into()),
        }
        assert!(candidate.verify_dispatch_slot(&substituted).is_err());
    }

    let mut substituted_root = candidate.clone();
    substituted_root.publication_root = digest("substituted-publication-root");
    assert!(qualify_release_execution(
        &substituted_root,
        &root_operation,
        &release_operation,
        &root_head,
        &release_head,
        &fixture.fence,
    )
    .is_err());

    let mut not_submitted = release_operation.to_persisted();
    not_submitted.state = AdmissionOperationState::MutationReady;
    not_submitted.version = 2;
    let not_submitted = AdmissionOperationV1::from_persisted(not_submitted)?;
    assert!(qualify_release_execution(
        &candidate,
        &root_operation,
        &not_submitted,
        &root_head,
        &release_head,
        &fixture.fence,
    )
    .is_err());

    assert!(qualify_release_execution(
        &candidate,
        &root_operation,
        &release_operation,
        &root_head,
        &root_head,
        &fixture.fence,
    )
    .is_err());
    Ok(())
}

#[test]
fn release_dispatch_requires_exact_durable_slot_and_verified_commit_identity() -> TestResult {
    let fixture = fixture()?;
    let (candidate, _, _, _, release_head) = qualified_execution_fixture(&fixture.fence)?;
    let durable_slot = economic_effect_slot_from_head(&release_head)?;
    let commit_id = digest("publisher-dispatch-commit");
    qualify_exact_dispatch_slot(&candidate, &durable_slot, &durable_slot, &commit_id)?;

    for mutation in ["anchor", "namespace", "target", "request", "handoff"] {
        let mut substituted = durable_slot.clone();
        match mutation {
            "anchor" => substituted.anchor_id = "substituted-anchor".to_owned(),
            "namespace" => substituted.namespace = "substituted-namespace".to_owned(),
            "target" => substituted.target.target_id = "substituted-target".to_owned(),
            "request" => substituted.request.request_id = "substituted-request".to_owned(),
            "handoff" => substituted.admission_handoff.operation_version += 1,
            _ => return Err("unknown exact dispatch mutation".into()),
        }
        assert!(
            qualify_exact_dispatch_slot(&candidate, &durable_slot, &substituted, &commit_id,)
                .is_err()
        );
    }
    assert!(qualify_exact_dispatch_slot(
        &candidate,
        &durable_slot,
        &durable_slot,
        "not-a-commit-id",
    )
    .is_err());
    Ok(())
}

#[test]
fn immediate_claim_has_one_winner_and_exact_replay_has_no_permit() -> TestResult {
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    assert!(fixture
        .store
        .replay_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000)?
        .is_none());
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let store = fixture.store.clone();
        let candidate = candidate.clone();
        let fence = fixture.fence.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let _runtime = chio_kernel::scope_fixed_runtime_for_current_thread(
                30,
                std::iter::empty::<String>(),
            );
            barrier.wait();
            store.claim_candidate_unqualified_for_test(&candidate, &fence, 30_000)
        }));
    }
    barrier.wait();
    let mut claims = Vec::new();
    for thread in threads {
        claims.push(thread.join().map_err(|_| "claim thread panicked")??);
    }
    assert_eq!(
        claims
            .iter()
            .filter(|claim| matches!(claim, ChannelReleasePermitClaimV1::Claimed { .. }))
            .count(),
        1
    );
    assert_eq!(
        claims
            .iter()
            .filter(|claim| matches!(claim, ChannelReleasePermitClaimV1::ExactReplay(_)))
            .count(),
        1
    );
    let retained = fixture
        .store
        .load(&candidate.channel_id)?
        .ok_or("publisher record missing")?;
    assert_eq!(
        retained.status(),
        ChannelReleasePublicationStatusV1::DispatchCommitted
    );
    assert_eq!(
        retained.prepared_call_digest(),
        candidate.prepared_call_digest
    );
    let replayed =
        fixture
            .store
            .replay_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000)?;
    assert_eq!(replayed.as_ref(), Some(&retained));
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(30, std::iter::empty::<String>());
    let ChannelReleasePermitClaimV1::ExactReplay(replayed) = fixture
        .store
        .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 29_999)?
    else {
        return Err("retained publisher record did not replay".into());
    };
    assert_eq!(replayed, retained);
    Ok(())
}

#[test]
fn claim_rejects_substituted_authority_call_and_stale_store_fence() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(30, std::iter::empty::<String>());
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    let claimed =
        fixture
            .store
            .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000)?;
    assert!(matches!(
        claimed,
        ChannelReleasePermitClaimV1::Claimed { .. }
    ));

    for mutation in [
        "reservation_version",
        "close",
        "release",
        "operator",
        "cutoff",
        "frost_slot",
        "publisher_fence",
        "prepared_call",
    ] {
        let mut substituted = candidate.clone();
        match mutation {
            "reservation_version" => substituted.source_escrow_reservation_version += 1,
            "close" => substituted.close_digest = digest("substituted-close"),
            "release" => substituted.release_token_base_units = "499999".to_owned(),
            "operator" => {
                substituted.original_operator =
                    "0x4444444444444444444444444444444444444444".to_owned();
            }
            "cutoff" => substituted.close_submission_cutoff_unix_ms += 1,
            "frost_slot" => substituted.frost_slot_id = digest("substituted-frost-slot"),
            "publisher_fence" => substituted.publisher_fence += 1,
            "prepared_call" => {
                let mut prepared_call: PreparedEvmCall =
                    serde_json::from_slice(&substituted.prepared_call_json)?;
                prepared_call.data = "0xcafebabe".to_owned();
                substituted.prepared_call_json = canonical_json_bytes(&prepared_call)?;
                substituted.prepared_call_digest = sha256_hex(&substituted.prepared_call_json);
            }
            _ => return Err("unknown mutation".into()),
        }
        assert!(matches!(
            fixture.store.claim_candidate_unqualified_for_test(
                &substituted,
                &fixture.fence,
                30_000
            ),
            Err(ChannelReleasePublisherError::Conflict)
                | Err(ChannelReleasePublisherError::Fenced)
                | Err(ChannelReleasePublisherError::Invalid(_))
        ));
    }

    let mut stale_fence = fixture.fence.clone();
    stale_fence.owner_epoch += 1;
    assert!(matches!(
        fixture
            .store
            .claim_candidate_unqualified_for_test(&candidate, &stale_fence, 30_000),
        Err(ChannelReleasePublisherError::Fenced)
    ));
    Ok(())
}

#[test]
fn cutoff_and_nonclosing_durable_state_fail_closed_before_claim() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(50, std::iter::empty::<String>());
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    assert!(matches!(
        fixture.store.claim_candidate_unqualified_for_test(
            &candidate,
            &fixture.fence,
            candidate.close_submission_cutoff_unix_ms,
        ),
        Err(ChannelReleasePublisherError::Fenced)
    ));

    let mut connection = fixture.store.connection()?;
    let transaction = connection.transaction()?;
    transaction.execute(
        "UPDATE channel_lifecycle_records SET lifecycle_state = 'incident', \
         state_version = state_version + 1, lifecycle_fence = lifecycle_fence + 1, \
         record_version = record_version + 1",
        [],
    )?;
    append_fixture_admission_projection(
        &fixture,
        &transaction,
        &candidate,
        "lifecycle-incident",
        30_000,
    )?;
    transaction.commit()?;
    fixture
        .store
        .serving_owner
        .sync_authority_anchor(&connection)?;
    drop(connection);
    assert!(matches!(
        fixture
            .store
            .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000),
        Err(ChannelReleasePublisherError::Fenced)
    ));
    Ok(())
}

#[test]
fn unknown_submission_retains_consumed_permit_and_closing_reservation() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(30, std::iter::empty::<String>());
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    let ChannelReleasePermitClaimV1::Claimed { permit, .. } = fixture
        .store
        .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000)?
    else {
        return Err("first claim did not win".into());
    };
    let unknown = fixture.store.record_submission_unknown(
        &permit,
        "RPC submission outcome is unknown",
        &fixture.fence,
        30_001,
    )?;
    assert_eq!(unknown.status(), ChannelReleasePublicationStatusV1::Unknown);
    let ChannelReleasePermitClaimV1::ExactReplay(replayed) = fixture
        .store
        .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_002)?
    else {
        return Err("unknown publisher record did not replay".into());
    };
    assert_eq!(replayed, unknown);
    assert_eq!(
        fixture.store.replay_candidate_unqualified_for_test(
            &candidate,
            &fixture.fence,
            candidate.escrow_deadline_unix_ms,
        )?,
        Some(unknown.clone())
    );
    let lifecycle_state = fixture.store.connection()?.query_row(
        "SELECT lifecycle_state FROM channel_lifecycle_records WHERE channel_id = ?1",
        [&candidate.channel_id],
        |row| row.get::<_, String>(0),
    )?;
    assert_eq!(lifecycle_state, "closing");
    Ok(())
}

#[test]
fn submitted_record_requires_an_evm_hash_and_replays_exactly() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(30, std::iter::empty::<String>());
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    let ChannelReleasePermitClaimV1::Claimed { permit, .. } = fixture
        .store
        .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000)?
    else {
        return Err("first claim did not win".into());
    };
    assert!(matches!(
        fixture.store.record_submission(
            &permit,
            SubmissionRecord::Submitted("0xabc"),
            &fixture.fence,
            30_001,
        ),
        Err(ChannelReleasePublisherError::Invalid(_))
    ));
    assert_eq!(
        fixture
            .store
            .load(&candidate.channel_id)?
            .ok_or("publisher record missing")?
            .status(),
        ChannelReleasePublicationStatusV1::DispatchCommitted
    );
    let transaction_hash = format!("0x{}", "a".repeat(64));
    let submitted = fixture.store.record_submission(
        &permit,
        SubmissionRecord::Submitted(&transaction_hash),
        &fixture.fence,
        30_001,
    )?;
    let replay = fixture.store.record_submission(
        &permit,
        SubmissionRecord::Submitted(&transaction_hash),
        &fixture.fence,
        30_001,
    )?;
    assert_eq!(submitted, replay);
    assert_eq!(
        submitted.transaction_hash(),
        Some(transaction_hash.as_str())
    );
    assert_eq!(
        fixture.store.replay_candidate_unqualified_for_test(
            &candidate,
            &fixture.fence,
            candidate.escrow_deadline_unix_ms,
        )?,
        Some(submitted)
    );
    Ok(())
}

#[test]
fn startup_quarantines_incomplete_dispatch_without_rebroadcast() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(30, std::iter::empty::<String>());
    let fixture = fixture()?;
    let candidate = candidate()?;
    seed_closing_lifecycle(&fixture, &candidate)?;
    assert!(matches!(
        fixture
            .store
            .claim_candidate_unqualified_for_test(&candidate, &fixture.fence, 30_000,)?,
        ChannelReleasePermitClaimV1::Claimed { .. }
    ));
    let Fixture {
        _temp,
        _database,
        _lock_root,
        _authority,
        store,
        fence: _,
    } = fixture;
    drop(store);
    drop(_authority);

    let reopened = SqliteAuthorityStore::open_serving(&_database, &_lock_root)?;
    let reopened_fence = reopened.mutation_fence();
    let publisher = reopened.channel_release_publisher_store();
    let quarantined = publisher
        .load(&candidate.channel_id)?
        .ok_or("quarantined publisher record missing")?;
    assert_eq!(
        quarantined.status(),
        ChannelReleasePublicationStatusV1::Unknown
    );
    assert_eq!(quarantined.record_version(), 2);
    assert!(
        quarantined.failure_detail().is_some_and(
            |detail| detail.contains("deterministic transaction recovery is unavailable")
        )
    );
    let retained_owner: (String, String, i64) = publisher.connection()?.query_row(
        r#"
        SELECT store_uuid, store_lease_id, store_owner_epoch
        FROM chio_channel_release_publications
        WHERE channel_id = ?1
        "#,
        [&candidate.channel_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(retained_owner.0, reopened_fence.store_uuid);
    assert_eq!(retained_owner.1, reopened_fence.lease_id);
    assert_eq!(u64::try_from(retained_owner.2)?, reopened_fence.owner_epoch);
    let recovery_commits = publisher.connection()?.query_row(
        r#"
        SELECT COUNT(*)
        FROM authority_global_commits
        WHERE mutation_kind = 'channel_release_startup_outcome_unknown'
          AND projection_kind = 'channel_release_publication'
          AND projection_key = ?1 AND projection_sequence = 2
        "#,
        [&candidate.channel_id],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(recovery_commits, 1);
    drop(publisher);
    drop(reopened);

    let reopened_again = SqliteAuthorityStore::open_serving(&_database, &_lock_root)?;
    let publisher = reopened_again.channel_release_publisher_store();
    assert_eq!(
        publisher
            .load(&candidate.channel_id)?
            .ok_or("quarantined publisher record missing after second restart")?
            .record_version(),
        2
    );
    assert_eq!(
        publisher.connection()?.query_row(
            "SELECT COUNT(*) FROM authority_global_commits \
             WHERE mutation_kind = 'channel_release_startup_outcome_unknown' \
               AND projection_key = ?1",
            [&candidate.channel_id],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    drop(_temp);
    Ok(())
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure temp directory: {error}"));
    }
    #[cfg(not(unix))]
    let _ = path;
}
