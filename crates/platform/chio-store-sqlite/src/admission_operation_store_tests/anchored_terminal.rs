use super::*;

fn economic_pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
    }
}

fn economic_key(request_id: &str) -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "admission_projection".to_owned(),
        scope_id: "test".to_owned(),
        resource_id: request_id.to_owned(),
    }
}

fn dispatched_effect_slot(
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
) -> AnchoredTestResult<EconomicEffectSlotV1> {
    let binding = operation.binding();
    let dispatch_commit = operation
        .dispatch_commit()
        .ok_or("anchored operation omitted its dispatch commit")?;
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: economic_digest("pending-effect-slot"),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: economic_key(binding.request_id().as_str()),
        operation_id: binding.operation_id().as_str().to_owned(),
        effect_kind: "admission_terminal_projection".to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: binding.request_namespace_digest().as_str().to_owned(),
            request_id: binding.request_id().as_str().to_owned(),
            request_binding_digest: binding.request_binding_hash().as_str().to_owned(),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: dispatch_commit.committed_version,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        },
        target: EconomicEffectTargetV1 {
            target_id: "admission-terminal-store".to_owned(),
            target_key_epoch: 1,
            qualification_digest: economic_digest("admission-terminal-qualification"),
        },
        action_digest: economic_digest("admission-terminal-action"),
        parameters_digest: binding.action_parameter_hash().as_str().to_owned(),
        resource_head_digest: economic_digest("admission-terminal-resource"),
        frost: None,
        idempotency_key: economic_digest("admission-terminal-idempotency"),
        state: EconomicEffectStateV1::DispatchCommitted,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
    Ok(slot)
}

fn effect_head(
    slot: &EconomicEffectSlotV1,
    version: u64,
    predecessor_digest: Option<String>,
) -> AnchoredTestResult<EconomicResourceHeadV1> {
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
    let state_digest = state.digest()?;
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: slot.resource_head_key(),
        head_version: version,
        resource_version: version,
        lifecycle_fence: version,
        lifecycle_state: if slot.state == EconomicEffectStateV1::Completed {
            "completed".to_owned()
        } else {
            "dispatch_committed".to_owned()
        },
        state_digest,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: slot.frost.clone(),
        terminal_result,
        trusted_clock_high_water: 100 + version,
        predecessor_digest,
    })
}

fn economic_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    heads: Vec<EconomicResourceHeadV1>,
    absent_resource_keys: Vec<EconomicResourceKeyV1>,
) -> AnchoredTestResult<EconomicStateAnchorViewV1> {
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: 100 + checkpoint_sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[0x41; 32]))?;
    Ok(view)
}

struct DirectEconomicTransitionVerifier;

impl EconomicTransitionProofVerifier for DirectEconomicTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

fn economic_advance(
    operation: &AdmissionOperationV1,
    envelope: &SignedAdmissionTerminalProjectionV1,
) -> AnchoredTestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let verified = envelope.verify()?;
    let dispatched_slot = dispatched_effect_slot(operation, &verified.context().store_fence)?;
    let dispatched_head = effect_head(&dispatched_slot, 1, None)?;
    let dispatched_digest = dispatched_head.digest()?;
    let resource_key = dispatched_slot.resource_head_key();
    let mut completed_slot = dispatched_slot;
    completed_slot.state = EconomicEffectStateV1::Completed;
    completed_slot.terminal = Some(admission_terminal_projection_effect_result(envelope)?);
    completed_slot.validate()?;
    let completed_head = effect_head(&completed_slot, 2, Some(dispatched_digest.clone()))?;
    let current = verify_economic_state_view(
        economic_view(
            1,
            economic_digest("anchored-checkpoint-1"),
            vec![dispatched_head],
            Vec::new(),
        )?,
        &economic_pins(),
    )?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key,
            expected_head_digest: Some(dispatched_digest),
            next_head: completed_head.clone(),
            transition_proof_digest: economic_digest("anchored-transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(operation.binding().operation_id().as_str().to_owned()),
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(
        &current,
        batch,
        &economic_pins(),
        &DirectEconomicTransitionVerifier,
    )?;
    let committed = verify_economic_state_view(
        economic_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![completed_head],
            Vec::new(),
        )?,
        &economic_pins(),
    )?;
    Ok((advance, committed))
}

fn signed_unknown_projection(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    signer: &Keypair,
    incident_id: &str,
    at: u64,
) -> AnchoredTestResult<(AdmissionRecoveryLease, SignedAdmissionTerminalProjectionV1)> {
    let claimant = format!("kernel:{}", signer.public_key().to_hex());
    let lease = claim(fixture, operation, &claimant, at);
    let envelope =
        signed_unknown_projection_for_lease(fixture, operation, signer, &lease, incident_id, at)?;
    Ok((lease, envelope))
}

fn signed_unknown_projection_for_lease(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    signer: &Keypair,
    lease: &AdmissionRecoveryLease,
    incident_id: &str,
    at: u64,
) -> AnchoredTestResult<SignedAdmissionTerminalProjectionV1> {
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at + 1,
        coordinator_lease_id: lease.coordinator_lease_id().clone(),
        coordinator_lease_epoch: lease.coordinator_lease_epoch(),
        store_fence: lease.store_fence().clone(),
    };
    let incident = AdmissionIncident::from_verified(
        operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", incident_id),
        digest("incident_digest", 'e'),
    )?;
    let projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    };
    Ok(SignedAdmissionTerminalProjectionV1::from_verified(
        operation,
        &projection,
        &fixture.store.admission_projection_capabilities(),
        signer,
    )?)
}

fn stage_anchor_advanced_projection(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    envelope: &SignedAdmissionTerminalProjectionV1,
    at: u64,
) -> AnchoredTestResult<String> {
    let (advance, committed) = economic_advance(operation, envelope)?;
    let cache = fixture.authority.economic_state_cache();
    let store: &dyn AnchoredAdmissionProjectionStore = &fixture.store;
    store.stage_anchored_terminal_projection(&advance, lease, envelope, &fixture.fence, at)?;
    cache.record_anchor_advanced(
        &advance,
        &committed,
        &economic_pins(),
        &fixture.fence,
        at + 1,
    )?;
    Ok(advance.batch().batch_id.clone())
}

#[test]
fn anchored_terminal_projection_commits_both_local_projections_and_replays() -> AnchoredTestResult {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-projection",
        "capability-anchored-projection",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-projection-incident",
        begun_at + 20_000,
    )?;
    let batch_id = stage_anchor_advanced_projection(
        &fixture,
        &operation,
        &lease,
        &envelope,
        begun_at + 20_002,
    )?;
    assert!(matches!(
        fixture.authority.economic_state_cache().finalize_stage(
            &batch_id,
            &fixture.fence,
            begun_at + 20_004,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));

    let terminal = AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
        &fixture.store,
        &batch_id,
        &fixture.fence,
        begun_at + 20_004,
    )?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
            &fixture.store,
            &batch_id,
            &fixture.fence,
            begun_at + 20_005,
        )?,
        terminal
    );
    let cache = fixture.authority.economic_state_cache();
    let finalized = cache
        .load_stage(&batch_id)?
        .ok_or("anchored finalization omitted its retained stage")?;
    assert_eq!(finalized.status(), EconomicStateStageStatus::DbFinalized);
    assert!(cache
        .load_finalized_head(
            &dispatched_effect_slot(&operation, &fixture.fence)?.resource_head_key()
        )?
        .is_some());
    Ok(())
}

#[test]
fn anchored_terminal_projection_rolls_back_both_local_projections_on_failure() -> AnchoredTestResult
{
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-rollback",
        "capability-anchored-rollback",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-rollback-incident",
        begun_at + 20_000,
    )?;
    let batch_id = stage_anchor_advanced_projection(
        &fixture,
        &operation,
        &lease,
        &envelope,
        begun_at + 20_002,
    )?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            r#"
                CREATE TEMP TRIGGER fail_anchored_projection_finalize
                BEFORE INSERT ON economic_state_stage_heads
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected anchored projection rollback');
                END;
                "#,
        )?;
    }

    assert!(
        AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
            &fixture.store,
            &batch_id,
            &fixture.fence,
            begun_at + 20_004,
        )
        .is_err()
    );
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER fail_anchored_projection_finalize")?;
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation.clone())
    );
    let cache = fixture.authority.economic_state_cache();
    let staged = cache
        .load_stage(&batch_id)?
        .ok_or("anchored rollback lost its retained stage")?;
    assert_eq!(
        staged.status(),
        EconomicStateStageStatus::EconomicAnchorAdvanced
    );
    assert!(cache
        .load_finalized_head(
            &dispatched_effect_slot(&operation, &fixture.fence)?.resource_head_key()
        )?
        .is_none());

    AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
        &fixture.store,
        &batch_id,
        &fixture.fence,
        begun_at + 20_005,
    )?;
    Ok(())
}

#[test]
fn anchored_terminal_projection_reconciles_a_prematurely_finalized_stage() -> AnchoredTestResult {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-db-finalized",
        "capability-anchored-db-finalized",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-db-finalized-incident",
        begun_at + 20_000,
    )?;
    let batch_id = stage_anchor_advanced_projection(
        &fixture,
        &operation,
        &lease,
        &envelope,
        begun_at + 20_002,
    )?;
    {
        let mut connection = fixture.store.connection()?;
        let transaction = connection.transaction()?;
        crate::economic_state_cache::finalize_stage_in_transaction(
            &transaction,
            &batch_id,
            &fixture.store.serving_owner,
            begun_at + 20_004,
        )?;
        transaction.commit()?;
        fixture
            .store
            .serving_owner
            .sync_authority_anchor(&connection)?;
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    let retained = fixture
        .authority
        .economic_state_cache()
        .load_stage(&batch_id)?
        .ok_or("premature finalization lost its retained stage")?;
    assert_eq!(retained.status(), EconomicStateStageStatus::DbFinalized);

    let terminal = AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
        &fixture.store,
        &batch_id,
        &fixture.fence,
        begun_at + 20_005,
    )?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    Ok(())
}

#[test]
fn anchored_terminal_projection_rejects_descriptor_substitution() -> AnchoredTestResult {
    let fixture = fixture();
    let begun_at = now_ms();
    let substitute_operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-substitute",
        "capability-anchored-substitute",
        begun_at,
    );
    let substitute_signer = Keypair::generate();
    let (substitute_lease, substitute) = signed_unknown_projection(
        &fixture,
        &substitute_operation,
        &substitute_signer,
        "anchored-substitute-incident",
        begun_at + 20_000,
    )?;
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-original",
        "capability-anchored-original",
        begun_at + 30_000,
    );
    let signer = Keypair::generate();
    let (_lease, _envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-original-incident",
        begun_at + 50_000,
    )?;
    let (advance, _) = economic_advance(&operation, &substitute)?;
    assert!(matches!(
        AnchoredAdmissionProjectionStore::stage_anchored_terminal_projection(
            &fixture.store,
            &advance,
            &substitute_lease,
            &substitute,
            &fixture.fence,
            begun_at + 50_002,
        ),
        Err(ReceiptStoreError::Conflict(_))
    ));
    let cache = fixture.authority.economic_state_cache();
    assert!(cache.load_stage(&advance.batch().batch_id)?.is_none());
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn anchored_terminal_projection_rejects_effect_record_substitution_at_staging() -> AnchoredTestResult
{
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-record-substitute",
        "capability-anchored-record-substitute",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-record-original",
        begun_at + 20_000,
    )?;
    let substituted = signed_unknown_projection_for_lease(
        &fixture,
        &operation,
        &signer,
        &lease,
        "anchored-record-substituted",
        begun_at + 20_000,
    )?;
    let (advance, _) = economic_advance(&operation, &envelope)?;
    assert!(matches!(
        AnchoredAdmissionProjectionStore::stage_anchored_terminal_projection(
            &fixture.store,
            &advance,
            &lease,
            &substituted,
            &fixture.fence,
            begun_at + 20_002,
        ),
        Err(ReceiptStoreError::Conflict(_))
    ));
    let cache = fixture.authority.economic_state_cache();
    assert!(cache.load_stage(&advance.batch().batch_id)?.is_none());
    Ok(())
}

#[test]
fn anchored_terminal_projection_rejects_a_stale_serving_fence() -> AnchoredTestResult {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-stale-fence",
        "capability-anchored-stale-fence",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-stale-fence-incident",
        begun_at + 20_000,
    )?;
    let batch_id = stage_anchor_advanced_projection(
        &fixture,
        &operation,
        &lease,
        &envelope,
        begun_at + 20_002,
    )?;
    let mut stale_fence = fixture.fence.clone();
    stale_fence.owner_epoch += 1;

    assert!(matches!(
        AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
            &fixture.store,
            &batch_id,
            &stale_fence,
            begun_at + 20_004,
        ),
        Err(ReceiptStoreError::Fenced)
    ));
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    let retained = fixture
        .authority
        .economic_state_cache()
        .load_stage(&batch_id)?
        .ok_or("stale fence rejection lost its retained stage")?;
    assert_eq!(
        retained.status(),
        EconomicStateStageStatus::EconomicAnchorAdvanced
    );
    Ok(())
}

#[test]
fn anchored_terminal_projection_survives_expiry_and_same_store_owner_takeover() -> AnchoredTestResult
{
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-anchored-owner-takeover",
        "capability-anchored-owner-takeover",
        begun_at,
    );
    let signer = Keypair::generate();
    let (lease, envelope) = signed_unknown_projection(
        &fixture,
        &operation,
        &signer,
        "anchored-owner-takeover-incident",
        begun_at + 20_000,
    )?;
    let (advance, committed) = economic_advance(&operation, &envelope)?;
    AnchoredAdmissionProjectionStore::stage_anchored_terminal_projection(
        &fixture.store,
        &advance,
        &lease,
        &envelope,
        &fixture.fence,
        begun_at + 20_002,
    )?;
    assert!(matches!(
        fixture
            .authority
            .economic_state_cache()
            .discard_unanchored_stage(
                &advance.batch().batch_id,
                "generic terminal discard must fail closed",
                &fixture.fence,
                begun_at + 20_003,
            ),
        Err(EconomicStateCacheError::Conflict)
    ));
    assert!(matches!(
        fixture.store.commit_signed_terminal_projection(&envelope),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    {
        let mut connection = fixture.store.connection()?;
        let transaction = fixture
            .store
            .begin_write(&mut connection, Some(&fixture.fence))?;
        assert!(matches!(
            append_participant_update_tx(
                &transaction,
                &fixture.store.serving_owner,
                &operation,
                &lease,
                &economic_digest("late-participant-update"),
                begun_at + 20_003,
            ),
            Err(AdmissionOperationStoreError::Fenced)
        ));
    }

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

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let second_fence = second.mutation_fence();
    assert_eq!(second_fence.store_uuid, first_fence.store_uuid);
    assert!(second_fence.owner_epoch > first_fence.owner_epoch);
    let second_store = second.admission_operation_store();
    let expired_at = begun_at + 30_000;
    assert!(matches!(
        second_store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", "replacement-worker"),
            expired_at + 1,
            expired_at + 10_000,
            &second_fence,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));

    let later = prepared_operation(
        &second_fence,
        AdmissionOperationKind::ToolDispatch,
        "request-later-high-water",
        "capability-later-high-water",
    );
    second_store.begin(&later, &second_fence, expired_at + 2)?;
    let cache = second.economic_state_cache();
    cache.record_anchor_advanced(
        &advance,
        &committed,
        &economic_pins(),
        &second_fence,
        expired_at + 3,
    )?;
    AnchoredAdmissionProjectionStore::qualify_anchored_terminal_projection(
        &second_store,
        &advance.batch().batch_id,
        &second_fence,
        expired_at + 4,
    )?;
    let terminal = AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
        &second_store,
        &advance.batch().batch_id,
        &second_fence,
        expired_at + 5,
    )?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        AnchoredAdmissionProjectionStore::commit_anchored_terminal_projection(
            &second_store,
            &advance.batch().batch_id,
            &second_fence,
            expired_at + 6,
        )?,
        terminal
    );
    let connection = second_store.connection()?;
    let (
        updated_at,
        high_water,
        owner_epoch,
        recorded_at,
        projection_committed_at,
        projection_owner_epoch,
    ): (i64, i64, i64, i64, i64, i64) = connection.query_row(
        r#"
            SELECT
                (SELECT updated_at_unix_ms FROM admission_operations
                 WHERE operation_id = ?1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                (SELECT store_owner_epoch FROM admission_operation_commits
                 WHERE operation_id = ?1 ORDER BY commit_sequence DESC LIMIT 1),
                (SELECT recorded_at_unix_ms FROM admission_operation_commits
                 WHERE operation_id = ?1 ORDER BY commit_sequence DESC LIMIT 1),
                (SELECT committed_at_unix_ms
                 FROM admission_operation_terminal_projections WHERE operation_id = ?1),
                (SELECT store_owner_epoch
                 FROM admission_operation_terminal_projections WHERE operation_id = ?1)
            "#,
        [operation.binding().operation_id().as_str()],
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
    assert_eq!(updated_at, i64::try_from(expired_at + 5)?);
    assert_eq!(high_water, i64::try_from(expired_at + 5)?);
    assert_eq!(owner_epoch, i64::try_from(second_fence.owner_epoch)?);
    assert_eq!(recorded_at, updated_at);
    assert_eq!(projection_committed_at, updated_at);
    assert_eq!(projection_owner_epoch, owner_epoch);
    let signed_decision_time = i64::try_from(envelope.verify()?.context().trusted_time_unix_ms)?;
    assert_ne!(projection_committed_at, signed_decision_time);
    Ok(())
}

#[test]
fn receipt_lookup_rejects_records_outside_the_terminal_manifest() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = finalizing_tool_operation(
        &fixture,
        "request-forged-receipt",
        "capability-forged-receipt",
        begun_at,
    );
    fixture
        .store
        .commit_terminal_projection(&unknown_projection(
            &fixture,
            &operation,
            "projection-forged-receipt-incident",
            'e',
            begun_at + 20,
        ))
        .expect("commit terminal projection");

    let connection = fixture.store.connection().expect("connection");
    connection
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_records (
                operation_id, record_kind, record_id, record_digest, record_json
            ) VALUES (?1, 'receipt', 'forged-receipt', ?2, X'7B7D')
            "#,
            params![operation.binding().operation_id().as_str(), "a".repeat(64),],
        )
        .expect("inject out-of-manifest record");
    drop(connection);

    assert!(matches!(
        fixture.store.load_chio_receipt("forged-receipt"),
        Err(ReceiptStoreError::Conflict(detail))
            if detail.contains("record count differs from its manifest")
    ));
}
