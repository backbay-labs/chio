use alloc::string::ToString;
use alloc::vec;

use serde_json::json;

use crate::economic_continuity::*;
use crate::{sha256_hex, Keypair};

pub(crate) fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

pub(crate) fn resource_key(resource_id: &str) -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "clearing_round".to_string(),
        scope_id: "tenant-1".to_string(),
        resource_id: resource_id.to_string(),
    }
}

pub(crate) fn inline_content(value: serde_json::Value) -> EconomicContentV1 {
    EconomicContentV1::Inline { value }
}

pub(crate) fn head(
    key: EconomicResourceKeyV1,
    head_version: u64,
    resource_version: u64,
    predecessor_digest: Option<String>,
) -> Result<EconomicResourceHeadV1, EconomicContinuityError> {
    let state = inline_content(json!({
        "resourceId": key.resource_id,
        "resourceVersion": resource_version,
    }));
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        resource_key: key,
        head_version,
        resource_version,
        lifecycle_fence: resource_version,
        lifecycle_state: "open".to_string(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 100 + resource_version,
        predecessor_digest,
    })
}

pub(crate) fn transition(
    next_head: EconomicResourceHeadV1,
    expected_head_digest: Option<String>,
) -> EconomicStateTransitionV1 {
    EconomicStateTransitionV1 {
        resource_key: next_head.resource_key.clone(),
        expected_head_digest,
        next_head,
        transition_proof_digest: digest("transition-proof"),
        prepared_effect: None,
    }
}

pub(crate) fn unsigned_batch(transitions: Vec<EconomicStateTransitionV1>) -> EconomicStateBatchV1 {
    EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_string(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        checkpoint_sequence: 1,
        previous_checkpoint_digest: None,
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
        issued_at: 110,
        signer_key_id: "anchor-key-1".to_string(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    }
}

fn signed_batch(
    transitions: Vec<EconomicStateTransitionV1>,
) -> Result<(EconomicStateBatchV1, Keypair), EconomicContinuityError> {
    let keypair = Keypair::from_seed(&[7; 32]);
    let mut batch = unsigned_batch(transitions);
    batch.seal(&keypair)?;
    Ok((batch, keypair))
}

#[test]
fn signed_batch_round_trips_with_stable_canonical_identity(
) -> Result<(), Box<dyn core::error::Error>> {
    let next = head(resource_key("round-1"), 1, 1, None)?;
    let (batch, keypair) = signed_batch(vec![transition(next, None)])?;

    batch.validate()?;
    batch.verify_signature(&keypair.public_key())?;
    let canonical = batch.canonical_bytes()?;
    let decoded: EconomicStateBatchV1 = serde_json::from_slice(&canonical)?;

    assert_eq!(decoded, batch);
    assert_eq!(decoded.recompute_batch_id()?, batch.batch_id);
    assert_eq!(
        decoded.recompute_checkpoint_digest()?,
        batch.checkpoint_digest
    );

    let mut tampered = decoded;
    let replacement = if tampered.anchor_signature.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered.anchor_signature.replace_range(0..1, replacement);
    tampered.checkpoint_digest = tampered.recompute_checkpoint_digest()?;
    tampered.validate()?;
    assert!(tampered.verify_signature(&keypair.public_key()).is_err());
    Ok(())
}

#[test]
fn batch_rejects_unsorted_duplicate_and_tampered_transitions(
) -> Result<(), Box<dyn core::error::Error>> {
    let first = head(resource_key("round-a"), 1, 1, None)?;
    let second = head(resource_key("round-b"), 1, 1, None)?;
    let (batch, _) = signed_batch(vec![
        transition(first.clone(), None),
        transition(second.clone(), None),
    ])?;

    let mut unsorted = batch.clone();
    unsorted.transitions.swap(0, 1);
    assert!(unsorted.validate().is_err());

    let mut duplicate = unsigned_batch(vec![
        transition(first.clone(), None),
        transition(first, None),
    ]);
    assert!(duplicate.seal(&Keypair::from_seed(&[8; 32])).is_err());

    let mut tampered = batch;
    tampered.transitions[0].next_head.lifecycle_state = "finalized".to_string();
    assert!(tampered.validate().is_err());
    Ok(())
}

#[test]
fn resource_heads_reject_regression_and_wrong_predecessor(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 3, None)?;
    let current_digest = current.digest()?;
    let next = head(resource_key("round-1"), 2, 4, Some(current_digest.clone()))?;
    current.validate_successor(&next)?;

    let mut regressed = next.clone();
    regressed.resource_version = current.resource_version;
    assert!(current.validate_successor(&regressed).is_err());

    let mut wrong_predecessor = next;
    wrong_predecessor.predecessor_digest = Some(digest("wrong"));
    assert!(current.validate_successor(&wrong_predecessor).is_err());
    Ok(())
}

pub(crate) fn ready_effect_slot() -> Result<EconomicEffectSlotV1, EconomicContinuityError> {
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_string(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        resource_key: resource_key("round-1"),
        operation_id: digest("operation-1"),
        effect_kind: "settlement_dispatch".to_string(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("request-namespace"),
            request_id: "request-1".to_string(),
            request_binding_digest: digest("request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: 4,
            lifecycle_fence: 9,
            store_fence: crate::StoreMutationFence {
                store_uuid: "store-1".to_string(),
                lease_id: "lease-1".to_string(),
                owner_epoch: 3,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "settlement-rail".to_string(),
            target_key_epoch: 2,
            qualification_digest: digest("target-qualification"),
        },
        action_digest: digest("action"),
        parameters_digest: digest("parameters"),
        resource_head_digest: digest("resource-head"),
        frost: None,
        idempotency_key: digest("idempotency-key"),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    Ok(slot)
}

#[test]
fn effect_slots_enforce_closed_transition_graph_and_retained_terminal_bytes(
) -> Result<(), Box<dyn core::error::Error>> {
    let ready = ready_effect_slot()?;
    ready.validate()?;

    let mut dispatched = ready.clone();
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    ready.validate_successor(&dispatched)?;

    let result = inline_content(json!({"transactionId": "tx-1"}));
    let mut completed = dispatched.clone();
    completed.state = EconomicEffectStateV1::Completed;
    completed.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: "tx-1".to_string(),
        result_digest: result.digest()?,
        result,
    });
    dispatched.validate_successor(&completed)?;

    let mut skipped = ready.clone();
    skipped.state = EconomicEffectStateV1::Completed;
    skipped.terminal = completed.terminal.clone();
    assert!(ready.validate_successor(&skipped).is_err());

    let mut digest_only = completed.clone();
    digest_only.terminal = None;
    assert!(digest_only.validate().is_err());
    assert!(completed.validate_successor(&dispatched).is_err());
    Ok(())
}

#[test]
fn post_dispatch_no_effect_requires_verified_post_commit_proof(
) -> Result<(), Box<dyn core::error::Error>> {
    let ready = ready_effect_slot()?;
    let mut dispatched = ready.clone();
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    let proof = inline_content(json!({"targetStatus": "not_accepted"}));

    let mut invalid = dispatched.clone();
    invalid.state = EconomicEffectStateV1::NoEffect;
    invalid.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::PreDispatch,
        proof_id: "proof-1".to_string(),
        proof_digest: proof.digest()?,
        proof: proof.clone(),
    });
    assert!(dispatched.validate_successor(&invalid).is_err());

    let mut valid = invalid;
    valid.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
        proof_id: "proof-1".to_string(),
        proof_digest: proof.digest()?,
        proof,
    });
    dispatched.validate_successor(&valid)?;
    Ok(())
}

#[test]
fn permanent_request_replay_mapping_rejects_conflicting_truth(
) -> Result<(), Box<dyn core::error::Error>> {
    let slot = ready_effect_slot()?;
    let retained = EconomicRequestReplayV1 {
        request: slot.request.clone(),
        operation_id: slot.operation_id.clone(),
        effect_slot_ids: vec![slot.slot_id.clone()],
    };
    retained.validate()?;
    retained.ensure_same_replay(&retained.clone())?;

    let mut conflicting = retained.clone();
    conflicting.request.request_binding_digest = digest("different-request");
    assert!(retained.ensure_same_replay(&conflicting).is_err());
    Ok(())
}

#[test]
fn batch_binds_prepared_effect_slot_and_request_replay() -> Result<(), Box<dyn core::error::Error>>
{
    let (mut batch, slot) = unsigned_prepared_effect_batch()?;
    let keypair = Keypair::from_seed(&[9; 32]);
    batch.seal(&keypair)?;
    batch.verify_signature(&keypair.public_key())?;

    let mut predecessor_bound = batch.clone();
    let predecessor_digest = digest("prepared-effect-predecessor");
    predecessor_bound.effect_slots[0].resource_head_digest = predecessor_digest.clone();
    let predecessor_slot = predecessor_bound.effect_slots[0].clone();
    let predecessor_slot_digest = predecessor_slot.digest()?;
    let owner_transition = predecessor_bound
        .transitions
        .iter_mut()
        .find(|transition| transition.prepared_effect.is_some())
        .ok_or("prepared effect owner is missing")?;
    owner_transition.expected_head_digest = Some(predecessor_digest.clone());
    owner_transition.next_head.head_version = 2;
    owner_transition.next_head.predecessor_digest = Some(predecessor_digest);
    owner_transition
        .prepared_effect
        .as_mut()
        .ok_or("prepared effect is missing")?
        .effect_slot_digest = predecessor_slot_digest;
    let slot_transition = predecessor_bound
        .transitions
        .iter_mut()
        .find(|transition| transition.resource_key == predecessor_slot.resource_head_key())
        .ok_or("effect slot transition is missing")?;
    let slot_content = inline_content(serde_json::to_value(&predecessor_slot)?);
    slot_transition.next_head.state_digest = slot_content.digest()?;
    slot_transition.next_head.state = slot_content;
    predecessor_bound.seal(&keypair)?;
    predecessor_bound.verify_signature(&keypair.public_key())?;

    let mut unrelated_bound = predecessor_bound.clone();
    unrelated_bound.effect_slots[0].resource_head_digest = digest("unrelated-resource-head");
    let unrelated_slot = unrelated_bound.effect_slots[0].clone();
    unrelated_bound
        .transitions
        .iter_mut()
        .find_map(|transition| transition.prepared_effect.as_mut())
        .ok_or("prepared effect is missing")?
        .effect_slot_digest = unrelated_slot.digest()?;
    let slot_transition = unrelated_bound
        .transitions
        .iter_mut()
        .find(|transition| transition.resource_key == unrelated_slot.resource_head_key())
        .ok_or("effect slot transition is missing")?;
    let slot_content = inline_content(serde_json::to_value(&unrelated_slot)?);
    slot_transition.next_head.state_digest = slot_content.digest()?;
    slot_transition.next_head.state = slot_content;
    assert!(unrelated_bound.seal(&keypair).is_err());

    let mut already_dispatched = batch.clone();
    already_dispatched.effect_slots[0].state = EconomicEffectStateV1::DispatchCommitted;
    let dispatched_slot = already_dispatched.effect_slots[0].clone();
    already_dispatched.transitions[0]
        .prepared_effect
        .as_mut()
        .ok_or("prepared effect is missing")?
        .effect_slot_digest = dispatched_slot.digest()?;
    let slot_transition = already_dispatched
        .transitions
        .iter_mut()
        .find(|transition| transition.resource_key == dispatched_slot.resource_head_key())
        .ok_or("effect slot transition is missing")?;
    let slot_content = inline_content(serde_json::to_value(&dispatched_slot)?);
    slot_transition.next_head.state_digest = slot_content.digest()?;
    slot_transition.next_head.state = slot_content;
    assert!(already_dispatched.seal(&keypair).is_err());

    let mut duplicate_prepared = batch.clone();
    let mut unowned_slot = slot.clone();
    unowned_slot.effect_kind = "settlement_refund".to_string();
    unowned_slot.slot_id = unowned_slot.recompute_slot_id()?;
    let unowned_content = inline_content(serde_json::to_value(&unowned_slot)?);
    let unowned_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: unowned_slot.anchor_id.clone(),
        namespace: unowned_slot.namespace.clone(),
        resource_key: unowned_slot.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: unowned_content.digest()?,
        state: unowned_content,
        operation_id: Some(unowned_slot.operation_id.clone()),
        effect_idempotency_key: Some(unowned_slot.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 110,
        predecessor_digest: None,
    };
    let mut unowned_transition = transition(unowned_head, None);
    unowned_transition.prepared_effect = duplicate_prepared.transitions[0].prepared_effect.clone();
    duplicate_prepared.transitions.push(unowned_transition);
    duplicate_prepared
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    duplicate_prepared.effect_slots.push(unowned_slot.clone());
    duplicate_prepared
        .effect_slots
        .sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    duplicate_prepared.request_replays[0]
        .effect_slot_ids
        .push(unowned_slot.slot_id);
    duplicate_prepared.request_replays[0]
        .effect_slot_ids
        .sort_unstable();
    assert!(duplicate_prepared.seal(&keypair).is_err());

    let mut wrong_target = batch.clone();
    let owner = wrong_target
        .transitions
        .iter_mut()
        .find(|transition| transition.prepared_effect.is_some())
        .ok_or("prepared effect owner is missing")?;
    owner.resource_key = resource_key("round-2");
    owner.next_head.resource_key = owner.resource_key.clone();
    wrong_target
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    assert!(wrong_target.seal(&keypair).is_err());

    let mut wrong_head = batch.clone();
    wrong_head
        .transitions
        .iter_mut()
        .find(|transition| transition.prepared_effect.is_some())
        .ok_or("prepared effect owner is missing")?
        .next_head
        .trusted_clock_high_water += 1;
    assert!(wrong_head.seal(&keypair).is_err());

    let mut conflicting = batch;
    conflicting.request_replays[0].request.request_id = "request-2".to_string();
    assert!(conflicting.seal(&keypair).is_err());
    Ok(())
}

#[test]
fn composite_prepared_effect_batch_accepts_two_exact_operation_owners(
) -> Result<(), Box<dyn core::error::Error>> {
    let (mut batch, _) = unsigned_prepared_effect_batch()?;
    let mut slot = ready_effect_slot()?;
    slot.resource_key = resource_key("round-2");
    slot.operation_id = digest("operation-2");
    slot.effect_kind = "settlement_refund".to_string();
    slot.request.request_id = "request-2".to_string();
    slot.request.request_binding_digest = digest("request-binding-2");
    slot.action_digest = digest("action-2");
    slot.parameters_digest = digest("parameters-2");
    slot.idempotency_key = digest("idempotency-key-2");
    slot.slot_id = slot.recompute_slot_id()?;

    let mut owner_head = head(resource_key("round-2"), 1, 1, None)?;
    owner_head.operation_id = Some(slot.operation_id.clone());
    owner_head.effect_idempotency_key = Some(slot.idempotency_key.clone());
    slot.resource_head_digest = owner_head.digest()?;
    slot.validate()?;
    let mut owner_transition = transition(owner_head, None);
    owner_transition.prepared_effect = Some(EconomicPreparedEffectV1 {
        operation_id: slot.operation_id.clone(),
        action_digest: slot.action_digest.clone(),
        effect_slot_id: slot.slot_id.clone(),
        effect_slot_digest: slot.digest()?,
        authorization: EconomicActionAuthorizationV1::Direct,
    });
    let slot_content = inline_content(serde_json::to_value(&slot)?);
    let slot_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: slot.anchor_id.clone(),
        namespace: slot.namespace.clone(),
        resource_key: slot.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: slot_content.digest()?,
        state: slot_content,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 110,
        predecessor_digest: None,
    };
    batch.transitions.push(owner_transition);
    batch.transitions.push(transition(slot_head, None));
    batch
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    batch.effect_slots.push(slot.clone());
    batch
        .effect_slots
        .sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    batch.request_replays.push(EconomicRequestReplayV1 {
        request: slot.request.clone(),
        operation_id: slot.operation_id.clone(),
        effect_slot_ids: vec![slot.slot_id.clone()],
    });
    batch.request_replays.sort_by(|left, right| {
        (
            &left.request.request_namespace_digest,
            &left.request.request_id,
        )
            .cmp(&(
                &right.request.request_namespace_digest,
                &right.request.request_id,
            ))
    });
    batch.operation_id = None;

    let keypair = Keypair::from_seed(&[17; 32]);
    batch.seal(&keypair)?;
    batch.verify_signature(&keypair.public_key())?;
    let canonical = batch.canonical_bytes()?;
    assert_eq!(
        serde_json::from_slice::<EconomicStateBatchV1>(&canonical)?,
        batch
    );

    let mut terminal_mix = batch.clone();
    let result = inline_content(json!({"status": "completed"}));
    let terminal_transition = terminal_mix
        .transitions
        .iter_mut()
        .find(|transition| transition.prepared_effect.is_some())
        .ok_or("prepared effect owner is missing")?;
    terminal_transition.next_head.lifecycle_state = "completed".to_string();
    terminal_transition.next_head.terminal_result = Some(EconomicTerminalResultV1 {
        result_id: "terminal-result".to_string(),
        result_digest: result.digest()?,
        result,
    });
    assert!(terminal_mix.seal(&keypair).is_err());

    let (mut single_owner, _) = unsigned_prepared_effect_batch()?;
    single_owner.operation_id = None;
    assert!(single_owner.seal(&keypair).is_err());

    let mut stray_owner = batch;
    stray_owner.request_replays[0].operation_id = digest("operation-3");
    assert!(stray_owner.seal(&keypair).is_err());
    Ok(())
}

pub(crate) fn unsigned_prepared_effect_batch(
) -> Result<(EconomicStateBatchV1, EconomicEffectSlotV1), Box<dyn core::error::Error>> {
    let mut slot = ready_effect_slot()?;
    let operation_id = slot.operation_id.clone();
    let idempotency_key = slot.idempotency_key.clone();
    let mut resource_head = head(slot.resource_key.clone(), 1, 1, None)?;
    resource_head.operation_id = Some(operation_id.clone());
    resource_head.effect_idempotency_key = Some(slot.idempotency_key.clone());
    slot.resource_head_digest = resource_head.digest()?;
    slot.validate()?;
    let slot_content = inline_content(serde_json::to_value(&slot)?);
    let slot_key = slot.resource_head_key();
    let slot_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: slot.anchor_id.clone(),
        namespace: slot.namespace.clone(),
        resource_key: slot_key,
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: slot_content.digest()?,
        state: slot_content,
        operation_id: Some(operation_id.clone()),
        effect_idempotency_key: Some(idempotency_key),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 110,
        predecessor_digest: None,
    };
    let prepared = EconomicPreparedEffectV1 {
        operation_id: operation_id.clone(),
        action_digest: slot.action_digest.clone(),
        effect_slot_id: slot.slot_id.clone(),
        effect_slot_digest: slot.digest()?,
        authorization: EconomicActionAuthorizationV1::Direct,
    };
    let mut resource_transition = transition(resource_head, None);
    resource_transition.prepared_effect = Some(prepared);
    let mut batch = unsigned_batch(vec![resource_transition, transition(slot_head, None)]);
    batch.operation_id = Some(operation_id.clone());
    batch.effect_slots = vec![slot.clone()];
    batch.request_replays = vec![EconomicRequestReplayV1 {
        request: slot.request.clone(),
        operation_id,
        effect_slot_ids: vec![slot.slot_id.clone()],
    }];
    Ok((batch, slot))
}

#[test]
fn unknown_fields_and_unknown_versions_fail_closed() -> Result<(), Box<dyn core::error::Error>> {
    let next = head(resource_key("round-1"), 1, 1, None)?;
    let (batch, _) = signed_batch(vec![transition(next, None)])?;
    let mut value = serde_json::to_value(batch)?;
    value["schema"] = json!("chio.economy.state-batch.v9");
    let decoded: EconomicStateBatchV1 = serde_json::from_value(value)?;
    assert!(decoded.validate().is_err());

    let mut value = serde_json::to_value(decoded)?;
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<EconomicStateBatchV1>(value).is_err());
    Ok(())
}

#[test]
fn wire_schemas_accept_canonical_values_and_reject_one_field_tampering(
) -> Result<(), Box<dyn core::error::Error>> {
    let next = head(resource_key("round-1"), 1, 1, None)?;
    let slot = ready_effect_slot()?;
    let (batch, _) = signed_batch(vec![transition(next.clone(), None)])?;
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .canonicalize()?;

    let resource_validator = schema_validator(&root, "resource-head.v1.json")?;
    let effect_validator = schema_validator(&root, "effect-slot.v1.json")?;
    let batch_validator = schema_validator(&root, "state-batch.v1.json")?;
    let resource_json = serde_json::to_value(next)?;
    let effect_json = serde_json::to_value(slot)?;
    let batch_json = serde_json::to_value(batch)?;
    assert!(resource_validator.is_valid(&resource_json));
    assert!(effect_validator.is_valid(&effect_json));
    assert!(batch_validator.is_valid(&batch_json));

    let mut tampered_resource = resource_json;
    tampered_resource["resourceVersion"] = json!(0);
    assert!(!resource_validator.is_valid(&tampered_resource));
    let mut tampered_effect = effect_json;
    tampered_effect["state"] = json!("future_state");
    assert!(!effect_validator.is_valid(&tampered_effect));
    let mut unknown_batch = batch_json;
    unknown_batch["schema"] = json!("chio.economy.state-batch.v9");
    assert!(!batch_validator.is_valid(&unknown_batch));
    Ok(())
}

pub(crate) fn schema_validator(
    root: &std::path::Path,
    name: &str,
) -> Result<jsonschema::Validator, Box<dyn core::error::Error>> {
    let mut schemas = std::collections::BTreeMap::new();
    for schema_name in [
        "resource-head.v1.json",
        "effect-slot.v1.json",
        "state-batch.v1.json",
        "anchor-view.v1.json",
        "effect-dispatch-commit.v1.json",
    ] {
        let schema: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(schema_name))?)?;
        let schema_id = schema
            .get("$id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("schema {schema_name} has no $id"))?;
        schemas.insert(schema_id.to_string(), schema);
    }
    let schema_id = match name {
        "resource-head.v1.json" => {
            "https://chio-protocol.dev/schemas/chio-economy/resource-head/v1"
        }
        "effect-slot.v1.json" => "https://chio-protocol.dev/schemas/chio-economy/effect-slot/v1",
        "state-batch.v1.json" => "https://chio-protocol.dev/schemas/chio-economy/state-batch/v1",
        "anchor-view.v1.json" => "https://chio-protocol.dev/schemas/chio-economy/anchor-view/v1",
        "effect-dispatch-commit.v1.json" => {
            "https://chio-protocol.dev/schemas/chio-economy/effect-dispatch-commit/v1"
        }
        _ => return Err(format!("unsupported economic schema {name}").into()),
    };
    let schema = schemas
        .get(schema_id)
        .ok_or_else(|| format!("schema {name} was not loaded"))?;
    Ok(jsonschema::options()
        .with_retriever(EconomicSchemaRetriever {
            schemas: schemas.clone(),
        })
        .build(schema)?)
}

#[derive(Clone)]
struct EconomicSchemaRetriever {
    schemas: std::collections::BTreeMap<String, serde_json::Value>,
}

impl jsonschema::Retrieve for EconomicSchemaRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn core::error::Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("schema not found: {uri}").into())
    }
}
