use super::*;

fn sha(value: &[u8]) -> String {
    sha256_hex(value)
}

fn attempt() -> ProviderAttemptBindingV1 {
    ProviderAttemptBindingV1 {
        operation_id: sha(b"operation"),
        attempt_id: "attempt-1".to_string(),
        transport_id: "qualified-provider".to_string(),
        transport_key_epoch: 7,
    }
}

fn blob() -> ProviderInvocationBlobBindingV1 {
    ProviderInvocationBlobBindingV1 {
        schema: PROVIDER_INVOCATION_BLOB_SCHEMA.to_string(),
        attempt: attempt(),
        request_digest: sha(b"request"),
        idempotency_key: sha(b"operation"),
        blob_ref: "cas://invocation".to_string(),
        blob_sha256: sha(b"invocation"),
        blob_size_bytes: 10,
        availability_ref: "anchor://availability".to_string(),
        availability_sha256: sha(b"availability"),
    }
}

fn acceptance() -> ProviderAcceptanceBindingV1 {
    ProviderAcceptanceBindingV1 {
        schema: PROVIDER_ACCEPTANCE_SCHEMA.to_string(),
        attempt: attempt(),
        acceptance_ref: "provider://accepted".to_string(),
        accepted_at: 20,
        cancellation_fence: 4,
        invocation_blob_digest: blob().digest().unwrap(),
        acceptance_envelope_sha256: sha(b"accepted"),
        acceptance_envelope_size_bytes: 8,
    }
}

fn lease() -> ProviderExecutionLeaseBindingV1 {
    ProviderExecutionLeaseBindingV1 {
        schema: PROVIDER_EXECUTION_LEASE_SCHEMA.to_string(),
        attempt: attempt(),
        lease_id: "lease-1".to_string(),
        executor_id: "worker-1".to_string(),
        lease_epoch: 2,
        execution_fence: 5,
        invocation_blob_digest: blob().digest().unwrap(),
        acceptance_digest: acceptance().digest().unwrap(),
        acquired_at: 21,
        expires_at: 40,
    }
}

fn cancellation() -> ProviderCancellationBindingV1 {
    ProviderCancellationBindingV1 {
        schema: PROVIDER_CANCELLATION_SCHEMA.to_string(),
        attempt: attempt(),
        cancellation_ref: "provider://cancelled".to_string(),
        cancelled_at: 20,
        cancellation_fence: 4,
        invocation_blob_digest: blob().digest().unwrap(),
        no_acceptance_proof_sha256: sha(b"cancelled"),
        no_acceptance_proof_size_bytes: 9,
    }
}

fn completion() -> ProviderCompletionBindingV1 {
    ProviderCompletionBindingV1 {
        schema: PROVIDER_COMPLETION_SCHEMA.to_string(),
        attempt: attempt(),
        tool_outcome_ref: "provider://outcome".to_string(),
        completed_at: 30,
        invocation_blob_digest: blob().digest().unwrap(),
        acceptance_digest: acceptance().digest().unwrap(),
        execution_lease_digest: lease().digest().unwrap(),
        outcome_sha256: sha(b"outcome"),
        outcome_size_bytes: 7,
        cost_units: 12,
        currency: "USD".to_string(),
        terminal_evidence_sha256: sha(b"terminal"),
        terminal_evidence_size_bytes: 8,
    }
}

fn checkpoint(
    sequence: u64,
    previous: Option<&ProviderAttemptCheckpointV1>,
    phase: ProviderAttemptPhaseV1,
) -> ProviderAttemptCheckpointV1 {
    ProviderAttemptCheckpointV1 {
        schema: PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA.to_string(),
        attempt: attempt(),
        checkpoint_sequence: sequence,
        previous_checkpoint_digest: previous.map(|value| value.digest().unwrap()),
        phase,
    }
}

fn lifecycle() -> Vec<ProviderAttemptCheckpointV1> {
    let pending = checkpoint(
        1,
        None,
        ProviderAttemptPhaseV1::Pending {
            invocation_blob: blob(),
        },
    );
    let accepted = checkpoint(
        2,
        Some(&pending),
        ProviderAttemptPhaseV1::Accepted {
            invocation_blob: blob(),
            acceptance: acceptance(),
        },
    );
    let executing = checkpoint(
        3,
        Some(&accepted),
        ProviderAttemptPhaseV1::Executing {
            invocation_blob: blob(),
            acceptance: acceptance(),
            execution_lease: lease(),
        },
    );
    let completed = checkpoint(
        4,
        Some(&executing),
        ProviderAttemptPhaseV1::Completed {
            invocation_blob: blob(),
            acceptance: acceptance(),
            execution_lease: lease(),
            completion: Box::new(completion()),
        },
    );
    vec![pending, accepted, executing, completed]
}

#[test]
fn canonical_digests_are_stable_and_domain_separated() {
    let lifecycle = lifecycle();
    let encoded = serde_json::to_vec(&lifecycle[0]).unwrap();
    let decoded: ProviderAttemptCheckpointV1 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(lifecycle[0].digest().unwrap(), decoded.digest().unwrap());
    assert_ne!(blob().digest().unwrap(), acceptance().digest().unwrap());
    assert_ne!(acceptance().digest().unwrap(), lease().digest().unwrap());
}

#[test]
fn exact_lifecycle_and_cancel_branch_validate() {
    let lifecycle = lifecycle();
    validate_provider_checkpoint_chain(None, &lifecycle).unwrap();

    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    validate_provider_checkpoint_transition(&lifecycle[0], &cancelled).unwrap();
}

#[test]
fn every_other_transition_is_rejected() {
    let lifecycle = lifecycle();
    let phases = lifecycle
        .iter()
        .map(|checkpoint| checkpoint.phase.clone())
        .chain(core::iter::once(ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        }))
        .collect::<Vec<_>>();
    for (from_index, from) in phases.iter().enumerate() {
        for (to_index, to) in phases.iter().enumerate() {
            let previous = checkpoint(1, None, from.clone());
            if previous.validate().is_err() {
                continue;
            }
            let next = checkpoint(2, Some(&previous), to.clone());
            let expected = matches!(
                (from.state(), to.state()),
                (
                    ProviderAttemptState::Pending,
                    ProviderAttemptState::Accepted
                ) | (
                    ProviderAttemptState::Pending,
                    ProviderAttemptState::Cancelled
                ) | (
                    ProviderAttemptState::Accepted,
                    ProviderAttemptState::Executing
                ) | (
                    ProviderAttemptState::Executing,
                    ProviderAttemptState::Completed
                )
            );
            assert_eq!(
                validate_provider_checkpoint_transition(&previous, &next).is_ok(),
                expected,
                "transition {from_index}->{to_index}"
            );
        }
    }
}

#[test]
fn checkpoint_and_nested_binding_substitution_fail() {
    let mut substituted_chain = lifecycle();
    substituted_chain[1].attempt.attempt_id = "substituted".to_string();
    assert!(validate_provider_checkpoint_chain(None, &substituted_chain).is_err());

    let mut accepted = lifecycle()[1].clone();
    if let ProviderAttemptPhaseV1::Accepted { acceptance, .. } = &mut accepted.phase {
        acceptance.attempt.transport_key_epoch += 1;
    }
    assert!(accepted.validate().is_err());
}

#[test]
fn predecessor_sequence_and_immutable_payload_changes_fail() {
    let lifecycle = lifecycle();
    let mut wrong_predecessor = lifecycle[1].clone();
    wrong_predecessor.previous_checkpoint_digest = Some(sha(b"wrong"));
    assert!(validate_provider_checkpoint_transition(&lifecycle[0], &wrong_predecessor).is_err());

    let mut skipped = lifecycle[1].clone();
    skipped.checkpoint_sequence = 3;
    assert!(validate_provider_checkpoint_transition(&lifecycle[0], &skipped).is_err());

    let mut changed = lifecycle[2].clone();
    if let ProviderAttemptPhaseV1::Executing {
        invocation_blob, ..
    } = &mut changed.phase
    {
        invocation_blob.blob_ref = "cas://other".to_string();
    }
    changed.previous_checkpoint_digest = Some(lifecycle[1].digest().unwrap());
    assert!(validate_provider_checkpoint_transition(&lifecycle[1], &changed).is_err());
}

#[test]
fn cancellation_and_execution_fences_are_enforced() {
    let mut weak = lifecycle()[2].clone();
    if let ProviderAttemptPhaseV1::Executing {
        execution_lease, ..
    } = &mut weak.phase
    {
        execution_lease.execution_fence = acceptance().cancellation_fence;
    }
    assert!(weak.validate().is_err());

    let mut late = lifecycle()[3].clone();
    if let ProviderAttemptPhaseV1::Completed { completion, .. } = &mut late.phase {
        completion.completed_at = lease().expires_at;
    }
    assert!(late.validate().is_err());

    let mut unfenced_cancellation = cancellation();
    unfenced_cancellation.cancellation_fence = 0;
    assert!(unfenced_cancellation.validate().is_err());
}

#[test]
fn terminal_anchor_allows_no_extra_checkpoint() {
    let lifecycle = lifecycle();
    let completed = lifecycle.last().unwrap();
    validate_provider_checkpoint_chain(Some(completed), &[]).unwrap();
    let extra = checkpoint(
        completed.checkpoint_sequence + 1,
        Some(completed),
        ProviderAttemptPhaseV1::Pending {
            invocation_blob: blob(),
        },
    );
    assert!(validate_provider_checkpoint_chain(Some(completed), &[extra]).is_err());

    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    validate_provider_checkpoint_chain(Some(&cancelled), &[]).unwrap();
    let extra = checkpoint(
        3,
        Some(&cancelled),
        ProviderAttemptPhaseV1::Pending {
            invocation_blob: blob(),
        },
    );
    assert!(validate_provider_checkpoint_chain(Some(&cancelled), &[extra]).is_err());
}

#[test]
fn schemas_digests_sizes_and_chain_length_are_bounded() {
    let mut invalid = blob();
    invalid.schema = "v2".to_string();
    assert!(invalid.validate().is_err());
    invalid = blob();
    invalid.blob_sha256 = "A".repeat(64);
    assert!(invalid.validate().is_err());
    invalid = blob();
    invalid.blob_size_bytes = MAX_PROVIDER_INVOCATION_BLOB_BYTES + 1;
    assert!(invalid.validate().is_err());
    invalid = blob();
    invalid.idempotency_key = sha(b"other-operation");
    assert!(matches!(
        invalid.validate(),
        Err(ProviderAttemptValidationError::BindingMismatch(
            "idempotency_key"
        ))
    ));

    let mut empty_outcome = completion();
    empty_outcome.outcome_size_bytes = 0;
    empty_outcome.outcome_sha256 = sha(b"");
    assert!(empty_outcome.validate().is_ok());

    let mut invalid_currency = completion();
    invalid_currency.currency = "usd".to_string();
    assert!(invalid_currency.validate().is_err());

    let mut unsafe_cost = completion();
    unsafe_cost.cost_units = 1_u64 << 53;
    assert!(unsafe_cost.validate().is_err());

    let mut unsafe_expiry = lease();
    unsafe_expiry.expires_at = 1_u64 << 53;
    assert!(unsafe_expiry.validate().is_err());

    let too_long = vec![lifecycle()[0].clone(); MAX_PROVIDER_CHECKPOINT_CHAIN + 1];
    assert!(validate_provider_checkpoint_chain(None, &too_long).is_err());
}
