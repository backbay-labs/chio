use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use super::*;
use chio_core_types::provider_attempt::{
    ProviderInvocationBlobBindingV1, PROVIDER_ACCEPTANCE_SCHEMA,
    PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA, PROVIDER_CANCELLATION_SCHEMA, PROVIDER_COMPLETION_SCHEMA,
    PROVIDER_EXECUTION_LEASE_SCHEMA, PROVIDER_INVOCATION_BLOB_SCHEMA,
};

fn sha(bytes: &[u8]) -> String {
    sha256_hex(bytes)
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

fn qualification(provider: FakeProvider) -> QualifiedDispatchStatusProvider {
    qualification_with_anchor(provider, "test-external-continuity-anchor")
}

fn qualification_with_anchor(
    provider: FakeProvider,
    continuity_anchor_id: &str,
) -> QualifiedDispatchStatusProvider {
    qualify_dispatch_status_provider_for_test(
        Arc::new(provider),
        "test-ed25519-verifier",
        continuity_anchor_id,
        11,
        "chio.test-provider-status.v1",
    )
    .unwrap()
}

fn resolve_qualified(
    provider: FakeProvider,
    query: &DispatchStatusQuery,
) -> Result<VerifiedDispatchStatus, DispatchStatusError> {
    let qualification = qualification(provider);
    resolve_dispatch_status(Some(&qualification), query)
}

struct FakeProvider {
    status: Result<ProviderDispatchStatusObservation, DispatchStatusProviderError>,
    acceptance: Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError>,
    not_accepted: Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError>,
    completed: Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError>,
    calls: Arc<AtomicUsize>,
    transport_id: String,
    transport_key_epoch: u64,
}

impl FakeProvider {
    fn with_status(status: ProviderDispatchStatusObservation) -> Self {
        Self {
            status: Ok(status),
            acceptance: Ok(AuthenticatedProviderAcceptance {
                binding: acceptance(),
                envelope: b"accepted".to_vec(),
            }),
            not_accepted: Ok(AuthenticatedProviderNotAccepted {
                binding: cancellation(),
                proof: b"cancelled".to_vec(),
            }),
            completed: Ok(AuthenticatedProviderCompletedOutcome {
                binding: completion(),
                outcome_bytes: b"outcome".to_vec(),
                cost_units: 12,
                currency: "USD".to_string(),
                terminal_evidence: b"terminal".to_vec(),
            }),
            calls: Arc::new(AtomicUsize::new(0)),
            transport_id: "qualified-provider".to_string(),
            transport_key_epoch: 7,
        }
    }
}

impl DispatchStatusProvider for FakeProvider {
    fn transport_id(&self) -> &str {
        &self.transport_id
    }

    fn transport_key_epoch(&self) -> u64 {
        self.transport_key_epoch
    }

    fn status(
        &self,
        _query: &DispatchStatusQuery,
    ) -> Result<ProviderDispatchStatusObservation, DispatchStatusProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.status.clone()
    }

    fn fetch_acceptance(
        &self,
        _binding: &ProviderAcceptanceBindingV1,
    ) -> Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError> {
        self.acceptance.clone()
    }

    fn fetch_not_accepted(
        &self,
        _binding: &ProviderCancellationBindingV1,
    ) -> Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError> {
        self.not_accepted.clone()
    }

    fn fetch_completed_outcome(
        &self,
        _binding: &ProviderCompletionBindingV1,
    ) -> Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError> {
        self.completed.clone()
    }
}

impl QualifiedDispatchStatusAdapter for FakeProvider {}

fn query(
    last_checkpoint: Option<ProviderAttemptCheckpointV1>,
    observed_at: u64,
) -> DispatchStatusQuery {
    DispatchStatusQuery {
        attempt: attempt(),
        last_checkpoint,
        observed_at,
    }
}

#[test]
fn opaque_qualification_is_required_for_unanchored_and_forged_anchor_queries() {
    let forged_cancelled_genesis = checkpoint(
        1,
        None,
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    for query in [query(None, 30), query(Some(forged_cancelled_genesis), 30)] {
        let status = resolve_dispatch_status(None, &query).unwrap();
        assert!(matches!(
            status,
            VerifiedDispatchStatus::Unknown(ref unknown)
                if unknown.reason() == DispatchUnknownReason::UnqualifiedProvider
        ));
    }
}

#[test]
fn empty_provider_response_cannot_promote_a_forged_pending_anchor() {
    let forged_pending = lifecycle()[0].clone();
    let provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(Vec::new()));
    let status = resolve_qualified(provider, &query(Some(forged_pending), 30)).unwrap();
    assert!(matches!(
        status,
        VerifiedDispatchStatus::Unknown(ref unknown)
            if unknown.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));
}

#[test]
fn qualification_mismatch_is_not_queried() {
    let mut provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(lifecycle()));
    provider.transport_key_epoch = 8;
    let calls = Arc::clone(&provider.calls);
    let qualification = qualification(provider);
    let status = resolve_dispatch_status(Some(&qualification), &query(None, 30)).unwrap();
    assert!(matches!(
        status,
        VerifiedDispatchStatus::Unknown(ref unknown)
            if unknown.reason() == DispatchUnknownReason::QualificationMismatch
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn test_qualification_binds_the_security_components() {
    let first = qualification(FakeProvider::with_status(
        ProviderDispatchStatusObservation::Unknown,
    ));
    let mut other_provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Unknown);
    other_provider.transport_key_epoch = 8;
    let other_epoch = qualification(other_provider);
    assert_ne!(
        first.qualification_digest(),
        other_epoch.qualification_digest()
    );

    for (verifier, anchor, high_water, domain) in [
        ("", "anchor", 1, "domain"),
        ("verifier", "", 1, "domain"),
        ("verifier", "anchor", 0, "domain"),
        ("verifier", "anchor", 1, " padded"),
    ] {
        assert!(qualify_dispatch_status_provider_for_test(
            Arc::new(FakeProvider::with_status(
                ProviderDispatchStatusObservation::Unknown
            )),
            verifier,
            anchor,
            high_water,
            domain,
        )
        .is_err());
    }

    let mut invalid_transport =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Unknown);
    invalid_transport.transport_id = " padded".to_string();
    assert!(qualify_dispatch_status_provider_for_test(
        Arc::new(invalid_transport),
        "verifier",
        "anchor",
        1,
        "domain",
    )
    .is_err());
}

#[test]
fn verified_status_retains_the_exact_qualification_digest() {
    let lifecycle = lifecycle();
    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(vec![
        lifecycle[0].clone(),
        cancelled,
    ]));
    let first = qualification_with_anchor(provider, "continuity-anchor-a");
    let status = resolve_dispatch_status(Some(&first), &query(None, 30)).unwrap();
    let second = qualification_with_anchor(
        FakeProvider::with_status(ProviderDispatchStatusObservation::Unknown),
        "continuity-anchor-b",
    );
    let VerifiedDispatchStatus::NotAccepted(status) = status else {
        panic!("expected verified provider non-acceptance");
    };
    assert_eq!(status.qualification_digest(), first.qualification_digest());
    assert_ne!(status.qualification_digest(), second.qualification_digest());
}

#[test]
fn pending_accepted_executing_completed_and_cancelled_resolve() {
    let lifecycle = lifecycle();
    for (end, expected) in [
        (1, "pending"),
        (2, "accepted"),
        (3, "accepted"),
        (4, "completed"),
    ] {
        let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(
            lifecycle[..end].to_vec(),
        ));
        let qualification = qualification(provider);
        let status = resolve_dispatch_status(Some(&qualification), &query(None, 30)).unwrap();
        assert!(matches!(
            (&status, expected),
            (VerifiedDispatchStatus::Pending(_), "pending")
                | (VerifiedDispatchStatus::Accepted(_), "accepted")
                | (VerifiedDispatchStatus::Completed(_), "completed")
        ));
        let status_qualification_digest = match &status {
            VerifiedDispatchStatus::Pending(status) => status.qualification_digest(),
            VerifiedDispatchStatus::Accepted(status) => status.qualification_digest(),
            VerifiedDispatchStatus::Completed(status) => status.qualification_digest(),
            _ => panic!("expected a non-terminal or completed provider status"),
        };
        assert_eq!(
            status_qualification_digest,
            qualification.qualification_digest()
        );
    }

    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(vec![
        lifecycle[0].clone(),
        cancelled,
    ]));
    let status = resolve_qualified(provider, &query(None, 30)).unwrap();
    let VerifiedDispatchStatus::NotAccepted(not_accepted) = status else {
        panic!("expected verified provider non-acceptance");
    };
    assert_eq!(not_accepted.proof(), b"cancelled");
}

#[test]
fn acceptance_cancel_race_has_only_one_legal_winner() {
    let lifecycle = lifecycle();
    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    let illegal_cancel_after_accept = checkpoint(
        3,
        Some(&lifecycle[1]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(vec![
        lifecycle[0].clone(),
        lifecycle[1].clone(),
        illegal_cancel_after_accept,
    ]));
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));
    assert!(
        chio_core_types::provider_attempt::validate_provider_checkpoint_transition(
            &lifecycle[0],
            &cancelled
        )
        .is_ok()
    );
}

#[test]
fn provider_event_times_after_trusted_observation_freeze_unknown() {
    assert!(query(None, 1_u64 << 53).validate().is_err());

    let lifecycle = lifecycle();
    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );

    for checkpoints in [
        lifecycle[..2].to_vec(),
        vec![lifecycle[0].clone(), cancelled],
        lifecycle[..3].to_vec(),
        lifecycle.clone(),
    ] {
        let provider =
            FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(checkpoints));
        let status = resolve_qualified(provider, &query(None, 19)).unwrap();
        assert!(matches!(
            status,
            VerifiedDispatchStatus::Unknown(ref value)
                if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
        ));
    }

    let provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(Vec::new()));
    let status = resolve_qualified(provider, &query(Some(lifecycle[3].clone()), 29)).unwrap();
    assert!(matches!(
        status,
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));
}

#[test]
fn stale_or_substituted_checkpoints_and_leases_freeze_unknown() {
    let lifecycle = lifecycle();
    let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(vec![
        lifecycle[0].clone(),
    ]));
    assert!(matches!(
        resolve_qualified(provider, &query(Some(lifecycle[1].clone()), 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));

    let provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(
        lifecycle[..3].to_vec(),
    ));
    assert!(matches!(
        resolve_qualified(provider, &query(None, 40)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::StaleExecutionLease
    ));

    let mut substituted = lifecycle.clone();
    substituted[1].attempt.attempt_id = "other-attempt".to_string();
    let provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(substituted));
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));
}

#[test]
fn fetched_acceptance_not_accepted_and_completion_must_match_exact_bytes() {
    let lifecycle = lifecycle();
    let mut provider = FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(
        lifecycle[..2].to_vec(),
    ));
    provider.acceptance.as_mut().unwrap().envelope.push(b'x');
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));

    let cancelled = checkpoint(
        2,
        Some(&lifecycle[0]),
        ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob(),
            cancellation: cancellation(),
        },
    );
    let mut provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(vec![
            lifecycle[0].clone(),
            cancelled,
        ]));
    provider
        .not_accepted
        .as_mut()
        .unwrap()
        .binding
        .cancellation_fence += 1;
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));

    let mut provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(lifecycle));
    provider.completed.as_mut().unwrap().cost_units += 1;
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::InvalidProviderEvidence
    ));
}

#[test]
fn unavailable_or_bare_terminal_references_freeze_unknown() {
    let lifecycle = lifecycle();
    let mut provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(lifecycle));
    provider.completed = Err(DispatchStatusProviderError::new("unavailable"));
    assert!(matches!(
        resolve_qualified(provider, &query(None, 30)).unwrap(),
        VerifiedDispatchStatus::Unknown(ref value)
            if value.reason() == DispatchUnknownReason::CompletedOutcomeUnavailable
    ));
}

#[test]
fn completed_result_exposes_only_verified_bound_values() {
    let provider =
        FakeProvider::with_status(ProviderDispatchStatusObservation::Checkpoints(lifecycle()));
    let status = resolve_qualified(provider, &query(None, 30)).unwrap();
    let VerifiedDispatchStatus::Completed(completed) = status else {
        panic!("expected completed provider result");
    };
    assert_eq!(completed.outcome_bytes(), b"outcome");
    assert_eq!(completed.cost_units(), 12);
    assert_eq!(completed.currency(), "USD");
    assert_eq!(completed.terminal_evidence(), b"terminal");
    assert_eq!(completed.completion(), &completion());
}
