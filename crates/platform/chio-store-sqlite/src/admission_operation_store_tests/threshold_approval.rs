use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, VerifiedApprovalSetBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_kernel::ThresholdApprovalReplayReservationV1;

fn replay_reservation(
    proposal_id: &str,
    request_id: &str,
    token_ids: [&str; 2],
    created_at: u64,
) -> ThresholdApprovalReplayReservationV1 {
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let approvers = [Keypair::generate(), Keypair::generate()];
    let deadline = created_at + 300;
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: proposal_id.to_owned(),
            request_id: request_id.to_owned(),
            governed_intent_hash: sha256_hex(b"threshold-intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"threshold-capability"),
            policy_hash: sha256_hex(b"threshold-policy"),
            threshold: 2,
            eligible_set_digest: sha256_hex(b"threshold-eligible-set"),
            proposal_created_at: created_at,
            proposal_deadline: deadline,
            policy_authority: authority.public_key(),
        },
        &authority,
    )
    .expect("proposal");
    let proposal_hash = proposal.artifact_digest().expect("proposal hash");
    let tokens = approvers
        .iter()
        .zip(token_ids)
        .map(|(approver, token_id)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: token_id.to_owned(),
                    approver: approver.public_key(),
                    subject: subject.public_key(),
                    governed_intent_hash: sha256_hex(b"threshold-intent"),
                    request_id: request_id.to_owned(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: created_at,
                    expires_at: deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .expect("token")
        })
        .collect::<Vec<_>>();
    let token_digests = tokens
        .iter()
        .map(|token| token.artifact_digest().expect("token digest"))
        .collect();
    let verified = VerifiedApprovalSetBody::new(token_digests, &proposal).expect("verified set");
    ThresholdApprovalReplayReservationV1::new(proposal, tokens, verified)
        .expect("replay reservation")
}

fn reserve(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    reservation: &ThresholdApprovalReplayReservationV1,
    now: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let proposal_hash = reservation
        .proposal()
        .artifact_digest()
        .expect("proposal hash");
    let set_hash = reservation
        .verified_set()
        .approval_set_hash()
        .expect("set hash");
    let lease = claim(fixture, operation, "threshold-worker", now);
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        vec![
            AdmissionAttachment::ThresholdProposalHash(
                AdmissionDigest::try_new("threshold_proposal_hash", proposal_hash)
                    .expect("proposal digest"),
            ),
            AdmissionAttachment::ApprovalSetHash(
                AdmissionDigest::try_new("approval_set_hash", set_hash).expect("set digest"),
            ),
        ],
        Some(AdmissionOperationState::ApprovalReserved),
        None,
        None,
    )
    .expect("reservation command");
    fixture
        .store
        .reserve_threshold_approval_and_commit_admission(&command, reservation, now)
        .map(|result| result.into_operation())
}

fn transition(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    state: AdmissionOperationState,
    now: u64,
) -> AdmissionOperationV1 {
    let lease = claim(fixture, operation, "threshold-worker", now);
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        Vec::new(),
        Some(state),
        None,
        None,
    )
    .expect("transition command");
    fixture
        .store
        .compare_and_swap(&command, now)
        .expect("transition")
        .into_operation()
}

#[test]
fn threshold_replay_reservation_scopes_token_ids_to_each_proposal() {
    let fixture = fixture();
    let now = now_ms();
    let created_at = now / 1_000;
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedActiveResponse,
        "threshold-request-a",
        "threshold-capability-a",
    );
    fixture
        .store
        .begin(&first, &fixture.fence, now)
        .expect("begin first");
    let reservation = replay_reservation(
        "threshold-proposal-a",
        "threshold-request-a",
        ["threshold-token-a", "threshold-token-b"],
        created_at,
    );
    let reserved = reserve(&fixture, &first, &reservation, now + 1).expect("reserve first");
    assert_eq!(reserved.state(), AdmissionOperationState::ApprovalReserved);

    let connection = fixture.store.connection().expect("connection");
    let stored: (String, i64, String) = connection
        .query_row(
            "SELECT state, proposal_deadline, approval_set_hash FROM threshold_approval_proposals WHERE operation_id = ?1",
            [first.binding().operation_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("stored proposal");
    assert_eq!(stored.0, "reserved");
    assert_eq!(stored.1, i64::try_from(created_at + 300).expect("deadline"));
    assert_eq!(
        stored.2,
        reservation
            .verified_set()
            .approval_set_hash()
            .expect("set hash")
    );
    let token_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM threshold_approval_tokens WHERE proposal_id = ?1",
            [reservation.proposal().body.proposal_id.as_str()],
            |row| row.get(0),
        )
        .expect("token count");
    assert_eq!(token_count, 2);
    drop(connection);

    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedActiveResponse,
        "threshold-request-b",
        "threshold-capability-b",
    );
    fixture
        .store
        .begin(&second, &fixture.fence, now + 2)
        .expect("begin second");
    let second_reservation = replay_reservation(
        "threshold-proposal-b",
        "threshold-request-b",
        ["threshold-token-a", "threshold-token-b"],
        created_at,
    );
    let second_reserved =
        reserve(&fixture, &second, &second_reservation, now + 3).expect("reserve second");
    assert_eq!(
        second_reserved.state(),
        AdmissionOperationState::ApprovalReserved
    );
    let connection = fixture.store.connection().expect("connection");
    let scoped_token_count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM threshold_approval_tokens
            WHERE token_id IN ('threshold-token-a', 'threshold-token-b')
            "#,
            [],
            |row| row.get(0),
        )
        .expect("scoped token count");
    assert_eq!(scoped_token_count, 4);
}

#[test]
fn threshold_replay_state_commits_when_dispatch_commits() {
    let fixture = fixture();
    let now = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedActiveResponse,
        "threshold-request-commit",
        "threshold-capability-commit",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now)
        .expect("begin");
    let reservation = replay_reservation(
        "threshold-proposal-commit",
        "threshold-request-commit",
        ["threshold-token-commit-a", "threshold-token-commit-b"],
        now / 1_000,
    );
    let reserved = reserve(&fixture, &operation, &reservation, now + 1).expect("reserve");
    let ready = transition(
        &fixture,
        &reserved,
        AdmissionOperationState::ReadyToDispatch,
        now + 2,
    );
    let committed = transition(
        &fixture,
        &ready,
        AdmissionOperationState::DispatchCommitted,
        now + 3,
    );
    assert_eq!(
        committed.state(),
        AdmissionOperationState::DispatchCommitted
    );
    let connection = fixture.store.connection().expect("connection");
    let state: String = connection
        .query_row(
            "SELECT state FROM threshold_approval_proposals WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .expect("replay state");
    assert_eq!(state, "committed");
}

fn prepared_approval_and_budget_operation(
    fence: &StoreMutationFence,
    request_id: &str,
    capability_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "local-test-authority",
    ))
    .expect("namespace");
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        approval: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", capability_id),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            requirements,
        )
        .expect("request binding"),
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

#[test]
fn approval_required_operations_are_persisted_but_excluded_from_recovery_pages() {
    let fixture = fixture();
    let now = now_ms();
    let created_at = now / 1_000;
    let operation = prepared_approval_and_budget_operation(
        &fixture.fence,
        "approval-required-request",
        "approval-required-capability",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now)
        .expect("begin operation");

    let lease = claim(&fixture, &operation, "approval-required-worker", now + 1);
    let registered = fixture
        .store
        .compare_and_swap(
            &AdmissionOperationCommand::new(
                operation.binding().operation_id().clone(),
                operation.version(),
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "approval-required-attempt",
                ))],
                Some(AdmissionOperationState::BrokerAttemptRegistered),
                None,
                None,
            )
            .expect("broker attempt command"),
            now + 2,
        )
        .expect("register broker attempt")
        .into_operation();

    let reservation = replay_reservation(
        "approval-required-proposal",
        "approval-required-request",
        ["approval-required-token-a", "approval-required-token-b"],
        created_at,
    );
    let proposal_hash = reservation
        .proposal()
        .artifact_digest()
        .expect("proposal hash");
    let lease = claim(&fixture, &registered, "approval-required-worker", now + 3);
    let command = AdmissionOperationCommand::new(
        registered.binding().operation_id().clone(),
        registered.version(),
        lease,
        vec![
            AdmissionAttachment::ThresholdProposalHash(
                AdmissionDigest::try_new("threshold_proposal_hash", proposal_hash)
                    .expect("proposal digest"),
            ),
            AdmissionAttachment::ThresholdProposal(Box::new(reservation.proposal().clone())),
            AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                "approval-required-hold",
            )),
        ],
        Some(AdmissionOperationState::ApprovalRequired),
        None,
        None,
    )
    .expect("approval-required command");

    // The generic compare-and-swap is the path that writes this state, so the SQL
    // state CHECK has to admit it or the transition can never be persisted.
    let advanced = fixture
        .store
        .compare_and_swap(&command, now + 4)
        .expect("advance to approval_required")
        .into_operation();
    assert_eq!(advanced.state(), AdmissionOperationState::ApprovalRequired);

    let connection = fixture.store.connection().expect("connection");
    let state: String = connection
        .query_row(
            "SELECT state FROM admission_operations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .expect("persisted state");
    assert_eq!(state, "approval_required");
    drop(connection);

    let later = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "recoverable-after-approval-required",
        "recoverable-after-approval-required-capability",
    );
    fixture
        .store
        .begin(&later, &fixture.fence, now + 5)
        .expect("begin later recoverable operation");
    assert_eq!(
        fixture
            .store
            .list_recoverable(now + 6, 1)
            .expect("recovery page must pass pending approval"),
        vec![later]
    );
}
