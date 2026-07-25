use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionRecoveryLease, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, ProviderAttemptBindingV1, QualifiedAdmissionOperationStoreExt,
    SideEffectClass, StoreMutationFence,
};
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve_with_blob, returned_value,
};
use chio_kernel::tool_outcome::{
    CanonicalResolvedOutputBlobV1, SettlementDispositionV1, ToolOutcomeInsertResultV1,
    ToolOutcomeStore, ToolOutcomeStoreError,
};
use tempfile::TempDir;

use super::*;
use crate::{SqliteAdmissionOperationStore, SqliteAuthorityStore};

struct Fixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
    authority: SqliteAuthorityStore,
    operations: SqliteAdmissionOperationStore,
    outcomes: SqliteToolOutcomeStore,
    fence: StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let operations = authority.admission_operation_store();
    let outcomes = authority.tool_outcome_store();
    Fixture {
        _temp: temp,
        database,
        lock_root,
        authority,
        operations,
        outcomes,
        fence,
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("millisecond clock")
}

fn id(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("valid identifier")
}

fn digest(field: &'static str, byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("valid digest")
}

fn prepared(fence: &StoreMutationFence, request_id: &str) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(id(
        "coordinator_authority_id",
        "tool-outcome-test-authority",
    ))
    .expect("request namespace");
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: id("request_id", request_id),
        capability_id: id("capability_id", "tool-outcome-capability"),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            requirements,
        )
        .expect("request binding"),
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn claim(fixture: &Fixture, operation: &AdmissionOperationV1, at: u64) -> AdmissionRecoveryLease {
    fixture
        .operations
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &id("claimant_id", "tool-outcome-worker"),
            at,
            at + 60_000,
            &fixture.fence,
        )
        .expect("claim operation")
}

fn advance(
    fixture: &Fixture,
    operation: AdmissionOperationV1,
    next: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
    at: u64,
) -> AdmissionOperationV1 {
    let lease = claim(fixture, &operation, at);
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next),
        None,
        None,
    )
    .expect("operation command");
    fixture
        .operations
        .compare_and_swap(&command, at + 1)
        .expect("advance operation")
        .into_operation()
}

fn committed(fixture: &Fixture, request_id: &str, begun_at: u64) -> AdmissionOperationV1 {
    let mut operation = prepared(&fixture.fence, request_id);
    fixture
        .operations
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin operation");
    let attempt = ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: format!("attempt:{}", operation.binding().operation_id().as_str()),
        transport_id: "tool-outcome-test-transport".to_owned(),
        transport_key_epoch: fixture.fence.owner_epoch,
    };
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(attempt)],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(id(
                "budget_hold_id",
                "tool-outcome-test-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
    ];
    for (index, (next, attachments)) in transitions.into_iter().enumerate() {
        operation = advance(
            fixture,
            operation,
            next,
            attachments,
            begun_at + 1 + u64::try_from(index).expect("transition index") * 2,
        );
    }
    operation
}

fn record_return(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    at: u64,
) -> (
    AdmissionOperationV1,
    chio_kernel::tool_outcome::ToolOutcomeRecordV1,
) {
    let (blob, outcome) = returned_value(
        operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
    )
    .expect("returned outcome");
    let lease = claim(fixture, operation, at);
    let inserted = fixture
        .outcomes
        .record_tool_returned(operation, &lease, &blob, &outcome, &fixture.fence, at + 1)
        .expect("record tool return");
    let (stored, finalizing) = inserted.into_parts();
    (finalizing, stored)
}

#[test]
fn tool_return_atomically_persists_blob_and_advances_operation() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = committed(&fixture, "atomic-return", begun_at);
    let at = begun_at + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        None,
    )
    .expect("returned outcome");
    let mut stale_fence = fixture.fence.clone();
    stale_fence.owner_epoch += 1;
    let lease = claim(&fixture, &operation, at);
    assert_eq!(
        fixture.outcomes.record_tool_returned(
            &operation,
            &lease,
            &blob,
            &outcome,
            &stale_fence,
            at + 1,
        ),
        Err(ToolOutcomeStoreError::Fenced)
    );
    let counts: (i64, i64) = fixture
        .outcomes
        .connection()
        .expect("connection")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tool_outcome_blobs), (SELECT COUNT(*) FROM tool_outcomes)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("outcome counts");
    assert_eq!(counts, (0, 0));

    let inserted = fixture
        .outcomes
        .record_tool_returned(&operation, &lease, &blob, &outcome, &fixture.fence, at + 1)
        .expect("atomic return commit");
    let ToolOutcomeInsertResultV1::Inserted {
        outcome: stored,
        operation: finalizing,
    } = inserted
    else {
        panic!("first return must insert");
    };
    assert_eq!(stored, outcome);
    assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
    assert_eq!(finalizing.tool_outcome_id(), Some(outcome.outcome_id()));
    assert_eq!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(operation.binding().operation_id())
            .expect("load raw outcome")
            .expect("raw outcome")
            .canonical_blob()
            .expect("canonical raw blob"),
        blob
    );
    assert_eq!(
        fixture
            .operations
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load operation"),
        Some(finalizing)
    );
}

#[test]
fn post_return_evaluation_is_fenced_staged_and_finalized_by_cas() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "evaluation-journal", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let prepared =
        prepared_evaluation(&operation, &outcome, begun_at + 22).expect("prepared evaluation");
    let lease = claim(&fixture, &operation, begun_at + 22);
    assert_eq!(
        fixture
            .outcomes
            .begin_post_return_evaluation(&lease, &prepared, &fixture.fence, begun_at + 23,)
            .expect("begin evaluation"),
        prepared
    );
    let pure = record_pure_step(&prepared).expect("pure result");
    assert_eq!(
        fixture
            .outcomes
            .stage_post_return_evaluation(
                operation.binding().operation_id(),
                prepared.version(),
                &lease,
                &pure,
                &fixture.fence,
                begun_at + 24,
            )
            .expect("stage pure result"),
        pure
    );
    assert_eq!(
        fixture.outcomes.stage_post_return_evaluation(
            operation.binding().operation_id(),
            prepared.version(),
            &lease,
            &pure,
            &fixture.fence,
            begun_at + 25,
        ),
        Err(ToolOutcomeStoreError::CasConflict)
    );
    let external = record_external_step(&pure, begun_at + 25).expect("external result");
    fixture
        .outcomes
        .stage_post_return_evaluation(
            operation.binding().operation_id(),
            pure.version(),
            &lease,
            &external,
            &fixture.fence,
            begun_at + 25,
        )
        .expect("stage external result");
    let (terminal_evaluation, terminal_outcome, resolved_blob) =
        resolve_with_blob(&outcome, &external, SettlementDispositionV1::NotApplicable)
            .expect("terminal records");
    assert!(matches!(
        fixture.outcomes.finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            None,
            &fixture.fence,
            begun_at + 26,
        ),
        Err(ToolOutcomeStoreError::Invariant(_))
    ));
    let substituted_blob =
        CanonicalResolvedOutputBlobV1::from_signing_preimage(b"substitute".to_vec())
            .expect("substituted blob");
    assert!(matches!(
        fixture.outcomes.finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            Some(&substituted_blob),
            &fixture.fence,
            begun_at + 26,
        ),
        Err(ToolOutcomeStoreError::Invariant(_))
    ));
    assert_eq!(
        fixture
            .outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .expect("lookup uncommitted evaluation"),
        Some(external.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("lookup uncommitted outcome"),
        Some(outcome.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(operation.binding().operation_id())
            .expect("lookup uncommitted resolved output"),
        None
    );
    let finalized = fixture
        .outcomes
        .finalize_post_return(
            operation.binding().operation_id(),
            external.version(),
            &lease,
            &terminal_evaluation,
            outcome.version(),
            &terminal_outcome,
            Some(&resolved_blob),
            &fixture.fence,
            begun_at + 26,
        )
        .expect("finalize evaluation and outcome");
    assert_eq!(
        finalized,
        (terminal_evaluation.clone(), terminal_outcome.clone())
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .expect("lookup evaluation"),
        Some(terminal_evaluation)
    );
    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("lookup outcome"),
        Some(terminal_outcome)
    );
    assert_eq!(
        fixture
            .outcomes
            .load_resolved_output_by_operation(operation.binding().operation_id())
            .expect("lookup resolved output"),
        Some(resolved_blob)
    );
}

#[test]
fn outcome_journal_survives_owner_rotation_and_detects_tampering() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "outcome-restart", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let database = fixture.database.clone();
    let lock_root = fixture.lock_root.clone();
    let Fixture {
        _temp,
        authority,
        operations,
        outcomes,
        ..
    } = fixture;
    drop(outcomes);
    drop(operations);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)
        .expect("reopen outcome authority");
    assert_eq!(
        reopened
            .tool_outcome_store()
            .lookup_by_operation(&operation_id)
            .expect("lookup after reopen"),
        Some(outcome)
    );
    drop(reopened);

    let connection = Connection::open(&database).expect("open database for tamper");
    connection
        .execute_batch(
            "UPDATE tool_outcomes
             SET participant_digest =
                    '0000000000000000000000000000000000000000000000000000000000000000',
                 outcome_version = outcome_version + 1,
                 store_uuid = (SELECT store_uuid FROM chio_serving_owner WHERE singleton = 1),
                 store_lease_id = (SELECT lease_id FROM chio_serving_owner WHERE singleton = 1),
                 store_owner_epoch = (SELECT owner_epoch FROM chio_serving_owner WHERE singleton = 1);",
        )
        .expect("tamper outcome commitment");
    drop(connection);
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    drop(_temp);
}

fn mark_operation_terminal(fixture: &Fixture, operation_id: &AdmissionOperationId) {
    // Reaching a terminal state through the real API requires the signed
    // terminal-projection machinery; this isolates the compaction gate, which
    // reads only `admission_operations.terminal`. The version bump keeps the
    // `admission_operations_versioned_body` trigger satisfied.
    let connection = fixture.outcomes.connection().expect("connection");
    let changed = connection
        .execute(
            "UPDATE admission_operations
             SET terminal = 1, version = version + 1
             WHERE operation_id = ?1",
            [operation_id.as_str()],
        )
        .expect("mark operation terminal");
    assert_eq!(changed, 1);
}

fn blob_state(fixture: &Fixture, digest: &str) -> (i64, bool) {
    let connection = fixture.outcomes.connection().expect("connection");
    connection
        .query_row(
            "SELECT blob_size_bytes, canonical_bytes IS NOT NULL
             FROM tool_outcome_blobs WHERE digest = ?1",
            [digest],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .expect("blob row")
}

#[test]
fn compaction_clears_a_terminal_blob_and_reports_compacted_reads() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "compaction-terminal", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let digest = outcome.raw_output_digest().as_str().to_owned();

    let (size_before, present_before) = blob_state(&fixture, &digest);
    assert!(present_before, "blob payload is present before compaction");

    mark_operation_terminal(&fixture, &operation_id);
    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compact terminal blob");
    assert_eq!(summary.compacted, 1);
    assert_eq!(summary.retained_live, 0);

    let (size_after, present_after) = blob_state(&fixture, &digest);
    assert!(!present_after, "blob payload is cleared after compaction");
    assert_eq!(size_after, size_before, "blob size is retained");

    let error = fixture
        .outcomes
        .load_raw_invocation_by_operation(&operation_id)
        .expect_err("a compacted raw invocation must not load silently");
    assert!(
        matches!(&error, ToolOutcomeStoreError::Invariant(message) if message.contains("compacted")),
        "compacted read reports a defined error, got {error:?}"
    );

    assert_eq!(
        fixture
            .outcomes
            .lookup_by_operation(&operation_id)
            .expect("outcome record survives compaction"),
        Some(outcome)
    );

    // A second pass is idempotent: the payload is already cleared.
    let repeat = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 201)
        .expect("second compaction pass");
    assert_eq!(repeat.compacted, 0);
    assert_eq!(repeat.retained_live, 0);
}

#[test]
fn reinserting_verified_bytes_rehydrates_a_compacted_blob() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "compaction-rehydrate", begun_at);
    let at = begun_at + 20;
    let (blob, outcome) = returned_value(
        &committed,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        None,
    )
    .expect("returned outcome");
    let bytes = blob.bytes().to_vec();
    let lease = claim(&fixture, &committed, at);
    let inserted = fixture
        .outcomes
        .record_tool_returned(&committed, &lease, &blob, &outcome, &fixture.fence, at + 1)
        .expect("record tool return");
    let (_, finalizing) = inserted.into_parts();
    let operation_id = finalizing.binding().operation_id().clone();
    let digest = outcome.raw_output_digest().as_str().to_owned();

    mark_operation_terminal(&fixture, &operation_id);
    fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compact terminal blob");
    assert!(!blob_state(&fixture, &digest).1, "blob starts compacted");

    let rehydrated_at = begun_at + 300;
    let mut connection = fixture.outcomes.connection().expect("connection");
    let transaction = fixture
        .outcomes
        .begin_write(&mut connection, &fixture.fence, rehydrated_at)
        .expect("begin rehydration write");
    insert_blob_bytes_tx(&transaction, &digest, &bytes, &fixture.fence, rehydrated_at)
        .expect("rehydrate verified bytes");
    fixture
        .outcomes
        .commit_write(transaction)
        .expect("commit rehydration");
    drop(connection);

    assert!(blob_state(&fixture, &digest).1, "blob payload is restored");
    assert!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(&operation_id)
            .expect("load rehydrated invocation")
            .is_some(),
        "the newly supplied canonical bytes can be loaded"
    );
}

#[test]
fn compaction_is_refused_while_an_owning_operation_is_live() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "compaction-live", begun_at);
    let (operation, _outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let digest = fixture
        .outcomes
        .lookup_by_operation(&operation_id)
        .expect("lookup outcome")
        .expect("outcome present")
        .raw_output_digest()
        .as_str()
        .to_owned();

    let summary = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 200)
        .expect("compaction pass over a live operation");
    assert_eq!(summary.compacted, 0, "a live operation is never compacted");
    assert_eq!(summary.retained_live, 1);

    let (_size, present) = blob_state(&fixture, &digest);
    assert!(present, "the live operation keeps its raw payload");
    assert!(
        fixture
            .outcomes
            .load_raw_invocation_by_operation(&operation_id)
            .expect("load raw invocation")
            .is_some(),
        "the raw invocation still reads back while the operation is live"
    );
}

#[test]
fn compaction_respects_the_retention_cutoff() {
    let fixture = fixture();
    let begun_at = now_ms();
    let committed = committed(&fixture, "compaction-cutoff", begun_at);
    let (operation, outcome) = record_return(&fixture, &committed, begun_at + 20);
    let operation_id = operation.binding().operation_id().clone();
    let digest = outcome.raw_output_digest().as_str().to_owned();
    mark_operation_terminal(&fixture, &operation_id);

    // The blob is recorded at `begun_at + 21`; a cutoff before it retains it.
    let early = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at, &fixture.fence, begun_at + 200)
        .expect("compaction below the cutoff");
    assert_eq!(
        early.compacted, 0,
        "a payload newer than the cutoff is kept"
    );
    assert_eq!(early.retained_live, 0);
    assert!(
        blob_state(&fixture, &digest).1,
        "payload retained below cutoff"
    );

    let due = fixture
        .outcomes
        .compact_retained_invocation_blobs(begun_at + 100, &fixture.fence, begun_at + 201)
        .expect("compaction at the cutoff");
    assert_eq!(due.compacted, 1, "a payload past the cutoff is compacted");
    assert!(
        !blob_state(&fixture, &digest).1,
        "payload cleared past cutoff"
    );
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}
