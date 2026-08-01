//! Integration tests for the SQLite HITL approval store.
//!
//! Exercises the store contract directly and simulates kernel restart
//! by opening a second store handle against the same database file. The
//! pending row, consumed-token registry, and resolved record must all
//! survive the restart.

use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    resume_with_decision, ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest,
    ApprovalStore, ApprovalStoreError,
};
use chio_store_sqlite::SqliteApprovalStore;

use chio_test_support::prelude::*;

fn unique_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn sample_request(id: &str, hash: &str) -> ApprovalRequest {
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    ApprovalRequest {
        approval_id: id.into(),
        policy_id: "policy-test".into(),
        subject_id: "agent-test".into(),
        capability_id: "cap-test".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: hash.into(),
        expires_at: 2_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "sqlite contract".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    }
}

fn sign_token(
    approver: &Keypair,
    subject: &Keypair,
    approval_id: &str,
    parameter_hash: &str,
    decision: GovernedApprovalDecision,
) -> GovernedApprovalToken {
    let body = GovernedApprovalTokenBody {
        id: format!("tok-{approval_id}"),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: parameter_hash.into(),
        request_id: approval_id.into(),
        threshold_proposal_hash: None,
        issued_at: 100,
        expires_at: 3600,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).test_unwrap()
}

#[test]
fn store_and_retrieve_round_trip() {
    let path = unique_path("chio-hitl-roundtrip");
    let store = SqliteApprovalStore::open(&path).test_unwrap();
    let r = sample_request("a-1", "h-1");
    store.store_pending(&r).test_unwrap();
    let fetched = store.get_pending("a-1").test_unwrap().test_unwrap();
    assert_eq!(fetched.approval_id, "a-1");
    let all = store.list_pending(&ApprovalFilter::default()).test_unwrap();
    assert_eq!(all.len(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn filter_list_by_subject_and_server() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let mut r1 = sample_request("a-1", "h-1");
    r1.subject_id = "alice".into();
    let mut r2 = sample_request("a-2", "h-2");
    r2.subject_id = "bob".into();
    r2.tool_server = "payment".into();
    store.store_pending(&r1).test_unwrap();
    store.store_pending(&r2).test_unwrap();

    let alice = store
        .list_pending(&ApprovalFilter {
            subject_id: Some("alice".into()),
            ..Default::default()
        })
        .test_unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].approval_id, "a-1");

    let payment = store
        .list_pending(&ApprovalFilter {
            tool_server: Some("payment".into()),
            ..Default::default()
        })
        .test_unwrap();
    assert_eq!(payment.len(), 1);
    assert_eq!(payment[0].approval_id, "a-2");
}

#[test]
fn resolve_marks_approved_and_records_consumption() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let mut r = sample_request("a-1", "h-1");
    r.subject_public_key = Some(subject.public_key());
    r.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r).test_unwrap();

    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "a-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
        received_at: 1000,
    };

    store.resolve("a-1", &decision).test_unwrap();
    assert!(store.get_pending("a-1").test_unwrap().is_none());
    assert!(store.get_resolution("a-1").test_unwrap().is_some());
    assert!(store.is_consumed(&token.id, "h-1").test_unwrap());
    assert_eq!(
        store
            .count_approved("agent-test", "policy-test")
            .test_unwrap(),
        1
    );
}

#[test]
fn resolve_rejects_replay() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let mut r = sample_request("a-1", "h-1");
    r.subject_public_key = Some(subject.public_key());
    r.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r).test_unwrap();

    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "a-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
        received_at: 1000,
    };
    store.resolve("a-1", &decision).test_unwrap();

    // Re-insert the pending row and attempt to resolve again with the
    // same token. Must return a replay error.
    store.store_pending(&r).test_unwrap();
    let err = store.resolve("a-1", &decision).test_unwrap_err();
    match err {
        ApprovalStoreError::Replay(_) => {}
        other => panic!("expected Replay, got {other:?}"),
    }
}

#[test]
fn persistence_survives_restart() {
    let path = unique_path("chio-hitl-restart");
    let approver = Keypair::generate();
    let subject = Keypair::generate();

    // First "kernel" writes a pending approval.
    {
        let store = SqliteApprovalStore::open(&path).test_unwrap();
        let mut r = sample_request("ap-restart", "h-restart");
        r.subject_public_key = Some(subject.public_key());
        r.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&r).test_unwrap();
    }

    // Second "kernel" opens at the same path (simulating a restart).
    let store2 = SqliteApprovalStore::open(&path).test_unwrap();
    let pending = store2
        .list_pending(&ApprovalFilter::default())
        .test_unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].approval_id, "ap-restart");

    // Resume via the kernel's resume_with_decision now that the store
    // is re-opened; the approval must resolve cleanly.
    let token = sign_token(
        &approver,
        &subject,
        "ap-restart",
        "h-restart",
        GovernedApprovalDecision::Approved,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-restart".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
        received_at: 1000,
    };
    let outcome = resume_with_decision(&store2, &decision, 1000).test_unwrap();
    assert_eq!(outcome, ApprovalOutcome::Approved);
    assert!(store2
        .list_pending(&ApprovalFilter::default())
        .test_unwrap()
        .is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn record_consumed_is_idempotent_on_first_write_only() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    store.record_consumed("tok-A", "hash-A", 1).test_unwrap();
    let err = store
        .record_consumed("tok-A", "hash-A", 2)
        .test_unwrap_err();
    match err {
        ApprovalStoreError::Replay(_) => {}
        other => panic!("expected Replay on second call, got {other:?}"),
    }
    assert!(store.is_consumed("tok-A", "hash-A").test_unwrap());
}

#[test]
fn count_approved_ignores_denied_rows() {
    let store = SqliteApprovalStore::open_in_memory().test_unwrap();
    let approver = Keypair::generate();
    let subject = Keypair::generate();

    let mut r_a = sample_request("r-a", "h-a");
    r_a.subject_id = "agent-x".into();
    r_a.policy_id = "policy-x".into();
    r_a.subject_public_key = Some(subject.public_key());
    r_a.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r_a).test_unwrap();
    let tok_a = sign_token(
        &approver,
        &subject,
        "r-a",
        "h-a",
        GovernedApprovalDecision::Approved,
    );
    store
        .resolve(
            "r-a",
            &ApprovalDecision {
                approval_id: "r-a".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: tok_a,
                received_at: 10,
            },
        )
        .test_unwrap();

    let mut r_b = sample_request("r-b", "h-b");
    r_b.subject_id = "agent-x".into();
    r_b.policy_id = "policy-x".into();
    r_b.subject_public_key = Some(subject.public_key());
    r_b.trusted_approvers = vec![approver.public_key()];
    store.store_pending(&r_b).test_unwrap();
    let tok_b = sign_token(
        &approver,
        &subject,
        "r-b",
        "h-b",
        GovernedApprovalDecision::Denied,
    );
    store
        .resolve(
            "r-b",
            &ApprovalDecision {
                approval_id: "r-b".into(),
                outcome: ApprovalOutcome::Denied,
                reason: None,
                approver: approver.public_key(),
                token: tok_b,
                received_at: 11,
            },
        )
        .test_unwrap();

    assert_eq!(store.count_approved("agent-x", "policy-x").test_unwrap(), 1);
}
