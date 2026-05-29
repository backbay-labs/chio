// HITL kernel-level flow tests.
//
// Included by `src/kernel/tests.rs`; the test module imports from the
// surrounding `kernel::tests` scope via `super::*`. Helpers such as
// `make_keypair` come from `tests/all.rs`.
//
// Scope: these tests exercise the HITL subsystem (approval store,
// approval guard, channels, replay protection, restart persistence)
// directly rather than through the full kernel evaluate path. Running
// the full pipeline would require standing up every downstream store
// (revocation, budget, authority, receipt log) for every case; a
// focused test against the primitives is faster and still covers every
// acceptance bullet in the phase spec.

use std::sync::Arc as StdArc;

// Note: `GovernedApprovalDecision`, `GovernedApprovalToken`,
// `GovernedApprovalTokenBody`, and `Keypair` are already brought into
// scope by `tests/all.rs`. Only pull in HITL-specific items. These
// paths intentionally resolve through `crate::approval*` so the test
// exercises the same type identities that downstream consumers see.
use crate::approval::{
    compute_parameter_hash, resume_with_decision, ApprovalContext, ApprovalDecision,
    ApprovalGuard, ApprovalOutcome, ApprovalRequest, ApprovalStore, ApprovalToken, BatchApproval,
    BatchApprovalStore, HitlVerdict, InMemoryApprovalStore, InMemoryBatchApprovalStore,
};
use crate::approval_channels::RecordingChannel;

type CoreKeypair = Keypair;

fn hitl_make_request() -> ToolCallRequest {
    let subject_kp = CoreKeypair::generate();
    let cap_builder_kernel = make_kernel(make_config());
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&cap_builder_kernel, &subject_kp, scope, 300);
    make_request("hitl-req-1", &cap, "read_file", "srv-a")
}

fn hitl_sign_token(
    approver: &CoreKeypair,
    subject: &CoreKeypair,
    approval_id: &str,
    parameter_hash: &str,
    decision: GovernedApprovalDecision,
    now: u64,
) -> GovernedApprovalToken {
    let body = GovernedApprovalTokenBody {
        id: format!("tok-{approval_id}"),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: parameter_hash.to_string(),
        request_id: approval_id.to_string(),
        issued_at: now.saturating_sub(10),
        expires_at: now + 600,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).unwrap()
}

// ---------------------------------------------------------------------
// (a) PendingApproval is returned when constraints require approval.
// ---------------------------------------------------------------------

#[test]
fn hitl_force_approval_returns_pending() {
    let store = StdArc::new(InMemoryApprovalStore::new());
    let recorder = StdArc::new(RecordingChannel::new());
    let guard = ApprovalGuard::new(store.clone()).with_channel(recorder.clone());

    let request = hitl_make_request();
    let approver = CoreKeypair::generate();
    let ctx = ApprovalContext {
        request: &request,
        constraints: &[],
        policy_id: "policy-hitl",
        trusted_approvers: &[approver.public_key()],
        presented_token: None,
        force_approval: true,
        approval_id_override: Some("ap-force-1".into()),
    };

    let verdict = guard.evaluate(ctx, 1_000_000).unwrap();
    match verdict {
        HitlVerdict::Pending { request: approval, .. } => {
            assert_eq!(approval.approval_id, "ap-force-1");
            assert_eq!(approval.subject_id, request.agent_id);
            assert_eq!(approval.tool_server, "srv-a");
            assert_eq!(approval.tool_name, "read_file");
        }
        other => panic!("expected Pending, got {other:?}"),
    }

    // Store now holds the pending request.
    let pending = store.get_pending("ap-force-1").unwrap().unwrap();
    assert_eq!(pending.approval_id, "ap-force-1");

    // Channel fired once.
    assert_eq!(recorder.len(), 1);
    let captured = recorder.captured();
    assert_eq!(captured[0].approval_id, "ap-force-1");
}

// ---------------------------------------------------------------------
// (b) Approved resume produces an Approved outcome.
// ---------------------------------------------------------------------

#[test]
fn hitl_resume_approved_executes() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-approve-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-approve-1",
        &hash,
        GovernedApprovalDecision::Approved,
        600,
    );

    let decision = ApprovalDecision {
        approval_id: "ap-approve-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: Some("looks good".into()),
        approver: approver.public_key(),
        token,
        received_at: 600,
    };
    let outcome = resume_with_decision(&store, &decision, 600).unwrap();
    assert_eq!(outcome, ApprovalOutcome::Approved);

    // Pending record is gone; resolved record exists.
    assert!(store.get_pending("ap-approve-1").unwrap().is_none());
    assert!(store
        .get_resolution("ap-approve-1")
        .unwrap()
        .is_some());
    assert_eq!(
        store.count_approved(&request.agent_id, "policy-hitl").unwrap(),
        1
    );
}

// ---------------------------------------------------------------------
// (c) Denied outcome records a denial and does not increment approvals.
// ---------------------------------------------------------------------

#[test]
fn hitl_resume_denied_records_denial() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-deny-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-deny-1",
        &hash,
        GovernedApprovalDecision::Denied,
        600,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-deny-1".into(),
        outcome: ApprovalOutcome::Denied,
        reason: Some("not authorized".into()),
        approver: approver.public_key(),
        token,
        received_at: 700,
    };
    let outcome = resume_with_decision(&store, &decision, 700).unwrap();
    assert_eq!(outcome, ApprovalOutcome::Denied);

    // Approved counter stays zero.
    assert_eq!(
        store.count_approved(&request.agent_id, "policy-hitl").unwrap(),
        0
    );
    // Resolution record is present with Denied outcome.
    let resolution = store.get_resolution("ap-deny-1").unwrap().unwrap();
    assert_eq!(resolution.outcome, ApprovalOutcome::Denied);
}

// ---------------------------------------------------------------------
// (d) Replay of a consumed approval token is rejected.
// ---------------------------------------------------------------------

#[test]
fn hitl_replay_of_consumed_token_rejected() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );
    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let approval = ApprovalRequest {
        approval_id: "ap-replay-1".into(),
        policy_id: "policy-hitl".into(),
        subject_id: request.agent_id.clone(),
        capability_id: request.capability.id.clone(),
        subject_public_key: Some(subject.public_key()),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action: "invoke".into(),
        parameter_hash: hash.clone(),
        expires_at: 1_000_000,
        callback_hint: None,
        created_at: 500,
        summary: "test".into(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    store.store_pending(&approval).unwrap();

    let token = hitl_sign_token(
        &approver,
        &subject,
        "ap-replay-1",
        &hash,
        GovernedApprovalDecision::Approved,
        600,
    );
    let decision = ApprovalDecision {
        approval_id: "ap-replay-1".into(),
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
        received_at: 600,
    };
    resume_with_decision(&store, &decision, 600).unwrap();

    // Re-submitting the same decision must fail. Because the pending
    // row has been removed, the error surface is "NotFound" wrapped as
    // ApprovalRejected by resume_with_decision's error mapping.
    let replay = resume_with_decision(&store, &decision, 605).unwrap_err();
    let msg = replay.to_string();
    assert!(
        msg.contains("approval rejected")
            || msg.contains("replay")
            || msg.contains("unknown approval"),
        "unexpected error: {msg}"
    );

    // Consumed registry records the token.
    assert!(store
        .is_consumed(&token.id, &hash)
        .unwrap());

    // Re-storing the pending row and replaying the consumed token
    // should also fail with a replay error (the consumed registry is
    // authoritative even if the pending row reappears).
    let approval2 = ApprovalRequest {
        approval_id: "ap-replay-1".into(),
        ..approval
    };
    store.store_pending(&approval2).unwrap();
    let replay2 = resume_with_decision(&store, &decision, 610).unwrap_err();
    let msg2 = replay2.to_string();
    assert!(
        msg2.contains("replay") || msg2.contains("already"),
        "expected replay error, got: {msg2}"
    );
}

// Note: (e) Persistence-survives-restart is covered by the integration
// test in `crates/chio-store-sqlite/tests/approval_store.rs`, which
// owns both the SqliteApprovalStore and the kernel's resume path.
// Keeping that test out of the kernel's lib tests avoids the
// two-copies-of-chio-kernel dependency cycle (chio-store-sqlite depends
// on chio-kernel; the kernel's dev-deps cannot include chio-store-sqlite
// for use in lib tests without duplicating the crate).

// ---------------------------------------------------------------------
// (f) Webhook / channel fires on pending approval.
// ---------------------------------------------------------------------

#[test]
fn hitl_channel_fires_on_pending() {
    let store = StdArc::new(InMemoryApprovalStore::new());
    let recorder = StdArc::new(RecordingChannel::new());

    let guard = ApprovalGuard::new(store.clone()).with_channel(recorder.clone());
    let request = hitl_make_request();
    let approver = CoreKeypair::generate();
    let ctx = ApprovalContext {
        request: &request,
        constraints: &[],
        policy_id: "policy-webhook",
        trusted_approvers: &[approver.public_key()],
        presented_token: None,
        force_approval: true,
        approval_id_override: Some("ap-webhook-1".into()),
    };

    assert!(recorder.is_empty());
    let _ = guard.evaluate(ctx, 1_000).unwrap();
    assert_eq!(recorder.len(), 1);
    let captured = recorder.captured();
    assert_eq!(captured[0].approval_id, "ap-webhook-1");
}

#[test]
fn hitl_force_approval_denies_without_trusted_approvers() {
    let store = StdArc::new(InMemoryApprovalStore::new());
    let guard = ApprovalGuard::new(store.clone());
    let request = hitl_make_request();
    let ctx = ApprovalContext {
        request: &request,
        constraints: &[],
        policy_id: "policy-hitl",
        trusted_approvers: &[],
        presented_token: None,
        force_approval: true,
        approval_id_override: Some("ap-misconfigured".into()),
    };

    let verdict = guard.evaluate(ctx, 1_000_000).unwrap();
    match verdict {
        HitlVerdict::Deny { reason } => {
            assert!(reason.contains("no trusted approvers"), "{reason}");
        }
        other => panic!("expected Deny, got {other:?}"),
    }
    assert!(store.get_pending("ap-misconfigured").unwrap().is_none());
}

// ---------------------------------------------------------------------
// (g) Batch respond applies multiple decisions at once.
// ---------------------------------------------------------------------

#[test]
fn hitl_batch_respond_applies_multiple_decisions() {
    let store = InMemoryApprovalStore::new();
    let request = hitl_make_request();
    let hash = compute_parameter_hash(
        &request.server_id,
        &request.tool_name,
        &request.arguments,
        request.governed_intent.as_ref(),
    );

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let ids = ["ap-batch-1", "ap-batch-2", "ap-batch-3"];
    for id in &ids {
        let approval = ApprovalRequest {
            approval_id: (*id).into(),
            policy_id: "policy-batch".into(),
            subject_id: request.agent_id.clone(),
            capability_id: request.capability.id.clone(),
            subject_public_key: Some(subject.public_key()),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action: "invoke".into(),
            parameter_hash: hash.clone(),
            expires_at: 2_000_000,
            callback_hint: None,
            created_at: 500,
            summary: "batch".into(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        store.store_pending(&approval).unwrap();
    }

    let decisions = [
        (ids[0], GovernedApprovalDecision::Approved, ApprovalOutcome::Approved),
        (ids[1], GovernedApprovalDecision::Denied, ApprovalOutcome::Denied),
        (ids[2], GovernedApprovalDecision::Approved, ApprovalOutcome::Approved),
    ];

    let mut approved = 0usize;
    let mut denied = 0usize;
    for (id, signed, envelope) in decisions {
        let token = hitl_sign_token(&approver, &subject, id, &hash, signed, 600);
        let decision = ApprovalDecision {
            approval_id: id.into(),
            outcome: envelope.clone(),
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 600,
        };
        let outcome = resume_with_decision(&store, &decision, 600).unwrap();
        assert_eq!(outcome, envelope);
        match outcome {
            ApprovalOutcome::Approved => approved += 1,
            ApprovalOutcome::Denied => denied += 1,
        }
    }
    assert_eq!(approved, 2);
    assert_eq!(denied, 1);
    assert_eq!(
        store.count_approved(&request.agent_id, "policy-batch").unwrap(),
        2
    );
}

// ---------------------------------------------------------------------
// Batch approval store: find_matching and record_usage.
// ---------------------------------------------------------------------

#[test]
fn hitl_batch_store_find_and_record() {
    let store = InMemoryBatchApprovalStore::new();
    let approver = CoreKeypair::generate();
    let batch = BatchApproval {
        batch_id: "ba-1".into(),
        approver_hex: approver.public_key().to_hex(),
        subject_id: "agent-1".into(),
        server_pattern: "search-*".into(),
        tool_pattern: "*".into(),
        max_amount_per_call: None,
        max_total_amount: None,
        max_calls: Some(3),
        not_before: 100,
        not_after: 1000,
        used_calls: 0,
        used_total_units: 0,
        revoked: false,
    };
    store.store(&batch).unwrap();

    let found = store
        .find_matching("agent-1", "search-primary", "query", None, 500)
        .unwrap()
        .expect("batch should match");
    assert_eq!(found.batch_id, "ba-1");

    store.record_usage("ba-1", None).unwrap();
    let after = store.get("ba-1").unwrap().unwrap();
    assert_eq!(after.used_calls, 1);
}

// ---------------------------------------------------------------------
// ApprovalToken.verify_against: signature, expiry, and binding guards.
// ---------------------------------------------------------------------

#[test]
fn hitl_token_verification_rejects_expired_tokens() {
    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "expired".into(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: "h".into(),
        request_id: "a".into(),
        issued_at: 10,
        expires_at: 20, // in the past relative to now=100
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).unwrap();
    let req = ApprovalRequest {
        approval_id: "a".into(),
        policy_id: "p".into(),
        subject_id: "s".into(),
        capability_id: "c".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: "h".into(),
        expires_at: 1000,
        callback_hint: None,
        created_at: 0,
        summary: String::new(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec![],
    };
    let approval_token = ApprovalToken {
        approval_id: "a".into(),
        governed_token: token,
        approver: approver.public_key(),
    };
    let err = approval_token.verify_against(&req, 100).unwrap_err();
    assert!(err.to_string().contains("expired"));
}
