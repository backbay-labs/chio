//! End-to-end tests for the HITL HTTP handlers.
//!
//! Exercises the four substrate-independent handlers through an
//! `ApprovalAdmin` bound to an in-memory approval store. No HTTP
//! server is spun up: the `chio-http-core` crate is protocol-agnostic,
//! so the handlers are driven directly, mirroring the style of
//! `emergency_endpoints.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core_types::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_http_core::approvals::{
    handle_batch_respond, handle_create_threshold_proposal, handle_deliver_threshold_approval,
    handle_get_approval, handle_list_pending, handle_respond, handle_submit_threshold_approval,
    ApprovalAdmin, ApprovalHandlerError, BatchDecisionEntry, BatchRespondRequest,
    CreateThresholdProposalRequest, PendingQuery, RespondRequest, SubmitThresholdApprovalRequest,
};
use chio_kernel::{
    ApprovalOutcome, ApprovalRequest, ApprovalStore, InMemoryApprovalStore,
    InMemoryThresholdApprovalCollectorStore, ThresholdApprovalCollector,
    ThresholdApprovalCollectorState,
};

fn make_admin() -> (ApprovalAdmin, Arc<InMemoryApprovalStore>) {
    let store = Arc::new(InMemoryApprovalStore::new());
    let admin = ApprovalAdmin::new(store.clone() as Arc<dyn ApprovalStore>);
    (admin, store)
}

fn store_pending(
    store: &InMemoryApprovalStore,
    id: &str,
    hash: &str,
    subject: &Keypair,
    trusted_approvers: &[chio_core_types::crypto::PublicKey],
) {
    let req = ApprovalRequest {
        approval_id: id.into(),
        policy_id: "p".into(),
        subject_id: "agent-1".into(),
        capability_id: "cap-1".into(),
        subject_public_key: Some(subject.public_key()),
        tool_server: "srv".into(),
        tool_name: "tool".into(),
        action: "invoke".into(),
        parameter_hash: hash.into(),
        expires_at: 2_000_000,
        callback_hint: None,
        created_at: 100,
        summary: "e2e".into(),
        governed_intent: None,
        trusted_approvers: trusted_approvers.to_vec(),
        triggered_by: vec![],
    };
    store.store_pending(&req).unwrap();
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
        expires_at: 1000,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).unwrap()
}

#[test]
fn list_pending_returns_stored_approvals() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);

    let response = handle_list_pending(&admin, PendingQuery::default()).unwrap();
    assert_eq!(response.count, 2);
    assert_eq!(response.approvals.len(), 2);
}

#[test]
fn list_pending_respects_filters() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);

    let response = handle_list_pending(
        &admin,
        PendingQuery {
            tool_name: Some("missing".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(response.count, 0);
}

#[test]
fn get_approval_returns_pending_then_resolution() {
    let (admin, store) = make_admin();
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);

    let resp = handle_get_approval(&admin, "a-1").unwrap();
    assert!(resp.pending.is_some());
    assert!(resp.resolution.is_none());

    // Resolve and fetch again.
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: Some("approved".into()),
        approver: approver.public_key(),
        token,
    };
    handle_respond(&admin, "a-1", body, 500).unwrap();

    let resp = handle_get_approval(&admin, "a-1").unwrap();
    assert!(resp.pending.is_none());
    assert!(resp.resolution.is_some());
}

#[test]
fn get_approval_404_for_unknown_id() {
    let (admin, _) = make_admin();
    let err = handle_get_approval(&admin, "unknown").unwrap_err();
    assert_eq!(err.status(), 404);
    assert_eq!(err.code(), "not_found");
}

#[test]
fn respond_approves_pending_request() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: Some("OK".into()),
        approver: approver.public_key(),
        token,
    };
    let resp = handle_respond(&admin, "a-1", body, 500).unwrap();
    assert_eq!(resp.approval_id, "a-1");
    assert_eq!(resp.outcome, ApprovalOutcome::Approved);
    assert!(store.get_pending("a-1").unwrap().is_none());
}

#[test]
fn respond_rejects_mismatched_approval_id() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    // Token signed for a different approval id.
    let token = sign_token(
        &approver,
        &subject,
        "a-OTHER",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 500).unwrap_err();
    assert_eq!(err.status(), 400);
    match err {
        ApprovalHandlerError::BadRequest(_) => {}
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn respond_rejects_replay() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token: token.clone(),
    };
    handle_respond(&admin, "a-1", body, 500).unwrap();

    // Store the pending row again and replay the same token.
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 501).unwrap_err();
    match err {
        ApprovalHandlerError::ReplayDetected(_) => {}
        other => panic!("expected ReplayDetected, got {other:?}"),
    }
    assert_eq!(err.status(), 409);
}

#[test]
fn batch_respond_mixes_success_and_rejection() {
    let (admin, store) = make_admin();
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(&store, "a-1", "h-1", &subject, &[approver.public_key()]);
    store_pending(&store, "a-2", "h-2", &subject, &[approver.public_key()]);
    let ok_token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    // This token's request_id doesn't match its envelope's approval_id
    // -- should be rejected per-entry but not fail the whole batch.
    let bad_token = sign_token(
        &approver,
        &subject,
        "a-MISMATCH",
        "h-2",
        GovernedApprovalDecision::Approved,
    );

    let body = BatchRespondRequest {
        decisions: vec![
            BatchDecisionEntry {
                approval_id: "a-1".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: ok_token,
            },
            BatchDecisionEntry {
                approval_id: "a-2".into(),
                outcome: ApprovalOutcome::Approved,
                reason: None,
                approver: approver.public_key(),
                token: bad_token,
            },
        ],
    };
    let resp = handle_batch_respond(&admin, body, 500).unwrap();
    assert_eq!(resp.summary.total, 2);
    assert_eq!(resp.summary.approved, 1);
    assert_eq!(resp.summary.rejected, 1);
    let statuses: Vec<&str> = resp.results.iter().map(|r| r.status.as_str()).collect();
    assert!(statuses.contains(&"resolved"));
    assert!(statuses.contains(&"rejected"));
}

#[test]
fn batch_respond_empty_is_bad_request() {
    let (admin, _) = make_admin();
    let err =
        handle_batch_respond(&admin, BatchRespondRequest { decisions: vec![] }, 500).unwrap_err();
    assert_eq!(err.status(), 400);
}

#[test]
fn respond_rejects_untrusted_approver() {
    let (admin, store) = make_admin();
    let trusted_approver = Keypair::generate();
    let rogue_approver = Keypair::generate();
    let subject = Keypair::generate();
    store_pending(
        &store,
        "a-1",
        "h-1",
        &subject,
        &[trusted_approver.public_key()],
    );

    let token = sign_token(
        &rogue_approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: rogue_approver.public_key(),
        token,
    };
    let err = handle_respond(&admin, "a-1", body, 500).unwrap_err();
    assert_eq!(err.status(), 403);
    match err {
        ApprovalHandlerError::Rejected(message) => {
            assert!(message.contains("not trusted"), "{message}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn threshold_handlers_collect_and_deliver_original_tokens() {
    let legacy_store = Arc::new(InMemoryApprovalStore::new());
    let authority = Keypair::generate();
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let subject = Keypair::generate();
    let policy_hash = sha256_hex(b"http-threshold-policy");
    let requirement = ThresholdApprovalRequirement::new(
        policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".to_string(),
                public_key: alice.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".to_string(),
                public_key: bob.public_key(),
            },
        ],
        "directory-v1".to_string(),
        100,
    )
    .unwrap();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "http-proposal".to_string(),
            request_id: "http-request".to_string(),
            governed_intent_hash: sha256_hex(b"http-intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"http-capability"),
            policy_hash: policy_hash.clone(),
            threshold: 2,
            eligible_set_digest: requirement.eligible_set_digest.clone(),
            proposal_created_at: 100,
            proposal_deadline: 200,
            policy_authority: authority.public_key(),
        },
        &authority,
    )
    .unwrap();
    let collector = ThresholdApprovalCollector::new(
        Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
        policy_hash,
        vec![authority.public_key()],
    );
    let admin = ApprovalAdmin::with_threshold_collector(legacy_store, collector);
    handle_create_threshold_proposal(
        &admin,
        CreateThresholdProposalRequest {
            proposal: proposal.clone(),
            requirement,
            submitter: None,
            require_submitter_separation: false,
        },
        100,
    )
    .unwrap();

    let make_token = |approver: &Keypair, id: &str| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest().unwrap()),
                issued_at: 101,
                expires_at: 199,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    };
    let collecting = handle_submit_threshold_approval(
        &admin,
        "http-proposal",
        SubmitThresholdApprovalRequest {
            token: make_token(&alice, "http-token-alice"),
        },
        110,
    )
    .unwrap();
    assert_eq!(
        collecting.state,
        ThresholdApprovalCollectorState::Collecting
    );
    let ready = handle_submit_threshold_approval(
        &admin,
        "http-proposal",
        SubmitThresholdApprovalRequest {
            token: make_token(&bob, "http-token-bob"),
        },
        111,
    )
    .unwrap();
    assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);

    let delivered = handle_deliver_threshold_approval(&admin, "http-proposal", 112).unwrap();
    assert_eq!(delivered.proposal, proposal);
    assert_eq!(
        delivered
            .tokens
            .iter()
            .map(|token| token.id.as_str())
            .collect::<Vec<_>>(),
        vec!["http-token-alice", "http-token-bob"]
    );
}
