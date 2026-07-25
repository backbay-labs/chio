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
// approval behaviour.

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
use crate::governed_active_response::{
    GovernedActiveResponseDispatchCommit, GovernedActiveResponseRequest,
};
use crate::threshold_approval::ThresholdApprovalRequirementResolver;
use chio_log_redact::redacted;
use chio_core::capability::governance::{
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntentBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ACTIVE_RESPONSE_PLAN_TOOL_NAME,
    ACTIVE_RESPONSE_SERVER_ID, GOVERNED_RESPONSE_PLAN_SCHEMA,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};

struct FixedThresholdRequirement(ThresholdApprovalRequirement);

impl ThresholdApprovalRequirementResolver for FixedThresholdRequirement {
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        _server_id: &str,
        _tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String> {
        Ok((policy_hash == self.0.policy_hash).then(|| self.0.clone()))
    }
}

type CoreKeypair = Keypair;

struct ActiveResponseFixture<'a> {
    kernel: &'a ChioKernel,
    requirement: &'a ThresholdApprovalRequirement,
    policy_authority: &'a CoreKeypair,
    approvers: [&'a CoreKeypair; 2],
    executor: &'a CoreKeypair,
    now: u64,
}

impl ActiveResponseFixture<'_> {
    fn request(
        &self,
        request_id: &str,
        effects: Vec<GovernedResponseEffect>,
        grants: Vec<ToolGrant>,
    ) -> GovernedActiveResponseRequest {
        let capability = make_capability(self.kernel, self.executor, make_scope(grants), 600);
        let canonical_plan_body = serde_json::json!({
            "actionId": request_id,
            "effects": effects,
            "target": {"sessionId": "session-active-1"}
        });
        let plan_body_hash =
            GovernedResponsePlanIntentBody::plan_body_hash(&canonical_plan_body).unwrap();
        let expires_at = self.now + 240;
        let intent = GovernedTransactionIntent {
            id: request_id.to_owned(),
            server_id: ACTIVE_RESPONSE_SERVER_ID.to_owned(),
            tool_name: ACTIVE_RESPONSE_PLAN_TOOL_NAME.to_owned(),
            purpose: "contain compromised session".to_owned(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: GovernedTransactionIntentBody::ActiveResponsePlan(Box::new(
                GovernedResponsePlanIntentBody {
                    plan_schema: GOVERNED_RESPONSE_PLAN_SCHEMA.to_owned(),
                    plan_id: request_id.to_owned(),
                    operator_capability_id: capability.id.clone(),
                    operator_capability_hash: sha256_hex(
                        &canonical_json_bytes(&capability).unwrap(),
                    ),
                    operator_capability_expires_at: capability.expires_at,
                    executor_subject: capability.subject.clone(),
                    canonical_plan_body,
                    plan_body_hash,
                    target_binding: serde_json::json!({"sessionId": "session-active-1"}),
                    ordered_effects: effects,
                    expires_at,
                    rollback_binding: serde_json::json!({"mode": "remove_contributions"}),
                },
            )),
        };
        let governed_intent_hash = intent.binding_hash().unwrap();
        let proposal_created_at = self.now;
        let proposal_deadline = ThresholdApprovalProposalBody::proposal_deadline(
            proposal_created_at,
            self.requirement.timeout_seconds,
            capability.expires_at,
            Some(expires_at),
        )
        .unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: format!("proposal-{request_id}"),
                request_id: request_id.to_owned(),
                governed_intent_hash: governed_intent_hash.clone(),
                subject: capability.subject.clone(),
                authorizing_capability_digest: sha256_hex(
                    &canonical_json_bytes(&capability).unwrap(),
                ),
                policy_hash: self.requirement.policy_hash.clone(),
                threshold: self.requirement.threshold,
                eligible_set_digest: self.requirement.eligible_set_digest.clone(),
                proposal_created_at,
                proposal_deadline,
                policy_authority: self.policy_authority.public_key(),
            },
            self.policy_authority,
        )
        .unwrap();
        let proposal_hash = proposal.artifact_digest().unwrap();
        let approval_tokens = self
            .approvers
            .into_iter()
            .enumerate()
            .map(|(index, approver)| {
                GovernedApprovalToken::sign(
                    GovernedApprovalTokenBody {
                        id: format!("token-{request_id}-{index}"),
                        approver: approver.public_key(),
                        subject: capability.subject.clone(),
                        governed_intent_hash: governed_intent_hash.clone(),
                        request_id: request_id.to_owned(),
                        threshold_proposal_hash: Some(proposal_hash.clone()),
                        issued_at: self.now,
                        expires_at: proposal_deadline,
                        decision: GovernedApprovalDecision::Approved,
                    },
                    approver,
                )
                .unwrap()
            })
            .collect();
        GovernedActiveResponseRequest {
            request_id: request_id.to_owned(),
            operator_capability: capability,
            governed_intent: intent,
            approval_tokens,
            threshold_approval_proposal: proposal,
            federated_origin_kernel_id: None,
        }
    }
}

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
        threshold_proposal_hash: None,
        issued_at: now.saturating_sub(10),
        expires_at: now + 600,
        decision,
    };
    GovernedApprovalToken::sign(body, approver).unwrap()
}

#[test]
fn threshold_approval_set_is_policy_bound_and_order_independent() {
    let policy_hash = sha256_hex(b"threshold-policy");
    let policy_authority = CoreKeypair::generate();
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let approver_c = CoreKeypair::generate();
    let mut config = make_config();
    config.policy_hash = policy_hash.clone();
    config.ca_public_keys.push(policy_authority.public_key());
    let mut kernel = make_kernel(config);
    let requirement = ThresholdApprovalRequirement::new(
        policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".to_string(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".to_string(),
                public_key: approver_b.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "carol".to_string(),
                public_key: approver_c.public_key(),
            },
        ],
        "directory-v1".to_string(),
        300,
    )
    .unwrap();
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(
        FixedThresholdRequirement(requirement.clone()),
    ));

    let subject = CoreKeypair::generate();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-threshold", "transfer")]),
        600,
    );
    let intent = GovernedTransactionIntent {
        id: "intent-threshold-1".to_string(),
        server_id: "srv-threshold".to_string(),
        tool_name: "transfer".to_string(),
        purpose: "approve transfer".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let intent_hash = intent.binding_hash().unwrap();
    let now = current_unix_timestamp();
    let capability_digest = sha256_hex(&canonical_json_bytes(&cap).unwrap());
    let proposal_created_at = now.saturating_sub(5);
    let proposal_deadline = ThresholdApprovalProposalBody::proposal_deadline(
        proposal_created_at,
        requirement.timeout_seconds,
        cap.expires_at,
        None,
    )
    .unwrap();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-threshold-1".to_string(),
            request_id: "request-threshold-1".to_string(),
            governed_intent_hash: intent_hash.clone(),
            subject: cap.subject.clone(),
            authorizing_capability_digest: capability_digest,
            policy_hash,
            threshold: requirement.threshold,
            eligible_set_digest: requirement.eligible_set_digest.clone(),
            proposal_created_at,
            proposal_deadline,
            policy_authority: policy_authority.public_key(),
        },
        &policy_authority,
    )
    .unwrap();
    let proposal_hash = proposal.artifact_digest().unwrap();
    let make_token = |id: &str, approver: &CoreKeypair| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_string(),
                approver: approver.public_key(),
                subject: cap.subject.clone(),
                governed_intent_hash: intent_hash.clone(),
                request_id: "request-threshold-1".to_string(),
                threshold_proposal_hash: Some(proposal_hash.clone()),
                issued_at: now,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    };
    let token_a = make_token("token-a", &approver_a);
    let token_b = make_token("token-b", &approver_b);
    let mut request = make_request(
        "request-threshold-1",
        &cap,
        "transfer",
        "srv-threshold",
    );
    request.governed_intent = Some(intent);
    request.approval_tokens = vec![token_b.clone(), token_a.clone()];
    request.threshold_approval_proposal = Some(proposal.clone());
    let first_digest = request.approval_artifact_digest().unwrap();
    request.approval_tokens = vec![token_a, token_b];
    assert_eq!(first_digest, request.approval_artifact_digest().unwrap());

    let verified = kernel
        .validate_threshold_approval_set(&request, &cap, &intent_hash, now)
        .unwrap();
    assert_eq!(verified.body.threshold, 2);
    assert_eq!(verified.body.token_digests.len(), 2);

    let mut insufficient = request.clone();
    insufficient.approval_tokens.pop();
    let error = kernel
        .validate_threshold_approval_set(&insufficient, &cap, &intent_hash, now)
        .unwrap_err();
    assert!(error.to_string().contains("quorum"));

    let mut extended_proposal = proposal.body.clone();
    extended_proposal.proposal_deadline = extended_proposal.proposal_deadline.saturating_add(1);
    let extended_proposal =
        ThresholdApprovalProposal::sign(extended_proposal, &policy_authority).unwrap();
    let extended_hash = extended_proposal.artifact_digest().unwrap();
    let mut extended = request;
    extended.approval_tokens = [&approver_a, &approver_b]
        .into_iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("extended-token-{index}"),
                    approver: approver.public_key(),
                    subject: cap.subject.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    request_id: "request-threshold-1".to_string(),
                    threshold_proposal_hash: Some(extended_hash.clone()),
                    issued_at: now,
                    expires_at: extended_proposal.body.proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        })
        .collect();
    extended.threshold_approval_proposal = Some(extended_proposal);
    let error = kernel
        .validate_threshold_approval_set(&extended, &cap, &intent_hash, now)
        .unwrap_err();
    assert!(error.to_string().contains("active policy"));
}

#[test]
fn active_response_approval_is_durable_and_recovery_does_not_recommit_dispatch() {
    let policy_hash = sha256_hex(b"active-response-policy");
    let policy_authority = CoreKeypair::generate();
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".to_owned(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".to_owned(),
                public_key: approver_b.public_key(),
            },
        ],
        "active-response-directory-v1".to_owned(),
        300,
    )
    .unwrap();
    let mut config = make_config();
    config.policy_hash = policy_hash;
    config.ca_public_keys.push(policy_authority.public_key());
    let mut kernel = make_kernel(config);
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(
        FixedThresholdRequirement(requirement.clone()),
    ));

    let fence = admission_test_fence();
    let store = StdArc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .unwrap();

    let executor = CoreKeypair::generate();
    let effects = vec![
        GovernedResponseEffect::RestrictEgress,
        GovernedResponseEffect::SuspendSession,
    ];
    let grants = effects
        .iter()
        .map(|effect| make_grant(ACTIVE_RESPONSE_SERVER_ID, effect.tool_name()))
        .collect();
    let now = current_unix_timestamp().saturating_add(60);
    let fixture = ActiveResponseFixture {
        kernel: &kernel,
        requirement: &requirement,
        policy_authority: &policy_authority,
        approvers: [&approver_a, &approver_b],
        executor: &executor,
        now,
    };
    let request = fixture.request(
        "active-response-1",
        effects.clone(),
        grants,
    );

    let mut mismatched = request.clone();
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &mut mismatched.governed_intent.body
    else {
        panic!("active-response body");
    };
    plan.canonical_plan_body["actionId"] = serde_json::json!("substituted-response");
    assert!(kernel
        .admit_governed_active_response_at(&mismatched, now, now * 1_000)
        .unwrap_err()
        .to_string()
        .contains("body hash"));

    let mut mismatched_effects = fixture.request(
        "active-response-mismatched-effects",
        vec![GovernedResponseEffect::RestrictEgress],
        vec![make_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &mut mismatched_effects.governed_intent.body
    else {
        panic!("active-response body");
    };
    plan.canonical_plan_body["effects"] = serde_json::json!([
        GovernedResponseEffect::RestrictEgress,
        GovernedResponseEffect::SuspendSession
    ]);
    plan.plan_body_hash =
        GovernedResponsePlanIntentBody::plan_body_hash(&plan.canonical_plan_body).unwrap();
    assert!(kernel
        .admit_governed_active_response_at(&mismatched_effects, now, now * 1_000)
        .unwrap_err()
        .to_string()
        .contains("effects do not match"));

    let mut raw_plan_hash = request.clone();
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &raw_plan_hash.governed_intent.body
    else {
        panic!("active-response body");
    };
    let substituted_hash = plan.plan_body_hash.clone();
    let mut substituted_proposal = raw_plan_hash.threshold_approval_proposal.body.clone();
    substituted_proposal.governed_intent_hash = substituted_hash.clone();
    raw_plan_hash.threshold_approval_proposal =
        ThresholdApprovalProposal::sign(substituted_proposal, &policy_authority).unwrap();
    let substituted_proposal_hash = raw_plan_hash
        .threshold_approval_proposal
        .artifact_digest()
        .unwrap();
    raw_plan_hash.approval_tokens = [&approver_a, &approver_b]
        .into_iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("raw-plan-token-{index}"),
                    approver: approver.public_key(),
                    subject: raw_plan_hash.operator_capability.subject.clone(),
                    governed_intent_hash: substituted_hash.clone(),
                    request_id: raw_plan_hash.request_id.clone(),
                    threshold_proposal_hash: Some(substituted_proposal_hash.clone()),
                    issued_at: now,
                    expires_at: raw_plan_hash
                        .threshold_approval_proposal
                        .body
                        .proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        })
        .collect();
    assert!(kernel
        .admit_governed_active_response_at(&raw_plan_hash, now, now * 1_000)
        .unwrap_err()
        .to_string()
        .contains("proposal does not match"));

    let missing_grant = fixture.request(
        "active-response-missing-grant",
        effects,
        vec![make_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    assert!(kernel
        .admit_governed_active_response_at(&missing_grant, now, now * 1_000)
        .unwrap_err()
        .to_string()
        .contains("suspend_session"));

    let revoked = fixture.request(
        "active-response-revoked",
        vec![GovernedResponseEffect::RestrictEgress],
        vec![make_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    kernel.set_revocation_store(Box::new(crate::InMemoryRevocationStore::new()));
    kernel
        .revoke_capability(&revoked.operator_capability.id)
        .unwrap();
    assert!(matches!(
        kernel.admit_governed_active_response_at(&revoked, now, now * 1_000),
        Err(KernelError::CapabilityRevoked(id)) if id == revoked.operator_capability.id
    ));

    let admitted = kernel
        .admit_governed_active_response_at(&request, now, now * 1_000)
        .unwrap();
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(admitted.requirement(), &requirement);
    assert_eq!(
        admitted.operator_capability().capability_id,
        request.operator_capability.id
    );
    assert_eq!(
        admitted.operation().binding().kind(),
        crate::admission_operation::AdmissionOperationKind::GovernedActiveResponse
    );
    assert_eq!(
        admitted.operation().binding().participant_requirements(),
        crate::admission_operation::AdmissionParticipantRequirements {
            approval: true,
            ..crate::admission_operation::AdmissionParticipantRequirements::NONE
        }
    );
    assert_eq!(
        admitted.approval_set().approval_set_hash().unwrap(),
        admitted.approval_set_hash()
    );
    let operation_id = admitted.operation_id().to_owned();
    let mut mismatched_approval_set = request.clone();
    mismatched_approval_set.approval_tokens = mismatched_approval_set
        .approval_tokens
        .iter()
        .zip([&approver_a, &approver_b])
        .enumerate()
        .map(|(index, (token, approver))| {
            let mut body = token.body();
            let replacement_token_id =
                redacted!(format!("replacement-active-response-token-{index}")).to_string();
            body.id = replacement_token_id;
            GovernedApprovalToken::sign(body, approver).unwrap()
        })
        .collect();
    assert!(kernel
        .admit_governed_active_response_at(&mismatched_approval_set, now, now * 1_000)
        .unwrap_err()
        .to_string()
        .contains("retained approval reservation"));
    let mut admitted = kernel
        .admit_governed_active_response_at(&request, now, now * 1_000)
        .expect("mismatched replay must not compensate retained admission");
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(
        kernel
            .commit_governed_active_response_dispatch_at(&mut admitted, now * 1_000)
            .unwrap(),
        GovernedActiveResponseDispatchCommit::Committed
    );
    assert_eq!(admitted.state(), AdmissionOperationState::DispatchCommitted);

    let mut recovered = kernel
        .admit_governed_active_response_at(&request, now, now * 1_000)
        .unwrap();
    assert_eq!(recovered.operation_id(), operation_id);
    assert_eq!(recovered.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(
        kernel
            .commit_governed_active_response_dispatch_at(&mut recovered, now * 1_000)
            .unwrap(),
        GovernedActiveResponseDispatchCommit::AlreadyCommitted
    );
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
        threshold_proposal_hash: None,
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

#[test]
fn governed_approval_token_binds_every_authorization_field_and_time_window(
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        RequestId,
        IntentHash,
        Subject,
        Approver,
        Decision,
        IssuedAt,
        ExpiresAt,
    }

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "governed-token-binding".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "intent-hash".to_string(),
            request_id: "request-1".to_string(),
            threshold_proposal_hash: None,
            issued_at: 1_000,
            expires_at: 2_000,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )?;

    assert!(token.verify_signature_at(1_500)?);

    for mutation in [
        Mutation::RequestId,
        Mutation::IntentHash,
        Mutation::Subject,
        Mutation::Approver,
        Mutation::Decision,
        Mutation::IssuedAt,
        Mutation::ExpiresAt,
    ] {
        let mut mutated = token.clone();
        match mutation {
            Mutation::RequestId => mutated.request_id = "request-2".to_string(),
            Mutation::IntentHash => {
                mutated.governed_intent_hash = "different-intent-hash".to_string();
            }
            Mutation::Subject => mutated.subject = CoreKeypair::generate().public_key(),
            Mutation::Approver => mutated.approver = CoreKeypair::generate().public_key(),
            Mutation::Decision => mutated.decision = GovernedApprovalDecision::Denied,
            Mutation::IssuedAt => mutated.issued_at = 999,
            Mutation::ExpiresAt => mutated.expires_at = 2_001,
        }
        assert!(
            matches!(mutated.verify_signature_at(1_500), Ok(false)),
            "{mutation:?} mutation must invalidate the signature"
        );
    }

    let not_yet_valid = token.verify_signature_at(999);
    assert!(
        not_yet_valid
            .as_ref()
            .is_err_and(|error| error.to_string().contains("not yet valid")),
        "unexpected not-yet-valid result: {not_yet_valid:?}"
    );
    let expired = token.verify_signature_at(2_000);
    assert!(
        expired
            .as_ref()
            .is_err_and(|error| error.to_string().contains("expired")),
        "unexpected expiry result: {expired:?}"
    );

    Ok(())
}
