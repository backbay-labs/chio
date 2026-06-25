#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test exercising the portable kernel core against a
//! realistic capability + guard + request tuple.
//!
//! This test doubles as the "portable build proof": it drives the
//! public API without touching any `std::*` type, and compiles as a
//! regular `cargo test` target. When `chio-core-types` is made
//! `no_std`, this same file will cross-compile to
//! `wasm32-unknown-unknown` unchanged.

use chio_core_types::capability::{
    attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof},
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::signing::ReceiptSigningHandle;
use chio_core_types::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
};
use chio_kernel_core::{
    evaluate, sign_receipt, sign_receipt_relaying_trusted_body, sign_receipt_with_handle,
    verify_capability, CapabilityError, EvaluateInput, FixedClock, Guard, GuardContext,
    KernelCoreError, PortableToolCallRequest, ReceiptSigningError, Verdict,
};
use serde_json::json;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    make_capability_with_constraints(subject, issuer, vec![])
}

fn make_capability_with_constraints(
    subject: &Keypair,
    issuer: &Keypair,
    constraints: Vec<Constraint>,
) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let body = CapabilityTokenBody {
        id: "cap-1".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

fn make_attenuated_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    let parent_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent_scope).unwrap(),
        child_scope_hash: scope_hash(&child_scope).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(&parent_scope, &child_scope).unwrap(),
    };
    let body = CapabilityTokenBody {
        id: "cap-attenuated-evaluate".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child_scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
    };
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        issuer,
    )
    .unwrap()
}

fn make_request(subject: &Keypair) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: "req-1".to_string(),
        tool_name: "echo".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({"msg": "hello"}),
    }
}

struct AllowGuard;

impl Guard for AllowGuard {
    fn name(&self) -> &str {
        "allow-all"
    }
    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<Verdict, KernelCoreError> {
        Ok(Verdict::Allow)
    }
}

struct DenyGuard;

impl Guard for DenyGuard {
    fn name(&self) -> &str {
        "deny-all"
    }
    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<Verdict, KernelCoreError> {
        Ok(Verdict::Deny)
    }
}

struct ErrorGuard;

impl Guard for ErrorGuard {
    fn name(&self) -> &str {
        "error-all"
    }
    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<Verdict, KernelCoreError> {
        Err(KernelCoreError::ConstraintError {
            reason: "guard failed internally".to_string(),
        })
    }
}

#[test]
fn evaluate_allow_path() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let allow_guard = AllowGuard;
    let guards: Vec<&dyn Guard> = vec![&allow_guard];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_allow());
    assert_eq!(verdict.matched_grant_index, Some(0));
    assert!(verdict.verified.is_some());
}

#[test]
fn evaluate_rejects_attenuated_capability_without_trust_root_binding() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_attenuated_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    assert!(verdict.verified.is_none());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("chain-binding"), "reason was: {reason}");
    assert!(reason.contains("trust-root"), "reason was: {reason}");
}

#[test]
fn evaluate_deny_on_guard() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let deny_guard = DenyGuard;
    let guards: Vec<&dyn Guard> = vec![&deny_guard];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("deny-all"), "reason was: {reason}");
}

#[test]
fn evaluate_deny_on_guard_error() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let error_guard = ErrorGuard;
    let guards: Vec<&dyn Guard> = vec![&error_guard];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("fail-closed"), "reason was: {reason}");
    assert!(reason.contains("error-all"), "reason was: {reason}");
}

#[test]
fn evaluate_out_of_scope() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let mut request = make_request(&subject);
    request.tool_name = "unknown-tool".to_string();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("not in capability scope"));
}

#[test]
fn evaluate_enforces_path_prefix_constraint() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_with_constraints(
        &subject,
        &issuer,
        vec![Constraint::PathPrefix("/workspace/safe".to_string())],
    );
    let mut request = make_request(&subject);
    request.arguments = serde_json::json!({"path": "/workspace/unsafe/file.txt"});
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(
        reason.contains("not in capability scope"),
        "reason was: {reason}"
    );
}

#[test]
fn evaluate_rejects_path_traversal_against_path_prefix_constraint() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_with_constraints(
        &subject,
        &issuer,
        vec![Constraint::PathPrefix("/workspace/safe".to_string())],
    );
    let mut request = make_request(&subject);
    request.arguments = serde_json::json!({"path": "/workspace/safe/../secret.txt"});
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
}

#[test]
fn evaluate_rejects_sibling_prefix_match_for_path_constraint() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_with_constraints(
        &subject,
        &issuer,
        vec![Constraint::PathPrefix("/workspace/safe".to_string())],
    );
    let mut request = make_request(&subject);
    request.arguments = serde_json::json!({"path": "/workspace/safeX/file.txt"});
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
}

#[test]
fn evaluate_fails_closed_on_unsupported_constraint() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability_with_constraints(
        &subject,
        &issuer,
        vec![Constraint::MinimumRuntimeAssurance(
            chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier::Attested,
        )],
    );
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(
        reason.contains("constraint evaluation failed"),
        "reason was: {reason}"
    );
    assert!(
        reason.contains("minimum_runtime_assurance"),
        "reason was: {reason}"
    );
}

#[test]
fn resolve_matching_grants_fails_closed_when_target_match_has_unsupported_constraint() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![
                    ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "echo".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::MinimumRuntimeAssurance(
                            chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier::Attested,
                        )],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                    ToolGrant {
                        server_id: "*".to_string(),
                        tool_name: "*".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                ],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            delegation_chain: vec![],
        },
        &issuer,
    )
    .unwrap();

    let error = chio_kernel_core::scope::resolve_matching_grants(
        &capability.scope,
        "echo",
        "srv-a",
        &serde_json::json!({"msg": "hello"}),
    )
    .expect_err("unsupported target-matching constraints must fail closed");

    match error {
        chio_kernel_core::ScopeMatchError::ConstraintError(reason) => {
            assert!(
                reason.contains("minimum_runtime_assurance"),
                "reason was: {reason}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn resolve_matching_grants_ignores_unsupported_constraints_on_unrelated_grants() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![
                    ToolGrant {
                        server_id: "srv-b".to_string(),
                        tool_name: "echo".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::MinimumRuntimeAssurance(
                            chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier::Attested,
                        )],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                    ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "echo".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                ],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            delegation_chain: vec![],
        },
        &issuer,
    )
    .unwrap();

    let matches = chio_kernel_core::scope::resolve_matching_grants(
        &capability.scope,
        "echo",
        "srv-a",
        &serde_json::json!({"msg": "hello"}),
    )
    .expect("unrelated unsupported constraints must not block authorized matches");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].grant.server_id, "srv-a");
}

#[test]
fn evaluate_expired_capability() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(EXPIRES_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("expired"));
}

#[test]
fn evaluate_subject_mismatch() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let mut request = make_request(&subject);
    request.agent_id = Keypair::generate().public_key().to_hex();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("does not match capability subject"));
}

#[test]
fn verify_capability_untrusted_issuer() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let clock = FixedClock::new(ISSUED_AT + 1);

    let err = verify_capability(&capability, &[other.public_key()], &clock).unwrap_err();
    assert_eq!(err, CapabilityError::UntrustedIssuer);
}

#[test]
fn sign_receipt_with_backend() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let body = ChioReceiptBody {
        id: "rcpt-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };

    let receipt = sign_receipt_relaying_trusted_body(body, &backend).unwrap();
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn sign_receipt_preserves_signed_body_fields() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let body = ChioReceiptBody {
        id: "rcpt-preserve-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-preserve-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Deny {
            reason: "blocked".to_string(),
            guard: "test-guard".to_string(),
        }),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "3".repeat(64),
        policy_hash: "4".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("tenant-a".to_string()),
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };

    let receipt = sign_receipt_relaying_trusted_body(body.clone(), &backend).unwrap();

    assert!(receipt.verify_signature().unwrap());
    // body.id is the content-addressed hash assigned by signing (verify_signature
    // re-derives and checks it); the caller-supplied id becomes the signing nonce.
    assert_eq!(receipt.body().capability_id, body.capability_id);
    assert_eq!(receipt.body().tool_server, body.tool_server);
    assert_eq!(receipt.body().tool_name, body.tool_name);
    assert_eq!(receipt.body().decision, body.decision);
    assert_eq!(receipt.body().policy_hash, body.policy_hash);
    assert_eq!(receipt.body().tenant_id, body.tenant_id);
}

#[test]
fn sign_receipt_rejects_kernel_key_mismatch() {
    let keypair = Keypair::generate();
    let other_keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair);

    let body = ChioReceiptBody {
        id: "rcpt-mismatch-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-mismatch-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "5".repeat(64),
        policy_hash: "6".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: other_keypair.public_key(),
        bbs_projection_version: None,
    };

    let error = sign_receipt_relaying_trusted_body(body, &backend).unwrap_err();
    assert_eq!(
        error,
        chio_kernel_core::ReceiptSigningError::KernelKeyMismatch
    );
}

#[test]
fn sign_receipt_signature_changes_when_economic_authorization_changes() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let mut body = ChioReceiptBody {
        id: "rcpt-economic-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-economic-1".to_string(),
        tool_server: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        action: ToolCallAction::from_parameters(json!({"invoice_id": "inv-1"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "1".repeat(64),
        policy_hash: "2".repeat(64),
        evidence: vec![],
        metadata: Some(json!({
            "governed_transaction": {
                "economic_authorization": {
                    "version": "v1",
                    "economic_mode": "metered_hold_capture",
                    "budget": {
                        "currency": "USD",
                        "cost_charged": 230,
                        "budget_remaining": 770,
                        "budget_total": 1000
                    }
                }
            }
        })),
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };

    let original = sign_receipt_relaying_trusted_body(body.clone(), &backend).unwrap();
    body.metadata = Some(json!({
        "governed_transaction": {
            "economic_authorization": {
                "version": "v1",
                "economic_mode": "metered_hold_capture",
                "budget": {
                    "currency": "USD",
                    "cost_charged": 231,
                    "budget_remaining": 769,
                    "budget_total": 1000
                }
            }
        }
    }));
    let changed = sign_receipt_relaying_trusted_body(body, &backend).unwrap();

    assert!(original.verify_signature().unwrap());
    assert!(changed.verify_signature().unwrap());
    assert_ne!(original.signature.to_hex(), changed.signature.to_hex());
}

/// Build a money-touching receipt body whose `content_hash` field is set
/// independently of any specific content, so a test can assert the signer
/// either accepts (matching hash) or refuses (mismatched hash) it.
fn wysiwys_body(keypair: &Keypair, content_hash: String) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-wysiwys-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-wysiwys-1".to_string(),
        tool_server: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        action: ToolCallAction::from_parameters(json!({"invoice_id": "inv-99"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash,
        policy_hash: "0".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

/// BAC-539 regression: the render-A / sign-B forgery is rejected.
///
/// A caller evaluates and renders content `A` to a human (so the human "sees"
/// the hash of `A`), but submits a receipt body claiming the hash of a
/// different content `B`. The signing handle is bound to `A`; the signer must
/// recompute `content_hash` over `A` and refuse, because the body claims `B`.
#[test]
fn sign_receipt_with_handle_rejects_render_a_sign_b() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    // Content A is what was actually evaluated and shown to the human.
    let content_a = json!({"transfer": {"to": "alice", "amount": 5}});
    // Content B is what the attacker wants the signature to silently cover.
    let content_b = json!({"transfer": {"to": "mallory", "amount": 5000}});

    // The handle is bound to A (the trust boundary recomputes its hash).
    let handle = ReceiptSigningHandle::from_content(&content_a).unwrap();

    // The caller submits a body claiming the hash of B (render-A / sign-B).
    let hash_b = chio_core_types::crypto::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&content_b).unwrap(),
    );
    let body = wysiwys_body(&keypair, hash_b.clone());

    let error = sign_receipt_with_handle(body, &backend, handle).unwrap_err();
    match error {
        ReceiptSigningError::ContentHashMismatch {
            recomputed,
            claimed,
        } => {
            // The signer recomputed the hash of A and refused the claimed B.
            let hash_a = chio_core_types::crypto::sha256_hex(
                &chio_core_types::canonical::canonical_json_bytes(&content_a).unwrap(),
            );
            assert_eq!(recomputed, hash_a);
            assert_eq!(claimed, hash_b);
            assert_ne!(recomputed, claimed);
        }
        other => panic!("expected ContentHashMismatch, got {other:?}"),
    }
}

/// BAC-539: signing succeeds when the body's claimed `content_hash` matches the
/// hash recomputed over the handle's canonical content, and the signed bytes
/// correspond to that recomputed content.
#[test]
fn sign_receipt_with_handle_accepts_matching_content_and_binds_recomputed_hash() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let content = json!({"transfer": {"to": "alice", "amount": 5}});
    let handle = ReceiptSigningHandle::from_content(&content).unwrap();
    let recomputed = handle.content_hash().to_string();

    // Honest caller: the body's content_hash is the hash of the real content.
    let body = wysiwys_body(&keypair, recomputed.clone());

    let receipt = sign_receipt_with_handle(body, &backend, handle).unwrap();

    // The signature verifies and the signed receipt carries exactly the
    // recomputed hash -- the signed bytes correspond to the canonical content.
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.content_hash, recomputed);
    let expected = chio_core_types::crypto::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&content).unwrap(),
    );
    assert_eq!(receipt.content_hash, expected);
}

/// BAC-539: the recompute gate runs before the kernel-key check and before any
/// signing work, so a hash mismatch fails closed even with a valid backend.
#[test]
fn sign_receipt_with_handle_is_fail_closed_on_any_mismatch() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let content = json!({"ok": true});
    let handle = ReceiptSigningHandle::from_content(&content).unwrap();

    // Body claims an all-zero hash that does not match the real content.
    let body = wysiwys_body(&keypair, "0".repeat(64));

    let error = sign_receipt_with_handle(body, &backend, handle).unwrap_err();
    assert!(matches!(
        error,
        ReceiptSigningError::ContentHashMismatch { .. }
    ));
}

/// BAC-539 (cycle 2) regression on the **production / non-handle** signing path.
///
/// `sign_receipt` is the primitive the production kernel signing path
/// (`build_and_sign_receipt` / the mpsc signing task) calls for every live
/// receipt. Before this change it trusted the caller-supplied
/// `body.content_hash`, leaving render-A / sign-B open on the live path. This
/// test proves the hole is closed: `sign_receipt` recomputes `content_hash`
/// over the supplied canonical content inside the trust boundary and refuses to
/// sign when the body claims the hash of a *different* content `B`, even though
/// the kernel key matches and the backend is valid.
#[test]
fn sign_receipt_production_path_rejects_render_a_sign_b() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    // Content A is what was actually evaluated/rendered to the human; the
    // production signer is handed the exact canonical bytes of A.
    let content_a = json!({"transfer": {"to": "alice", "amount": 5}});
    let canonical_a = chio_core_types::canonical::canonical_json_bytes(&content_a).unwrap();
    let hash_a = chio_core_types::crypto::sha256_hex(&canonical_a);

    // Content B is what the attacker wants the signature to silently cover.
    let content_b = json!({"transfer": {"to": "mallory", "amount": 5000}});
    let hash_b = chio_core_types::crypto::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&content_b).unwrap(),
    );
    assert_ne!(hash_a, hash_b);

    // Render-A / sign-B: the body claims hash(B) while the signer is given the
    // canonical content of A.
    let body = wysiwys_body(&keypair, hash_b.clone());

    let error = sign_receipt(body, &backend, &canonical_a).unwrap_err();
    match error {
        ReceiptSigningError::ContentHashMismatch {
            recomputed,
            claimed,
        } => {
            // The production signer recomputed hash(A) and refused claimed B.
            assert_eq!(recomputed, hash_a);
            assert_eq!(claimed, hash_b);
            assert_ne!(recomputed, claimed);
        }
        other => panic!("expected ContentHashMismatch on the production path, got {other:?}"),
    }
}

/// BAC-539 (cycle 2): the production `sign_receipt` path signs when the body's
/// claimed `content_hash` matches the hash recomputed over the supplied
/// canonical content, and the signed receipt carries exactly that recomputed
/// hash (the signed bytes correspond to the canonical content).
#[test]
fn sign_receipt_production_path_accepts_matching_content() {
    let keypair = Keypair::generate();
    let backend = chio_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let content = json!({"transfer": {"to": "alice", "amount": 5}});
    let canonical = chio_core_types::canonical::canonical_json_bytes(&content).unwrap();
    let recomputed = chio_core_types::crypto::sha256_hex(&canonical);

    // Honest caller: the body's content_hash is the hash of the real content.
    let body = wysiwys_body(&keypair, recomputed.clone());

    let receipt = sign_receipt(body, &backend, &canonical).unwrap();

    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.content_hash, recomputed);
}
