use super::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use chio_core_types::capability::{
    attenuation::{
        compute_attenuation_witness, delegate, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody, ScopeHash,
    },
    features::{CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, CUMULATIVE_APPROVAL_BUDGET},
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::delegation_receipt::ScopeAttenuation;
use chio_core_types::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::BoundaryClass,
    kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin, kinds::TrustLevel,
};
use chio_kernel_core::FixedClock;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(make_capability_body("cap-1", subject, issuer), issuer).unwrap()
}

fn make_delegated_capability(
    id: &str,
    parent_id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> CapabilityToken {
    let body = make_capability_body(id, subject, issuer);
    let parent_scope_hash = scope_hash(&body.scope).unwrap();
    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: std::vec![],
            timestamp: ISSUED_AT,
            scope_hash: Some(parent_scope_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        issuer,
    )
    .unwrap();
    let proof = AttenuationProof {
        parent_scope_hash,
        child_scope_hash: scope_hash(&body.scope).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(&body.scope, &body.scope).unwrap(),
    };
    let mut body = body;
    body.delegation_chain = std::vec![parent_link];
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: std::vec![],
            scope_attenuations: std::vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        issuer,
    )
    .unwrap()
}

fn trust_roots_for_scope(issuer: &Keypair, scope: &ChioScope) -> BTreeMap<String, ScopeHash> {
    let mut roots = BTreeMap::new();
    roots.insert(issuer.public_key().to_hex(), scope_hash(scope).unwrap());
    roots
}

fn parent_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshotJson {
    ParentBudgetSnapshotJson {
        parent_token_id: parent_id.to_string(),
        parent_share_bps: 10_000,
        admitted_children: std::vec![],
    }
}

fn oversubscribed_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshotJson {
    ParentBudgetSnapshotJson {
        parent_token_id: parent_id.to_string(),
        parent_share_bps: 10_000,
        admitted_children: std::vec![AdmittedChildBudgetJson {
            child_token_id: "cap-sibling".to_string(),
            share_bps: 1,
        }],
    }
}

fn make_capability_body(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityTokenBody {
    let scope = ChioScope {
        grants: std::vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: std::vec![Operation::Invoke],
            constraints: std::vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: std::vec![],
        prompt_grants: std::vec![],
    };
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: std::vec![],
        aggregate_invocation_budget: None,
    }
}

fn aggregate_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(AGGREGATE_INVOCATION_BUDGET.to_string(), true);
    peer
}

fn cumulative_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(CUMULATIVE_APPROVAL_BUDGET.to_string(), true);
    peer
}

fn aggregate_family_fixture() -> TestResult<(
    Keypair,
    Keypair,
    CapabilityToken,
    CapabilityToken,
    CapabilityToken,
)> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_body = make_capability_body("cap-aggregate-root", &root_subject, &issuer);
    root_body
        .scope
        .grants
        .first_mut()
        .ok_or_else(|| std::io::Error::other("aggregate root grant missing"))?
        .operations
        .push(Operation::Delegate);
    let root = CapabilityToken::sign_aggregate_family_root(root_body.clone(), 4, &issuer)?;
    let child_body = make_capability_body("cap-aggregate-child", &delegatee, &issuer);
    let receipt = delegate(
        &root,
        &child_body.scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        ISSUED_AT + 1,
        [7_u8; 16],
    )?;
    let mut child_body = child_body;
    child_body.issued_at = ISSUED_AT + 1;
    child_body.delegation_chain = receipt.complete_chain();
    child_body.aggregate_invocation_budget = root.aggregate_invocation_budget.clone();
    let child = CapabilityToken::sign(child_body, &issuer)?;

    root_body.id = "cap-aggregate-wrong-root".to_string();
    root_body.subject = Keypair::generate().public_key();
    let wrong_root = CapabilityToken::sign_aggregate_family_root(root_body, 4, &issuer)?;
    Ok((issuer, delegatee, root, child, wrong_root))
}

fn cumulative_family_fixture(
) -> TestResult<(Keypair, CapabilityToken, CapabilityToken, CapabilityToken)> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_body = make_capability_body("cap-cumulative-root", &root_subject, &issuer);
    let root_grant = root_body
        .scope
        .grants
        .first_mut()
        .ok_or_else(|| std::io::Error::other("cumulative root grant missing"))?;
    root_grant.operations.push(Operation::Delegate);
    root_grant
        .constraints
        .push(cumulative_constraint(100, None));
    let root = CapabilityToken::sign_cumulative_approval_family_root(root_body.clone(), &issuer)?;
    let binding = root
        .scope
        .grants
        .first()
        .and_then(|grant| grant.constraints.first())
        .and_then(Constraint::cumulative_approval_root_binding)
        .cloned()
        .ok_or_else(|| std::io::Error::other("cumulative root binding missing"))?;

    let mut child_body = make_capability_body("cap-cumulative-child", &delegatee, &issuer);
    child_body.scope.grants[0]
        .constraints
        .push(cumulative_constraint(80, Some(binding)));
    let receipt = delegate(
        &root,
        &child_body.scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        ISSUED_AT + 1,
        [8_u8; 16],
    )?;
    child_body.issued_at = ISSUED_AT + 1;
    child_body.delegation_chain = receipt.complete_chain();
    let child = CapabilityToken::sign(child_body, &issuer)?;

    root_body.id = "cap-cumulative-wrong-root".to_string();
    root_body.subject = Keypair::generate().public_key();
    let wrong_root = CapabilityToken::sign_cumulative_approval_family_root(root_body, &issuer)?;
    Ok((issuer, root, child, wrong_root))
}

fn cumulative_constraint(
    threshold_units: u64,
    root_binding: Option<
        chio_core_types::capability::cumulative_approval::CumulativeApprovalRootBinding,
    >,
) -> Constraint {
    Constraint::RequireCumulativeApprovalAbove {
        threshold: MonetaryAmount {
            units: threshold_units,
            currency: "USD".to_string(),
        },
        approval_budget_id: "budget-1".to_string(),
        approval_budget_epoch: 1,
        cumulative_approval_root_binding: root_binding.map(Box::new),
    }
}

fn make_v2_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    let body = make_capability_body("cap-v2", subject, issuer);
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&body.scope).expect("parent scope hash"),
        child_scope_hash: scope_hash(&body.scope).expect("child scope hash"),
        normalized_subset_proof: compute_attenuation_witness(&body.scope, &body.scope)
            .expect("attenuation witness"),
    };
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: std::vec![],
            scope_attenuations: std::vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        issuer,
    )
    .unwrap()
}

fn make_request_json(subject: &Keypair) -> ToolCallRequestJson {
    ToolCallRequestJson {
        request_id: "req-1".to_string(),
        tool_name: "echo".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({"msg": "hello"}),
        governed_intent: None,
        approval_token: None,
        approval_tokens: std::vec::Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
    }
}

#[test]
fn evaluate_pure_allow_path() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request_json(&subject);

    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
    assert_eq!(verdict.verdict, "pending_approval");
    assert_eq!(verdict.capability_verdict, "allow");
    assert!(!verdict.authorized);
    assert_eq!(verdict.authorization_basis, "capability_only");
    assert!(!verdict.guards_evaluated);
    assert!(verdict
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("mediated prevent receipt"));
    assert_eq!(verdict.matched_grant_index, Some(0));
    assert!(verdict.subject_hex.is_some());
    assert!(verdict.issuer_hex.is_some());
    assert_eq!(verdict.capability_id.as_deref(), Some("cap-1"));
}

#[test]
fn evaluate_pure_rejects_unsupported_authorization_extensions() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let mut request = make_request_json(&subject);
    request.supplemental_authorization = Some(serde_json::json!({
        "signed_extension": "b3BhcXVl"
    }));
    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![],
    };

    let error = evaluate_pure(input, &FixedClock::new(ISSUED_AT + 1))
        .expect_err("unsupported authorization extension must fail closed");

    assert_eq!(error.code, "unsupported_authorization_extension");
}

#[test]
fn evaluate_pure_deny_on_expired_capability() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request_json(&subject);

    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(EXPIRES_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![],
    };
    let clock = FixedClock::new(EXPIRES_AT + 1);

    let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
    assert_eq!(verdict.verdict, "deny");
    assert!(verdict
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("expired"));
}

#[test]
fn evaluate_pure_v2_without_trust_root_fails_closed() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_v2_capability(&subject, &issuer);
    let request = make_request_json(&subject);

    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");
    assert_eq!(verdict.verdict, "deny");
    assert!(verdict
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("no trust-root scope hash"));
}

#[test]
fn evaluate_pure_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);
    let request = make_request_json(&subject);

    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots,
        parent_budget_snapshots: std::vec![parent_budget_snapshot("cap-parent")],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");

    assert_eq!(verdict.verdict, "pending_approval");
    assert_eq!(verdict.capability_verdict, "allow");
    assert!(!verdict.authorized);
    assert_eq!(verdict.capability_id.as_deref(), Some("cap-child"));
}

#[test]
fn evaluate_pure_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);
    let request = make_request_json(&subject);

    let input = EvaluateRequestJson {
        request,
        capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots,
        parent_budget_snapshots: std::vec![oversubscribed_budget_snapshot("cap-parent")],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let verdict = evaluate_pure(input, &clock).expect("evaluate_pure");

    assert_eq!(verdict.verdict, "deny");
    assert!(verdict
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("budget split rejected"));
}

#[test]
fn verify_capability_pure_untrusted() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let input = VerifyCapabilityRequestJson {
        token: capability,
        trusted_issuers_hex: std::vec![other.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let err = verify_capability_pure(input, &clock).expect_err("must reject untrusted issuer");
    assert_eq!(err.code, "capability_verification_failed");
    assert!(err.message.contains("not in the trusted set"));
}

#[test]
fn verify_capability_pure_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);

    let input = VerifyCapabilityRequestJson {
        token: capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots,
        parent_budget_snapshots: std::vec![parent_budget_snapshot("cap-parent")],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let verified = verify_capability_pure(input, &clock).expect("verify delegated token");

    assert_eq!(verified.id, "cap-child");
}

#[test]
fn verify_capability_pure_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);
    let capability_trust_roots = trust_roots_for_scope(&issuer, &capability.scope);

    let input = VerifyCapabilityRequestJson {
        token: capability,
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots,
        parent_budget_snapshots: std::vec![oversubscribed_budget_snapshot("cap-parent")],
    };
    let clock = FixedClock::new(ISSUED_AT + 1);

    let err =
        verify_capability_pure(input, &clock).expect_err("oversubscribed sibling must be rejected");

    assert_eq!(err.code, "capability_verification_failed");
    assert!(err.message.contains("sibling-sum budget split"));
}

#[test]
fn negotiated_aggregate_family_requires_matching_root_and_evaluation_denies() -> TestResult {
    let (issuer, subject, root, child, wrong_root) = aggregate_family_fixture()?;
    let clock = FixedClock::new(ISSUED_AT + 2);
    let verify_input = |direct_root_capability| VerifyCapabilityRequestJson {
        token: child.clone(),
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 2),
        peer_capabilities: Some(aggregate_peer()),
        direct_root_capability,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![parent_budget_snapshot(&root.id)],
    };

    let verified = verify_capability_pure(verify_input(Some(root.clone())), &clock)
        .map_err(|error| std::io::Error::other(error.message))?;
    assert_eq!(verified.id, child.id);

    let missing = match verify_capability_pure(verify_input(None), &clock) {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other(
                "delegated aggregate budget accepted without its direct root",
            )
            .into());
        }
    };
    assert!(missing.message.contains("direct-root"));

    let mismatch = match verify_capability_pure(verify_input(Some(wrong_root)), &clock) {
        Err(error) => error,
        Ok(_) => {
            return Err(std::io::Error::other(
                "delegated aggregate budget accepted the wrong root",
            )
            .into());
        }
    };
    assert!(mismatch
        .message
        .contains("does not originate from the authenticated root"));

    let verdict = evaluate_pure(
        EvaluateRequestJson {
            request: make_request_json(&subject),
            capability: child,
            trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 2),
            session_filesystem_roots: None,
            peer_capabilities: Some(aggregate_peer()),
            direct_root_capability: Some(root.clone()),
            capability_trust_roots: BTreeMap::new(),
            parent_budget_snapshots: std::vec![parent_budget_snapshot(&root.id)],
        },
        &clock,
    )
    .map_err(|error| std::io::Error::other(error.message))?;
    assert_eq!(verdict.verdict, "deny");
    assert!(
        verdict
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains(
                "capability feature unsupported on this runtime: aggregate invocation enforcement"
            )),
        "unexpected aggregate denial: {:?}",
        verdict.reason
    );
    Ok(())
}

#[test]
fn negotiated_cumulative_family_requires_matching_root_in_verify_and_evaluate() -> TestResult {
    let (issuer, root, child, wrong_root) = cumulative_family_fixture()?;
    let clock = FixedClock::new(ISSUED_AT + 2);
    let verify_input = |direct_root_capability| VerifyCapabilityRequestJson {
        token: child.clone(),
        trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 2),
        peer_capabilities: Some(cumulative_peer()),
        direct_root_capability,
        capability_trust_roots: BTreeMap::new(),
        parent_budget_snapshots: std::vec![parent_budget_snapshot(&root.id)],
    };

    let verified = verify_capability_pure(verify_input(Some(root.clone())), &clock)
        .map_err(|error| std::io::Error::other(error.message))?;
    assert_eq!(verified.id, child.id);

    for (supplied_root, expected) in [
        (None, "direct-root"),
        (
            Some(wrong_root.clone()),
            "does not originate from the authenticated root",
        ),
    ] {
        let error = match verify_capability_pure(verify_input(supplied_root), &clock) {
            Err(error) => error,
            Ok(_) => {
                return Err(std::io::Error::other(
                    "delegated cumulative approval accepted invalid root evidence",
                )
                .into());
            }
        };
        assert!(error.message.contains(expected), "{}", error.message);
    }

    for (name, supplied_root, expected) in [
        (
            "valid",
            Some(root.clone()),
            "capability feature unsupported on this runtime: cumulative approval enforcement",
        ),
        ("missing", None, "direct-root"),
        (
            "mismatched",
            Some(wrong_root),
            "does not originate from the authenticated root",
        ),
    ] {
        let verdict = evaluate_pure(
            EvaluateRequestJson {
                request: ToolCallRequestJson {
                    request_id: std::format!("req-cumulative-{name}"),
                    tool_name: "echo".to_string(),
                    server_id: "srv-a".to_string(),
                    agent_id: child.subject.to_hex(),
                    arguments: serde_json::json!({"msg": "hello"}),
                    governed_intent: None,
                    approval_token: None,
                    approval_tokens: std::vec::Vec::new(),
                    threshold_approval_proposal: None,
                    supplemental_authorization: None,
                },
                capability: child.clone(),
                trusted_issuers_hex: std::vec![issuer.public_key().to_hex()],
                clock_override_unix_secs: Some(ISSUED_AT + 2),
                session_filesystem_roots: None,
                peer_capabilities: Some(cumulative_peer()),
                direct_root_capability: supplied_root,
                capability_trust_roots: BTreeMap::new(),
                parent_budget_snapshots: std::vec![parent_budget_snapshot(&root.id)],
            },
            &clock,
        )
        .map_err(|error| std::io::Error::other(error.message))?;
        assert_eq!(verdict.verdict, "deny", "{name}");
        let reason = verdict.reason.as_deref().unwrap_or_default();
        assert!(reason.contains(expected), "{name}: {reason}");
    }
    Ok(())
}

#[test]
fn sign_receipt_pure_round_trip() {
    // The PUBLIC signer is fail-closed and requires the canonical content
    // preimage; supply one whose hash matches `content_hash` so the recompute
    // gate passes and the receipt round-trips.
    let seed = [1u8; 32];
    let canonical_content = br#"{"shown":"round-trip"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = ChioReceiptBody {
        id: "rcpt-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash,
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        // Placeholder; sign_receipt_pure replaces this with the seed's public key.
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let receipt = sign_receipt_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: Some(canonical_content),
        },
        &seed,
    )
    .expect("sign_receipt_pure");
    assert!(receipt.verify_signature().unwrap());

    let seed_pubkey = Keypair::from_seed(&seed).public_key();
    assert_eq!(receipt.kernel_key, seed_pubkey);
}

#[test]
fn sign_receipt_pure_refuses_without_canonical_content() {
    // WYSIWYS (): the PUBLIC browser signer must NOT silently
    // relay a trusted body. With no canonical content preimage it fails closed
    // so a caller cannot render content A while signing a body claiming hash(B)
    // and slip past the recompute gate by omitting the preimage.
    let seed = [9u8; 32];
    let body = ChioReceiptBody {
        id: "rcpt-no-preimage".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let err = sign_receipt_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: None,
        },
        &seed,
    )
    .expect_err("public signer must refuse without canonical content");
    assert_eq!(err.code, "canonical_content_required");
}

#[test]
fn sign_receipt_relaying_trusted_body_pure_relays_without_preimage() {
    // The explicitly named relay seam is the ONLY path that forwards a
    // trusted body without a preimage. It trusts `content_hash` and signs.
    let seed = [10u8; 32];
    let body = ChioReceiptBody {
        id: "rcpt-relay".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let receipt = sign_receipt_relaying_trusted_body_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: None,
        },
        &seed,
    )
    .expect("relay seam signs an upstream-trusted body");
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn sign_receipt_pure_recomputes_content_hash_when_preimage_present() {
    // WYSIWYS: when the browser caller carries the canonical content
    // preimage, sign_receipt_pure recomputes the hash inside the signer. A body
    // whose content_hash matches the preimage signs and verifies.
    let seed = [3u8; 32];
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = ChioReceiptBody {
        id: "rcpt-wysiwys".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash,
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let receipt = sign_receipt_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: Some(canonical_content),
        },
        &seed,
    )
    .expect("matching content signs");
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn sign_receipt_pure_refuses_render_a_sign_b() {
    // WYSIWYS: a body claiming hash(B) handed a preimage for content A
    // must be refused fail-closed.
    let seed = [4u8; 32];
    let content_a = br#"{"shown":"to-the-human"}"#.to_vec();
    let hash_b = chio_core_types::crypto::sha256_hex(br#"{"secretly":"signed-instead"}"#);
    let body = ChioReceiptBody {
        id: "rcpt-forgery".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash: hash_b,
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let err = sign_receipt_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: Some(content_a),
        },
        &seed,
    )
    .expect_err("render-A/sign-B must be refused");
    assert_eq!(err.code, "receipt_signing_failed");
    assert!(
        err.message.contains("WYSIWYS refused"),
        "got: {}",
        err.message
    );
}

#[test]
fn sign_receipt_pure_refuses_zero_seed() {
    let seed = [0u8; 32];
    let body = ChioReceiptBody {
        id: "rcpt-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };

    let err = sign_receipt_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: None,
        },
        &seed,
    )
    .expect_err("must refuse zero seed");
    assert_eq!(err.code, "weak_entropy");
}

#[test]
fn decode_seed_hex_round_trip() {
    let bytes = [0xa5u8; 32];
    let hex_encoded = hex_encode_lower(&bytes);
    let decoded = decode_seed_hex(&hex_encoded).expect("decode");
    assert_eq!(decoded, bytes);

    let with_prefix = std::format!("0x{}", hex_encoded);
    let decoded_prefixed = decode_seed_hex(&with_prefix).expect("decode prefixed");
    assert_eq!(decoded_prefixed, bytes);
}

#[test]
fn decode_seed_hex_rejects_wrong_length() {
    let err = decode_seed_hex("deadbeef").expect_err("must reject short input");
    assert_eq!(err.code, "invalid_seed_hex");
}

#[test]
fn parse_authority_input_accepts_single_and_array() {
    let single = parse_authority_input("deadbeef").expect("single");
    assert_eq!(single, std::vec!["deadbeef".to_string()]);

    let multi = parse_authority_input("[\"aa\",\"bb\"]").expect("array");
    assert_eq!(multi, std::vec!["aa".to_string(), "bb".to_string()]);

    assert!(parse_authority_input("").is_err());
}

#[test]
fn parse_authority_input_rejects_empty_array() {
    let result = parse_authority_input("[]");

    assert!(matches!(
        result,
        Err(BindingError { code, .. }) if code == "invalid_authority_input"
    ));
}

fn make_signed_receipt(seed: [u8; 32]) -> chio_core_types::receipt::body::ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-verify-pure".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "verify"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: std::vec![],
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: std::vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    };
    // Verify-receipt tests only need a validly signed envelope, not a WYSIWYS
    // proof, so route through the relay seam which accepts a body without a
    // canonical content preimage.
    sign_receipt_relaying_trusted_body_pure(
        SignReceiptRequestJson {
            body,
            canonical_content: None,
        },
        &seed,
    )
    .unwrap()
}

#[test]
fn verify_receipt_pure_signature_only_without_trust_pinning() {
    let receipt = make_signed_receipt([7u8; 32]);
    let envelope = serde_json::to_vec(&receipt).unwrap();

    let result = verify_receipt_pure(&envelope, &[]).expect("verify_receipt_pure");
    assert!(!result.ok);
    assert!(result.signature_valid);
    assert!(result.parameter_hash_valid);
    assert!(!result.signer_trusted);
    assert_eq!(result.decision, "allow");
    assert_eq!(result.receipt_id.len(), 64);
    assert!(result
        .receipt_id
        .chars()
        .all(|value| value.is_ascii_hexdigit()));
    assert!(result.receipt_id_valid);
    assert_eq!(result.receipt_kind, "mediated_decision");
    assert_eq!(result.boundary_class, "prevent");
    assert_eq!(result.result, "Authorized");
    assert!(!result.authorized);
    assert_eq!(result.signer_key_hex, receipt.kernel_key.to_hex());
}

#[test]
fn verify_receipt_pure_allow_path_with_pinned_trusted_signer() {
    let receipt = make_signed_receipt([9u8; 32]);
    let envelope = serde_json::to_vec(&receipt).unwrap();

    let result = verify_receipt_pure(&envelope, core::slice::from_ref(&receipt.kernel_key))
        .expect("verify_receipt_pure");
    assert!(result.ok);
    assert!(result.signer_trusted);
    assert!(result.authorized);
}

#[test]
fn verify_receipt_pure_rejects_untrusted_signer() {
    let receipt = make_signed_receipt([11u8; 32]);
    let envelope = serde_json::to_vec(&receipt).unwrap();
    let other = Keypair::generate().public_key();

    let result =
        verify_receipt_pure(&envelope, std::slice::from_ref(&other)).expect("verify_receipt_pure");
    assert!(!result.ok);
    assert!(result.signature_valid);
    assert!(!result.signer_trusted);
}

#[test]
fn verify_receipt_pure_rejects_tampered_signature() {
    let receipt = make_signed_receipt([13u8; 32]);
    let mut envelope: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    // Flip the first hex character of the signature so the math fails.
    let sig = envelope["signature"].as_str().unwrap().to_string();
    let mut tampered = sig.clone();
    let first = if tampered.as_bytes()[0] == b'a' {
        '0'
    } else {
        'a'
    };
    tampered.replace_range(0..1, &first.to_string());
    envelope["signature"] = serde_json::Value::String(tampered);
    let bytes = serde_json::to_vec(&envelope).unwrap();

    let result = verify_receipt_pure(&bytes, &[]).expect("verify_receipt_pure");
    assert!(!result.ok);
    assert!(!result.signature_valid);
}

#[test]
fn verify_receipt_pure_rejects_malformed_envelope() {
    let err = verify_receipt_pure(b"not a receipt", &[])
        .expect_err("malformed envelope must surface as an error");
    assert_eq!(err.code, "invalid_receipt_envelope");
}
