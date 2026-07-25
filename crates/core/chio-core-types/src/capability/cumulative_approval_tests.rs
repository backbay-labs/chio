use alloc::string::ToString;
use alloc::vec;

use super::aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope};
use super::attenuation::{
    compute_attenuation_witness, delegate, scope_hash, AttenuationProof, DelegationLink,
    DelegationLinkBody,
};
use super::cumulative_approval::{
    verify_cumulative_approval_constraints, CumulativeApprovalDelegationMarker,
    CumulativeApprovalRootBinding, CumulativeApprovalRootBindingBody,
    MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER,
};
use super::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use super::token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody};
use crate::canonical::canonical_json_bytes;
use crate::crypto::{Ed25519Backend, Keypair, PublicKey, SigningBackend};
use crate::delegation_receipt::ScopeAttenuation;

type TestResult = core::result::Result<(), Box<dyn std::error::Error>>;

fn cumulative_constraint(threshold: u64) -> Constraint {
    cumulative_constraint_for("budget-1", 7, threshold)
}

fn cumulative_constraint_for(
    approval_budget_id: &str,
    approval_budget_epoch: u64,
    threshold: u64,
) -> Constraint {
    Constraint::RequireCumulativeApprovalAbove {
        threshold: MonetaryAmount {
            units: threshold,
            currency: "USD".to_string(),
        },
        approval_budget_id: approval_budget_id.to_string(),
        approval_budget_epoch,
        cumulative_approval_root_binding: None,
    }
}

fn bound_tool_scope(
    root: &CapabilityToken,
    delegable: bool,
    threshold: u64,
) -> TestResultValue<ChioScope> {
    let mut scope = tool_scope(delegable, Some(threshold));
    let constraint = scope
        .grants
        .first_mut()
        .and_then(|grant| grant.constraints.first_mut())
        .ok_or_else(|| std::io::Error::other("child constraint missing"))?;
    constraint.set_cumulative_approval_root_binding(Some(binding(root)?.clone()))?;
    Ok(scope)
}

fn tool_scope(delegable: bool, threshold: Option<u64>) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations,
            constraints: threshold.into_iter().map(cumulative_constraint).collect(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn token_body(
    id: &str,
    issuer: &PublicKey,
    subject: &PublicKey,
    scope: ChioScope,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.clone(),
        subject: subject.clone(),
        scope,
        issued_at: 100,
        expires_at: 1_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

fn family_root(issuer: &Keypair, subject: &Keypair) -> crate::error::Result<CapabilityToken> {
    CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-root",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(true, Some(100)),
        ),
        issuer,
    )
}

fn binding(
    root: &CapabilityToken,
) -> TestResultValue<&super::cumulative_approval::CumulativeApprovalRootBinding> {
    binding_for_grant(root, 0)
}

fn binding_for_grant(
    root: &CapabilityToken,
    grant_index: usize,
) -> TestResultValue<&super::cumulative_approval::CumulativeApprovalRootBinding> {
    root.scope
        .grants
        .get(grant_index)
        .and_then(|grant| grant.constraints.first())
        .and_then(Constraint::cumulative_approval_root_binding)
        .ok_or_else(|| std::io::Error::other("root binding missing").into())
}

type TestResultValue<T> = core::result::Result<T, Box<dyn std::error::Error>>;

fn child_token(
    root: &CapabilityToken,
    root_subject: &Keypair,
    delegatee: &Keypair,
    threshold: Option<u64>,
    issuer: &Keypair,
) -> TestResultValue<CapabilityToken> {
    let mut child_scope = tool_scope(false, threshold);
    if let Some(constraint) = child_scope
        .grants
        .first_mut()
        .and_then(|grant| grant.constraints.first_mut())
    {
        constraint.set_cumulative_approval_root_binding(Some(binding(root)?.clone()))?;
    }
    let receipt = delegate(
        root,
        &child_scope,
        root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        200,
        [9_u8; 16],
    )?;
    let mut body = token_body(
        "cap-child",
        &root.issuer,
        &delegatee.public_key(),
        child_scope,
    );
    body.issued_at = receipt.link.timestamp;
    body.delegation_chain = receipt.complete_chain();
    Ok(CapabilityToken::sign(body, issuer)?)
}

fn two_grant_scope() -> ChioScope {
    let mut first = tool_scope(true, Some(100)).grants.remove(0);
    first.server_id = "server-a".to_string();
    let mut second = first.clone();
    second.server_id = "server-b".to_string();
    ChioScope {
        grants: vec![first, second],
        ..ChioScope::default()
    }
}

fn mutation_rejected(
    root: &CapabilityToken,
    token_signer: &Keypair,
    binding_signer: &Keypair,
    mutate: impl FnOnce(&mut CumulativeApprovalRootBindingBody),
) -> TestResultValue<bool> {
    let mut body = root.body();
    let constraint = body
        .scope
        .grants
        .first_mut()
        .and_then(|grant| grant.constraints.first_mut())
        .ok_or_else(|| std::io::Error::other("root constraint missing"))?;
    let mut binding_body = constraint
        .cumulative_approval_root_binding()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .body
        .clone();
    mutate(&mut binding_body);
    constraint.set_cumulative_approval_root_binding(Some(CumulativeApprovalRootBinding::sign(
        binding_body,
        binding_signer,
    )?))?;
    Ok(CapabilityToken::sign(body, token_signer).is_err())
}

#[test]
fn cumulative_approval_wire_is_distinct_from_legacy_per_request_threshold() -> TestResult {
    let legacy = Constraint::RequireApprovalAbove {
        threshold_units: 100,
    };
    let cumulative = cumulative_constraint(100);
    let legacy_value = serde_json::to_value(&legacy)?;
    let cumulative_value = serde_json::to_value(&cumulative)?;

    assert_eq!(legacy_value["type"], "require_approval_above");
    assert_eq!(
        cumulative_value["type"],
        "require_cumulative_approval_above"
    );
    assert!(legacy_value["value"].get("approval_budget_id").is_none());
    assert!(cumulative_value["value"].get("threshold_units").is_none());
    assert!(!legacy.is_cumulative_approval());
    assert!(cumulative.is_cumulative_approval());
    Ok(())
}

#[test]
fn cumulative_approval_delegable_direct_signing_requires_family_helper() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let body = token_body(
        "cap-unbound-root",
        &issuer.public_key(),
        &subject.public_key(),
        tool_scope(true, Some(100)),
    );

    assert!(CapabilityToken::sign(body, &issuer).is_err());
    Ok(())
}

#[test]
fn aggregate_and_cumulative_roots_require_a_joint_binding() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = family_root(&issuer, &subject)?;

    let composition = CapabilityToken::sign_aggregate_family_root(root.body(), 3, &issuer);
    assert!(matches!(
        composition,
        Err(error) if error.to_string().contains("cannot be combined")
    ));

    let mut combined = CapabilityToken::sign(
        token_body(
            "cap-combined-wire",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(false, Some(100)),
        ),
        &issuer,
    )?;
    combined.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 3,
        root_binding: None,
    });
    let validation = combined.validate_schema();
    assert!(matches!(
        validation,
        Err(error) if error.to_string().contains("cannot be combined")
    ));
    Ok(())
}

#[test]
fn cumulative_approval_wire_rejects_unknown_fields() -> TestResult {
    let mut value = serde_json::to_value(cumulative_constraint(100))?;
    value["value"]["rogue"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Constraint>(value).is_err());
    Ok(())
}

#[test]
fn cumulative_approval_direct_nondelegable_constraint_has_no_family_binding() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CapabilityToken::sign(
        token_body(
            "cap-direct",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(false, Some(100)),
        ),
        &issuer,
    )?;
    let verified = verify_cumulative_approval_constraints(&token, &[issuer.public_key()], None)?;

    assert_eq!(verified.len(), 1);
    assert!(!verified[0].owner_id.is_empty());
    assert_eq!(verified[0].authority_id, issuer.public_key());
    assert!(verified[0].delegation_root_id.is_none());
    assert!(verified[0].root_binding_digest.is_none());
    assert_eq!(verified[0].authority_threshold, verified[0].threshold);
    Ok(())
}

#[test]
fn cumulative_approval_family_root_and_sibling_share_owner() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let first_delegatee = Keypair::generate();
    let second_delegatee = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let first = child_token(&root, &root_subject, &first_delegatee, Some(100), &issuer)?;
    let second = child_token(&root, &root_subject, &second_delegatee, Some(80), &issuer)?;

    let root_verified =
        verify_cumulative_approval_constraints(&root, &[issuer.public_key()], None)?;
    let first_verified =
        verify_cumulative_approval_constraints(&first, &[issuer.public_key()], Some(&root))?;
    let second_verified =
        verify_cumulative_approval_constraints(&second, &[issuer.public_key()], Some(&root))?;

    assert_eq!(root_verified[0].owner_id, first_verified[0].owner_id);
    assert_eq!(first_verified[0].owner_id, second_verified[0].owner_id);
    assert_eq!(second_verified[0].authority_id, issuer.public_key());
    assert_eq!(
        second_verified[0].delegation_root_id.as_deref(),
        Some(root.id.as_str())
    );
    assert_eq!(
        root_verified[0].root_grant_hash,
        first_verified[0].root_grant_hash
    );
    assert_eq!(second_verified[0].threshold.units, 80);
    assert_eq!(second_verified[0].authority_threshold.units, 100);
    assert_eq!(
        first_verified[0].authority_threshold,
        second_verified[0].authority_threshold
    );
    assert_eq!(
        canonical_json_bytes(binding(&first)?)?,
        canonical_json_bytes(binding(&second)?)?
    );
    Ok(())
}

#[test]
fn cumulative_approval_delegation_rejects_omission() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;

    assert!(delegate(
        &root,
        &tool_scope(false, None),
        &root_subject,
        &Keypair::generate().public_key(),
        ScopeAttenuation::empty(),
        200,
        [1_u8; 16],
    )
    .is_err());
    Ok(())
}

#[test]
fn cumulative_approval_delegation_rejects_binding_mutation() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let mut child_scope = tool_scope(false, Some(100));
    let mut changed = binding(&root)?.clone();
    changed.body.approval_budget_epoch += 1;
    child_scope.grants[0].constraints[0].set_cumulative_approval_root_binding(Some(changed))?;

    assert!(delegate(
        &root,
        &child_scope,
        &root_subject,
        &Keypair::generate().public_key(),
        ScopeAttenuation::empty(),
        200,
        [2_u8; 16],
    )
    .is_err());
    Ok(())
}

#[test]
fn cumulative_approval_delegation_rejects_fresh_constraint() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let root = CapabilityToken::sign(
        token_body(
            "cap-unbound",
            &issuer.public_key(),
            &root_subject.public_key(),
            tool_scope(true, None),
        ),
        &issuer,
    )?;
    let child_scope = tool_scope(false, Some(100));

    assert!(delegate(
        &root,
        &child_scope,
        &root_subject,
        &Keypair::generate().public_key(),
        ScopeAttenuation::empty(),
        200,
        [3_u8; 16],
    )
    .is_err());
    Ok(())
}

#[test]
fn cumulative_approval_verifier_rejects_unrelated_root_evidence() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let child = child_token(&root, &root_subject, &delegatee, Some(100), &issuer)?;
    let unrelated = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-other",
            &issuer.public_key(),
            &Keypair::generate().public_key(),
            tool_scope(true, Some(100)),
        ),
        &issuer,
    )?;

    assert!(verify_cumulative_approval_constraints(
        &child,
        &[issuer.public_key()],
        Some(&unrelated),
    )
    .is_err());
    Ok(())
}

#[test]
fn cumulative_approval_link_scope_hash_authenticates_bound_root_scope() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some(scope_hash(&root.scope)?),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &root_subject,
    )?;

    assert_eq!(link.scope_hash, Some(scope_hash(&root.scope)?));
    Ok(())
}

#[test]
fn cumulative_approval_identical_budget_fields_on_distinct_grants_have_distinct_owners(
) -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-two-grants",
            &issuer.public_key(),
            &subject.public_key(),
            two_grant_scope(),
        ),
        &issuer,
    )?;
    let verified = verify_cumulative_approval_constraints(&root, &[issuer.public_key()], None)?;

    assert_eq!(verified.len(), 2);
    assert_eq!(verified[0].grant_index, 0);
    assert_eq!(verified[1].grant_index, 1);
    assert_ne!(verified[0].root_grant_hash, verified[1].root_grant_hash);
    assert_ne!(verified[0].owner_id, verified[1].owner_id);
    Ok(())
}

#[test]
fn cumulative_approval_projection_preserves_sparse_grant_indices() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut grants = two_grant_scope().grants;
    grants[1].constraints = vec![cumulative_constraint_for("budget-2", 8, 80)];
    let mut gap = grants[0].clone();
    gap.server_id = "gap-a".to_string();
    gap.constraints.clear();
    grants.insert(0, gap.clone());
    gap.server_id = "gap-b".to_string();
    grants.insert(2, gap);
    let token = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-sparse-grants",
            &issuer.public_key(),
            &subject.public_key(),
            ChioScope {
                grants,
                ..ChioScope::default()
            },
        ),
        &issuer,
    )?;

    let verified = verify_cumulative_approval_constraints(&token, &[issuer.public_key()], None)?;
    let projected = verified
        .iter()
        .map(|constraint| {
            (
                constraint.approval_budget_id.as_str(),
                constraint.grant_index,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(projected, vec![("budget-1", 1), ("budget-2", 3)]);
    Ok(())
}

#[test]
fn cumulative_approval_grafted_grant_binding_rejects() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-graft",
            &issuer.public_key(),
            &subject.public_key(),
            two_grant_scope(),
        ),
        &issuer,
    )?;
    let mut body = root.body();
    let first_binding = binding_for_grant(&root, 0)?.clone();
    body.scope.grants[1].constraints[0]
        .set_cumulative_approval_root_binding(Some(first_binding))?;

    assert!(CapabilityToken::sign(body, &issuer).is_err());
    Ok(())
}

#[test]
fn cumulative_approval_backend_root_round_trip() -> TestResult {
    let backend = Ed25519Backend::generate();
    let subject = Keypair::generate();
    let root = CapabilityToken::sign_cumulative_approval_family_root_with_backend(
        token_body(
            "cap-backend-root",
            &backend.public_key(),
            &subject.public_key(),
            tool_scope(true, Some(100)),
        ),
        &backend,
    )?;
    let wire = serde_json::to_vec(&root)?;
    let decoded: CapabilityToken = serde_json::from_slice(&wire)?;

    assert!(decoded.verify_signature()?);
    assert_eq!(
        canonical_json_bytes(binding(&root)?)?,
        canonical_json_bytes(binding(&decoded)?)?
    );
    assert_eq!(
        verify_cumulative_approval_constraints(&decoded, &[backend.public_key()], None)?.len(),
        1
    );
    Ok(())
}

#[test]
fn cumulative_approval_root_binds_signer_key_epoch() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = CapabilityToken::sign_cumulative_approval_family_root_at_epoch(
        token_body(
            "cap-key-epoch",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(true, Some(100)),
        ),
        7,
        &issuer,
    )?;

    assert_eq!(binding(&root)?.body.signer_key_epoch, 7);
    assert!(root.verify_signature()?);
    Ok(())
}

#[test]
fn cumulative_approval_rejects_every_root_binding_field_mutation() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = family_root(&issuer, &subject)?;
    let other = Keypair::generate();

    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.schema = "chio.cumulative-approval-root.invalid".to_string();
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.signer_key_epoch += 1;
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_capability_id.push_str("-changed");
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_capability_hash = "00".repeat(32);
    })?);
    assert!(mutation_rejected(&root, &issuer, &other, |body| {
        body.root_issuer = other.public_key();
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_subject = Keypair::generate().public_key();
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_scope_hash = "11".repeat(32);
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_grant_hash = "22".repeat(32);
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.approval_budget_id.push_str("-changed");
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.approval_budget_epoch += 1;
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.threshold.units += 1;
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.threshold.currency = "EUR".to_string();
    })?);
    assert!(mutation_rejected(&root, &issuer, &issuer, |body| {
        body.root_expires_at += 1;
    })?);
    Ok(())
}

#[test]
fn cumulative_approval_rejects_multi_hop_scope_pivot_and_intermediate_predating() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let intermediate = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_scope = tool_scope(true, Some(100));
    root_scope.grants[0].server_id = "*".to_string();
    let root = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-multi-root",
            &issuer.public_key(),
            &root_subject.public_key(),
            root_scope,
        ),
        &issuer,
    )?;
    let mut intermediate_scope = bound_tool_scope(&root, true, 90)?;
    intermediate_scope.grants[0].server_id = "server-a".to_string();
    let first = delegate(
        &root,
        &intermediate_scope,
        &root_subject,
        &intermediate.public_key(),
        ScopeAttenuation::empty(),
        200,
        [10_u8; 16],
    )?;
    assert!(first.cumulative_approval.is_some());
    assert_eq!(first.cumulative_approval, first.link.cumulative_approval);
    first.canonical_bytes()?;

    let mut intermediate_body = token_body(
        "cap-intermediate",
        &issuer.public_key(),
        &intermediate.public_key(),
        intermediate_scope,
    );
    intermediate_body.issued_at = 250;
    intermediate_body.delegation_chain = first.complete_chain();
    let intermediate_token = CapabilityToken::sign(intermediate_body, &issuer)?;
    let mut chronology_scope = bound_tool_scope(&root, false, 80)?;
    chronology_scope.grants[0].server_id = "server-a".to_string();
    let projected = delegate(
        &intermediate_token,
        &chronology_scope,
        &intermediate,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        300,
        [11_u8; 16],
    )?;
    assert_eq!(projected.cumulative_approval, first.cumulative_approval);
    assert_eq!(
        projected.cumulative_approval,
        projected.link.cumulative_approval
    );
    projected.canonical_bytes()?;

    let marker = first
        .cumulative_approval
        .clone()
        .ok_or_else(|| std::io::Error::other("cumulative marker missing"))?;
    let make_leaf =
        |id: &str, scope: ChioScope, timestamp: u64| -> crate::error::Result<CapabilityToken> {
            let second = DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: intermediate_token.id.clone(),
                    delegator: intermediate.public_key(),
                    delegatee: delegatee.public_key(),
                    attenuations: vec![],
                    timestamp,
                    scope_hash: Some(scope_hash(&intermediate_token.scope)?),
                    aggregate_budget: None,
                    cumulative_approval: Some(marker.clone()),
                },
                &intermediate,
            )?;
            let mut body = token_body(id, &issuer.public_key(), &delegatee.public_key(), scope);
            body.issued_at = 300;
            body.delegation_chain = intermediate_token
                .delegation_chain
                .iter()
                .cloned()
                .chain(core::iter::once(second))
                .collect();
            CapabilityToken::sign(body, &issuer)
        };

    let mut pivot_scope = bound_tool_scope(&root, false, 80)?;
    pivot_scope.grants[0].server_id = "server-b".to_string();
    let pivot = make_leaf("cap-multi-pivot", pivot_scope, 275)?;
    let chronology = make_leaf(
        "cap-multi-chronology",
        chronology_scope,
        intermediate_token.issued_at.saturating_sub(1),
    )?;

    for leaf in [&pivot, &chronology] {
        let error =
            match verify_cumulative_approval_constraints(leaf, &[issuer.public_key()], Some(&root))
            {
                Err(error) => error,
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "multi-hop cumulative family did not fail closed",
                    )
                    .into());
                }
            };
        assert!(error.to_string().contains("per-hop signed child-scope"));
    }
    Ok(())
}

#[test]
fn cumulative_approval_marker_is_bounded_sorted_and_deduplicated() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![
                cumulative_constraint_for("budget-z", 9, 100),
                cumulative_constraint_for("budget-z", 9, 100),
                cumulative_constraint_for("budget-a", 3, 50),
            ],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let root = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-marker-root",
            &issuer.public_key(),
            &subject.public_key(),
            root_scope,
        ),
        &issuer,
    )?;
    let receipt = delegate(
        &root,
        &root.scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        200,
        [12_u8; 16],
    )?;
    let marker = receipt
        .cumulative_approval
        .as_ref()
        .ok_or_else(|| std::io::Error::other("cumulative marker missing"))?;
    assert_eq!(marker.bindings().len(), 2);
    let value = serde_json::to_value(marker)?;
    assert_eq!(
        value["bindings"][0]["approval_budget_id"],
        serde_json::json!("budget-a")
    );
    assert_eq!(
        value["bindings"][1]["approval_budget_id"],
        serde_json::json!("budget-z")
    );

    let mut reversed_value = value.clone();
    reversed_value["bindings"]
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("marker bindings missing"))?
        .reverse();
    let reversed: CumulativeApprovalDelegationMarker = serde_json::from_value(reversed_value)?;
    let mut reversed_body = receipt.link.body();
    reversed_body.cumulative_approval = Some(reversed);
    assert!(DelegationLink::sign(reversed_body, &subject).is_err());

    let entry = value["bindings"][0].clone();
    let oversized_value = serde_json::json!({
        "bindings": vec![entry; MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER + 1]
    });
    let oversized: CumulativeApprovalDelegationMarker = serde_json::from_value(oversized_value)?;
    let mut oversized_body = receipt.link.body();
    oversized_body.cumulative_approval = Some(oversized);
    assert!(DelegationLink::sign(oversized_body, &subject).is_err());

    let mut unknown_value = value;
    unknown_value["bindings"][0]["rogue"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<CumulativeApprovalDelegationMarker>(unknown_value).is_err());
    Ok(())
}

#[test]
fn cumulative_approval_rejects_link_witness_and_receipt_projection_changes() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let child_scope = bound_tool_scope(&root, false, 80)?;
    let receipt = delegate(
        &root,
        &child_scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        200,
        [13_u8; 16],
    )?;
    let marker = receipt
        .cumulative_approval
        .clone()
        .ok_or_else(|| std::io::Error::other("cumulative marker missing"))?;
    let mut marker_value = serde_json::to_value(&marker)?;
    marker_value["bindings"][0]["root_binding_digest"] = serde_json::Value::String("00".repeat(32));
    let changed_marker: CumulativeApprovalDelegationMarker = serde_json::from_value(marker_value)?;

    let mut omitted_link_body = receipt.link.body();
    omitted_link_body.cumulative_approval = None;
    let omitted_link = DelegationLink::sign(omitted_link_body, &root_subject)?;
    let mut omitted_token_body = token_body(
        "cap-omitted-marker",
        &issuer.public_key(),
        &delegatee.public_key(),
        child_scope.clone(),
    );
    omitted_token_body.delegation_chain = vec![omitted_link];
    assert!(CapabilityToken::sign(omitted_token_body, &issuer).is_err());

    let mut changed_link_body = receipt.link.body();
    changed_link_body.cumulative_approval = Some(changed_marker.clone());
    let changed_link = DelegationLink::sign(changed_link_body, &root_subject)?;
    let mut changed_token_body = token_body(
        "cap-changed-marker",
        &issuer.public_key(),
        &delegatee.public_key(),
        child_scope.clone(),
    );
    changed_token_body.delegation_chain = vec![changed_link];
    assert!(CapabilityToken::sign(changed_token_body, &issuer).is_err());

    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&root.scope)?,
        child_scope_hash: scope_hash(&child_scope)?,
        normalized_subset_proof: compute_attenuation_witness(&root.scope, &child_scope)?,
    };
    let mut attenuated_body = CapabilityTokenAttenuationBody {
        body: token_body(
            "cap-witness",
            &issuer.public_key(),
            &delegatee.public_key(),
            child_scope,
        ),
        caveats: vec![],
        scope_attenuations: vec![],
        attenuation_proof: proof,
        budget_share_bps: None,
    };
    attenuated_body.body.delegation_chain = receipt.complete_chain();
    CapabilityToken::sign_attenuated(attenuated_body.clone(), &issuer)?;

    let mut omitted_witness = attenuated_body.clone();
    omitted_witness
        .attenuation_proof
        .normalized_subset_proof
        .cumulative_approval = None;
    assert!(CapabilityToken::sign_attenuated(omitted_witness, &issuer).is_err());

    let mut changed_witness = attenuated_body;
    changed_witness
        .attenuation_proof
        .normalized_subset_proof
        .cumulative_approval = Some(changed_marker);
    assert!(CapabilityToken::sign_attenuated(changed_witness, &issuer).is_err());

    let mut changed_receipt = receipt;
    changed_receipt.cumulative_approval = None;
    assert!(changed_receipt.canonical_bytes().is_err());
    Ok(())
}

#[test]
fn cumulative_approval_rejects_root_binding_and_first_marker_grafts() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let other_subject = Keypair::generate();
    let intermediate = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = family_root(&issuer, &root_subject)?;
    let mut other_scope = tool_scope(true, Some(100));
    other_scope.grants[0].constraints = vec![cumulative_constraint_for("budget-z", 9, 100)];
    let other_root = CapabilityToken::sign_cumulative_approval_family_root(
        token_body(
            "cap-other-marker-root",
            &issuer.public_key(),
            &other_subject.public_key(),
            other_scope,
        ),
        &issuer,
    )?;
    let child_scope = bound_tool_scope(&root, false, 80)?;
    let other_child_scope = {
        let mut scope = tool_scope(false, None);
        scope.grants[0].constraints = vec![Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 80,
                currency: "USD".to_string(),
            },
            approval_budget_id: "budget-z".to_string(),
            approval_budget_epoch: 9,
            cumulative_approval_root_binding: Some(Box::new(binding(&other_root)?.clone())),
        }];
        scope
    };
    let first = delegate(
        &root,
        &child_scope,
        &root_subject,
        &intermediate.public_key(),
        ScopeAttenuation::empty(),
        200,
        [14_u8; 16],
    )?;
    let other = delegate(
        &other_root,
        &other_child_scope,
        &other_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        200,
        [15_u8; 16],
    )?;
    let root_marker = first
        .cumulative_approval
        .clone()
        .ok_or_else(|| std::io::Error::other("root marker missing"))?;
    let other_marker = other
        .cumulative_approval
        .clone()
        .ok_or_else(|| std::io::Error::other("other marker missing"))?;

    let mut combined_value = serde_json::to_value(&root_marker)?;
    let other_value = serde_json::to_value(&other_marker)?;
    let other_entry = other_value["bindings"]
        .as_array()
        .and_then(|bindings| bindings.first())
        .cloned()
        .ok_or_else(|| std::io::Error::other("other binding marker missing"))?;
    combined_value["bindings"]
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("root binding markers missing"))?
        .push(other_entry);
    let combined_marker: CumulativeApprovalDelegationMarker =
        serde_json::from_value(combined_value)?;
    let mut grafted_first_body = first.link.body();
    grafted_first_body.cumulative_approval = Some(combined_marker);
    let grafted_first = DelegationLink::sign(grafted_first_body, &root_subject)?;
    let second = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-intermediate".to_string(),
            delegator: intermediate.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp: 300,
            scope_hash: Some(scope_hash(&child_scope)?),
            aggregate_budget: None,
            cumulative_approval: Some(root_marker),
        },
        &intermediate,
    )?;
    let mut leaf_body = token_body(
        "cap-extra-first-marker",
        &issuer.public_key(),
        &delegatee.public_key(),
        child_scope,
    );
    leaf_body.delegation_chain = vec![grafted_first, second];
    let leaf = CapabilityToken::sign(leaf_body, &issuer)?;
    assert!(
        verify_cumulative_approval_constraints(&leaf, &[issuer.public_key()], Some(&root)).is_err()
    );

    let grafted_binding_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some(scope_hash(&root.scope)?),
            aggregate_budget: None,
            cumulative_approval: Some(other_marker),
        },
        &root_subject,
    )?;
    let mut grafted_binding_body = token_body(
        "cap-grafted-binding",
        &issuer.public_key(),
        &delegatee.public_key(),
        other_child_scope,
    );
    grafted_binding_body.delegation_chain = vec![grafted_binding_link];
    let grafted_binding = CapabilityToken::sign(grafted_binding_body, &issuer)?;
    assert!(verify_cumulative_approval_constraints(
        &grafted_binding,
        &[issuer.public_key()],
        Some(&root)
    )
    .is_err());
    Ok(())
}
