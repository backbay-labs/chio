use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use serde::Serialize;

use super::aggregate_invocation::{
    verify_aggregate_invocation_budget, AggregateBudgetRootBinding, AggregateInvocationBudget,
    AggregateInvocationScope,
};
use super::attenuation::{delegate, scope_hash, DelegationLink, DelegationLinkBody};
use super::scope::{ChioScope, Operation, PromptGrant, ResourceGrant, ToolGrant};
use super::token::{
    CapabilityToken, CapabilityTokenBody, CapabilityTokenSigningBody, CHIO_CAPABILITY_SCHEMA,
};
use crate::canonical::canonical_json_bytes;
use crate::crypto::{Ed25519Backend, Keypair, PublicKey, SigningBackend};
use crate::delegation_receipt::ScopeAttenuation;

type TestResult = core::result::Result<(), Box<dyn std::error::Error>>;

fn tool_scope(delegable: bool) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations,
            constraints: vec![],
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

fn signed_family_root(
    id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    max_invocations: u32,
) -> crate::error::Result<CapabilityToken> {
    CapabilityToken::sign_aggregate_family_root(
        token_body(
            id,
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(true),
        ),
        max_invocations,
        issuer,
    )
}

fn signed_link(
    root: &CapabilityToken,
    subject: &Keypair,
    delegatee: &PublicKey,
    aggregate_budget: Option<super::aggregate_invocation::AggregateBudgetDelegationMarker>,
) -> crate::error::Result<DelegationLink> {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some(scope_hash(&root.scope)?),
            aggregate_budget,
            cumulative_approval: None,
        },
        subject,
    )
}

#[test]
fn delegation_marker_rejects_noncanonical_root_digest() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-invalid-marker", &issuer, &subject, 2)?;
    let marker = super::aggregate_invocation::AggregateBudgetDelegationMarker {
        root_binding_digest: "root-binding-digest".to_string(),
        max_invocations: 2,
    };

    assert!(signed_link(&root, &subject, &delegatee.public_key(), Some(marker)).is_err());
    Ok(())
}

fn descendant(
    id: &str,
    issuer: &Keypair,
    delegatee: &PublicKey,
    link: DelegationLink,
    aggregate_invocation_budget: Option<AggregateInvocationBudget>,
) -> crate::error::Result<CapabilityToken> {
    let mut body = token_body(id, &issuer.public_key(), delegatee, tool_scope(false));
    body.issued_at = link.timestamp;
    body.delegation_chain = vec![link];
    body.aggregate_invocation_budget = aggregate_invocation_budget;
    CapabilityToken::sign(body, issuer)
}

fn resign_root_binding(
    root: &CapabilityToken,
    issuer: &Keypair,
    binding_signer: &Keypair,
    max_invocations: u32,
    mutate: impl FnOnce(&mut super::aggregate_invocation::AggregateBudgetRootBindingBody),
) -> crate::error::Result<CapabilityToken> {
    let mut body = root.body();
    let budget = body.aggregate_invocation_budget.as_mut().ok_or_else(|| {
        crate::error::Error::AttenuationViolation {
            reason: "root budget missing".to_string(),
        }
    })?;
    let binding =
        budget
            .root_binding
            .as_mut()
            .ok_or_else(|| crate::error::Error::AttenuationViolation {
                reason: "root binding missing".to_string(),
            })?;
    mutate(&mut binding.body);
    budget.max_invocations = max_invocations;
    binding.body.max_invocations = max_invocations;
    *binding = AggregateBudgetRootBinding::sign(binding.body.clone(), binding_signer)?;
    CapabilityToken::sign(body, issuer)
}

#[derive(Serialize)]
struct LegacyBody<'a> {
    id: &'a str,
    issuer: &'a PublicKey,
    subject: &'a PublicKey,
    scope: &'a ChioScope,
    issued_at: u64,
    expires_at: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    delegation_chain: &'a Vec<DelegationLink>,
}

#[derive(Serialize)]
struct LegacySigningBody<'a> {
    schema: &'a str,
    #[serde(flatten)]
    body: LegacyBody<'a>,
}

#[test]
fn aggregate_invocation_absent_field_preserves_signing_bytes() -> TestResult {
    let issuer = Keypair::from_seed(&[7_u8; 32]);
    let subject = Keypair::from_seed(&[8_u8; 32]);
    let body = token_body(
        "cap-legacy-bytes",
        &issuer.public_key(),
        &subject.public_key(),
        tool_scope(false),
    );
    let signing = CapabilityTokenSigningBody {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        body: body.clone(),
        caveats: vec![],
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
    };
    let legacy = LegacySigningBody {
        schema: CHIO_CAPABILITY_SCHEMA,
        body: LegacyBody {
            id: &body.id,
            issuer: &body.issuer,
            subject: &body.subject,
            scope: &body.scope,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            delegation_chain: &body.delegation_chain,
        },
    };

    assert_eq!(
        canonical_json_bytes(&signing)?,
        canonical_json_bytes(&legacy)?
    );
    Ok(())
}

#[test]
fn aggregate_invocation_zero_limit_round_trips_and_verifies() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = signed_family_root("cap-zero", &issuer, &subject, 0)?;
    let bytes = canonical_json_bytes(&root)?;
    let decoded: CapabilityToken = serde_json::from_slice(&bytes)?;
    let verified = verify_aggregate_invocation_budget(&decoded, &[issuer.public_key()], None)?
        .ok_or_else(|| std::io::Error::other("aggregate budget missing"))?;

    assert_eq!(verified.max_invocations, 0);
    assert_eq!(verified.scope, AggregateInvocationScope::DelegationFamily);
    Ok(())
}

#[test]
fn aggregate_invocation_capability_scope_rejects_all_delegation_grants() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let tool = tool_scope(true);
    let resource = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "resource://*".to_string(),
            operations: vec![Operation::Read, Operation::Delegate],
        }],
        ..ChioScope::default()
    };
    let prompt = ChioScope {
        prompt_grants: vec![PromptGrant {
            prompt_name: "*".to_string(),
            operations: vec![Operation::Get, Operation::Delegate],
        }],
        ..ChioScope::default()
    };

    for (index, scope) in [tool, resource, prompt].into_iter().enumerate() {
        let mut body = token_body(
            &format!("cap-delegate-{index}"),
            &issuer.public_key(),
            &subject.public_key(),
            scope,
        );
        body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
            scope: AggregateInvocationScope::Capability,
            max_invocations: 1,
            root_binding: None,
        });
        assert!(CapabilityToken::sign(body, &issuer).is_err());
    }
}

#[test]
fn aggregate_invocation_family_root_and_descendant_share_owner() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-family", &issuer, &root_subject, 9)?;
    let budget = root.aggregate_invocation_budget.clone();
    let binding = budget
        .as_ref()
        .and_then(|value| value.root_binding.as_ref())
        .ok_or_else(|| std::io::Error::other("root binding missing"))?;
    let link = signed_link(
        &root,
        &root_subject,
        &delegatee.public_key(),
        Some(binding.delegation_marker()?),
    )?;
    let child = descendant(
        "cap-family-child",
        &issuer,
        &delegatee.public_key(),
        link,
        budget,
    )?;
    let root_verified = verify_aggregate_invocation_budget(&root, &[issuer.public_key()], None)?
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let child_verified =
        verify_aggregate_invocation_budget(&child, &[issuer.public_key()], Some(&root))?
            .ok_or_else(|| std::io::Error::other("child budget missing"))?;

    assert_eq!(root_verified.owner_id, child_verified.owner_id);
    assert_eq!(
        root_verified.max_invocations,
        child_verified.max_invocations
    );
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_widened_or_predated_descendant() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-descendant-bounds", &issuer, &root_subject, 9)?;
    let budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;

    let widened_link = signed_link(
        &root,
        &root_subject,
        &delegatee.public_key(),
        Some(marker.clone()),
    )?;
    let mut widened_body = token_body(
        "cap-widened-descendant",
        &issuer.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    widened_body.scope.grants[0].server_id = "*".to_string();
    widened_body.issued_at = widened_link.timestamp;
    widened_body.delegation_chain = vec![widened_link];
    widened_body.aggregate_invocation_budget = Some(budget.clone());
    let widened = CapabilityToken::sign(widened_body, &issuer)?;
    assert!(
        verify_aggregate_invocation_budget(&widened, &[issuer.public_key()], Some(&root),).is_err()
    );

    let predating_link = signed_link(&root, &root_subject, &delegatee.public_key(), Some(marker))?;
    let mut predating_body = token_body(
        "cap-predating-descendant",
        &issuer.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    predating_body.issued_at = predating_link.timestamp.saturating_sub(1);
    predating_body.delegation_chain = vec![predating_link];
    predating_body.aggregate_invocation_budget = Some(budget);
    let predating = CapabilityToken::sign(predating_body, &issuer)?;
    assert!(
        verify_aggregate_invocation_budget(&predating, &[issuer.public_key()], Some(&root),)
            .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_authenticates_ordinary_root_delegation_bounds() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign(
        token_body(
            "cap-ordinary-root",
            &issuer.public_key(),
            &root_subject.public_key(),
            tool_scope(true),
        ),
        &issuer,
    )?;

    let widened_link = signed_link(&root, &root_subject, &delegatee.public_key(), None)?;
    let mut widened_scope = tool_scope(false);
    widened_scope.grants[0].server_id = "*".to_string();
    let mut widened_body = token_body(
        "cap-ordinary-widened",
        &issuer.public_key(),
        &delegatee.public_key(),
        widened_scope,
    );
    widened_body.issued_at = widened_link.timestamp;
    widened_body.delegation_chain = vec![widened_link];
    let widened = CapabilityToken::sign(widened_body, &issuer)?;
    assert!(
        verify_aggregate_invocation_budget(&widened, &[issuer.public_key()], Some(&root),).is_err()
    );

    let nondelegable_root = CapabilityToken::sign(
        token_body(
            "cap-ordinary-nondelegable-root",
            &issuer.public_key(),
            &root_subject.public_key(),
            tool_scope(false),
        ),
        &issuer,
    )?;
    let unauthorized_link = signed_link(
        &nondelegable_root,
        &root_subject,
        &delegatee.public_key(),
        None,
    )?;
    let unauthorized = descendant(
        "cap-ordinary-unauthorized",
        &issuer,
        &delegatee.public_key(),
        unauthorized_link,
        None,
    )?;
    assert!(verify_aggregate_invocation_budget(
        &unauthorized,
        &[issuer.public_key()],
        Some(&nondelegable_root),
    )
    .is_err());

    let overlong_link = signed_link(&root, &root_subject, &delegatee.public_key(), None)?;
    let mut overlong_body = token_body(
        "cap-ordinary-overlong",
        &issuer.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    overlong_body.issued_at = overlong_link.timestamp;
    overlong_body.expires_at = root.expires_at.saturating_add(1);
    overlong_body.delegation_chain = vec![overlong_link];
    let overlong = CapabilityToken::sign(overlong_body, &issuer)?;
    assert!(
        verify_aggregate_invocation_budget(&overlong, &[issuer.public_key()], Some(&root),)
            .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_root_evidence_detects_first_hop_omission() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-omission", &issuer, &root_subject, 4)?;
    let link = signed_link(&root, &root_subject, &delegatee.public_key(), None)?;
    let child = descendant(
        "cap-omission-child",
        &issuer,
        &delegatee.public_key(),
        link,
        None,
    )?;

    assert!(
        verify_aggregate_invocation_budget(&child, &[issuer.public_key()], Some(&root),).is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_descendant_maximum_changes_and_scope_conversion() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-immutable", &issuer, &root_subject, 4)?;
    let root_budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = root_budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;

    for changed_max in [3_u32, 5_u32] {
        let mut changed = root_budget.clone();
        changed.max_invocations = changed_max;
        let link = signed_link(
            &root,
            &root_subject,
            &delegatee.public_key(),
            Some(marker.clone()),
        )?;
        let child = descendant(
            &format!("cap-max-{changed_max}"),
            &issuer,
            &delegatee.public_key(),
            link,
            Some(changed),
        );
        assert!(child.is_err());
    }

    let link = signed_link(&root, &root_subject, &delegatee.public_key(), Some(marker))?;
    let converted = descendant(
        "cap-converted",
        &issuer,
        &delegatee.public_key(),
        link,
        Some(AggregateInvocationBudget {
            scope: AggregateInvocationScope::Capability,
            max_invocations: 4,
            root_binding: None,
        }),
    );
    assert!(converted.is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_family_creation_below_unbound_root() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root_body = token_body(
        "cap-unbound",
        &issuer.public_key(),
        &root_subject.public_key(),
        tool_scope(true),
    );
    let unbound_root = CapabilityToken::sign(root_body.clone(), &issuer)?;
    let bound_root = CapabilityToken::sign_aggregate_family_root(root_body, 5, &issuer)?;
    let budget = bound_root.aggregate_invocation_budget.clone();
    let binding = budget
        .as_ref()
        .and_then(|value| value.root_binding.as_ref())
        .ok_or_else(|| std::io::Error::other("root binding missing"))?;
    let link = signed_link(
        &unbound_root,
        &root_subject,
        &delegatee.public_key(),
        Some(binding.delegation_marker()?),
    )?;
    let child = descendant(
        "cap-created-family",
        &issuer,
        &delegatee.public_key(),
        link,
        budget,
    )?;

    assert!(verify_aggregate_invocation_budget(
        &child,
        &[issuer.public_key()],
        Some(&unbound_root),
    )
    .is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_changed_maximum_and_binding_graft() -> TestResult {
    let issuer = Keypair::generate();
    let first_subject = Keypair::generate();
    let second_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let first = signed_family_root("cap-first", &issuer, &first_subject, 3)?;
    let second = signed_family_root("cap-second", &issuer, &second_subject, 3)?;
    let mut changed = first
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = changed
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;
    let link = signed_link(
        &second,
        &second_subject,
        &delegatee.public_key(),
        Some(marker),
    )?;
    changed.max_invocations = 2;
    assert!(descendant(
        "cap-changed-maximum",
        &issuer,
        &delegatee.public_key(),
        link.clone(),
        Some(changed),
    )
    .is_err());
    let child = descendant(
        "cap-grafted",
        &issuer,
        &delegatee.public_key(),
        link,
        first.aggregate_invocation_budget.clone(),
    )?;

    assert!(
        verify_aggregate_invocation_budget(&child, &[issuer.public_key()], Some(&first),).is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_forged_root_fields() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = signed_family_root("cap-forged", &issuer, &subject, 6)?;
    let mut body = root.body();
    let budget = body
        .aggregate_invocation_budget
        .as_mut()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let binding = budget
        .root_binding
        .as_mut()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?;
    binding.body.root_subject = Keypair::generate().public_key();
    *binding = AggregateBudgetRootBinding::sign(binding.body.clone(), &issuer)?;
    assert!(CapabilityToken::sign(body, &issuer).is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_each_changed_root_commitment_field() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let root = signed_family_root("cap-root-fields", &issuer, &subject, 6)?;
    let wrong_issuer = Keypair::generate();
    let forged = [
        resign_root_binding(&root, &issuer, &issuer, 6, |body| {
            body.root_capability_id = "cap-other".to_string();
        }),
        resign_root_binding(&root, &issuer, &issuer, 6, |body| {
            body.root_capability_hash = "00".repeat(32);
        }),
        resign_root_binding(&root, &issuer, &issuer, 6, |body| {
            body.root_subject = Keypair::generate().public_key();
        }),
        resign_root_binding(&root, &issuer, &issuer, 6, |body| {
            body.root_expires_at = body.root_expires_at.saturating_sub(1);
        }),
        resign_root_binding(&root, &issuer, &issuer, 6, |body| {
            body.root_scope_hash = "11".repeat(32);
        }),
        resign_root_binding(&root, &issuer, &issuer, 5, |_| {}),
    ];
    for result in forged {
        assert!(result.is_err());
    }
    assert!(
        resign_root_binding(&root, &issuer, &wrong_issuer, 6, |body| body.root_issuer =
            wrong_issuer.public_key(),)
        .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_wrong_root_binding_signature() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut root = signed_family_root("cap-root-signature", &issuer, &subject, 6)?;
    let other = signed_family_root("cap-other-signature", &issuer, &Keypair::generate(), 6)?;
    let other_signature = other
        .aggregate_invocation_budget
        .as_ref()
        .and_then(|budget| budget.root_binding.as_ref())
        .ok_or_else(|| std::io::Error::other("other root binding missing"))?
        .signature
        .clone();
    root.aggregate_invocation_budget
        .as_mut()
        .and_then(|budget| budget.root_binding.as_mut())
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .signature = other_signature;
    assert!(CapabilityToken::sign(root.body(), &issuer).is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_untrusted_root_and_tampered_chain() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-chain", &issuer, &root_subject, 6)?;
    assert!(verify_aggregate_invocation_budget(&root, &[], None).is_err());

    let budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;
    let mut link = signed_link(&root, &root_subject, &delegatee.public_key(), Some(marker))?;
    link.capability_id = "cap-tampered".to_string();
    let child = descendant(
        "cap-chain-child",
        &issuer,
        &delegatee.public_key(),
        link,
        Some(budget),
    )?;

    assert!(
        verify_aggregate_invocation_budget(&child, &[issuer.public_key()], Some(&root),).is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_untrusted_leaf_and_final_subject_mismatch() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let wrong_subject = Keypair::generate();
    let rogue_issuer = Keypair::generate();
    let root = signed_family_root("cap-leaf-root", &issuer, &root_subject, 6)?;
    let budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;
    let link = signed_link(
        &root,
        &root_subject,
        &delegatee.public_key(),
        Some(marker.clone()),
    )?;
    let mismatched = descendant(
        "cap-subject-mismatch",
        &issuer,
        &wrong_subject.public_key(),
        link,
        Some(budget.clone()),
    )?;
    assert!(
        verify_aggregate_invocation_budget(&mismatched, &[issuer.public_key()], Some(&root),)
            .is_err()
    );

    let rogue_link = signed_link(&root, &root_subject, &delegatee.public_key(), Some(marker))?;
    let untrusted = descendant(
        "cap-untrusted-leaf",
        &rogue_issuer,
        &delegatee.public_key(),
        rogue_link,
        Some(budget),
    )?;
    assert!(
        verify_aggregate_invocation_budget(&untrusted, &[issuer.public_key()], Some(&root),)
            .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_invocation_present_field_disables_legacy_body_fallback() -> TestResult {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut body = token_body(
        "cap-no-fallback",
        &issuer.public_key(),
        &subject.public_key(),
        tool_scope(false),
    );
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 2,
        root_binding: None,
    });
    let (signature, _) = issuer.sign_canonical(&body)?;
    let token = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: body.id,
        issuer: body.issuer,
        subject: body.subject,
        scope: body.scope,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        delegation_chain: body.delegation_chain,
        aggregate_invocation_budget: body.aggregate_invocation_budget,
        algorithm: None,
        caveats: vec![],
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature,
    };

    assert!(!token.verify_signature()?);
    Ok(())
}

#[test]
fn aggregate_invocation_nested_shapes_reject_unknown_fields() -> TestResult {
    let value = serde_json::json!({
        "scope": "capability",
        "max_invocations": 1,
        "rogue": true
    });
    let parsed: core::result::Result<AggregateInvocationBudget, _> = serde_json::from_value(value);
    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_backend_binding_survives_root_round_trip() -> TestResult {
    let backend = Ed25519Backend::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign_aggregate_family_root_with_backend(
        token_body(
            "cap-backend-root",
            &backend.public_key(),
            &root_subject.public_key(),
            tool_scope(true),
        ),
        8,
        &backend,
    )?;
    let round_trip_root: CapabilityToken = serde_json::from_slice(&canonical_json_bytes(&root)?)?;
    let budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;
    let link = signed_link(
        &round_trip_root,
        &root_subject,
        &delegatee.public_key(),
        Some(marker),
    )?;
    let mut child_body = token_body(
        "cap-backend-child",
        &backend.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    child_body.issued_at = link.timestamp;
    child_body.delegation_chain = vec![link];
    child_body.aggregate_invocation_budget = Some(budget);
    let child = CapabilityToken::sign_with_backend(child_body, &backend)?;

    assert!(verify_aggregate_invocation_budget(
        &child,
        &[backend.public_key()],
        Some(&round_trip_root),
    )?
    .is_some());
    Ok(())
}

#[test]
fn aggregate_invocation_root_helper_rejects_delegated_body() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign(
        token_body(
            "cap-helper-parent",
            &issuer.public_key(),
            &root_subject.public_key(),
            tool_scope(true),
        ),
        &issuer,
    )?;
    let link = signed_link(&root, &root_subject, &delegatee.public_key(), None)?;
    let mut body = token_body(
        "cap-helper-child",
        &issuer.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    body.delegation_chain = vec![link];

    assert!(CapabilityToken::sign_aggregate_family_root(body, 1, &issuer).is_err());
    Ok(())
}

#[test]
fn aggregate_invocation_rejects_multi_hop_scope_pivot_and_intermediate_predating() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let intermediate = Keypair::generate();
    let delegatee = Keypair::generate();
    let mut root_body = token_body(
        "cap-multi-root",
        &issuer.public_key(),
        &root_subject.public_key(),
        tool_scope(true),
    );
    root_body.scope.grants[0].server_id = "*".to_string();
    let root = CapabilityToken::sign_aggregate_family_root(root_body, 7, &issuer)?;
    let budget = root
        .aggregate_invocation_budget
        .clone()
        .ok_or_else(|| std::io::Error::other("root budget missing"))?;
    let marker = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root binding missing"))?
        .delegation_marker()?;
    let mut intermediate_scope = tool_scope(true);
    intermediate_scope.grants[0].server_id = "server-a".to_string();
    let first_receipt = delegate(
        &root,
        &intermediate_scope,
        &root_subject,
        &intermediate.public_key(),
        ScopeAttenuation::empty(),
        200,
        [3_u8; 16],
    )?;
    let mut intermediate_body = token_body(
        "cap-intermediate",
        &issuer.public_key(),
        &intermediate.public_key(),
        intermediate_scope.clone(),
    );
    intermediate_body.issued_at = 250;
    intermediate_body.delegation_chain = first_receipt.complete_chain();
    intermediate_body.aggregate_invocation_budget = Some(budget.clone());
    let intermediate_token = CapabilityToken::sign(intermediate_body, &issuer)?;

    let make_leaf =
        |id: &str, mut scope: ChioScope, timestamp: u64| -> crate::error::Result<CapabilityToken> {
            let second = DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: intermediate_token.id.clone(),
                    delegator: intermediate.public_key(),
                    delegatee: delegatee.public_key(),
                    attenuations: vec![],
                    timestamp,
                    scope_hash: Some(scope_hash(&intermediate_token.scope)?),
                    aggregate_budget: Some(marker.clone()),
                    cumulative_approval: None,
                },
                &intermediate,
            )?;
            scope.grants[0]
                .operations
                .retain(|op| op != &Operation::Delegate);
            let mut body = token_body(id, &issuer.public_key(), &delegatee.public_key(), scope);
            body.issued_at = 300;
            body.delegation_chain = intermediate_token
                .delegation_chain
                .iter()
                .cloned()
                .chain(core::iter::once(second))
                .collect();
            body.aggregate_invocation_budget = Some(budget.clone());
            CapabilityToken::sign(body, &issuer)
        };

    let mut pivot_scope = tool_scope(false);
    pivot_scope.grants[0].server_id = "server-b".to_string();
    let pivot = make_leaf("cap-multi-pivot", pivot_scope, 275)?;
    let chronology = make_leaf(
        "cap-multi-chronology",
        intermediate_scope,
        intermediate_token.issued_at.saturating_sub(1),
    )?;

    for leaf in [&pivot, &chronology] {
        let error =
            match verify_aggregate_invocation_budget(leaf, &[issuer.public_key()], Some(&root)) {
                Err(error) => error,
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "multi-hop aggregate family did not fail closed",
                    )
                    .into());
                }
            };
        assert!(error.to_string().contains("per-hop signed child-scope"));
    }
    Ok(())
}

#[test]
fn aggregate_invocation_delegate_projects_marker_across_hops() -> TestResult {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let intermediate = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = signed_family_root("cap-delegate-root", &issuer, &root_subject, 7)?;
    let first = delegate(
        &root,
        &tool_scope(true),
        &root_subject,
        &intermediate.public_key(),
        ScopeAttenuation::empty(),
        200,
        [1_u8; 16],
    )?;
    assert_eq!(first.aggregate_budget, first.link.aggregate_budget);
    assert!(first.aggregate_budget.is_some());
    first.canonical_bytes()?;

    let mut intermediate_body = token_body(
        "cap-delegate-intermediate",
        &issuer.public_key(),
        &intermediate.public_key(),
        tool_scope(true),
    );
    intermediate_body.issued_at = first.link.timestamp;
    intermediate_body.delegation_chain = first.complete_chain();
    intermediate_body.aggregate_invocation_budget = root.aggregate_invocation_budget.clone();
    let intermediate_token = CapabilityToken::sign(intermediate_body, &issuer)?;
    let second = delegate(
        &intermediate_token,
        &tool_scope(false),
        &intermediate,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        300,
        [2_u8; 16],
    )?;

    assert_eq!(second.aggregate_budget, first.aggregate_budget);
    assert_eq!(second.aggregate_budget, second.link.aggregate_budget);
    second.canonical_bytes()?;
    Ok(())
}

#[test]
fn aggregate_invocation_all_nested_shapes_reject_unknown_fields() -> TestResult {
    let issuer = Keypair::generate();
    let root = signed_family_root("cap-strict-shapes", &issuer, &Keypair::generate(), 2)?;
    let binding = root
        .aggregate_invocation_budget
        .as_ref()
        .and_then(|budget| budget.root_binding.as_ref())
        .ok_or_else(|| std::io::Error::other("root binding missing"))?;
    let marker = binding.delegation_marker()?;

    let mut binding_body = serde_json::to_value(&binding.body)?;
    binding_body
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("binding body is not an object"))?
        .insert("rogue".to_string(), serde_json::Value::Bool(true));
    let mut binding_value = serde_json::to_value(binding)?;
    binding_value
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("binding is not an object"))?
        .insert("rogue".to_string(), serde_json::Value::Bool(true));
    let mut marker_value = serde_json::to_value(marker)?;
    marker_value
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("marker is not an object"))?
        .insert("rogue".to_string(), serde_json::Value::Bool(true));

    assert!(
        serde_json::from_value::<super::aggregate_invocation::AggregateBudgetRootBindingBody>(
            binding_body
        )
        .is_err()
    );
    assert!(serde_json::from_value::<AggregateBudgetRootBinding>(binding_value).is_err());
    assert!(
        serde_json::from_value::<super::aggregate_invocation::AggregateBudgetDelegationMarker>(
            marker_value
        )
        .is_err()
    );
    Ok(())
}
