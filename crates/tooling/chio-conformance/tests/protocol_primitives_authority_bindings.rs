use std::error::Error;
use std::sync::Arc;

use chio_adversarial_suite::{bundled_cases_by_class, AttackClass};
use chio_core::capability::aggregate_invocation::{
    verify_aggregate_invocation_budget, AggregateBudgetDelegationMarker, AggregateBudgetRootBinding,
};
use chio_core::capability::attenuation::{scope_hash, DelegationLink, DelegationLinkBody};
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, VerifiedApprovalSetBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_kernel::threshold_approval::{
    InMemoryThresholdApprovalCollectorStore, ThresholdApprovalCollector,
    ThresholdApprovalCollectorState,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

fn family_root(
    issuer: &Keypair,
    subject: &Keypair,
    max_invocations: u32,
) -> chio_core::Result<CapabilityToken> {
    CapabilityToken::sign_aggregate_family_root(
        token_body(
            "family-root",
            &issuer.public_key(),
            &subject.public_key(),
            tool_scope(true),
        ),
        max_invocations,
        issuer,
    )
}

fn family_descendant(
    root: &CapabilityToken,
    issuer: &Keypair,
    root_subject: &Keypair,
    delegatee: &Keypair,
    marker_digest: String,
) -> chio_core::Result<CapabilityToken> {
    let budget = root.aggregate_invocation_budget.clone().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
    })?;
    let marker = AggregateBudgetDelegationMarker {
        root_binding_digest: marker_digest,
        max_invocations: budget.max_invocations,
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp: 200,
            scope_hash: Some(scope_hash(&root.scope)?),
            aggregate_budget: Some(marker),
            cumulative_approval: None,
        },
        root_subject,
    )?;
    let mut body = token_body(
        "family-child",
        &issuer.public_key(),
        &delegatee.public_key(),
        tool_scope(false),
    );
    body.issued_at = 200;
    body.expires_at = 900;
    body.delegation_chain = vec![link];
    body.aggregate_invocation_budget = Some(budget);
    CapabilityToken::sign(body, issuer)
}

fn resign_root_binding(
    root: &CapabilityToken,
    outer_signer: &Keypair,
    binding_signer: &Keypair,
    mutate: impl FnOnce(
        &mut chio_core::capability::aggregate_invocation::AggregateBudgetRootBindingBody,
    ),
) -> chio_core::Result<CapabilityToken> {
    let mut body = root.body();
    let budget = body.aggregate_invocation_budget.as_mut().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
    })?;
    let binding = budget.root_binding.as_mut().ok_or_else(|| {
        chio_core::Error::CanonicalJson("aggregate root binding missing".to_string())
    })?;
    mutate(&mut binding.body);
    *binding = AggregateBudgetRootBinding::sign(binding.body.clone(), binding_signer)?;
    CapabilityToken::sign(body, outer_signer)
}

fn mutation_names(primitive: &str) -> TestResult<Vec<String>> {
    let cases = bundled_cases_by_class(AttackClass::AuthorityBindingMutation)?;
    let case = cases
        .iter()
        .find(|case| case.artifact["primitive"] == primitive)
        .ok_or_else(|| std::io::Error::other(format!("missing {primitive} vector")))?;
    serde_json::from_value(case.artifact["mutations"].clone()).map_err(Into::into)
}

#[test]
fn aggregate_root_binding_mutation_vectors_fail_closed() -> TestResult {
    let issuer = Keypair::from_seed(&[1; 32]);
    let root_subject = Keypair::from_seed(&[2; 32]);
    let attacker = Keypair::from_seed(&[3; 32]);
    let root = family_root(&issuer, &root_subject, 7)?;
    let trusted = [issuer.public_key()];

    for mutation in mutation_names("aggregate_budget_root_binding")? {
        if mutation == "root_binding_digest" {
            let delegatee = Keypair::from_seed(&[4; 32]);
            let child = family_descendant(
                &root,
                &issuer,
                &root_subject,
                &delegatee,
                sha256_hex(b"forged-binding-digest"),
            );
            if let Ok(child) = child {
                assert!(verify_aggregate_invocation_budget(&child, &trusted, Some(&root)).is_err());
            }
            continue;
        }

        let forged = match mutation.as_str() {
            "root_capability_id" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_capability_id = "forged-root".to_string();
            }),
            "root_capability_hash" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_capability_hash = sha256_hex(b"forged-root");
            }),
            "root_issuer" => resign_root_binding(&root, &issuer, &attacker, |body| {
                body.root_issuer = attacker.public_key();
            }),
            "root_subject" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_subject = attacker.public_key();
            }),
            "root_scope_hash" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_scope_hash = sha256_hex(b"forged-scope");
            }),
            "root_expires_at" => resign_root_binding(&root, &issuer, &issuer, |body| {
                body.root_expires_at = body.root_expires_at.saturating_add(1);
            }),
            "signature" => {
                let mut body = root.body();
                let budget = body.aggregate_invocation_budget.as_mut().ok_or_else(|| {
                    chio_core::Error::CanonicalJson("aggregate root budget missing".to_string())
                })?;
                let binding = budget.root_binding.as_mut().ok_or_else(|| {
                    chio_core::Error::CanonicalJson("aggregate root binding missing".to_string())
                })?;
                let mut other_body = binding.body.clone();
                other_body.root_capability_id = "signature-source".to_string();
                binding.signature =
                    AggregateBudgetRootBinding::sign(other_body, &issuer)?.signature;
                CapabilityToken::sign(body, &issuer)
            }
            other => return Err(std::io::Error::other(format!("unknown mutation {other}")).into()),
        };
        let Ok(forged) = forged else {
            continue;
        };
        assert!(
            verify_aggregate_invocation_budget(&forged, &trusted, None).is_err(),
            "mutation {mutation} was accepted"
        );
    }
    Ok(())
}

struct ThresholdFixture {
    collector: ThresholdApprovalCollector,
    authority: Keypair,
    alice: Keypair,
    bob: Keypair,
    subject: Keypair,
    requirement: ThresholdApprovalRequirement,
}

fn threshold_fixture() -> TestResult<ThresholdFixture> {
    let authority = Keypair::from_seed(&[11; 32]);
    let alice = Keypair::from_seed(&[12; 32]);
    let bob = Keypair::from_seed(&[13; 32]);
    let subject = Keypair::from_seed(&[14; 32]);
    let policy_hash = sha256_hex(b"active-policy");
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
    .map_err(std::io::Error::other)?;
    let collector = ThresholdApprovalCollector::new(
        Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
        policy_hash,
        vec![authority.public_key()],
    );
    Ok(ThresholdFixture {
        collector,
        authority,
        alice,
        bob,
        subject,
        requirement,
    })
}

fn proposal(fixture: &ThresholdFixture) -> chio_core::Result<ThresholdApprovalProposal> {
    ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-1".to_string(),
            request_id: "request-1".to_string(),
            governed_intent_hash: sha256_hex(b"intent"),
            subject: fixture.subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"capability"),
            policy_hash: fixture.requirement.policy_hash.clone(),
            threshold: fixture.requirement.threshold,
            eligible_set_digest: fixture.requirement.eligible_set_digest.clone(),
            proposal_created_at: 100,
            proposal_deadline: 200,
            policy_authority: fixture.authority.public_key(),
        },
        &fixture.authority,
    )
}

fn approval_token(
    proposal: &ThresholdApprovalProposal,
    approver: &Keypair,
    id: &str,
) -> chio_core::Result<GovernedApprovalToken> {
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: id.to_string(),
            approver: approver.public_key(),
            subject: proposal.body.subject.clone(),
            governed_intent_hash: proposal.body.governed_intent_hash.clone(),
            request_id: proposal.body.request_id.clone(),
            threshold_proposal_hash: Some(proposal.artifact_digest()?),
            issued_at: 101,
            expires_at: 199,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
}

#[test]
fn threshold_proposal_mutations_and_exact_quorum_fail_closed() -> TestResult {
    let fixture = threshold_fixture()?;
    let proposal = proposal(&fixture)?;

    for mutation in mutation_names("threshold_approval_proposal")? {
        match mutation.as_str() {
            "future" => assert!(proposal.validate_at(99).is_err()),
            "expired" => assert!(proposal.validate_at(200).is_err()),
            "proposal_deadline" => {
                let mut changed = proposal.clone();
                changed.body.proposal_deadline = 201;
                assert!(!changed.verify_signature()?);
            }
            "eligible_set_digest" => {
                let mut changed = proposal.clone();
                changed.body.eligible_set_digest = sha256_hex(b"changed-set");
                assert!(!changed.verify_signature()?);
            }
            "governed_intent_hash" => {
                let mut changed = proposal.clone();
                changed.body.governed_intent_hash = sha256_hex(b"changed-intent");
                assert!(!changed.verify_signature()?);
            }
            "authorizing_capability_digest" => {
                let mut changed = proposal.clone();
                changed.body.authorizing_capability_digest = sha256_hex(b"changed-capability");
                assert!(!changed.verify_signature()?);
            }
            other => return Err(std::io::Error::other(format!("unknown mutation {other}")).into()),
        }
    }

    fixture.collector.create_proposal(
        proposal.clone(),
        fixture.requirement.clone(),
        None,
        false,
        100,
    )?;
    let one = fixture.collector.submit_token(
        "proposal-1",
        approval_token(&proposal, &fixture.alice, "token-alice")?,
        110,
    )?;
    assert_eq!(one.state, ThresholdApprovalCollectorState::Collecting);
    assert!(fixture
        .collector
        .submit_token(
            "proposal-1",
            approval_token(&proposal, &fixture.alice, "token-alice-replay")?,
            111,
        )
        .is_err());
    let exact = fixture.collector.submit_token(
        "proposal-1",
        approval_token(&proposal, &fixture.bob, "token-bob")?,
        112,
    )?;
    assert_eq!(exact.state, ThresholdApprovalCollectorState::Ready);
    assert_eq!(exact.tokens.len(), 2);
    Ok(())
}

#[test]
fn verified_approval_set_is_order_invariant_and_domain_separated() -> TestResult {
    let fixture = threshold_fixture()?;
    let proposal = proposal(&fixture)?;
    let alice = approval_token(&proposal, &fixture.alice, "token-alice")?.artifact_digest()?;
    let bob = approval_token(&proposal, &fixture.bob, "token-bob")?.artifact_digest()?;
    let first = VerifiedApprovalSetBody::new(vec![alice.clone(), bob.clone()], &proposal)?;
    let second = VerifiedApprovalSetBody::new(vec![bob, alice], &proposal)?;

    assert_eq!(first, second);
    assert_eq!(first.approval_set_hash()?, second.approval_set_hash()?);
    assert_ne!(first.approval_set_hash()?, proposal.artifact_digest()?);
    assert!(VerifiedApprovalSetBody::new(
        vec![sha256_hex(b"duplicate"), sha256_hex(b"duplicate")],
        &proposal,
    )
    .is_err());
    Ok(())
}
