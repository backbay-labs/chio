use super::*;
use crate::InMemoryBudgetRegistry;
use alloc::vec;
use chio_core_types::capability::{
    aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
    attenuation::{
        compute_attenuation_witness, delegate, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    features,
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::delegation_receipt::ScopeAttenuation;
use core::cell::Cell;

#[test]
fn aggregate_invocation_budget_rejects_until_negotiated() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let mut body = CapabilityTokenBody {
        id: "cap-aggregate-disabled".to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::generate().public_key(),
        scope: ChioScope::default(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    let token = CapabilityToken::sign(body, &issuer)
        .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let clock = crate::FixedClock::new(150);

    let result = verify_capability(&token, &[issuer.public_key()], &clock);
    assert!(matches!(
        result,
        Err(CapabilityError::AttenuationViolation(_))
    ));
    Ok(())
}

fn aggregate_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(features::AGGREGATE_INVOCATION_BUDGET.to_string(), true);
    peer
}

fn cumulative_peer() -> CapabilityNegotiation {
    let mut peer = CapabilityNegotiation::v1_default();
    peer.features
        .insert(features::CUMULATIVE_APPROVAL_BUDGET.to_string(), true);
    peer
}

fn delegable_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn cumulative_scope(delegable: bool, constraint: Constraint) -> ChioScope {
    let mut operations = vec![Operation::Invoke];
    if delegable {
        operations.push(Operation::Delegate);
    }
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server".to_string(),
            tool_name: "tool".to_string(),
            operations,
            constraints: vec![constraint],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn cumulative_constraint(
    binding: Option<
        chio_core_types::capability::cumulative_approval::CumulativeApprovalRootBinding,
    >,
) -> Constraint {
    Constraint::RequireCumulativeApprovalAbove {
        threshold: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        approval_budget_id: "budget-1".to_string(),
        approval_budget_epoch: 7,
        cumulative_approval_root_binding: binding.map(alloc::boxed::Box::new),
    }
}

#[test]
fn aggregate_invocation_budget_accepts_only_when_negotiated() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let mut body = CapabilityTokenBody {
        id: "cap-aggregate-negotiated".to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::generate().public_key(),
        scope: ChioScope::default(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    let token = CapabilityToken::sign(body, &issuer)
        .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let clock = crate::FixedClock::new(150);
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = NoopBudgetRegistry;

    let verified = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &aggregate_peer(),
        &resolver,
        &mut budgets,
    )?;

    assert_eq!(verified.id, token.id);
    Ok(())
}

#[test]
fn full_verifier_rejects_malformed_peer_before_feature_use() {
    let issuer = Keypair::generate();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-malformed-peer".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    );
    let Ok(token) = token else {
        panic!("test token must sign");
    };
    let mut peer = aggregate_peer();
    peer.schema = "chio.capabilities.invalid".to_string();
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = NoopBudgetRegistry;

    let result = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &crate::FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &resolver,
        &mut budgets,
    );

    assert!(matches!(
        result,
        Err(CapabilityError::AttenuationViolation(message))
            if message.contains("invalid capability negotiation profile")
    ));
}

#[test]
fn delegated_aggregate_mode_requires_root_and_detects_omission() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign_aggregate_family_root(
        CapabilityTokenBody {
            id: "cap-aggregate-root".to_string(),
            issuer: issuer.public_key(),
            subject: root_subject.public_key(),
            scope: delegable_scope(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        4,
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: root.id.clone(),
            delegator: root.subject.clone(),
            delegatee: delegatee.public_key(),
            attenuations: Vec::new(),
            timestamp: 120,
            scope_hash: Some(
                scope_hash(&root.scope)
                    .map_err(|error| CapabilityError::Internal(error.to_string()))?,
            ),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &root_subject,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-aggregate-omission".to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.public_key(),
            scope: ChioScope::default(),
            issued_at: 120,
            expires_at: 190,
            delegation_chain: vec![link],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let clock = crate::FixedClock::new(150);
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = NoopBudgetRegistry;

    let missing_root = verify_capability_full(
        &child,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &aggregate_peer(),
        &resolver,
        &mut budgets,
    );
    assert!(matches!(
        missing_root,
        Err(CapabilityError::AttenuationViolation(message))
            if message.contains("authenticated direct-root token")
    ));

    let omission = verify_capability_full_with_root(
        &child,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        CapabilityFeatureContext {
            peer: &aggregate_peer(),
            direct_root: Some(&root),
        },
        &resolver,
        &mut budgets,
    );
    assert!(matches!(
        omission,
        Err(CapabilityError::AttenuationViolation(message))
            if message.contains("omitted its family aggregate budget")
    ));
    Ok(())
}

#[test]
fn delegated_aggregate_budget_accepts_authenticated_root() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign_aggregate_family_root(
        CapabilityTokenBody {
            id: "cap-aggregate-family".to_string(),
            issuer: issuer.public_key(),
            subject: root_subject.public_key(),
            scope: delegable_scope(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        4,
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let receipt = delegate(
        &root,
        &ChioScope::default(),
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        120,
        [7_u8; 16],
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-aggregate-child".to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.public_key(),
            scope: ChioScope::default(),
            issued_at: 120,
            expires_at: 190,
            delegation_chain: receipt.complete_chain(),
            aggregate_invocation_budget: root.aggregate_invocation_budget.clone(),
        },
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = InMemoryBudgetRegistry::new();
    budgets.register_parent(root.id.clone(), crate::MAX_BUDGET_SHARE_BPS)?;

    let verified = verify_capability_full_with_root(
        &child,
        &[issuer.public_key()],
        &crate::FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        CapabilityFeatureContext {
            peer: &aggregate_peer(),
            direct_root: Some(&root),
        },
        &resolver,
        &mut budgets,
    )?;

    assert_eq!(verified.id, child.id);
    Ok(())
}

#[test]
fn cumulative_approval_requires_negotiation() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-cumulative-direct".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: cumulative_scope(false, cumulative_constraint(None)),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let clock = crate::FixedClock::new(150);
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = NoopBudgetRegistry;

    let disabled = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &CapabilityNegotiation::v1_default(),
        &resolver,
        &mut budgets,
    );
    assert!(matches!(
        disabled,
        Err(CapabilityError::AttenuationViolation(message))
            if message.contains("cumulative_approval_budget was not negotiated")
    ));

    let verified = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &cumulative_peer(),
        &resolver,
        &mut budgets,
    )?;
    assert_eq!(verified.id, token.id);
    Ok(())
}

#[test]
fn delegated_cumulative_approval_requires_authenticated_root() -> Result<(), CapabilityError> {
    let issuer = Keypair::generate();
    let root_subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let root = CapabilityToken::sign_cumulative_approval_family_root(
        CapabilityTokenBody {
            id: "cap-cumulative-root".to_string(),
            issuer: issuer.public_key(),
            subject: root_subject.public_key(),
            scope: cumulative_scope(true, cumulative_constraint(None)),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let binding = root
        .scope
        .grants
        .first()
        .and_then(|grant| grant.constraints.first())
        .and_then(Constraint::cumulative_approval_root_binding)
        .cloned()
        .ok_or_else(|| CapabilityError::Internal("cumulative root binding missing".to_string()))?;
    let child_scope = cumulative_scope(false, cumulative_constraint(Some(binding)));
    let receipt = delegate(
        &root,
        &child_scope,
        &root_subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        120,
        [8_u8; 16],
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-cumulative-child".to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.public_key(),
            scope: child_scope,
            issued_at: 120,
            expires_at: 190,
            delegation_chain: receipt.complete_chain(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .map_err(|error| CapabilityError::Internal(error.to_string()))?;
    let clock = crate::FixedClock::new(150);
    let resolver = |_issuer: &PublicKey| None;
    let mut budgets = InMemoryBudgetRegistry::new();
    budgets.register_parent(root.id.clone(), crate::MAX_BUDGET_SHARE_BPS)?;

    let missing_root = verify_capability_full(
        &child,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &cumulative_peer(),
        &resolver,
        &mut budgets,
    );
    assert!(matches!(
        missing_root,
        Err(CapabilityError::AttenuationViolation(message))
            if message.contains("direct-root evidence")
    ));

    let verified = verify_capability_full_with_root(
        &child,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        CapabilityFeatureContext {
            peer: &cumulative_peer(),
            direct_root: Some(&root),
        },
        &resolver,
        &mut budgets,
    )?;
    assert_eq!(verified.id, child.id);
    Ok(())
}

struct CountingTrustRootResolver {
    issuer: PublicKey,
    root: ScopeHash,
    calls: Cell<u32>,
}

impl CountingTrustRootResolver {
    fn new(issuer: PublicKey, root: ScopeHash) -> Self {
        Self {
            issuer,
            root,
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.get()
    }
}

impl TrustRootResolver for CountingTrustRootResolver {
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash> {
        self.calls.set(self.calls.get() + 1);
        if issuer == &self.issuer {
            Some(self.root.clone())
        } else {
            None
        }
    }
}

#[test]
fn pq_required_rejects_classical_capability() {
    let issuer = Keypair::generate();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-classical".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign classical capability");
    let clock = crate::FixedClock::new(150);

    let mut budgets = NoopBudgetRegistry;
    let err = verify_capability_with_floor(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::PqRequired,
        &mut budgets,
    )
    .expect_err("classical capability must fail under pq_required");

    assert!(matches!(err, CapabilityError::CryptoFloorRejected(_)));
}

#[test]
fn allow_classical_accepts_classical_capability() {
    let issuer = Keypair::generate();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-classical".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign classical capability");
    let clock = crate::FixedClock::new(150);

    let mut budgets = NoopBudgetRegistry;
    let verified = verify_capability_with_floor(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect("classical capability is accepted under allow_classical");

    assert_eq!(verified.id, "cap-classical");
}

fn make_attenuated_token(id: &str, issuer: &Keypair, subject: &Keypair) -> CapabilityToken {
    let scope = ChioScope::default();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).expect("parent scope hash"),
        child_scope_hash: scope_hash(&scope).expect("child scope hash"),
        normalized_subset_proof: compute_attenuation_witness(&scope, &scope)
            .expect("attenuation witness"),
    };
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope,
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        issuer,
    )
    .expect("sign attenuated token")
}

fn counting_resolver_for(issuer: &Keypair) -> CountingTrustRootResolver {
    CountingTrustRootResolver::new(
        issuer.public_key(),
        scope_hash(&ChioScope::default()).expect("trust root hash"),
    )
}

#[test]
fn full_verifier_rejects_attenuated_token_when_chain_binding_feature_is_disabled() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = make_attenuated_token("cap-attenuated-disabled-chain-binding", &issuer, &subject);
    let clock = crate::FixedClock::new(150);
    let mut peer = CapabilityNegotiation::t1_default();
    peer.features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect_err("attenuated token must fail when chain binding is disabled");

    assert!(matches!(err, CapabilityError::AttenuationViolation(_)));
}

#[test]
fn full_verifier_rejects_untrusted_attenuated_token_before_resolver_lookup() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = make_attenuated_token("cap-untrusted-before-resolver", &issuer, &subject);
    let clock = crate::FixedClock::new(150);
    let peer = CapabilityNegotiation::t1_default();
    let resolver = counting_resolver_for(&issuer);
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &resolver,
        &mut budgets,
    )
    .expect_err("untrusted attenuated token must fail before chain binding");

    assert_eq!(err, CapabilityError::UntrustedIssuer);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn full_verifier_rejects_tampered_attenuated_token_before_resolver_lookup() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut token = make_attenuated_token("cap-tampered-before-resolver", &issuer, &subject);
    token.id.push_str("-tampered");
    let clock = crate::FixedClock::new(150);
    let peer = CapabilityNegotiation::t1_default();
    let resolver = counting_resolver_for(&issuer);
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &resolver,
        &mut budgets,
    )
    .expect_err("tampered attenuated token must fail before chain binding");

    assert_eq!(err, CapabilityError::InvalidSignature);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn full_verifier_rejects_expired_attenuated_token_before_resolver_lookup() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = make_attenuated_token("cap-expired-before-resolver", &issuer, &subject);
    let clock = crate::FixedClock::new(201);
    let peer = CapabilityNegotiation::t1_default();
    let resolver = counting_resolver_for(&issuer);
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &resolver,
        &mut budgets,
    )
    .expect_err("expired attenuated token must fail before chain binding");

    assert_eq!(err, CapabilityError::Expired);
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn full_verifier_accepts_plain_pass_through_delegation_when_chain_binding_feature_is_disabled() {
    // A pass-through delegation that introduces no new attenuation does
    // not require chain binding, so the negotiated
    // `DELEGATION_CHAIN_BINDING=false` profile must NOT reject it. The
    // leaf token is signed by its issuer and each `DelegationLink`
    // carries its own signature; there is nothing about the leaf scope
    // for the chain-binding rule to bind against.
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "parent-capability".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "delegated-current-v1-token".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::from([parent_link]),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign delegated token");
    let clock = crate::FixedClock::new(150);
    let mut peer = CapabilityNegotiation::t1_default();
    peer.features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    // The parent must already be registered in the budget registry for
    // sibling-sum admission; pass-through delegations admit at the full
    // parent share.
    let mut budgets = InMemoryBudgetRegistry::new();
    BudgetRegistry::register_parent(
        &mut budgets,
        "parent-capability".to_string(),
        crate::budget_split::MAX_BUDGET_SHARE_BPS,
    )
    .expect("register parent");

    let verified = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect("pass-through delegation must verify when no new attenuation is introduced");

    assert_eq!(verified.id, "delegated-current-v1-token");
}

#[test]
fn full_verifier_rejects_delegation_chain_with_wrong_final_delegatee() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "parent-capability".to_string(),
            delegator: issuer.public_key(),
            delegatee: issuer.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "delegated-wrong-final-delegatee".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::from([parent_link]),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign delegated token");
    let clock = crate::FixedClock::new(150);
    let mut peer = CapabilityNegotiation::t1_default();
    peer.features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    let mut budgets = InMemoryBudgetRegistry::new();

    let err = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect_err("mismatched final delegatee must fail");

    match err {
        CapabilityError::AttenuationViolation(message) => {
            assert!(message.contains("final delegatee does not match capability subject"));
        }
        other => panic!("expected attenuation violation, got {other:?}"),
    }
}

#[test]
fn full_verifier_rejects_tampered_delegation_link_payload() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "parent-capability".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    parent_link.capability_id = "tampered-parent".to_string();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "delegated-tampered-link".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::from([parent_link]),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign delegated token");
    let clock = crate::FixedClock::new(150);
    let mut peer = CapabilityNegotiation::t1_default();
    peer.features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    let mut budgets = InMemoryBudgetRegistry::new();

    let err = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect_err("tampered delegation link must fail");

    match err {
        CapabilityError::AttenuationViolation(message) => {
            assert!(message.contains("signature invalid"));
        }
        other => panic!("expected attenuation violation, got {other:?}"),
    }
}

#[test]
fn resolver_entrypoints_reject_tampered_plain_delegation_link() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let mut parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "parent-capability".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    parent_link.capability_id = "tampered-parent-capability".to_string();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "plain-delegated-token-with-tampered-link".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::from([parent_link]),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .expect("sign outer token");
    let clock = crate::FixedClock::new(150);
    let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
    let resolver = counting_resolver_for(&issuer);

    let resolver_err = verify_capability_with_floor_and_resolver(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &resolver,
    )
    .expect_err("resolver verifier must validate plain delegation-chain links");
    let trust_root_err = verify_capability_with_floor_and_trust_root(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &trust_root_hash,
    )
    .expect_err("trust-root verifier must validate plain delegation-chain links");

    for err in [resolver_err, trust_root_err] {
        match err {
            CapabilityError::AttenuationViolation(message) => {
                assert!(message.contains("signature invalid"));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }
}

#[test]
fn full_verifier_rejects_delegated_attenuation_unbound_from_trust_root() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let authorized_scope = ChioScope::default();
    let inflated_scope = ChioScope {
        grants: vec![chio_core_types::capability::scope::ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![chio_core_types::capability::scope::Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let inflated_hash = scope_hash(&inflated_scope).expect("inflated scope hash");
    let trust_root_hash = scope_hash(&authorized_scope).expect("trust root hash");
    assert_ne!(inflated_hash, trust_root_hash);

    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "parent-capability".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: Some(inflated_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    let proof = AttenuationProof {
        parent_scope_hash: inflated_hash,
        child_scope_hash: scope_hash(&authorized_scope).expect("child scope hash"),
        normalized_subset_proof: compute_attenuation_witness(&inflated_scope, &authorized_scope)
            .expect("attenuation witness"),
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "delegated-unbound-root".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: authorized_scope,
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![parent_link],
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("sign attenuated token");
    let clock = crate::FixedClock::new(150);
    let peer = CapabilityNegotiation::t1_default();
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect_err("first delegation link must bind to issuer trust root");

    match err {
        CapabilityError::AttenuationViolation(message) => {
            assert!(message.contains("scope_hash does not match trust root"));
        }
        other => panic!("expected attenuation violation, got {other:?}"),
    }
}

#[test]
fn full_verifier_rejects_multi_hop_attenuation_without_child_scope_witnesses() {
    let issuer = Keypair::generate();
    let intermediate = Keypair::generate();
    let subject = Keypair::generate();
    let authorized_scope = ChioScope::default();
    let trust_root_hash = scope_hash(&authorized_scope).expect("trust root hash");
    let intermediate_scope = ChioScope {
        grants: vec![chio_core_types::capability::scope::ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "tool-a".to_string(),
            operations: vec![chio_core_types::capability::scope::Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let intermediate_hash = scope_hash(&intermediate_scope).expect("intermediate scope hash");

    let first_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "root-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: intermediate.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: Some(trust_root_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign first delegation link");
    let second_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "intermediate-parent".to_string(),
            delegator: intermediate.public_key(),
            delegatee: subject.public_key(),
            attenuations: Vec::new(),
            timestamp: 101,
            scope_hash: Some(intermediate_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &intermediate,
    )
    .expect("sign second delegation link");
    let proof = AttenuationProof {
        parent_scope_hash: intermediate_hash,
        child_scope_hash: scope_hash(&authorized_scope).expect("child scope hash"),
        normalized_subset_proof: compute_attenuation_witness(
            &intermediate_scope,
            &authorized_scope,
        )
        .expect("attenuation witness"),
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "delegated-multi-hop-without-witnesses".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: authorized_scope,
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![first_link, second_link],
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("sign attenuated token");
    let clock = crate::FixedClock::new(150);
    let peer = CapabilityNegotiation::t1_default();
    let issuer_public = issuer.public_key();
    let resolver_issuer = issuer_public.clone();
    let trust_roots = move |candidate: &PublicKey| {
        if candidate == &resolver_issuer {
            Some(trust_root_hash.clone())
        } else {
            None
        }
    };
    let mut budgets = NoopBudgetRegistry;

    let err = verify_capability_full(
        &token,
        &[issuer_public],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .expect_err("multi-hop attenuated chains need per-hop child-scope witnesses");

    match err {
        CapabilityError::AttenuationViolation(message) => {
            assert!(message.contains("multi-hop attenuated delegation chains"));
        }
        other => panic!("expected attenuation violation, got {other:?}"),
    }
}

#[test]
fn delegated_budget_unknown_parent_fails_closed() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "missing-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: issuer.public_key(),
            attenuations: Vec::new(),
            timestamp: 100,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &issuer,
    )
    .expect("sign delegation link");
    let scope = ChioScope::default();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).expect("parent scope hash"),
        child_scope_hash: scope_hash(&scope).expect("child scope hash"),
        normalized_subset_proof: compute_attenuation_witness(&scope, &scope)
            .expect("attenuation witness"),
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope,
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("sign child token");
    let clock = crate::FixedClock::new(150);
    let mut budgets = crate::InMemoryBudgetRegistry::new();

    let err = verify_capability_with_floor(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
    .expect_err("unknown budget parent must fail closed");

    assert!(matches!(
        err,
        CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
    ));
}
