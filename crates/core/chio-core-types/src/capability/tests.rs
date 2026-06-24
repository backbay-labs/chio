use alloc::collections::BTreeMap;

use crate::crypto::{Keypair, PublicKey, SigningBackend};
use crate::error::{Error, Result};
use crate::runtime_attestation::AttestationVerifierFamily;
use crate::session::SessionAnchorReference;

use super::attenuation::*;
use super::caveat::GrantSubsetRelation;
use super::crypto_floor::*;
use super::features;
use super::features::*;
use super::governance::*;
use super::runtime_attestation::*;
use super::scope::*;
use super::token::*;
use super::trust_policy::*;
use super::workload_identity::*;

fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: ops,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

#[test]
fn capability_token_serde_roundtrip() {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-001".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();

    let json = serde_json::to_string_pretty(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

    assert_eq!(token.id, restored.id);
    assert_eq!(token.issuer, restored.issuer);
    assert_eq!(token.subject, restored.subject);
    assert_eq!(token.issued_at, restored.issued_at);
    assert_eq!(token.expires_at, restored.expires_at);
    assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
}

#[test]
fn capability_token_signature_verification() {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-002".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "shell_exec",
            vec![Operation::Invoke, Operation::ReadResult],
        )]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    assert!(token.verify_signature().unwrap());
}

#[test]
fn legacy_body_signed_capability_token_still_verifies() -> Result<()> {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-legacy-body".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let (signature, _bytes) = kp.sign_canonical(&body)?;
    let token = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: body.id,
        issuer: body.issuer,
        subject: body.subject,
        scope: body.scope,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        delegation_chain: body.delegation_chain,
        algorithm: None,
        caveats: Vec::new(),
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature,
    };

    assert!(token.verify_signature()?);
    assert!(matches!(
        token.verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical),
        Ok(true)
    ));
    Ok(())
}

#[test]
fn wrong_key_signature_fails() {
    let kp = Keypair::generate();
    let other_kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-003".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let mut token = CapabilityToken::sign(body, &kp).unwrap();
    token.issuer = other_kp.public_key();
    // Tampering the embedded verifier key after signing should fail.
    assert!(!token.verify_signature().unwrap());
}

#[test]
fn time_validation() {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-time".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: make_scope(vec![]),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();

    assert!(token.is_valid_at(1000));
    assert!(token.is_valid_at(1500));
    assert!(token.is_valid_at(1999));
    assert!(!token.is_valid_at(999)); // before issued_at
    assert!(!token.is_valid_at(2000)); // at expires_at (exclusive)
    assert!(!token.is_valid_at(3000)); // after expires_at

    assert!(token.is_expired_at(2000));
    assert!(token.is_expired_at(3000));
    assert!(!token.is_expired_at(1999));

    assert!(token.validate_time(1500).is_ok());
    assert!(token.validate_time(999).is_err());
    assert!(token.validate_time(2000).is_err());
}

#[test]
fn scope_subset_same() {
    let scope = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    assert!(scope.is_subset_of(&scope));
}

#[test]
fn scope_subset_fewer_grants() {
    let parent = make_scope(vec![
        make_grant("a", "t1", vec![Operation::Invoke]),
        make_grant("a", "t2", vec![Operation::Invoke]),
    ]);
    let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    assert!(child.is_subset_of(&parent));
    assert!(!parent.is_subset_of(&child));
}

#[test]
fn scope_subset_fewer_operations() {
    let parent = make_scope(vec![make_grant(
        "a",
        "t1",
        vec![Operation::Invoke, Operation::ReadResult],
    )]);
    let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    assert!(child.is_subset_of(&parent));
    assert!(!parent.is_subset_of(&child));
}

#[test]
fn scope_not_subset_different_server() {
    let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    let child = make_scope(vec![make_grant("b", "t1", vec![Operation::Invoke])]);
    assert!(!child.is_subset_of(&parent));
}

#[test]
fn scope_not_subset_different_tool() {
    let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    let child = make_scope(vec![make_grant("a", "t2", vec![Operation::Invoke])]);
    assert!(!child.is_subset_of(&parent));
}

#[test]
fn scope_subset_wildcard_tool() {
    let parent = make_scope(vec![make_grant("a", "*", vec![Operation::Invoke])]);
    let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    assert!(child.is_subset_of(&parent));
}

#[test]
fn grant_subset_with_invocation_budget() {
    let parent = ToolGrant {
        server_id: "a".to_string(),
        tool_name: "t1".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: Some(10),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let child_ok = ToolGrant {
        max_invocations: Some(5),
        ..parent.clone()
    };
    let child_exceed = ToolGrant {
        max_invocations: Some(20),
        ..parent.clone()
    };
    let child_none = ToolGrant {
        max_invocations: None,
        ..parent.clone()
    };

    assert!(child_ok.is_subset_of(&parent));
    assert!(!child_exceed.is_subset_of(&parent));
    assert!(!child_none.is_subset_of(&parent)); // uncapped child of capped parent
}

#[test]
fn grant_subset_with_constraints() {
    let parent = ToolGrant {
        server_id: "a".to_string(),
        tool_name: "t1".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::PathPrefix("/app".to_string())],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    // Child has parent's constraint + an extra one (more restrictive)
    let child = ToolGrant {
        constraints: vec![
            Constraint::PathPrefix("/app".to_string()),
            Constraint::MaxLength(1024),
        ],
        ..parent.clone()
    };
    // Child missing parent's constraint (less restrictive)
    let bad_child = ToolGrant {
        constraints: vec![Constraint::MaxLength(1024)],
        ..parent.clone()
    };

    assert!(child.is_subset_of(&parent));
    assert!(!bad_child.is_subset_of(&parent));
}

#[test]
fn grant_subset_with_wildcard_server() {
    let parent = ToolGrant {
        server_id: "*".to_string(),
        tool_name: "read_file".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let child = ToolGrant {
        server_id: "filesystem".to_string(),
        tool_name: "read_file".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };

    assert!(child.is_subset_of(&parent));
}

#[test]
fn validate_attenuation_ok() {
    let parent = make_scope(vec![
        make_grant("a", "t1", vec![Operation::Invoke, Operation::ReadResult]),
        make_grant("a", "t2", vec![Operation::Invoke]),
    ]);
    let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    assert!(validate_attenuation(&parent, &child).is_ok());
}

#[test]
fn validate_attenuation_escalation_fails() {
    let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
    let child = make_scope(vec![make_grant(
        "a",
        "t1",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    assert!(validate_attenuation(&parent, &child).is_err());
}

#[test]
fn attenuation_witness_roundtrip_and_forgery_rejection() {
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::ReadResult],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);

    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let parent_hash = scope_hash(&parent).unwrap();
    let child_hash = scope_hash(&child).unwrap();

    verify_attenuation_witness(&parent_hash, &child_hash, &witness).unwrap();
    let forged = "00".repeat(32);
    assert!(verify_attenuation_witness(&forged, &child_hash, &witness).is_err());
}

#[test]
fn attenuated_capability_schema_and_budget_fail_closed() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent).unwrap(),
        child_scope_hash: scope_hash(&child).unwrap(),
        normalized_subset_proof: witness,
    };
    let body = CapabilityTokenBody {
        id: "cap-attenuated".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: body.clone(),
            caveats: vec![],
            scope_attenuations: vec![Attenuation::RemoveOperation {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operation: Operation::ReadResult,
            }],
            attenuation_proof: proof.clone(),
            budget_share_bps: Some(5_000),
        },
        &issuer,
    )
    .unwrap();
    assert_eq!(token.schema, CHIO_CAPABILITY_SCHEMA);
    assert!(token.verify_signature().unwrap());

    let mut bad_schema = token.clone();
    bad_schema.schema = "chio.capability.v999".to_string();
    assert!(bad_schema.verify_signature().is_err());

    let bad_budget = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(10_001),
        },
        &issuer,
    );
    assert!(bad_budget.is_err());
}

#[test]
fn attenuated_capability_chain_binding_feature_disabled_fails_closed() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let scope = ChioScope::default();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(&scope, &scope).unwrap(),
    };
    let body = CapabilityTokenBody {
        id: "cap-attenuated-disabled-chain-binding".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .unwrap();
    let mut negotiated = CapabilityNegotiation::t1_default();
    negotiated
        .features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);

    let err = token
        .validate_chain_binding_with_features(
            &scope_hash(&ChioScope::default()).unwrap(),
            &negotiated,
        )
        .expect_err("disabled chain binding must reject attenuated tokens");
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[test]
fn attenuated_capability_requires_attenuation_proof() -> Result<()> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent)?,
        child_scope_hash: scope_hash(&child)?,
        normalized_subset_proof: compute_attenuation_witness(&parent, &child)?,
    };
    let body = CapabilityTokenBody {
        id: "cap-attenuated".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
    };
    let mut token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(10_000),
        },
        &issuer,
    )?;
    token.attenuation_proof = None;

    assert!(token.verify_signature().is_err());
    Ok(())
}

#[test]
fn empty_child_scope_attenuation_proof_survives_serialization() -> Result<()> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = make_scope(vec![make_grant(
        "srv",
        "tool",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let child = ChioScope::default();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent)?,
        child_scope_hash: scope_hash(&child)?,
        normalized_subset_proof: compute_attenuation_witness(&parent, &child)?,
    };
    let body = CapabilityTokenBody {
        id: "cap-empty-child".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child,
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )?;

    let value = serde_json::to_value(&token)?;
    assert!(value.get("attenuation_proof").is_some());
    Ok(())
}

#[test]
fn attenuation_proof_validation_rejects_non_subset_scope() -> Result<()> {
    let parent = ChioScope::default();
    let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
    let witness = AttenuationWitness {
        normalized_parent_scope: canonical_scope_string(&parent)?,
        normalized_child_scope: canonical_scope_string(&child)?,
        subset_relations: vec![GrantSubsetRelation {
            grant_kind: "tool".to_string(),
            child_index: 0,
            parent_index: 0,
            subset: true,
        }],
        restricted_predicates: vec![],
    };

    let parent_hash = scope_hash(&parent)?;
    let child_hash = scope_hash(&child)?;
    assert!(validate_attenuation_proof(&parent_hash, &child_hash, &witness).is_err());
    Ok(())
}

#[test]
fn capability_negotiation_intersection_rejects_malformed_feature() {
    let local = CapabilityNegotiation::t1_default();
    let remote = CapabilityNegotiation::v1_default();
    let negotiated = local.negotiated_with(&remote).unwrap();
    assert_eq!(negotiated.schema, CHIO_CAPABILITIES_SCHEMA);

    let mut malformed = CapabilityNegotiation::t1_default();
    malformed.features.insert("bad feature".to_string(), true);
    assert!(local.negotiated_with(&malformed).is_err());
}

#[test]
fn capability_negotiation_preserves_explicit_disabled_features() {
    let local = CapabilityNegotiation::t1_default();
    let mut remote = CapabilityNegotiation::t1_default();
    remote
        .features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);

    let negotiated = local.negotiated_with(&remote).unwrap();

    assert_eq!(negotiated.schema, CHIO_CAPABILITIES_SCHEMA);
    assert_eq!(
        negotiated
            .features
            .get(features::DELEGATION_CHAIN_BINDING)
            .copied(),
        Some(false)
    );
}

#[test]
fn chain_binding_disabled_does_not_reject_v1_tokens() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-v1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 10,
            expires_at: 20,
            delegation_chain: vec![],
        },
        &issuer,
    )
    .unwrap();
    let mut negotiated = CapabilityNegotiation::t1_default();
    negotiated
        .features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);

    token
        .validate_chain_binding_with_features(
            &scope_hash(&ChioScope::default()).unwrap(),
            &negotiated,
        )
        .unwrap();
}

#[test]
fn plain_delegated_token_without_attenuation_proof_verifies_and_skips_chain_binding() {
    // Regression: a plain pass-through delegation that introduces no
    // new attenuation must not trigger the chain-binding requirement.
    // The leaf token is signed by its issuer, each `DelegationLink`
    // carries its own signature, and the chain connectivity invariants
    // hold via `validate_delegation_chain`. Requiring an
    // `attenuation_proof` in this shape would make every plain mobile/
    // context delegation flow unverifiable while adding no soundness.
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: None,
        },
        &issuer,
    )
    .unwrap();

    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-delegated-passthrough".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: vec![parent_link],
        },
        &issuer,
    )
    .unwrap();

    // A plain pass-through delegation should not require chain binding.
    assert!(
        !token.requires_chain_binding(),
        "plain delegation without new attenuation must not require chain binding"
    );

    // The leaf-token signature still verifies and the chain links still
    // validate independently.
    assert!(token.verify_signature().unwrap());
    assert!(validate_delegation_chain(&token.delegation_chain, None).is_ok());

    // The chain-binding entry point is a no-op for non-attenuated tokens.
    token
        .validate_chain_binding(&scope_hash(&ChioScope::default()).unwrap())
        .unwrap();

    // Even when the peer disables `delegation_chain_binding`, a plain
    // pass-through delegation must still verify: there is no attenuation
    // for the rule to bind against.
    let mut negotiated = CapabilityNegotiation::t1_default();
    negotiated
        .features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    token
        .validate_chain_binding_with_features(
            &scope_hash(&ChioScope::default()).unwrap(),
            &negotiated,
        )
        .unwrap();
}

#[test]
fn requires_chain_binding_tracks_only_new_attenuation() {
    // `requires_chain_binding` must reflect that the token introduces
    // new narrowing relative to its parent. `delegation_chain` alone
    // does NOT introduce narrowing; an explicit `attenuation_proof`,
    // non-empty `scope_attenuations`, or a `budget_share_bps` value
    // do.
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let plain_token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-plain".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: vec![],
        },
        &issuer,
    )
    .unwrap();
    assert!(!plain_token.requires_chain_binding());

    let parent_link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-parent".to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: None,
        },
        &issuer,
    )
    .unwrap();
    let mut delegated_token = plain_token.clone();
    delegated_token.delegation_chain = vec![parent_link];
    assert!(
        !delegated_token.requires_chain_binding(),
        "pass-through delegation does not introduce new attenuation"
    );

    // budget_share_bps narrows the parent's budget: chain binding fires.
    let mut budget_narrowed = delegated_token.clone();
    budget_narrowed.budget_share_bps = Some(5_000);
    assert!(budget_narrowed.requires_chain_binding());

    // A non-empty scope_attenuations list also fires chain binding.
    let mut scope_narrowed = delegated_token.clone();
    scope_narrowed.scope_attenuations = Some(vec![Attenuation::ShortenExpiry {
        new_expires_at: 150,
    }]);
    assert!(scope_narrowed.requires_chain_binding());
}

fn make_signed_link(
    capability_id: &str,
    delegator_kp: &Keypair,
    delegatee: &PublicKey,
    timestamp: u64,
) -> DelegationLink {
    let body = DelegationLinkBody {
        capability_id: capability_id.to_string(),
        delegator: delegator_kp.public_key(),
        delegatee: delegatee.clone(),
        attenuations: vec![],
        timestamp,
        scope_hash: None,
    };
    DelegationLink::sign(body, delegator_kp).unwrap()
}

#[test]
fn delegation_chain_valid() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();

    let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
    let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

    assert!(validate_delegation_chain(&[link1, link2], None).is_ok());
}

#[test]
fn delegation_chain_broken_connectivity() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();
    let kp_d = Keypair::generate();

    // link1: A -> B, link2: C -> D (not connected)
    let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
    let link2 = make_signed_link("cap-c", &kp_c, &kp_d.public_key(), 200);

    let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
    assert!(err.to_string().contains("does not match"));
}

#[test]
fn delegation_chain_non_monotonic_timestamps() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();

    let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 200);
    let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 100); // earlier!

    let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
    assert!(err.to_string().contains("precedes"));
}

#[test]
fn delegation_chain_exceeds_depth() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();

    let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
    let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

    let err = validate_delegation_chain(&[link1, link2], Some(1)).unwrap_err();
    assert!(err.to_string().contains("exceeds maximum"));
}

#[test]
fn delegation_chain_invalid_signature() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();

    let mut link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
    // Tamper: change the delegatee after signing
    link1.delegatee = kp_c.public_key();

    let err = validate_delegation_chain(&[link1], None).unwrap_err();
    assert!(err.to_string().contains("signature invalid"));
}

#[test]
fn delegation_link_serde_roundtrip() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let link = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 12345);

    let json = serde_json::to_string_pretty(&link).unwrap();
    let restored: DelegationLink = serde_json::from_str(&json).unwrap();

    assert_eq!(link.capability_id, restored.capability_id);
    assert_eq!(link.delegator, restored.delegator);
    assert_eq!(link.delegatee, restored.delegatee);
    assert_eq!(link.timestamp, restored.timestamp);
    assert_eq!(link.signature.to_hex(), restored.signature.to_hex());
}

#[test]
fn constraint_serde_roundtrip() {
    let constraints = vec![
        Constraint::PathPrefix("/app/src".to_string()),
        Constraint::DomainExact("api.example.com".to_string()),
        Constraint::DomainGlob("*.example.com".to_string()),
        Constraint::RegexMatch(r"^[a-z]+$".to_string()),
        Constraint::MaxLength(1024),
        Constraint::GovernedIntentRequired,
        Constraint::RequireApprovalAbove {
            threshold_units: 500,
        },
        Constraint::SellerExact("merchant.example".to_string()),
        Constraint::MinimumRuntimeAssurance(RuntimeAssuranceTier::Attested),
        Constraint::MinimumAutonomyTier(GovernedAutonomyTier::Delegated),
        Constraint::Custom("category".to_string(), "read-only".to_string()),
    ];

    let json = serde_json::to_string_pretty(&constraints).unwrap();
    let restored: Vec<Constraint> = serde_json::from_str(&json).unwrap();
    assert_eq!(constraints, restored);
}

#[test]
fn governed_transaction_intent_binding_hash_changes_with_payload() {
    let base = GovernedTransactionIntent {
        id: "intent-1".to_string(),
        server_id: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        purpose: "pay supplier".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
        commerce: Some(GovernedCommerceContext {
            seller: "merchant.example".to_string(),
            shared_payment_token_id: "spt_123".to_string(),
        }),
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::AllowThenSettle,
            quote: MeteredBillingQuote {
                quote_id: "quote-1".to_string(),
                provider: "meter.chio".to_string(),
                billing_unit: "1k_tokens".to_string(),
                quoted_units: 12,
                quoted_cost: MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                },
                issued_at: 950,
                expires_at: Some(1300),
            },
            max_billed_units: Some(20),
        }),
        runtime_attestation: Some(RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 900,
            expires_at: 1200,
            evidence_sha256: "attestation-digest".to_string(),
            runtime_identity: Some("spiffe://chio/runtime/123".to_string()),
            workload_identity: None,
            claims: None,
        }),
        call_chain: Some(GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        }),
        autonomy: Some(GovernedAutonomyContext {
            tier: GovernedAutonomyTier::Delegated,
            delegation_bond_id: Some("bond-1".to_string()),
        }),
        context: None,
    };
    let mut changed = base.clone();
    changed
        .call_chain
        .as_mut()
        .expect("call chain present")
        .parent_request_id = "req-parent-2".to_string();

    assert_ne!(
        base.binding_hash().unwrap(),
        changed.binding_hash().unwrap()
    );
}

#[test]
fn metered_billing_quote_validity_window_respects_optional_expiry() {
    let quote = MeteredBillingQuote {
        quote_id: "quote-1".to_string(),
        provider: "meter.chio".to_string(),
        billing_unit: "1k_tokens".to_string(),
        quoted_units: 8,
        quoted_cost: MonetaryAmount {
            units: 125,
            currency: "USD".to_string(),
        },
        issued_at: 100,
        expires_at: Some(200),
    };

    assert!(!quote.is_valid_at(99));
    assert!(quote.is_valid_at(100));
    assert!(quote.is_valid_at(199));
    assert!(!quote.is_valid_at(200));
}

#[test]
fn governed_approval_token_signature_roundtrip() {
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "approval-1".to_string(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: "intent-hash".to_string(),
        request_id: "req-1".to_string(),
        issued_at: 1000,
        expires_at: 2000,
        decision: GovernedApprovalDecision::Approved,
    };

    let token = GovernedApprovalToken::sign(body, &approver).unwrap();

    assert!(token.verify_signature().unwrap());
    assert!(token.is_valid_at(1500));
    assert!(!token.is_valid_at(2000));
    assert_eq!(token.subject, subject.public_key());
}

#[test]
fn governed_upstream_call_chain_proof_roundtrip_and_context_extraction() {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let proof = GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: "chain-proof-1".to_string(),
            parent_request_id: "req-parent-proof-1".to_string(),
            parent_receipt_id: Some("rc-parent-proof-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
            issued_at: 1000,
            expires_at: 2000,
        },
        &signer,
    )
    .unwrap();
    let intent = GovernedTransactionIntent {
        id: "intent-proof-1".to_string(),
        server_id: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        purpose: "pay supplier".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(GovernedCallChainContext {
            chain_id: "chain-proof-1".to_string(),
            parent_request_id: "req-parent-proof-1".to_string(),
            parent_receipt_id: Some("rc-parent-proof-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        }),
        autonomy: None,
        context: Some(serde_json::json!({
            GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: proof.clone(),
            "note": "preserve-other-context"
        })),
    };

    assert!(proof.verify_signature().unwrap());
    assert!(proof.is_valid_at(1500));
    assert!(!proof.is_valid_at(2000));
    assert!(proof.matches_context(intent.call_chain.as_ref().unwrap()));
    assert_eq!(intent.upstream_call_chain_proof().unwrap(), Some(proof));
}

#[test]
fn call_chain_continuation_token_roundtrip_and_matching_helpers() {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let session_anchor = SessionAnchorReference::new("anchor-1", "anchor-hash-1");
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-cont-1".to_string(),
        parent_request_id: "req-parent-cont-1".to_string(),
        parent_receipt_id: Some("rc-parent-cont-1".to_string()),
        origin_subject: "origin-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
    };
    let token = CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: "continuation-1".to_string(),
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            parent_receipt_hash: Some("receipt-hash-1".to_string()),
            parent_session_anchor: Some(session_anchor.clone()),
            current_subject: subject.public_key().to_hex(),
            delegator_subject: call_chain.delegator_subject.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            parent_capability_id: Some("cap-parent-1".to_string()),
            delegation_link_hash: Some("delegation-link-hash-1".to_string()),
            governed_intent_hash: Some("intent-hash-1".to_string()),
            audience: Some(CallChainContinuationAudience {
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
            }),
            nonce: Some("nonce-1".to_string()),
            issued_at: 1000,
            expires_at: 2000,
        },
        &signer,
    )
    .unwrap();
    let intent = GovernedTransactionIntent {
        id: "intent-cont-1".to_string(),
        server_id: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        purpose: "pay supplier".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: Some(serde_json::json!({
            GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: token.clone()
        })),
    };

    assert!(token.verify_signature().unwrap());
    assert!(token.matches_context(&call_chain));
    assert!(token.matches_session_anchor(&session_anchor));
    assert!(token.matches_target("srv-pay", "charge"));
    assert!(token.matches_intent_hash("intent-hash-1"));
    assert!(token.matches_subject(&subject.public_key()));
    assert_eq!(
        intent.explicit_continuation_token().unwrap(),
        Some(token.clone())
    );
    assert_eq!(intent.continuation_token().unwrap(), Some(token));
}

#[test]
fn governed_call_chain_provenance_separates_asserted_and_verified_views() {
    let asserted_context = GovernedCallChainContext {
        chain_id: "chain-prov-1".to_string(),
        parent_request_id: "req-parent-prov-1".to_string(),
        parent_receipt_id: Some("rc-parent-prov-1".to_string()),
        origin_subject: "origin-asserted".to_string(),
        delegator_subject: "delegator-asserted".to_string(),
    };
    let verified_context = GovernedCallChainContext {
        chain_id: "chain-prov-1".to_string(),
        parent_request_id: "req-parent-prov-1".to_string(),
        parent_receipt_id: Some("rc-parent-prov-1".to_string()),
        origin_subject: "origin-verified".to_string(),
        delegator_subject: "delegator-verified".to_string(),
    };
    let provenance = GovernedCallChainProvenance::verified(verified_context.clone())
        .with_asserted_context(asserted_context.clone())
        .with_continuation_token_id("continuation-1")
        .with_session_anchor_id("anchor-1")
        .with_receipt_lineage_statement_id("statement-1");

    let encoded = serde_json::to_value(&provenance).unwrap();

    assert!(provenance.is_verified());
    assert_eq!(provenance.asserted_context(), Some(&asserted_context));
    assert_eq!(provenance.verified_context(), Some(&verified_context));
    assert_eq!(encoded["continuationTokenId"], "continuation-1");
    assert_eq!(encoded["sessionAnchorId"], "anchor-1");
    assert_eq!(encoded["receiptLineageStatementId"], "statement-1");
    assert_eq!(
        encoded["assertedContext"]["originSubject"],
        "origin-asserted"
    );
    assert_eq!(encoded["originSubject"], "origin-verified");
}

#[test]
fn runtime_attestation_evidence_validity_window_is_half_open() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Verified,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };

    assert!(!attestation.is_valid_at(99));
    assert!(attestation.is_valid_at(100));
    assert!(attestation.is_valid_at(199));
    assert!(!attestation.is_valid_at(200));
}

#[test]
fn workload_identity_parses_spiffe_uri() {
    let workload = WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments/worker")
        .expect("parse SPIFFE workload identity");

    assert_eq!(workload.scheme, WorkloadIdentityScheme::Spiffe);
    assert_eq!(workload.credential_kind, WorkloadCredentialKind::Uri);
    assert_eq!(workload.trust_domain, "prod.chio");
    assert_eq!(workload.path, "/payments/worker");
}

#[test]
fn workload_identity_rejects_invalid_spiffe_variants() {
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri(" "),
        Err(WorkloadIdentityError::EmptyUri)
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments/worker?version=1"),
        Err(WorkloadIdentityError::InvalidSuffix)
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("https://prod.chio/payments/worker"),
        Err(WorkloadIdentityError::UnsupportedScheme(_))
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("spiffe://user@prod.chio/payments/worker"),
        Err(WorkloadIdentityError::InvalidAuthority)
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("spiffe:///payments/worker"),
        Err(WorkloadIdentityError::MissingTrustDomain)
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments//worker"),
        Err(WorkloadIdentityError::InvalidPath(_))
    ));
    assert!(matches!(
        WorkloadIdentity::parse_spiffe_uri("%%%"),
        Err(WorkloadIdentityError::MalformedUri(_))
    ));
}

#[test]
fn runtime_attestation_normalizes_spiffe_runtime_identity() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
        workload_identity: None,
        claims: None,
    };

    let workload = attestation
        .normalized_workload_identity()
        .expect("normalize workload identity")
        .expect("workload identity present");
    assert_eq!(workload.trust_domain, "prod.chio");
    assert_eq!(workload.path, "/payments/worker");
}

#[test]
fn runtime_attestation_rejects_conflicting_explicit_workload_identity() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
        workload_identity: Some(WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::X509Svid,
            uri: "spiffe://dev.chio/payments/worker".to_string(),
            trust_domain: "dev.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    };

    let error = attestation
        .validate_workload_identity_binding()
        .expect_err("conflicting workload identities should fail");
    assert!(error.to_string().contains("trust_domain"));
}

#[test]
fn workload_identity_validation_and_runtime_identity_conflicts_cover_remaining_paths() {
    let identity = WorkloadIdentity {
        scheme: WorkloadIdentityScheme::Spiffe,
        credential_kind: WorkloadCredentialKind::Uri,
        uri: "spiffe://prod.chio/payments/worker".to_string(),
        trust_domain: "prod.chio".to_string(),
        path: "/payments/other".to_string(),
    };
    assert!(matches!(
        identity.validate(),
        Err(WorkloadIdentityError::Conflict { field: "path", .. })
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: Some("   ".to_string()),
        workload_identity: None,
        claims: None,
    };
    assert!(matches!(
        attestation.normalized_workload_identity(),
        Err(WorkloadIdentityError::EmptyRuntimeIdentity)
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: Some("//compute.googleapis.com/projects/demo".to_string()),
        workload_identity: Some(WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::Uri,
            uri: "spiffe://prod.chio/payments/worker".to_string(),
            trust_domain: "prod.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    };
    assert!(matches!(
        attestation.normalized_workload_identity(),
        Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(_))
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: Some(WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::Uri,
            uri: "spiffe://prod.chio/payments/worker".to_string(),
            trust_domain: "prod.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    };
    let normalized = attestation
        .normalized_workload_identity()
        .expect("explicit workload identity should normalize")
        .expect("workload identity should exist");
    assert_eq!(normalized.trust_domain, "prod.chio");
}

#[test]
fn runtime_attestation_trust_policy_rebinds_effective_tier() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let resolved = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect("resolve effective tier");
    assert_eq!(resolved.raw_tier, RuntimeAssuranceTier::Attested);
    assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
    assert_eq!(resolved.matched_rule.as_deref(), Some("azure-contoso"));
}

#[test]
fn runtime_attestation_trust_policy_rejects_stale_verified_evidence() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 400,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(30),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("stale evidence should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::EvidenceTooOld { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_rejects_disallowed_attestation_type() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sev_snp"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("unexpected attestation type should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::DisallowedAttestationType { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_rejects_untrusted_verifier() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.untrusted.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: Vec::new(),
            required_assertions: BTreeMap::new(),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("untrusted verifier should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::UntrustedEvidence { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_matches_google_family_and_required_assertions() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([
                ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                ("secureBoot".to_string(), "enabled".to_string()),
            ]),
        }],
    };

    let resolved = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect("google attestation should satisfy appraisal-aware trust policy");
    assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
    assert_eq!(
        resolved.matched_rule.as_deref(),
        Some("google-confidential")
    );
}

#[test]
fn runtime_attestation_trust_policy_rejects_missing_required_assertion() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([(
                "secureBoot".to_string(),
                "enabled".to_string(),
            )]),
        }],
    };

    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("missing secureBoot assertion should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::MissingAssertion { .. }
    ));
}

#[test]
fn runtime_attestation_trust_policy_covers_remaining_fail_closed_paths() {
    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("missing attestationType should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::MissingAttestationType { .. }
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest-google".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_INTEL_TDX",
                "secureBoot": "enabled"
            }
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "google-confidential".to_string(),
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
            max_evidence_age_seconds: None,
            allowed_attestation_types: vec!["confidential_vm".to_string()],
            required_assertions: BTreeMap::from([(
                "hardwareModel".to_string(),
                "GCP_AMD_SEV".to_string(),
            )]),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("mismatched required assertion should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::AssertionMismatch { .. }
    ));

    let attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.unsupported.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "unsupported".to_string(),
            schema: "chio.runtime-attestation.unsupported.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: None,
            max_evidence_age_seconds: None,
            allowed_attestation_types: Vec::new(),
            required_assertions: BTreeMap::new(),
        }],
    };
    let error = attestation
        .resolve_effective_runtime_assurance(Some(&policy), 150)
        .expect_err("unsupported evidence schema should fail closed");
    assert!(matches!(
        error,
        AttestationTrustError::UnsupportedEvidence { .. }
    ));
}

#[test]
fn operation_serde_roundtrip() {
    let ops = vec![
        Operation::Invoke,
        Operation::ReadResult,
        Operation::Delegate,
    ];
    let json = serde_json::to_string(&ops).unwrap();
    let restored: Vec<Operation> = serde_json::from_str(&json).unwrap();
    assert_eq!(ops, restored);
}

#[test]
fn attenuation_serde_roundtrip() {
    let attenuations = vec![
        Attenuation::RemoveTool {
            server_id: "srv".to_string(),
            tool_name: "danger".to_string(),
        },
        Attenuation::RemoveOperation {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            operation: Operation::Delegate,
        },
        Attenuation::AddConstraint {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            constraint: Constraint::PathPrefix("/safe".to_string()),
        },
        Attenuation::ReduceBudget {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            max_invocations: 5,
        },
        Attenuation::ShortenExpiry {
            new_expires_at: 9999,
        },
    ];

    let json = serde_json::to_string_pretty(&attenuations).unwrap();
    let restored: Vec<Attenuation> = serde_json::from_str(&json).unwrap();
    assert_eq!(attenuations, restored);
}

#[test]
fn ed25519_capability_token_is_byte_identical_without_algorithm_field() {
    // Pre-existing Ed25519 tokens must serialize without any `algorithm`
    // envelope field, so captured on-disk receipts and capability
    // artifacts continue to round-trip through the schema validators.
    let kp = Keypair::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-compat".to_string(),
        issuer: kp.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    let json = serde_json::to_value(&token).unwrap();
    assert!(
        json.get("algorithm").is_none(),
        "Ed25519 tokens must omit the `algorithm` envelope field"
    );
    assert!(token.verify_signature().unwrap());
}

#[test]
fn capability_token_backend_signing_with_ed25519_verifies() {
    let backend = crate::crypto::Ed25519Backend::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-backend".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(
        token.algorithm,
        Some(crate::crypto::SigningAlgorithm::Ed25519)
    );
    assert!(token.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p256_round_trip() {
    // A capability token signed with P-256 verifies when reconstructed
    // through the exact same API path the kernel uses
    // (`verify_signature` -> `PublicKey::verify_canonical`).
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-p256".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
    assert!(token.verify_signature().unwrap());

    // Round-trip through JSON (the wire format the kernel receives).
    let wire = serde_json::to_string(&token).unwrap();
    assert!(wire.contains("\"p256:"));
    assert!(wire.contains("\"algorithm\":\"p256\""));
    let restored: CapabilityToken = serde_json::from_str(&wire).unwrap();
    assert!(restored.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p384_round_trip() {
    let backend = crate::crypto::P384Backend::generate().expect("p384 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-p384".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P384));
    assert!(token.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn capability_token_p256_tampered_body_fails() {
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "cap-tamper".to_string(),
        issuer: backend.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 2000,
        delegation_chain: vec![],
    };
    let mut token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
    token.id = "cap-tampered".to_string();
    assert!(!token.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn governed_approval_token_p256_verifies() {
    let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
    let subject = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "approval-p256".to_string(),
        approver: backend.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: "hash-xyz".to_string(),
        request_id: "req-1".to_string(),
        issued_at: 1000,
        expires_at: 2000,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign_with_backend(body, &backend).unwrap();
    assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
    assert!(token.verify_signature().unwrap());
}

// ----- `delegate` mint helper -----------------------------------

#[cfg(feature = "delegation")]
fn delegate_parent_token(
    parent_kp: &Keypair,
    subject_kp: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-parent".to_string(),
        issuer: parent_kp.public_key(),
        subject: subject_kp.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, parent_kp).unwrap()
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_mints_signed_link_for_subset_scope() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);
    let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

    let receipt = delegate(
        &parent,
        &child_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [7_u8; 16],
    )
    .unwrap();

    assert!(receipt.link.verify_signature().unwrap());
    assert_eq!(
        receipt.link.scope_hash,
        Some(scope_hash(&parent_scope).unwrap())
    );
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_widening_scope() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    // Child tries to add a non-parent operation, widening the parent.
    let widened = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::ReadResult],
    )]);

    let err = delegate(
        &parent,
        &widened,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_parent_without_delegate_operation() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);

    let err = delegate(
        &parent,
        &parent_scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_extending_expiry() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let attenuation = crate::delegation_receipt::ScopeAttenuation {
        steps: vec![],
        child_expires_at: Some(3000), // > parent.expires_at
    };
    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        attenuation,
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));

    // sanity: at-or-below parent expiry is accepted.
    let ok = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation {
            steps: vec![],
            child_expires_at: Some(1800),
        },
        1500,
        [0_u8; 16],
    );
    assert!(ok.is_ok());
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_wrong_delegator_key() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let imposter = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &imposter, // not parent.subject
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_tampered_parent_signature() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let mut parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
    parent.id = "cap-parent-tampered".to_string();

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        1500,
        [0_u8; 16],
    )
    .unwrap_err();

    assert!(matches!(err, Error::SignatureVerificationFailed));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_parent_before_issued_at() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        999,
        [0_u8; 16],
    )
    .unwrap_err();

    assert!(matches!(
        err,
        Error::CapabilityNotYetValid { not_before: 1000 }
    ));
}

#[cfg(feature = "delegation")]
#[test]
fn delegate_rejects_signed_at_at_or_after_parent_expiry() {
    use crate::delegation_receipt::ScopeAttenuation;

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let delegatee = Keypair::generate();
    let parent_scope = make_scope(vec![make_grant(
        "srv-a",
        "tool-x",
        vec![Operation::Invoke, Operation::Delegate],
    )]);
    let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
    let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

    let err = delegate(
        &parent,
        &scope,
        &subject,
        &delegatee.public_key(),
        ScopeAttenuation::empty(),
        2000, // == parent.expires_at
        [0_u8; 16],
    )
    .unwrap_err();
    assert!(matches!(err, Error::AttenuationViolation { .. }));
}

// ---------------------------------------------------------------------------
// BAC-573: time-checked verify entry points fold the validity window into the
// signature-verification path so "signature-valid" cannot diverge from
// "unexpired". Each checked entry point is fail-closed and signature-first.
// ---------------------------------------------------------------------------

fn bac573_capability_token(issued_at: u64, expires_at: u64) -> (Keypair, CapabilityToken) {
    let kp = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "bac573-cap".to_string(),
        issuer: kp.public_key(),
        subject: Keypair::generate().public_key(),
        scope: make_scope(vec![make_grant(
            "srv-a",
            "file_read",
            vec![Operation::Invoke],
        )]),
        issued_at,
        expires_at,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign(body, &kp).unwrap();
    (kp, token)
}

#[test]
fn bac573_capability_token_verify_at_within_window_passes() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    // Boundaries: issued_at is inclusive, expires_at is exclusive.
    assert!(token.verify_signature_at(1000).unwrap());
}

#[test]
fn bac573_capability_token_verify_at_expired_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // now == expires_at and now > expires_at both reject (fail-closed).
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(9999),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_not_yet_valid_is_rejected() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_capability_token_verify_at_bad_signature_fails_before_time_check() {
    // An expired token whose signature is ALSO invalid must report the
    // signature failure (Ok(false)), not the time error: signature is checked
    // first, so the time window cannot leak through a forged token.
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_signature_at(9999).unwrap());
    // And in-window with a broken signature is still a plain rejection.
    assert!(!token.verify_signature_at(1500).unwrap());
}

#[test]
fn bac573_capability_token_verify_with_floor_at_folds_time_and_floor() {
    let (_kp, token) = bac573_capability_token(1000, 2000);
    // In-window + allowed floor verifies.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 1500),
        Ok(true)
    ));
    // In-window but floor rejects classical: floor error, not a time error.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::PqRequired, 1500),
        Err(CapabilityFloorVerifyError::RejectedByCryptoFloor { .. })
    ));
    // Floor + signature pass but expired: surfaced as Crypto(CapabilityExpired).
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 2000),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityExpired { expires_at: 2000 }
        ))
    ));
    // Not yet valid: surfaced as Crypto(CapabilityNotYetValid).
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 999),
        Err(CapabilityFloorVerifyError::Crypto(
            Error::CapabilityNotYetValid { not_before: 1000 }
        ))
    ));
}

#[test]
fn bac573_capability_token_verify_with_floor_at_bad_signature_fails_first() {
    let (_kp, mut token) = bac573_capability_token(1000, 2000);
    // Break the signature, then verify an expired window.
    token.subject = Keypair::generate().public_key();
    // Expired AND broken signature: floor ok, signature fails -> Ok(false),
    // never the time error.
    assert!(matches!(
        token.verify_signature_with_floor_at(CapabilityCryptoFloor::AllowClassical, 9999),
        Ok(false)
    ));
}

fn bac573_approval_token(issued_at: u64, expires_at: u64) -> (Keypair, GovernedApprovalToken) {
    let approver = Keypair::generate();
    let body = GovernedApprovalTokenBody {
        id: "bac573-approval".to_string(),
        approver: approver.public_key(),
        subject: Keypair::generate().public_key(),
        governed_intent_hash: "intent-hash".to_string(),
        request_id: "req-1".to_string(),
        issued_at,
        expires_at,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).unwrap();
    (approver, token)
}

#[test]
fn bac573_approval_token_verify_at_window_enforced() {
    let (_approver, token) = bac573_approval_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_approval_token_verify_at_bad_signature_fails_first() {
    let (_approver, mut token) = bac573_approval_token(1000, 2000);
    // Break the signature; expired and forged -> signature failure first.
    token.subject = Keypair::generate().public_key();
    assert!(!token.verify_signature_at(9999).unwrap());
}

fn bac573_upstream_proof(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, GovernedUpstreamCallChainProof) {
    let signer = Keypair::generate();
    let proof = GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: Keypair::generate().public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, proof)
}

#[test]
fn bac573_upstream_proof_verify_at_window_enforced() {
    let (_signer, proof) = bac573_upstream_proof(1000, 2000);
    assert!(proof.verify_signature_at(1500).unwrap());
    assert!(matches!(
        proof.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        proof.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_upstream_proof_verify_at_bad_signature_fails_first() {
    let (_signer, mut proof) = bac573_upstream_proof(1000, 2000);
    proof.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!proof.verify_signature_at(9999).unwrap());
}

fn bac573_continuation_token(
    issued_at: u64,
    expires_at: u64,
) -> (Keypair, CallChainContinuationToken) {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let token = CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: "continuation-1".to_string(),
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            parent_receipt_hash: Some("receipt-hash-1".to_string()),
            parent_session_anchor: None,
            current_subject: subject.public_key().to_hex(),
            delegator_subject: "delegator-subject".to_string(),
            origin_subject: "origin-subject".to_string(),
            parent_capability_id: Some("cap-parent-1".to_string()),
            delegation_link_hash: Some("delegation-link-hash-1".to_string()),
            governed_intent_hash: Some("intent-hash-1".to_string()),
            audience: None,
            nonce: Some("nonce-1".to_string()),
            issued_at,
            expires_at,
        },
        &signer,
    )
    .unwrap();
    (signer, token)
}

#[test]
fn bac573_continuation_token_verify_at_window_enforced() {
    let (_signer, token) = bac573_continuation_token(1000, 2000);
    assert!(token.verify_signature_at(1500).unwrap());
    assert!(matches!(
        token.verify_signature_at(2000),
        Err(Error::CapabilityExpired { expires_at: 2000 })
    ));
    assert!(matches!(
        token.verify_signature_at(999),
        Err(Error::CapabilityNotYetValid { not_before: 1000 })
    ));
}

#[test]
fn bac573_continuation_token_verify_at_bad_signature_fails_first() {
    let (_signer, mut token) = bac573_continuation_token(1000, 2000);
    token.subject = Keypair::generate().public_key(); // breaks the signature
    assert!(!token.verify_signature_at(9999).unwrap());
}
