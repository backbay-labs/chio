//! Standalone negative conformance test for W1.3 capability negotiation.
//!
//! Closes the downgrade attack: a v1-only Mallory presents a v2 token
//! across a federated link whose negotiated ceiling is v1. The verifier
//! must reject the token before any signature, time, or floor check
//! runs. The symmetric direction (v1 token presented to a v2 peer) must
//! still verify, because v1 remains the universal floor of the schema
//! lattice.
//!
//! See `theorem.handshake.negotiation_safety` in
//! `formal/theorem-inventory.json` and the negotiated-ceiling rule in
//! `spec/PROTOCOL.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    capability_features, compute_attenuation_witness, scope_hash, Attenuation, AttenuationProof,
    CapabilityCryptoFloor, CapabilityNegotiation, CapabilityToken, CapabilityTokenBody,
    CapabilityTokenV2Body, Caveat, CaveatKind, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_kernel_core::{
    verify_capability_with_negotiated_floor, CapabilityError as CoreCapabilityError, FixedClock,
};

const NOW: u64 = 1_700_000_100;
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_001_000;

fn parent_grant() -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke, Operation::Delegate],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn child_grant() -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn parent_scope() -> ChioScope {
    ChioScope {
        grants: vec![parent_grant()],
        ..ChioScope::default()
    }
}

fn child_scope() -> ChioScope {
    ChioScope {
        grants: vec![child_grant()],
        ..ChioScope::default()
    }
}

fn sign_v1_token(issuer: &Keypair, subject_pk: chio_core::crypto::PublicKey) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-v1".to_string(),
            issuer: issuer.public_key(),
            subject: subject_pk,
            scope: child_scope(),
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            delegation_chain: vec![],
        },
        issuer,
    )
    .unwrap()
}

fn sign_v2_token(issuer: &Keypair, subject_pk: chio_core::crypto::PublicKey) -> CapabilityToken {
    let parent = parent_scope();
    let child = child_scope();
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent).unwrap(),
        child_scope_hash: scope_hash(&child).unwrap(),
        normalized_subset_proof: witness,
    };
    CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body: CapabilityTokenBody {
                id: "cap-v2".to_string(),
                issuer: issuer.public_key(),
                subject: subject_pk,
                scope: child,
                issued_at: ISSUED_AT,
                expires_at: EXPIRES_AT,
                delegation_chain: vec![],
            },
            caveats: vec![Caveat {
                kind: CaveatKind::RestrictTool,
                predicate: "srv/tool".to_string(),
                sig: None,
            }],
            scope_attenuations: vec![Attenuation::RemoveOperation {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operation: Operation::ReadResult,
            }],
            attenuation_proof: proof,
            budget_share_bps: Some(5_000),
        },
        issuer,
    )
    .unwrap()
}

#[test]
fn verify_rejects_v2_token_when_peer_negotiated_v1_only() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = sign_v2_token(&issuer, subject.public_key());
    let clock = FixedClock::new(NOW);

    let peer = CapabilityNegotiation::v1_default();
    let trusted = [issuer.public_key()];

    let err = verify_capability_with_negotiated_floor(
        &token,
        &trusted,
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
    )
    .expect_err("v2 token must be rejected when peer ceiling is v1 only");

    match err {
        CoreCapabilityError::SchemaExceedsNegotiatedCeiling {
            token_schema,
            peer_max,
        } => {
            assert_eq!(
                token_schema,
                chio_core::capability::CHIO_CAPABILITY_V2_SCHEMA
            );
            assert_eq!(peer_max, chio_core::capability::CHIO_CAPABILITY_V1_SCHEMA);
        }
        other => panic!("expected SchemaExceedsNegotiatedCeiling, got {other:?}"),
    }
}

#[test]
fn verify_accepts_v1_token_when_peer_negotiated_v2_capable() {
    // Symmetric direction: a v1 token presented to a v2-aware peer must
    // still verify. v1 is the universal floor of the schema lattice and
    // raising the ceiling never invalidates legacy tokens.
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = sign_v1_token(&issuer, subject.public_key());
    let clock = FixedClock::new(NOW);

    let mut peer = CapabilityNegotiation::v1_default();
    peer.max_capability_schema = chio_core::capability::CHIO_CAPABILITY_V2_SCHEMA.to_string();
    peer.features
        .insert(capability_features::ACCEPTS_CAPABILITY_V2.to_string(), true);
    let trusted = [issuer.public_key()];

    let verified = verify_capability_with_negotiated_floor(
        &token,
        &trusted,
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
    )
    .expect("v1 token must verify when peer ceiling is v2");

    assert_eq!(verified.id, "cap-v1");
}

#[test]
fn verify_accepts_v2_token_when_peer_negotiated_v2_capable() {
    // Positive control: a v2 token presented to a v2-aware peer must
    // verify. This guards against a regression that would reject every
    // v2 token regardless of negotiated ceiling.
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = sign_v2_token(&issuer, subject.public_key());
    let clock = FixedClock::new(NOW);

    let mut peer = CapabilityNegotiation::v1_default();
    peer.max_capability_schema = chio_core::capability::CHIO_CAPABILITY_V2_SCHEMA.to_string();
    peer.features
        .insert(capability_features::ACCEPTS_CAPABILITY_V2.to_string(), true);
    let trusted = [issuer.public_key()];

    let verified = verify_capability_with_negotiated_floor(
        &token,
        &trusted,
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
    )
    .expect("v2 token must verify when peer ceiling is v2");

    assert_eq!(verified.id, "cap-v2");
}
