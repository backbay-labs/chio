#![allow(unused_imports)]

use std::path::Path;

use chio_core::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel::{CapabilitySnapshot, CapabilitySnapshotProvenance, ReceiptStore};
use chio_store_sqlite::SqliteReceiptStore;

pub(crate) fn make_capability_token(
    id: &str,
    subject_keypair: &Keypair,
    issuer_keypair: &Keypair,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 9999999999,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer_keypair).expect("sign capability token")
}

pub(crate) fn make_delegated_capability_token(
    id: &str,
    subject_keypair: &Keypair,
    delegator_keypair: &Keypair,
    parent: &CapabilityToken,
) -> CapabilityToken {
    let mut body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: delegator_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: parent.scope.clone(),
        issued_at: parent.issued_at.saturating_add(1),
        expires_at: parent.expires_at,
        delegation_chain: parent.delegation_chain.clone(),
        aggregate_invocation_budget: None,
    };
    body.delegation_chain.push(
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: delegator_keypair.public_key(),
                delegatee: subject_keypair.public_key(),
                attenuations: Vec::new(),
                timestamp: body.issued_at,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            delegator_keypair,
        )
        .expect("sign delegation link"),
    );
    CapabilityToken::sign(body, delegator_keypair).expect("sign delegated capability token")
}

pub(crate) fn signed_snapshot(token: &CapabilityToken) -> CapabilitySnapshot {
    CapabilitySnapshot {
        capability_id: token.id.clone(),
        subject_key: token.subject.to_hex(),
        issuer_key: token.issuer.to_hex(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        grants_json: serde_json::to_string(&token.scope).expect("serialize capability scope"),
        delegation_depth: token.delegation_chain.len() as u64,
        parent_capability_id: token
            .delegation_chain
            .last()
            .map(|link| link.capability_id.clone()),
        federated_parent_capability_id: None,
        provenance: CapabilitySnapshotProvenance::SignedToken,
        signed_capability: Some(token.clone()),
    }
}

pub(crate) fn prepopulate_lineage(db_path: &Path, entries: &[(&CapabilityToken, Option<&str>)]) {
    let store = SqliteReceiptStore::open(db_path).expect("open receipt store for lineage");
    for (token, parent_id) in entries {
        store
            .record_capability_snapshot(token, *parent_id)
            .expect("record_capability_snapshot");
    }
}

pub(crate) fn run_large_stack_test(name: &str, test_fn: fn()) {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(test_fn)
        .expect("spawn large-stack test thread")
        .join()
        .expect("join large-stack test thread");
}
