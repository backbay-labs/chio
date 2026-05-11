#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use chio_chiodos::{
    proof_package_from_json, verification_context_from_json, verifier_trust_bundle_from_json,
};
use chio_federation::{PheromoneGossipBatch, PheromoneTransitPolicy};
use chio_pheromone_runtime::{
    runtime_policy_from_json, PheromoneReceiver, PheromoneReceiverConfig, PheromoneRuntimeStore,
    SqlitePheromoneRuntimeStore, StaticPeerWeightProvider, VerifiedChiodosWorkflowResolver,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/chiodos-3vendor/fixtures")
        .join(path)
}

fn load_batch() -> PheromoneGossipBatch {
    serde_json::from_str(&fs::read_to_string(fixture("pheromone/gossip-batch.json")).unwrap())
        .unwrap()
}

fn load_runtime_policy() -> (PheromoneTransitPolicy, PheromoneReceiverConfig) {
    runtime_policy_from_json(
        &fs::read_to_string(fixture("pheromone/transit-policy.json")).unwrap(),
        1_766_000_000_500,
    )
    .unwrap()
}

fn resolver() -> VerifiedChiodosWorkflowResolver {
    let package = proof_package_from_json(
        &fs::read_to_string(fixture("buyer-auditor-proof-package.json")).unwrap(),
    )
    .unwrap();
    let trust_bundle = verifier_trust_bundle_from_json(
        &fs::read_to_string(fixture("verifier-trust-bundle.json")).unwrap(),
    )
    .unwrap();
    let context = verification_context_from_json(
        &fs::read_to_string(fixture("verification-context.json")).unwrap(),
    )
    .unwrap();
    VerifiedChiodosWorkflowResolver::from_verified_package(&package, &trust_bundle, &context)
        .unwrap()
}

#[test]
fn receiver_accepts_fixture_and_persists_report() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);

    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(report.accepted);
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.frames[0].code, "accepted");
    assert_eq!(receiver.store().receive_reports().unwrap().len(), 1);
}

#[test]
fn replay_nonce_survives_store_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pheromone.sqlite3");
    {
        let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
        let (policy, config) = load_runtime_policy();
        let receiver = PheromoneReceiver::new(store, resolver(), config);
        assert!(
            receiver
                .receive_batch(&load_batch(), &policy)
                .unwrap()
                .accepted
        );
    }

    let store = SqlitePheromoneRuntimeStore::open(&path).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let report = receiver.receive_batch(&load_batch(), &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.frames[0].code, "replay_window_exceeded");
}

#[test]
fn workflow_context_mismatch_is_rejected_before_storage() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    let mut batch = load_batch();
    batch.frames[0]
        .deposit
        .body
        .workflow_context
        .as_mut()
        .unwrap()
        .tool_receipt_id = "rcpt-wrong".to_string();

    let report = receiver.receive_batch(&batch, &policy).unwrap();

    assert!(!report.accepted);
    assert_eq!(report.frames[0].code, "workflow_context_mismatch");
    assert!(receiver
        .store()
        .query_deposits(None, None)
        .unwrap()
        .is_empty());
}

#[test]
fn concentration_query_rejects_bad_weights_and_unknown_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRuntimeStore::open(temp.path().join("pheromone.sqlite3")).unwrap();
    let (policy, config) = load_runtime_policy();
    let receiver = PheromoneReceiver::new(store, resolver(), config);
    assert!(
        receiver
            .receive_batch(&load_batch(), &policy)
            .unwrap()
            .accepted
    );

    let unknown_epoch = receiver
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            99,
            &StaticPeerWeightProvider::new(99, [("did:chio:llamaworks".to_string(), 1.0)]),
        )
        .unwrap_err();
    assert_eq!(unknown_epoch.code(), "unknown_reputation_epoch");

    let bad_weight = receiver
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            42,
            &StaticPeerWeightProvider::new(42, [("did:chio:llamaworks".to_string(), f64::NAN)]),
        )
        .unwrap_err();
    assert_eq!(bad_weight.code(), "weight_out_of_range");
}
