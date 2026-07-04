use std::collections::BTreeMap;

use chio_core_types::crypto::Keypair;
use chio_test_support::prelude::*;
use serde_json::json;
use sha2::Digest;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn claim_set_bytes(id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": id,
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": [{
            "claim_id": "claim.transaction.passport_root_verified",
            "status": "verified",
            "required_evidence": [
                "transaction-passport.json",
                "evidence-graph.json",
                "verifier-policy.json"
            ],
            "evidence_refs": [
                "transaction-passport.json",
                "evidence-graph.json",
                "verifier-policy.json"
            ],
            "verifier_module": "chio-transaction-passport::minimal"
        }]
    }))
    .test_expect("claim set serializes")
}

fn verifier_policy_bytes() -> Vec<u8> {
    br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-minimal-valid","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#.to_vec()
}

fn evidence_graph_bytes(claim_set_sha256: &str, verifier_policy_sha256: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "evidence-graph-minimal-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": [
            {
                "id": claim_set_sha256,
                "schema": "chio.transaction.claim-set.v1",
                "path": "claim-set.json",
                "sha256": claim_set_sha256,
                "role": "claim-set"
            },
            {
                "id": verifier_policy_sha256,
                "schema": "chio.transaction.verifier-policy.v1",
                "path": "verifier-policy.json",
                "sha256": verifier_policy_sha256,
                "role": "verifier-policy"
            }
        ],
        "edges": [{
            "from": claim_set_sha256,
            "to": verifier_policy_sha256,
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }]
    }))
    .test_expect("evidence graph serializes")
}

#[test]
fn root_claim_set_rejects_tampered_claim_set_bytes() {
    let keypair = Keypair::from_seed(&[54_u8; 32]);
    let original_claim_set = claim_set_bytes("claim-set-original");
    let verifier_policy = verifier_policy_bytes();
    let evidence_graph = evidence_graph_bytes(
        &sha256_hex(&original_claim_set),
        &sha256_hex(&verifier_policy),
    );
    let mut passport = chio_transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-claim-set-digest-bound".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        issuer: format!("did:chio:{}", keypair.public_key().to_hex()),
        evidence_graph_sha256: sha256_hex(&evidence_graph),
        evidence_graph_path: "evidence-graph.json".to_string(),
        not_before: None,
        expires_at: None,
        claim_set_sha256: sha256_hex(&original_claim_set),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: sha256_hex(&verifier_policy),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: String::new(),
    };
    passport.signature = chio_transaction_passport::sign_transaction_passport(&passport, &keypair)
        .test_expect("transaction passport signs");

    let artifacts = BTreeMap::from([
        (
            "claim-set.json".to_string(),
            claim_set_bytes("claim-set-tampered-after-root-signature"),
        ),
        ("verifier-policy.json".to_string(), verifier_policy.clone()),
    ]);
    let error = chio_transaction_passport::verify_passport_root_and_claim_set_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph,
        &verifier_policy,
        &artifacts,
        &[keypair.public_key()],
    )
    .test_expect_err("library verifier must hash claim set bytes");

    assert!(
        error
            .to_string()
            .contains("evidence graph artifact digest mismatch for claim-set.json"),
        "{error}"
    );
}
