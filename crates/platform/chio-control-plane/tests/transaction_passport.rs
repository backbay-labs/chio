use chio_test_support::prelude::*;

#[test]
fn control_plane_reexports_transaction_passport_verifier() {
    let passport = chio_control_plane::transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-minimal-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        issuer: "did:chio:66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
            .to_string(),
        not_before: None,
        expires_at: None,
        evidence_graph_sha256: "0".repeat(64),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: "2".repeat(64),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: "1".repeat(64),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "0".repeat(128),
    };

    chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect("control-plane should re-export transaction passport verifier primitives");
}
