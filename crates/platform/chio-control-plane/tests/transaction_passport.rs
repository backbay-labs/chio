use chio_test_support::prelude::*;

#[test]
fn control_plane_reexports_transaction_passport_verifier() {
    let passport = chio_control_plane::transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-minimal-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        evidence_graph_sha256: "0".repeat(64),
        evidence_graph_path: "evidence-graph.json".to_string(),
        verifier_policy_sha256: "1".repeat(64),
        verifier_policy_path: "verifier-policy.json".to_string(),
    };

    chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect("control-plane should re-export transaction passport verifier primitives");
}
