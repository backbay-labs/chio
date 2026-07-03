use super::*;

#[test]
fn agent_web_receipt_scope_uses_schema_not_fixture_filename() {
    assert!(is_agent_web_evidence_graph_node_parts(
        "receipt",
        "receipts/webhook-allow.json",
        Some("chio.receipt.v1"),
    ));
}

#[test]
fn enterprise_artifact_loader_includes_retained_jurisdiction_receipts() {
    assert!(is_enterprise_evidence_graph_role(
        "adjudication-jurisdiction-receipt"
    ));
    assert!(is_enterprise_artifact_role(
        "adjudication-jurisdiction-receipt"
    ));
}

#[test]
fn trust_market_artifact_loader_includes_retained_receipts() {
    assert!(is_trust_market_evidence_graph_role("receipt"));
    assert!(is_trust_market_artifact_role("receipt"));
}

#[test]
fn runtime_artifact_loader_includes_policy_activation_receipt() {
    assert!(is_runtime_artifact_role("policy-activation-receipt"));
}

#[test]
fn merge_family_reports_rejects_ok_but_unverified_family_report() {
    let passport = chio_control_plane::transaction_passport::TransactionPassport {
        schema: "chio.transaction.passport.v1".to_string(),
        id: "passport-test".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: None,
        expires_at: None,
        issuer: "did:example:issuer".to_string(),
        evidence_graph_sha256: "evidence-graph-sha256".to_string(),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: "claim-set-sha256".to_string(),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: "verifier-policy-sha256".to_string(),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "signature".to_string(),
    };
    let rejected_family_report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": "verifier-report-rejected-family",
        "verdict": "failed",
        "accepted": false,
        "state": "failed",
        "verified_claims": []
    });

    let merged = merge_family_verifier_reports(
        &passport,
        "transaction-passport.json".to_string(),
        vec![rejected_family_report],
        "complete",
    );

    assert_ne!(
        merged.get("verdict").and_then(serde_json::Value::as_str),
        Some("verified"),
        "merge must not report verified when a family report is not verified"
    );
    assert_eq!(
        merged.get("accepted").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_ne!(
        merged.get("state").and_then(serde_json::Value::as_str),
        Some("verified")
    );
}
