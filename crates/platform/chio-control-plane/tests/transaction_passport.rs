use chio_core::PublicKey;
use chio_test_support::prelude::*;
use std::{collections::BTreeMap, fs, path::PathBuf};

fn enterprise_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce")
}

fn read_enterprise_fixture(name: &str) -> Vec<u8> {
    fs::read(enterprise_fixture_dir().join(name)).test_expect("enterprise fixture reads")
}

fn public_key(hex: &str) -> PublicKey {
    PublicKey::from_hex(hex).test_expect("trusted public key parses")
}

fn enterprise_risk_bundle(
) -> chio_control_plane::transaction_passport_risk::TransactionPassportRiskVerificationBundle {
    let passport = serde_json::from_slice(&read_enterprise_fixture("transaction-passport.json"))
        .test_expect("enterprise passport parses");
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "claim-set.json".to_string(),
        read_enterprise_fixture("claim-set.json"),
    );
    artifacts.insert(
        "risk-comptroller-report.json".to_string(),
        read_enterprise_fixture("risk-comptroller-report.json"),
    );

    chio_control_plane::transaction_passport_risk::TransactionPassportRiskVerificationBundle {
        passport,
        passport_path: "transaction-passport.json".to_string(),
        evidence_graph_bytes: read_enterprise_fixture("evidence-graph.json"),
        verifier_policy_bytes: read_enterprise_fixture("verifier-policy.json"),
        artifacts,
        trusted_passport_signer_keys: vec![public_key(
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        )],
        trusted_risk_comptroller_signer_keys: vec![public_key(
            "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2",
        )],
    }
}

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

#[test]
fn control_plane_verifies_passport_with_signed_risk_report() {
    let report =
        chio_control_plane::transaction_passport_risk::verify_passport_root_claim_set_and_risk_report(
            &enterprise_risk_bundle(),
        )
        .test_expect("signed risk comptroller report should satisfy passport risk verification");

    assert!(report.accepted);
    assert_eq!(report.passport_id, "passport-enterprise-valid");
}

#[test]
fn control_plane_rejects_untrusted_risk_report_signer() {
    let mut bundle = enterprise_risk_bundle();
    bundle.trusted_risk_comptroller_signer_keys = vec![public_key(
        "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",
    )];

    let error =
        chio_control_plane::transaction_passport_risk::verify_passport_root_claim_set_and_risk_report(
            &bundle,
        )
        .test_expect_err("untrusted risk comptroller signer must fail closed");

    assert!(error
        .to_string()
        .contains("risk comptroller report signer untrusted"));
}
