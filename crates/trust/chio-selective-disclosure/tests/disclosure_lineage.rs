use chio_core_types::Keypair;
use chio_selective_disclosure::{
    compute_signed_lineage_subgraph_digest, sign_lineage_subgraph,
    verify_disclosure_lineage_bundle, DisclosureCapsule, DisclosureContextVerdict,
    DisclosureCryptoContextReport, DisclosureLeakageLedger, DisclosureLeakageLedgerEntry,
    DisclosureLineageBundle, DisclosureSignedLineageEdge, DisclosureSignedLineageNode,
    DisclosureSignedLineageRedaction, SignedLineageSubgraph, DISCLOSURE_CAPSULE_SCHEMA_V1,
    DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1, DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
    DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1, LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
};

fn valid_bundle() -> Result<DisclosureLineageBundle, Box<dyn std::error::Error>> {
    let capsule = DisclosureCapsule {
        schema: DISCLOSURE_CAPSULE_SCHEMA_V1.to_string(),
        id: "disclosure-capsule-valid".to_string(),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        crypto_context_report_ref: "crypto-context-report-valid".to_string(),
        privacy_profile_ref: "privacy-profile-valid".to_string(),
        lineage_subgraph_ref: "lineage-subgraph-valid".to_string(),
        leakage_ledger_ref: "leakage-ledger-valid".to_string(),
        disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
        hidden_predicates: vec!["amount_lte_100".to_string()],
    };
    let mut lineage = SignedLineageSubgraph {
        schema: LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1.to_string(),
        id: "lineage-subgraph-valid".to_string(),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        root_receipt_ids: vec!["receipt-root".to_string()],
        nodes: vec![
            DisclosureSignedLineageNode {
                id: "receipt-root".to_string(),
                receipt_ref: "receipt-root".to_string(),
                disclosure_state: "disclosed".to_string(),
            },
            DisclosureSignedLineageNode {
                id: "receipt-child".to_string(),
                receipt_ref: "receipt-child".to_string(),
                disclosure_state: "redacted".to_string(),
            },
        ],
        edges: vec![DisclosureSignedLineageEdge {
            from: "receipt-root".to_string(),
            to: "receipt-child".to_string(),
            relation: "continued".to_string(),
        }],
        redactions: vec![DisclosureSignedLineageRedaction {
            node_id: "receipt-child".to_string(),
            reason: "privacy_profile".to_string(),
        }],
        subgraph_sha256: String::new(),
        signature: String::new(),
    };
    lineage.subgraph_sha256 = compute_signed_lineage_subgraph_digest(&lineage)?;
    lineage.signature = sign_lineage_subgraph(&lineage, &lineage_signer())?;
    let leakage_ledger = DisclosureLeakageLedger {
        schema: DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1.to_string(),
        id: "leakage-ledger-valid".to_string(),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        privacy_profile_ref: "privacy-profile-valid".to_string(),
        entries: vec![
            DisclosureLeakageLedgerEntry {
                field: "capability_id".to_string(),
                leakage_kind: "disclosed_field".to_string(),
                allowed_by_profile: true,
                residual_inference_note: None,
            },
            DisclosureLeakageLedgerEntry {
                field: "tool_name".to_string(),
                leakage_kind: "disclosed_field".to_string(),
                allowed_by_profile: true,
                residual_inference_note: None,
            },
            DisclosureLeakageLedgerEntry {
                field: "amount_lte_100".to_string(),
                leakage_kind: "hidden_predicate".to_string(),
                allowed_by_profile: true,
                residual_inference_note: Some("predicate reveals capped amount band".to_string()),
            },
        ],
    };
    let crypto_context_report = DisclosureCryptoContextReport {
        schema: DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.to_string(),
        id: "crypto-context-report-valid".to_string(),
        context_id: "crypto-context-valid".to_string(),
        artifact_ref: "disclosure-capsule-valid".to_string(),
        verdict: DisclosureContextVerdict::Verified,
        evidence_class: "verifier_context".to_string(),
        cryptographic_proof_verified: true,
        verified_claims: vec![
            "claim.disclosure.crypto_context_bound".to_string(),
            "claim.disclosure.profile_context_policy_enforced".to_string(),
        ],
        rejected_checks: Vec::new(),
        disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
    };
    Ok(DisclosureLineageBundle {
        capsule,
        lineage,
        leakage_ledger,
        crypto_context_report: Some(crypto_context_report),
    })
}

fn lineage_signer() -> Keypair {
    Keypair::from_seed(&[29u8; 32])
}

#[test]
fn disclosure_lineage_verifies_valid_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = valid_bundle()?;

    let report = verify_disclosure_lineage_bundle(&bundle)?;

    assert_eq!(report.schema, DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1);
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.capsule_id, "disclosure-capsule-valid");
    assert!(report
        .verified_claims
        .contains(&"claim.disclosure.lineage_subgraph_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.disclosure.leakage_ledger_complete".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.disclosure.crypto_context_bound".to_string()));
    Ok(())
}

#[test]
fn disclosure_lineage_rejects_disclosed_field_absent_from_ledger() {
    let Ok(mut bundle) = valid_bundle() else {
        panic!("valid bundle fixture should build");
    };
    bundle
        .leakage_ledger
        .entries
        .retain(|entry| entry.field != "tool_name");

    let error = match verify_disclosure_lineage_bundle(&bundle) {
        Ok(_) => panic!("missing leakage ledger entry must fail"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("disclosed field absent from leakage ledger"));
}

#[test]
fn disclosure_lineage_rejects_crypto_context_artifact_ref_mismatch() {
    let Ok(mut bundle) = valid_bundle() else {
        panic!("valid bundle fixture should build");
    };
    let Some(report) = bundle.crypto_context_report.as_mut() else {
        panic!("valid bundle should include crypto context report");
    };
    report.artifact_ref = "disclosure-capsule-other".to_string();

    let error = match verify_disclosure_lineage_bundle(&bundle) {
        Ok(_) => panic!("crypto context artifact mismatch must fail"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("crypto context artifact ref mismatch"));
}

#[test]
fn disclosure_lineage_rejects_crypto_context_missing_disclosed_field() {
    let Ok(mut bundle) = valid_bundle() else {
        panic!("valid bundle fixture should build");
    };
    let Some(report) = bundle.crypto_context_report.as_mut() else {
        panic!("valid bundle should include crypto context report");
    };
    report.disclosed_fields.retain(|field| field != "tool_name");

    let error = match verify_disclosure_lineage_bundle(&bundle) {
        Ok(_) => panic!("crypto context missing disclosed field must fail"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("crypto context report missing disclosed field: tool_name"));
}

#[test]
fn disclosure_lineage_rejects_unknown_lineage_root() {
    let Ok(mut bundle) = valid_bundle() else {
        panic!("valid bundle fixture should build");
    };
    bundle.lineage.root_receipt_ids = vec!["receipt-missing".to_string()];

    let error = match verify_disclosure_lineage_bundle(&bundle) {
        Ok(_) => panic!("unknown lineage root must fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("unknown lineage root receipt"));
}
