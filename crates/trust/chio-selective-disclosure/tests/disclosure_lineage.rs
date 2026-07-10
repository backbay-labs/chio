use chio_core_types::{sha256_hex, Keypair};
use chio_selective_disclosure::{
    compute_signed_lineage_subgraph_digest, sign_crypto_context_report, sign_lineage_subgraph,
    verify_disclosure_lineage_bundle_with_trust, DisclosureCapsule, DisclosureContextVerdict,
    DisclosureCryptoContextReport, DisclosureHiddenPredicate, DisclosureLeakageLedger,
    DisclosureLeakageLedgerEntry, DisclosureLineageBundle, DisclosureLineageError,
    DisclosureLineageVerifierReport, DisclosureLineageVerifierTrust,
    DisclosureProfileLeakageBudget, DisclosureSensitivityClass, DisclosureSignedLineageEdge,
    DisclosureSignedLineageNode, DisclosureSignedLineageRedaction,
    DisclosureVerifierPrivacyProfile, SignedLineageSubgraph, TransparencyState,
    DISCLOSURE_CAPSULE_SCHEMA_V1, DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
    DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1, DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1,
    DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1, LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
};

fn valid_bundle() -> Result<DisclosureLineageBundle, Box<dyn std::error::Error>> {
    let capsule = DisclosureCapsule {
        schema: DISCLOSURE_CAPSULE_SCHEMA_V1.to_string(),
        id: "disclosure-capsule-valid".to_string(),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        crypto_context_report_ref: "crypto-context-report-valid".to_string(),
        projection_manifest_ref: "bbs-projection-manifest-valid".to_string(),
        privacy_profile_ref: "privacy-profile-valid".to_string(),
        lineage_subgraph_ref: "lineage-subgraph-valid".to_string(),
        leakage_ledger_ref: "leakage-ledger-valid".to_string(),
        disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
        hidden_predicates: vec![amount_cap_hidden_predicate()],
    };
    let privacy_profile = DisclosureVerifierPrivacyProfile {
        schema: DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1.to_string(),
        profile_id: "privacy-profile-valid".to_string(),
        allowed_proof_mechanisms: vec!["bbs".to_string()],
        required_holder_binding: Some("holder:buyer-agent".to_string()),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        leakage_budget: DisclosureProfileLeakageBudget {
            max_disclosed_fields: 2,
            max_hidden_predicates: 1,
        },
        sensitivity_classes: vec![
            DisclosureSensitivityClass {
                class_id: "capability_identifier".to_string(),
                fields: vec!["capability_id".to_string()],
            },
            DisclosureSensitivityClass {
                class_id: "tool_identity".to_string(),
                fields: vec!["tool_name".to_string()],
            },
            DisclosureSensitivityClass {
                class_id: "amount_or_budget".to_string(),
                fields: vec!["amount_lte_100".to_string()],
            },
            DisclosureSensitivityClass {
                class_id: "runtime_assurance".to_string(),
                fields: vec![
                    "derived.crypto.issuer_status".to_string(),
                    "derived.crypto.revocation_freshness".to_string(),
                ],
            },
            DisclosureSensitivityClass {
                class_id: "timing".to_string(),
                fields: vec!["derived.crypto.presentation_timing".to_string()],
            },
        ],
        allowed_issuer_keys: vec![
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ],
        required_key_epoch_min: 7,
        forbidden_key_epochs: vec![9],
        required_status_freshness_seconds: 300,
        required_audience: "https://auditor.example/chio".to_string(),
        nonce_policy: "no_replay".to_string(),
        allowed_algorithms: vec!["bbs-bls12381-sha256".to_string()],
        forbidden_algorithms: vec!["rsa-pkcs1v15-sha1".to_string()],
        required_transparency_state: TransparencyState::Anchored,
        max_presentation_age_seconds: 600,
        allowed_disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
        forbidden_disclosed_fields: vec!["customer_email".to_string()],
        allowed_hidden_predicates: vec!["amount_lte_100".to_string()],
        forbidden_hidden_predicates: vec!["raw_amount".to_string()],
    };
    let frontier_sha256 = lineage_frontier_digest("receipt-child", &digest("receipt-child"), 1);
    let checkpoint_ref = "checkpoint-disclosure-valid".to_string();
    let mut lineage = SignedLineageSubgraph {
        schema: LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1.to_string(),
        id: "lineage-subgraph-valid".to_string(),
        transaction_passport_ref: "passport-disclosure-valid".to_string(),
        policy_profile_id: "privacy-profile-valid".to_string(),
        generated_at: "2026-06-10T00:00:00Z".to_string(),
        audience: "https://auditor.example/chio".to_string(),
        challenge_nonce: "disclosure-lineage-fixture-nonce".to_string(),
        frontier_sha256: frontier_sha256.clone(),
        checkpoint_ref: checkpoint_ref.clone(),
        checkpoint_inclusion_sha256: digest(&format!("{checkpoint_ref}|{frontier_sha256}")),
        max_depth: 1,
        required_evidence_class: "observed".to_string(),
        lineage_anchor_ref: "lineage-anchor-local-fixture".to_string(),
        redaction_map_sha256: digest("receipt-child|privacy_profile"),
        leakage_ledger_sha256: digest("leakage-ledger-valid"),
        projection_manifest_sha256: digest("bbs-projection-manifest-valid"),
        root_receipt_ids: vec!["receipt-root".to_string()],
        nodes: vec![
            DisclosureSignedLineageNode {
                id: "receipt-root".to_string(),
                kind: "receipt".to_string(),
                receipt_ref: "receipt-root".to_string(),
                artifact_sha256: digest("receipt-root"),
                artifact_schema: "chio.receipt.v1".to_string(),
                evidence_class: "observed".to_string(),
                tenant_hash: digest("tenant-fixture"),
                source_table: "receipts".to_string(),
                source_id_hash: digest("receipt-root"),
                depth: 0,
                parent_ids: Vec::new(),
                disclosure_state: "disclosed".to_string(),
            },
            DisclosureSignedLineageNode {
                id: "receipt-child".to_string(),
                kind: "receipt_lineage_statement".to_string(),
                receipt_ref: "receipt-child".to_string(),
                artifact_sha256: digest("receipt-child"),
                artifact_schema: "chio.receipt-lineage-statement.v1".to_string(),
                evidence_class: "derived".to_string(),
                tenant_hash: digest("tenant-fixture"),
                source_table: "receipt_lineage_statements".to_string(),
                source_id_hash: digest("receipt-child"),
                depth: 1,
                parent_ids: vec!["receipt-root".to_string()],
                disclosure_state: "redacted".to_string(),
            },
        ],
        edges: vec![DisclosureSignedLineageEdge {
            edge_id: "edge-receipt-root-receipt-child".to_string(),
            from: "receipt-root".to_string(),
            to: "receipt-child".to_string(),
            relation: "continued".to_string(),
            kind: "continued_by".to_string(),
            evidence_class: "observed".to_string(),
            source_artifact_sha256: digest("edge-receipt-root-receipt-child"),
            statement_sha256: digest("receipt-root|receipt-child|continued_by"),
            disclosure_state: "disclosed".to_string(),
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
        policy_profile_id: "privacy-profile-valid".to_string(),
        subject_artifact_sha256: digest("disclosure-capsule-valid"),
        generated_at: "2026-06-10T00:00:00Z".to_string(),
        audience: "https://auditor.example/chio".to_string(),
        total_leakage_score: 7,
        max_allowed_leakage_score: 7,
        tenant_leakage_notice_ref: "tenant-leakage-notice-none".to_string(),
        accepted: true,
        entries: vec![
            leakage_entry(
                "leakage-capability-id",
                "capability_id",
                "disclosed_field",
                "capability_identifier",
                1,
                None,
            ),
            leakage_entry(
                "leakage-tool-name",
                "tool_name",
                "disclosed_field",
                "tool_identity",
                1,
                None,
            ),
            leakage_entry(
                "leakage-amount-cap",
                "amount_lte_100",
                "hidden_predicate",
                "amount_or_budget",
                2,
                Some("predicate reveals capped amount band"),
            ),
            leakage_entry(
                "leakage-derived-issuer-status",
                "derived.crypto.issuer_status",
                "derived_fact",
                "runtime_assurance",
                1,
                None,
            ),
            leakage_entry(
                "leakage-derived-revocation-freshness",
                "derived.crypto.revocation_freshness",
                "derived_fact",
                "runtime_assurance",
                1,
                None,
            ),
            leakage_entry(
                "leakage-derived-presentation-timing",
                "derived.crypto.presentation_timing",
                "derived_fact",
                "timing",
                1,
                None,
            ),
        ],
    };
    let mut crypto_context_report = DisclosureCryptoContextReport {
        schema: DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.to_string(),
        id: "crypto-context-report-valid".to_string(),
        context_id: "crypto-context-valid".to_string(),
        artifact_ref: "disclosure-capsule-valid".to_string(),
        projection_manifest_ref: "bbs-projection-manifest-valid".to_string(),
        verdict: DisclosureContextVerdict::Verified,
        evidence_class: "verifier_context".to_string(),
        cryptographic_proof_verified: true,
        verified_claims: vec![
            "claim.disclosure.crypto_context_bound".to_string(),
            "claim.disclosure.profile_context_policy_enforced".to_string(),
        ],
        rejected_checks: Vec::new(),
        disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
        signature: None,
    };
    crypto_context_report.signature = Some(sign_crypto_context_report(
        &crypto_context_report,
        &lineage_signer(),
    )?);
    Ok(DisclosureLineageBundle {
        capsule,
        privacy_profile,
        lineage,
        leakage_ledger,
        crypto_context_report: Some(crypto_context_report),
    })
}

fn lineage_signer() -> Keypair {
    Keypair::from_seed(&[29u8; 32])
}

fn disclosure_lineage_trust() -> DisclosureLineageVerifierTrust {
    let signer = lineage_signer().public_key();
    DisclosureLineageVerifierTrust::new()
        .with_trusted_lineage_signer_keys(vec![signer.clone()])
        .with_trusted_crypto_context_report_signer_keys(vec![signer])
}

fn verify_bundle(
    bundle: &DisclosureLineageBundle,
) -> Result<DisclosureLineageVerifierReport, DisclosureLineageError> {
    verify_disclosure_lineage_bundle_with_trust(bundle, &disclosure_lineage_trust())
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn lineage_frontier_digest(node_id: &str, artifact_sha256: &str, depth: u32) -> String {
    digest(&format!("{node_id}:{artifact_sha256}:{depth}"))
}

fn leakage_entry(
    entry_id: &str,
    field: &str,
    leakage_kind: &str,
    sensitivity_class: &str,
    score: u32,
    residual_inference_note: Option<&str>,
) -> DisclosureLeakageLedgerEntry {
    DisclosureLeakageLedgerEntry {
        entry_id: entry_id.to_string(),
        source: "disclosure-capsule".to_string(),
        field: field.to_string(),
        leakage_kind: leakage_kind.to_string(),
        disclosure_kind: leakage_kind.to_string(),
        sensitivity_class: sensitivity_class.to_string(),
        value_class: "identifier_or_predicate".to_string(),
        reason: "required by disclosure profile".to_string(),
        policy_rule: "profile.allowed_disclosure".to_string(),
        derived_inferences: Vec::new(),
        cross_tenant_risk: false,
        mitigation: None,
        score,
        allowed_by_profile: true,
        residual_inference_note: residual_inference_note.map(str::to_string),
    }
}

fn amount_cap_hidden_predicate() -> DisclosureHiddenPredicate {
    DisclosureHiddenPredicate {
        predicate_id: "amount_lte_100".to_string(),
        kind: "amount_cap".to_string(),
        field: "amount".to_string(),
        operator: "<=".to_string(),
        operand: "100".to_string(),
        unit: "USD".to_string(),
        result: true,
        proof_ref: "selective-disclosure-proof".to_string(),
        projection_slot: 2,
    }
}

#[test]
fn disclosure_lineage_verifies_valid_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = valid_bundle()?;

    let report = verify_bundle(&bundle)?;

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
    bundle.leakage_ledger.total_leakage_score = 6;

    let error = match verify_bundle(&bundle) {
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

    let error = match verify_bundle(&bundle) {
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

    let error = match verify_bundle(&bundle) {
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

    let error = match verify_bundle(&bundle) {
        Ok(_) => panic!("unknown lineage root must fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("unknown lineage root receipt"));
}
