#[test]
fn compliance_certificate_rejects_empty_invalid_and_non_compliant_receipts() {
    let signer = Keypair::generate();
    let now = now_secs();
    let config = ComplianceConfig {
        budget_limit: 4,
        required_guards: vec!["fs_guard".to_string()],
        authorized_scopes: vec!["fs/".to_string()],
        expected_tenant_id: None,
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
    };

    let empty = generate_compliance_certificate("session-empty", &[], &config, &signer);
    assert!(matches!(
        empty,
        Err(ComplianceCertificateError::EmptySession(ref id)) if id == "session-empty"
    ));

    let mut invalid_receipt = make_receipt_for_session(
        &signer,
        "session-invalid",
        "receipt-invalid",
        now,
        "fs/read_text_file",
        Decision::Allow,
        vec![GuardEvidence {
            guard_name: "fs_guard".to_string(),
            verdict: true,
            details: Some("ok".to_string()),
        }],
    );
    invalid_receipt.tool_name = "tampered".to_string();
    let invalid_entries = vec![ComplianceReceiptEntry {
        receipt: invalid_receipt,
        seq: 0,
    }];
    let invalid =
        generate_compliance_certificate("session-invalid", &invalid_entries, &config, &signer);
    assert!(matches!(
        invalid,
        Err(ComplianceCertificateError::InvalidReceiptSignature { .. })
    ));

    let gap_entries = vec![
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer,
                "session-gap",
                "receipt-gap-1",
                now,
                "fs/read_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: None,
                }],
            ),
            seq: 0,
        },
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer,
                "session-gap",
                "receipt-gap-2",
                now + 1,
                "fs/read_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: None,
                }],
            ),
            seq: 2,
        },
    ];
    let gap = generate_compliance_certificate("session-gap", &gap_entries, &config, &signer);
    assert!(matches!(
        gap,
        Err(ComplianceCertificateError::ChainDiscontinuity {
            expected: 1,
            found: 2
        })
    ));

    let scope_entries = vec![ComplianceReceiptEntry {
        receipt: make_receipt_for_session(
            &signer,
            "session-scope",
            "receipt-scope",
            now,
            "terminal/create",
            Decision::Allow,
            vec![GuardEvidence {
                guard_name: "fs_guard".to_string(),
                verdict: true,
                details: None,
            }],
        ),
        seq: 0,
    }];
    let scope =
        generate_compliance_certificate("session-scope", &scope_entries, &config, &signer);
    assert!(matches!(
        scope,
        Err(ComplianceCertificateError::ScopeViolation { .. })
    ));

    let budget_entries = (0..5)
        .map(|idx| ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer,
                "session-budget",
                &format!("receipt-budget-{idx}"),
                now + idx,
                "fs/read_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: None,
                }],
            ),
            seq: idx,
        })
        .collect::<Vec<_>>();
    let budget =
        generate_compliance_certificate("session-budget", &budget_entries, &config, &signer);
    assert!(matches!(
        budget,
        Err(ComplianceCertificateError::BudgetExceeded { used: 5, limit: 4 })
    ));

    let guard_entries = vec![ComplianceReceiptEntry {
        receipt: make_receipt_for_session(
            &signer,
            "session-guard",
            "receipt-guard",
            now,
            "fs/read_text_file",
            Decision::Allow,
            Vec::new(),
        ),
        seq: 0,
    }];
    let guard =
        generate_compliance_certificate("session-guard", &guard_entries, &config, &signer);
    assert!(matches!(
        guard,
        Err(ComplianceCertificateError::GuardBypass { .. })
    ));
}

#[test]
fn compliance_certificate_rejects_mixed_kernel_keys() {
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
    assert_ne!(signer_a.public_key(), signer_b.public_key());
    let config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([
            signer_a.public_key().to_hex(),
            signer_b.public_key().to_hex(),
        ]),
        ..ComplianceConfig::default()
    };
    let now = now_secs();
    let entries = vec![
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer_a,
                "session-mixed-keys",
                "receipt-a",
                now,
                "fs/read_text_file",
                Decision::Allow,
                Vec::new(),
            ),
            seq: 0,
        },
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer_b,
                "session-mixed-keys",
                "receipt-b",
                now + 1,
                "fs/read_text_file",
                Decision::Allow,
                Vec::new(),
            ),
            seq: 1,
        },
    ];
    let expected_receipt_id = entries[1].receipt.id.clone();
    let result =
        generate_compliance_certificate("session-mixed-keys", &entries, &config, &signer_a);
    assert!(
        matches!(
            result,
            Err(ComplianceCertificateError::KernelKeyMismatch { ref receipt_id })
            if receipt_id == &expected_receipt_id
        ),
        "expected KernelKeyMismatch on heterogeneous kernel keys, got: {:?}",
        result.as_ref().err()
    );
}

#[test]
fn compliance_certificate_round_trips_and_detects_full_bundle_tampering() {
    let signer = Keypair::generate();
    let now = now_secs();
    let receipts = vec![
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer,
                "session-good",
                "receipt-1",
                now,
                "fs/read_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: Some("read ok".to_string()),
                }],
            ),
            seq: 0,
        },
        ComplianceReceiptEntry {
            receipt: make_receipt_for_session(
                &signer,
                "session-good",
                "receipt-2",
                now + 1,
                "fs/write_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: Some("write ok".to_string()),
                }],
            ),
            seq: 1,
        },
    ];
    let config = ComplianceConfig {
        budget_limit: 2,
        required_guards: vec!["fs_guard".to_string()],
        authorized_scopes: vec!["fs/".to_string()],
        expected_tenant_id: None,
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
    };

    let cert = generate_compliance_certificate("session-good", &receipts, &config, &signer)
        .expect("certificate should generate");

    let lightweight =
        verify_compliance_certificate(
            &cert,
            VerificationMode::Lightweight,
            Some(&receipts),
            &config,
        );
    assert!(lightweight.passed);
    assert!(lightweight.certificate_signature_valid);
    assert_eq!(lightweight.summary, "lightweight verification passed");

    let untrusted_config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        ..config.clone()
    };
    let untrusted = verify_compliance_certificate(
        &cert,
        VerificationMode::Lightweight,
        Some(&receipts),
        &untrusted_config,
    );
    assert!(!untrusted.passed);
    assert!(untrusted.summary.contains("certificate signer is not trusted"));

    let full_bundle =
        verify_compliance_certificate(
            &cert,
            VerificationMode::FullBundle,
            Some(&receipts),
            &config,
        );
    assert!(full_bundle.passed);
    assert_eq!(full_bundle.receipts_reverified, 2);
    assert_eq!(full_bundle.receipt_failures, 0);

    let mut tampered_entries = receipts.clone();
    tampered_entries[1].receipt.tool_name = "fs/tampered".to_string();
    let tampered = verify_compliance_certificate(
        &cert,
        VerificationMode::FullBundle,
        Some(&tampered_entries),
        &config,
    );
    assert!(!tampered.passed);
    assert_eq!(tampered.receipts_reverified, 2);
    assert_eq!(tampered.receipt_failures, 1);
    assert!(tampered
        .summary
        .contains("1 receipt authority check(s) failed"));

    let mut inconsistent_cert = cert.clone();
    inconsistent_cert
        .body
        .anomalies
        .push("missing guard".to_string());
    let body_bytes = chio_core::canonical::canonical_json_bytes(&inconsistent_cert.body)
        .expect("certificate body should serialize");
    inconsistent_cert.signature = signer.sign(&body_bytes);
    let inconsistent =
        verify_compliance_certificate(
            &inconsistent_cert,
            VerificationMode::Lightweight,
            None,
            &config,
        );
    assert!(!inconsistent.passed);
    assert!(inconsistent.certificate_signature_valid);
    assert!(!inconsistent.body_consistent);
}

#[test]
fn compliance_verification_signer_mismatch_omits_redundant_body_reason() {
    let receipt_signer = Keypair::generate();
    let certificate_signer = Keypair::generate();
    let now = now_secs();
    let receipts = vec![ComplianceReceiptEntry {
        receipt: make_receipt_for_session(
            &receipt_signer,
            "session-signer-mismatch",
            "receipt-1",
            now,
            "fs/read_text_file",
            Decision::Allow,
            vec![GuardEvidence {
                guard_name: "fs_guard".to_string(),
                verdict: true,
                details: Some("read ok".to_string()),
            }],
        ),
        seq: 0,
    }];
    let config = ComplianceConfig {
        budget_limit: 1,
        required_guards: vec!["fs_guard".to_string()],
        authorized_scopes: vec!["fs/".to_string()],
        expected_tenant_id: None,
        trusted_kernel_keys: std::collections::BTreeSet::from([
            receipt_signer.public_key().to_hex(),
            certificate_signer.public_key().to_hex(),
        ]),
    };

    let mut cert = generate_compliance_certificate(
        "session-signer-mismatch",
        &receipts,
        &config,
        &receipt_signer,
    )
    .expect("certificate should generate");
    let body_bytes = chio_core::canonical::canonical_json_bytes(&cert.body)
        .expect("certificate body should serialize");
    cert.signer_key = certificate_signer.public_key();
    cert.signature = certificate_signer.sign(&body_bytes);

    let result = verify_compliance_certificate(
        &cert,
        VerificationMode::Lightweight,
        None,
        &config,
    );
    assert!(!result.passed);
    assert!(result.certificate_signature_valid);
    assert!(!result.body_consistent);
    assert!(
        result
            .summary
            .contains("certificate signer does not match body kernel key"),
        "summary must name signer mismatch: {}",
        result.summary
    );
    assert!(
        !result.summary.contains("body consistency check failed"),
        "signer mismatch alone must not also report generic body failure: {}",
        result.summary
    );
}

#[test]
fn compliance_certificate_serializes_snake_case() {
    let signer = Keypair::generate();
    let now = now_secs();
    let receipts = vec![ComplianceReceiptEntry {
        receipt: make_receipt_for_session(
            &signer,
            "session-snake",
            "receipt-snake",
            now,
            "fs/read_text_file",
            Decision::Allow,
            vec![GuardEvidence {
                guard_name: "fs_guard".to_string(),
                verdict: true,
                details: Some("ok".to_string()),
            }],
        ),
        seq: 0,
    }];
    let config = ComplianceConfig {
        budget_limit: 1,
        required_guards: vec!["fs_guard".to_string()],
        authorized_scopes: vec!["fs/".to_string()],
        expected_tenant_id: None,
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
    };

    let cert = generate_compliance_certificate("session-snake", &receipts, &config, &signer)
        .expect("certificate should generate");

    let json = serde_json::to_value(&cert).expect("certificate should serialize");
    assert!(json.get("signer_key").is_some());
    assert!(json.get("signerKey").is_none());
    let body = json
        .get("body")
        .and_then(serde_json::Value::as_object)
        .expect("body should be an object");
    assert!(body.get("session_id").is_some());
    assert!(body.get("receipt_count").is_some());
    assert!(body.get("kernel_key").is_some());
    assert!(body.get("sessionId").is_none());
}
