use super::*;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};

fn sample_receipt(kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-b4-sample".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-b4".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k":"v"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "pol".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, kp).unwrap()
}

fn strict_treaty_extensions(receipt: &ChioReceipt) -> BilateralPredicateExtensions {
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: "lease-bilateral".to_string(),
            issuer: "kernel.org-a".to_string(),
            expires_at_unix_ms: 1_734_000_060_000,
            scope_digest: None,
        }),
        policy_evaluation_summary: Some(PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-a".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-b".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        }),
        governance_receipt_ref: Some(GovernanceReceiptRef {
            receipt_id: "gov-receipt-1".to_string(),
            kernel_id: "kernel.org-b".to_string(),
            digest: HashRecord {
                alg: "sha256".to_string(),
                value: "d".repeat(64),
            },
        }),
        consistency_anchor: Some("anchor-live".to_string()),
        consistency_model: Some("totally-ordered".to_string()),
        cross_org_visibility: Some("treaty_only".to_string()),
        treaty_binding_ref: Some(TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.destructive.vendor_call".to_string(),
            consistency_model: "totally-ordered".to_string(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: receipt.content_hash.clone(),
            local_receipt_sha256: "8".repeat(64),
            remote_receipt_sha256: receipt_canonical_digest_hex(receipt).unwrap(),
            lease_refs: vec!["lease-bilateral".to_string()],
            governance_refs: vec!["gov-receipt-1".to_string()],
            signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
        }),
    }
}

#[test]
fn pae_matches_dsse_v1_format_known_vector() {
    // Sanity: the leading bytes are literally "DSSEv1 ".
    let bytes = pae("application/x", b"hello");
    assert!(bytes.starts_with(b"DSSEv1 "));
    // "DSSEv1 13 application/x 5 hello"
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "DSSEv1 13 application/x 5 hello"
    );
}

#[test]
fn happy_path_signs_and_verifies() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    assert_eq!(envelope.signatures.len(), 2);
    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("envelope must verify under matching public keys");
    assert_eq!(
        statement.predicate_type, PREDICATE_TYPE_BILATERAL,
        "predicate type emitted by bilateral hot path"
    );
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));
}

#[test]
fn strict_chio_signer_binds_treaty_runtime_refs() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-bilateral".to_string(),
                issuer: "kernel.org-a".to_string(),
                expires_at_unix_ms: 1_734_000_060_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-receipt-1".to_string(),
                kernel_id: "kernel.org-b".to_string(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some("totally-ordered".to_string()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: "treaty-buyer-vendor".to_string(),
                treaty_scope_sha256: "1".repeat(64),
                ladder_intersection_sha256: "2".repeat(64),
                admission_report_sha256: "3".repeat(64),
                continuation_sha256: "4".repeat(64),
                lineage_bundle_sha256: "5".repeat(64),
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                consistency_model: "totally-ordered".to_string(),
                request_sha256: receipt.action.parameter_hash.clone(),
                outcome_sha256: receipt.content_hash.clone(),
                local_receipt_sha256: "8".repeat(64),
                remote_receipt_sha256: receipt_canonical_digest_hex(&receipt).unwrap(),
                lease_refs: vec!["lease-bilateral".to_string()],
                governance_refs: vec!["gov-receipt-1".to_string()],
                signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
            }),
        },
    )
    .expect("strict Chio treaty DSSE signs");
    let statement =
        verify_chio_bilateral_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect("strict Chio treaty DSSE verifies");
    let treaty = statement
        .predicate
        .treaty_binding_ref
        .expect("strict treaty DSSE must carry treaty binding");
    assert_eq!(treaty.treaty_id, "treaty-buyer-vendor");
    assert_eq!(
        treaty.signer_kernel_ids,
        vec!["kernel.org-a", "kernel.org-b"]
    );
}

#[test]
fn strict_chio_signer_accepts_treaty_binding_without_governance_ref() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut extensions = strict_treaty_extensions(&receipt);
    extensions.governance_receipt_ref = None;
    extensions
        .treaty_binding_ref
        .as_mut()
        .expect("strict treaty extension carries binding")
        .governance_refs = Vec::new();

    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        extensions,
    )
    .expect("lease-bound treaty DSSE signs without governance receipt material");
    let statement =
        verify_chio_bilateral_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect("lease-bound treaty DSSE verifies");
    let treaty = statement
        .predicate
        .treaty_binding_ref
        .expect("strict treaty DSSE must carry treaty binding");
    assert_eq!(treaty.lease_refs, vec!["lease-bilateral".to_string()]);
    assert!(treaty.governance_refs.is_empty());
    assert!(statement.predicate.governance_receipt_ref.is_none());
}

#[test]
fn strict_chio_signer_rejects_treaty_request_hash_mismatch() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let err = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-bilateral".to_string(),
                issuer: "kernel.org-a".to_string(),
                expires_at_unix_ms: 1_734_000_060_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-receipt-1".to_string(),
                kernel_id: "kernel.org-b".to_string(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some("totally-ordered".to_string()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: "treaty-buyer-vendor".to_string(),
                treaty_scope_sha256: "1".repeat(64),
                ladder_intersection_sha256: "2".repeat(64),
                admission_report_sha256: "3".repeat(64),
                continuation_sha256: "4".repeat(64),
                lineage_bundle_sha256: "5".repeat(64),
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                consistency_model: "totally-ordered".to_string(),
                request_sha256: "6".repeat(64),
                outcome_sha256: receipt.content_hash.clone(),
                local_receipt_sha256: "8".repeat(64),
                remote_receipt_sha256: receipt_canonical_digest_hex(&receipt).unwrap(),
                lease_refs: vec!["lease-bilateral".to_string()],
                governance_refs: vec!["gov-receipt-1".to_string()],
                signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
            }),
        },
    )
    .expect_err("strict Chio signer must reject mismatched treaty request hash");
    assert!(err.to_string().contains("request_sha256"));
}

#[test]
fn strict_chio_signer_rejects_treaty_outcome_hash_mismatch() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut extensions = strict_treaty_extensions(&receipt);
    extensions
        .treaty_binding_ref
        .as_mut()
        .unwrap()
        .outcome_sha256 = "7".repeat(64);

    let err = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        extensions,
    )
    .expect_err("strict Chio signer must reject mismatched treaty outcome hash");
    assert!(err.to_string().contains("outcome_sha256"));
}

#[test]
fn strict_chio_signer_rejects_treaty_remote_receipt_hash_mismatch() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut extensions = strict_treaty_extensions(&receipt);
    extensions
        .treaty_binding_ref
        .as_mut()
        .unwrap()
        .remote_receipt_sha256 = "9".repeat(64);

    let err = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        extensions,
    )
    .expect_err("strict Chio signer must reject mismatched treaty receipt hash");
    assert!(err.to_string().contains("remote_receipt_sha256"));
}

#[test]
fn strict_chio_signer_rejects_treaty_runtime_ref_mismatch() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let err = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-bilateral".to_string(),
                issuer: "kernel.org-a".to_string(),
                expires_at_unix_ms: 1_734_000_060_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-receipt-1".to_string(),
                kernel_id: "kernel.org-b".to_string(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some("totally-ordered".to_string()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: "treaty-buyer-vendor".to_string(),
                treaty_scope_sha256: "1".repeat(64),
                ladder_intersection_sha256: "2".repeat(64),
                admission_report_sha256: "3".repeat(64),
                continuation_sha256: "4".repeat(64),
                lineage_bundle_sha256: "5".repeat(64),
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                consistency_model: "totally-ordered".to_string(),
                request_sha256: receipt.action.parameter_hash.clone(),
                outcome_sha256: receipt.content_hash.clone(),
                local_receipt_sha256: "8".repeat(64),
                remote_receipt_sha256: receipt_canonical_digest_hex(&receipt).unwrap(),
                lease_refs: vec!["other-lease".to_string()],
                governance_refs: vec!["gov-receipt-1".to_string()],
                signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
            }),
        },
    )
    .expect_err("strict Chio signer must reject mismatched treaty refs");
    assert!(err.to_string().contains("lease_refs"));
}

#[test]
fn strict_chio_signer_rejects_identical_signer_keys() {
    let kp = Keypair::generate();
    let receipt = sample_receipt(&kp);
    let err = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp,
        &kp,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-bilateral".to_string(),
                issuer: "kernel.org-a".to_string(),
                expires_at_unix_ms: 1_734_000_060_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: None,
            consistency_anchor: None,
            consistency_model: None,
            cross_org_visibility: None,
            treaty_binding_ref: None,
        },
    )
    .expect_err("strict Chio DSSE needs two independent signer keys");
    assert!(err.to_string().contains("independent"));
}

#[test]
fn strict_chio_verifier_rejects_duplicate_signature_keyids() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-bilateral".to_string(),
                issuer: "kernel.org-a".to_string(),
                expires_at_unix_ms: 1_734_000_060_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: None,
            consistency_anchor: None,
            consistency_model: None,
            cross_org_visibility: None,
            treaty_binding_ref: None,
        },
    )
    .unwrap();
    envelope.signatures[1].keyid = envelope.signatures[0].keyid.clone();

    let err =
        verify_chio_bilateral_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect_err("strict Chio rejects duplicate signature key IDs");
    assert!(err.to_string().contains("duplicate signature keyid"));
}

#[test]
fn round_trip_preserves_pae_bytes() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let pae_a = envelope.pae_bytes().unwrap();
    // Re-decode and re-derive: the bytes are stable.
    let (_stmt, bytes) = envelope.decode_statement().unwrap();
    let pae_b = pae(&envelope.payload_type, &bytes);
    assert_eq!(pae_a, pae_b);
}

#[test]
fn keyid_is_sha256_of_raw_ed25519_public_key_bytes() {
    // Key-identifier invariant: the spec's keyid contract is
    // SHA-256 of RAW key material (Ed25519 = 32 verifying-key
    // bytes). An earlier revision hashed `to_hex().as_bytes()`
    // which silently broke cross-implementation interop. This
    // test pins the raw-bytes invariant.
    let kp = Keypair::generate();
    let pk = kp.public_key();
    let keyid = Keyid::from_public_key(&pk);
    let want = sha256_hex(pk.as_bytes());
    assert_eq!(keyid.0, want);
    // hashing the hex form must NOT match.
    let hex_form = sha256_hex(pk.to_hex().as_bytes());
    assert_ne!(
        keyid.0, hex_form,
        "Ed25519 keyid must hash raw bytes, not hex string"
    );
}

#[test]
fn signer_rejects_empty_schema_required_identifiers() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    let mut empty_receipt_id = sample_receipt(&kp_b);
    empty_receipt_id.id.clear();
    let err = sign_dsse_envelope(
        &empty_receipt_id,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .expect_err("empty receipt id must not sign");
    assert!(err.to_string().contains("invocation_id must be non-empty"));

    let mut empty_tool = sample_receipt(&kp_b);
    empty_tool.tool_name.clear();
    let err = sign_dsse_envelope(
        &empty_tool,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "",
        1_734_000_000_000,
    )
    .expect_err("empty tool name must not sign");
    assert!(err.to_string().contains("tool_name must be non-empty"));

    let receipt = sample_receipt(&kp_b);
    let err = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .expect_err("empty org-a kernel id must not sign");
    assert!(err
        .to_string()
        .contains("tool_server_a.kernel_id must be non-empty"));

    let err = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "",
        "file_read",
        1_734_000_000_000,
    )
    .expect_err("empty org-b kernel id must not sign");
    assert!(err
        .to_string()
        .contains("tool_server_b.kernel_id must be non-empty"));
}

#[test]
fn tampered_payload_fails_verification() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    envelope.payload.push('A'); // breaks base64 + PAE preimage
    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err());
}

#[test]
fn mismatched_payload_type_fails_verification() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    envelope.payload_type = "application/json".to_string();
    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err());
}

#[test]
fn verifier_accepts_reversed_signature_order_by_keyid() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    envelope.signatures.swap(0, 1);
    verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("signature array order is not security-relevant");
}

#[test]
fn verifier_rejects_noncanonical_statement_payload_even_if_resigned() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (statement, _) = envelope.decode_statement().unwrap();
    let noncanonical = serde_json::to_vec_pretty(&statement).unwrap();
    resign_payload(&mut envelope, &kp_a, &kp_b, &noncanonical);

    let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect_err("non-canonical payload bytes must be rejected");
    assert!(err.to_string().contains("not canonical JSON"));
}

#[test]
fn verifier_rejects_invalid_embedded_receipt_signature_even_if_dsse_resigned() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    let mut embedded: ChioReceipt =
        serde_json::from_str(statement.predicate.receipt_canonical_json.as_ref().unwrap()).unwrap();
    embedded.content_hash = sha256_hex(b"tampered-content");
    statement.predicate.receipt_canonical_json =
        Some(String::from_utf8(canonical_json_bytes(&embedded).unwrap()).unwrap());
    let bytes = statement.canonical_bytes().unwrap();
    resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

    let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect_err("embedded receipt signature must be checked");
    assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
}

#[test]
fn verifier_rejects_embedded_receipt_not_signed_by_tool_host() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let rogue_kp = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut rogue_receipt = sample_receipt(&rogue_kp);
    rogue_receipt.id = receipt.id.clone();
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement.predicate.receipt_canonical_json =
        Some(String::from_utf8(canonical_json_bytes(&rogue_receipt).unwrap()).unwrap());
    statement.subject[0].digest.sha256 = receipt_body_digest_hex(&rogue_receipt).unwrap();
    let bytes = statement.canonical_bytes().unwrap();
    resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

    let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect_err("embedded receipt kernel_key must equal Org B passport key");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn verifier_rejects_ordered_or_quorum_consistency_claims_without_anchor_metadata() {
    for unsupported in ["totally-ordered", "quorum-required"] {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = sample_receipt(&kp_b);
        let mut envelope = sign_dsse_envelope(
            &receipt,
            &kp_a,
            &kp_b,
            "kernel.org-a",
            "kernel.org-b",
            "file_read",
            1_734_000_000_000,
        )
        .unwrap();
        let (mut statement, _) = envelope.decode_statement().unwrap();
        statement.predicate.consistency_model = unsupported.to_string();
        let bytes = statement.canonical_bytes().unwrap();
        resign_payload(&mut envelope, &kp_a, &kp_b, &bytes);

        let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
            .expect_err("signature-slice profile cannot verify ordered/quorum claims");
        assert!(err.to_string().contains(&format!(
            "consistency_model \"{unsupported}\" is not supported"
        )));
    }
}

#[test]
fn signer_rejects_tool_name_that_does_not_match_receipt() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let err = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_write",
        1_734_000_000_000,
    )
    .expect_err("producer must bind predicate.tool_name to receipt.tool_name");
    assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
}

fn policy_evaluation_summary_with_verdict(verdict: &str) -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: verdict.to_string(),
            policy_id: "policy-a".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: verdict.to_string(),
            policy_id: "policy-b".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some(verdict.to_string()),
    }
}

#[test]
fn require_policy_evaluation_allow_admission_accepts_unanimous_allow() {
    let summary = policy_evaluation_summary_with_verdict("allow");
    require_policy_evaluation_allow_admission(&summary).unwrap();
}

#[test]
fn require_policy_evaluation_allow_admission_rejects_deny() {
    let summary = policy_evaluation_summary_with_verdict("deny");
    let err = require_policy_evaluation_allow_admission(&summary)
        .expect_err("admission must require allow verdict");
    assert!(matches!(err, BilateralCoSigningError::CanonicalJson(_)));
    assert!(err
        .to_string()
        .contains("policy_evaluation_summary requires allow verdict for admission"));
}

#[test]
fn require_policy_evaluation_allow_admission_propagates_summary_validation() {
    let mut summary = policy_evaluation_summary_with_verdict("allow");
    summary.server_b_verdict.verdict = "deny".to_string();
    let err = require_policy_evaluation_allow_admission(&summary)
        .expect_err("mismatched server verdicts must fail before admission");
    assert!(matches!(err, BilateralCoSigningError::CanonicalJson(_)));
    assert!(err.to_string().contains("server_a=allow server_b=deny"));
}

#[test]
fn validate_policy_evaluation_summary_rejects_unsupported_verdict() {
    let mut summary = policy_evaluation_summary_with_verdict("allow");
    summary.server_a_verdict.verdict = "abstain".to_string();
    summary.server_b_verdict.verdict = "abstain".to_string();
    summary.joint_disposition = Some("abstain".to_string());
    let err = validate_policy_evaluation_summary(&summary)
        .expect_err("admission summaries must reject unknown verdict strings");
    assert!(matches!(err, BilateralCoSigningError::CanonicalJson(_)));
    assert!(err.to_string().contains("unsupported verdict"));
}

fn resign_payload(
    envelope: &mut DsseEnvelope,
    kp_a: &Keypair,
    kp_b: &Keypair,
    statement_bytes: &[u8],
) {
    envelope.payload = BASE64_STANDARD.encode(statement_bytes);
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, statement_bytes);
    let sig_a = Ed25519Backend::new(kp_a.clone())
        .sign_bytes(&pae_bytes)
        .unwrap();
    let sig_b = Ed25519Backend::new(kp_b.clone())
        .sign_bytes(&pae_bytes)
        .unwrap();
    envelope.signatures[0].sig = BASE64_STANDARD.encode(sig_a.to_bytes());
    envelope.signatures[1].sig = BASE64_STANDARD.encode(sig_b.to_bytes());
}
