use crate::context::*;
use crate::disclosure::*;
use crate::error::*;
use crate::issuer::*;
use crate::proof_package::*;
use crate::report::*;
use crate::revocation::*;
use crate::trust_bundle::*;
use crate::validation::*;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_governance::authorization::SignedGovernanceReceipt;
use chio_governance::lease::SignedCapabilityLease;
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_receipt_body, sign_projection,
    DisclosureSet, BBS_CIPHERSUITE_SHA256, PROJECTION_VERSION_RECEIPT_V1,
};

#[test]
fn lower_sha256_hex_helper_accepts_exact_lowercase_digest_only() {
    assert!(is_lower_sha256_hex(&"a".repeat(64)));
    assert!(!is_lower_sha256_hex(&"A".repeat(64)));
    assert!(!is_lower_sha256_hex(&"a".repeat(63)));
    assert!(!is_lower_sha256_hex(&format!("{}g", "a".repeat(63))));
}

fn trust_bundle_document_from_fixture() -> ChioVerifierTrustBundleDocument {
    serde_json::from_str(include_str!(
        "../../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
    ))
    .expect("trust bundle fixture parses")
}

fn trust_bundle_from_fixture() -> Result<ChioVerifierTrustBundle, ChioPackageError> {
    ChioVerifierTrustBundle::from_document(trust_bundle_document_from_fixture())
}

fn verification_context_from_fixture() -> ChioVerificationContext {
    verification_context_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/verification-context.json"
    ))
    .expect("verification context fixture parses")
}

fn receipt_v1_disclosure_policy(message_count: usize) -> ChioDisclosurePolicy {
    ChioDisclosurePolicy {
        projection_version: PROJECTION_VERSION_RECEIPT_V1.to_string(),
        ciphersuite: BBS_CIPHERSUITE_SHA256.to_string(),
        message_count,
        required_disclosed_indices: vec![1, 5, 11],
        required_disclosed_fields: vec![
            "capability_id".to_string(),
            "id".to_string(),
            "tool_name".to_string(),
        ],
    }
}

fn trust_bundle_with_revocations(revoked_key_fingerprints: Vec<String>) -> ChioVerifierTrustBundle {
    let mut document = trust_bundle_document_from_fixture();
    let ChioRevocationMaterial::Checkpoint(checkpoint) = document.revocation else {
        panic!("fixture carries signed revocation checkpoint");
    };
    let checkpoint = *checkpoint;
    let mut body = checkpoint.body;
    body.revoked_key_fingerprints = revoked_key_fingerprints;
    document.revocation = ChioRevocationMaterial::Checkpoint(Box::new(
        SignedExportEnvelope::sign(body, &Keypair::from_seed(&[11; 32]))
            .expect("revocation checkpoint re-signs"),
    ));
    ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses")
}

fn resign_lease(lease: &mut SignedCapabilityLease) {
    *lease = SignedExportEnvelope::sign(lease.body.clone(), &Keypair::from_seed(&[11; 32]))
        .expect("lease re-signs");
}

fn resign_governance_receipt(receipt: &mut SignedGovernanceReceipt) {
    *receipt = SignedExportEnvelope::sign(receipt.body.clone(), &Keypair::from_seed(&[12; 32]))
        .expect("governance receipt re-signs");
}

#[test]
fn committed_fixture_verifies_through_production_crate() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let context = verification_context_from_fixture();
    let report =
        verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");
    assert!(report.accepted);
    assert_eq!(report.schema, VERIFIER_REPORT_SCHEMA);
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "workflow.intersection"));
    let context_sha256 = verification_context_sha256(&context).expect("context hash computes");
    assert_eq!(
        report.context_sha256.as_deref(),
        Some(context_sha256.as_str())
    );
}

#[test]
fn receipt_v1_disclosure_requires_receipt_embedded_bbs() {
    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let context = verification_context_from_fixture();
    let bbs_keypair =
        generate_bbs_keypair(b"chio-bbs-receipt-v1-negative-test-key-material", b"chio")
            .expect("BBS keypair derives");
    let projection =
        project_receipt_body(&package.tool_receipts[0].body()).expect("receipt projection derives");
    let signed = sign_projection(&projection, &bbs_keypair).expect("sidecar projection signs");
    package.selective_disclosure_proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &bbs_keypair,
        &DisclosureSet(vec![1, 5, 11]),
        &context
            .expected_bbs_proof_nonce()
            .expect("context nonce derives"),
    )
    .expect("receipt sidecar proof derives");

    let mut document = trust_bundle_document_from_fixture();
    document.trusted_bbs_issuers = vec![TrustedBbsIssuer {
        issuer_fingerprint: bbs_keypair.issuer_fingerprint.clone(),
        public_key_hex: bbs_keypair.public_key_hex.clone(),
    }];
    document.disclosure_policy = Some(receipt_v1_disclosure_policy(projection.messages.len()));
    let trust_bundle =
        ChioVerifierTrustBundle::from_document(document).expect("receipt v1 policy parses");

    let error = verify_package(&package, &trust_bundle, &context)
        .expect_err("receipt v1 sidecar proof must not verify without receipt BBS");
    assert!(error.to_string().contains("receipt BBS binding failed"));
    assert!(error.to_string().contains("BBS signature material"));
}

#[test]
fn verifier_trust_bundle_rejects_unsupported_receipt_projection_policy() {
    let mut document = trust_bundle_document_from_fixture();
    document.disclosure_policy = Some(ChioDisclosurePolicy {
        projection_version: "chio.bbs-projection.receipt.v0".to_string(),
        ciphersuite: BBS_CIPHERSUITE_SHA256.to_string(),
        message_count: 14,
        required_disclosed_indices: vec![1, 5, 11],
        required_disclosed_fields: vec![
            "capability_id".to_string(),
            "id".to_string(),
            "tool_name".to_string(),
        ],
    });

    let error = ChioVerifierTrustBundle::from_document(document)
        .expect_err("unsupported receipt projection policy must fail closed");
    assert!(error.to_string().contains("projection version"));
    assert!(error.to_string().contains("unsupported"));
}

#[test]
fn verification_context_rejects_blank_or_padded_fields() {
    let mut context = verification_context_from_fixture();
    context.challenge = " ".to_string();
    let error = context.validate().unwrap_err();
    assert!(error.to_string().contains("verificationContext.challenge"));

    let mut context = verification_context_from_fixture();
    context.audience = format!("{} ", context.audience);
    let error = context.validate().unwrap_err();
    assert!(error.to_string().contains("verificationContext.audience"));

    let mut context = verification_context_from_fixture();
    context.proof_purpose = format!(" {}", context.proof_purpose);
    let error = context.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("verificationContext.proofPurpose"));
}

#[test]
fn proof_package_parser_rejects_treaty_bilateral_side_channel() {
    let mut package: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses as JSON");
    package["treatyBilateralEnvelopes"] = serde_json::json!([]);
    let err = proof_package_from_json(&package.to_string())
        .expect_err("canonical proof package parser must reject unknown side-channel fields");
    assert!(err.to_string().contains("treatyBilateralEnvelopes"));
}

#[test]
fn verifier_trust_bundle_parser_rejects_unknown_fields() {
    let mut document = serde_json::to_value(trust_bundle_document_from_fixture())
        .expect("trust bundle serializes");
    document["ignoredTrustRoot"] = serde_json::json!({
        "issuer": "did:chio:ignored"
    });
    let error = verifier_trust_bundle_from_json(
        &serde_json::to_string(&document).expect("trust bundle json serializes"),
    )
    .expect_err("trust bundle parser accepted unknown top-level trust field");
    assert!(error.to_string().contains("ignoredTrustRoot"));

    let mut nested = serde_json::to_value(trust_bundle_document_from_fixture())
        .expect("trust bundle serializes");
    nested["leaseAuthorities"][0]["shadowStatus"] = serde_json::json!("active");
    let error = verifier_trust_bundle_from_json(
        &serde_json::to_string(&nested).expect("trust bundle json serializes"),
    )
    .expect_err("trust bundle parser accepted unknown nested authority field");
    assert!(error.to_string().contains("shadowStatus"));
}

#[test]
fn verifier_report_parses_through_production_api() {
    let report = verifier_report_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/verifier-report.json"
    ))
    .expect("report fixture parses");
    assert!(report.accepted);
    assert_eq!(report.schema, VERIFIER_REPORT_SCHEMA);
    assert!(report.context_sha256.is_some());
    assert!(report.revocation_epoch_height.is_some());
}

#[test]
fn verifier_trust_bundle_may_contain_unrelated_trust_roots() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let mut document = trust_bundle_document_from_fixture();

    let mut extra_peer = document.peers[0].clone();
    extra_peer.kernel_id = "did:chio:unrelated-peer".to_string();
    extra_peer.ladder_manifest_ref.manifest_id = "ladder:unrelated:v1".to_string();
    document.peers.push(extra_peer);

    let mut extra_vendor = document.vendors[0].clone();
    extra_vendor.vendor_id = "vendor-unrelated".to_string();
    document.vendors.push(extra_vendor);

    let trust_bundle =
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");
    let context = verification_context_from_fixture();
    let report =
        verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");

    assert!(report.accepted);
}

#[test]
fn verifier_trust_bundle_requires_signed_fresh_revocation_checkpoint() {
    let mut document = serde_json::to_value(trust_bundle_document_from_fixture())
        .expect("trust bundle serializes");
    assert_eq!(
        document["schema"],
        serde_json::Value::String(VERIFIER_TRUST_BUNDLE_SCHEMA.to_string())
    );

    document["revocation"]["body"]["expiresAtUnixMs"] =
        serde_json::Value::Number(serde_json::Number::from(1_u64));
    let error = verifier_trust_bundle_from_json(
        &serde_json::to_string(&document).expect("trust bundle json serializes"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("revocation"));

    let mut unsigned = serde_json::to_value(trust_bundle_document_from_fixture())
        .expect("trust bundle serializes");
    unsigned["revocation"]["signature"] = serde_json::Value::String("00".to_string());
    let error = verifier_trust_bundle_from_json(
        &serde_json::to_string(&unsigned).expect("trust bundle json serializes"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("revocation") || error.to_string().contains("JSON"));
}

#[test]
fn revocation_checkpoint_must_cover_verifier_context() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let context = verification_context_from_fixture();
    let mut document = trust_bundle_document_from_fixture();
    let ChioRevocationMaterial::Checkpoint(checkpoint) = document.revocation else {
        panic!("fixture carries signed revocation checkpoint");
    };
    let checkpoint = *checkpoint;
    let mut body = checkpoint.body;
    body.expires_at_unix_ms = context.expires_at_unix_ms - 1;
    document.revocation = ChioRevocationMaterial::Checkpoint(Box::new(
        SignedExportEnvelope::sign(body, &Keypair::from_seed(&[11; 32]))
            .expect("revocation checkpoint re-signs"),
    ));
    let trust_bundle = ChioVerifierTrustBundle::from_document(document)
        .expect("trust bundle remains structurally valid");

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revocation checkpoint"));
    assert!(error.to_string().contains("stale"));
}

#[test]
fn revoked_trust_roots_fail_closed() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let context = verification_context_from_fixture();

    let revoked_peer = key_fingerprint(&package.peer_ladder_bindings[1].public_key);
    let trust_bundle = trust_bundle_with_revocations(vec![revoked_peer]);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revoked"));

    let revoked_vendor = key_fingerprint(&package.vendor_keys[0].public_key);
    let trust_bundle = trust_bundle_with_revocations(vec![revoked_vendor]);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revoked"));

    let revoked_issuer = package
        .selective_disclosure_proof
        .issuer_fingerprint
        .clone();
    let trust_bundle = trust_bundle_with_revocations(vec![revoked_issuer]);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revoked"));
}

#[test]
fn revoked_authority_roots_fail_closed() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let context = verification_context_from_fixture();
    let document = trust_bundle_document_from_fixture();

    let revoked_lease_authority = key_fingerprint(&document.lease_authorities[0].public_key);
    let trust_bundle = trust_bundle_with_revocations(vec![revoked_lease_authority]);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revoked"));

    let revoked_governance_authority =
        key_fingerprint(&document.governance_authorities[0].public_key);
    let trust_bundle = trust_bundle_with_revocations(vec![revoked_governance_authority]);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("revoked"));
}

#[test]
fn authority_lifecycle_and_artifact_time_windows_fail_closed() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let context = verification_context_from_fixture();
    let mut document = trust_bundle_document_from_fixture();
    document.lease_authorities[0].valid_from_unix_ms = Some(1);
    document.lease_authorities[0].valid_until_unix_ms = Some(2);
    let trust_bundle =
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("not active"));

    let mut inactive = trust_bundle_document_from_fixture();
    inactive.governance_authorities[0].status = Some(ChioAuthorityStatus::Inactive);
    let error = ChioVerifierTrustBundle::from_document(inactive).unwrap_err();
    assert!(error.to_string().contains("status"));

    let mut future_package = package.clone();
    future_package.lease_scope_bindings[0].issued_at_unix_ms = 1_766_000_010_000;
    future_package.capability_leases[0].body.issued_at_unix_ms = 1_766_000_010_000;
    future_package.capability_leases[0].body.scope_digest = future_package.lease_scope_bindings[0]
        .scope_digest()
        .expect("scope digest rebuilds");
    resign_lease(&mut future_package.capability_leases[0]);
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let error = verify_package(&future_package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("future"));

    let mut outside_lease = package;
    outside_lease.governance_receipts[0].body.expires_at_unix_ms =
        outside_lease.capability_leases[2].body.expires_at_unix_ms + 1;
    resign_governance_receipt(&mut outside_lease.governance_receipts[0]);
    let error = verify_package(&outside_lease, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("outside lease"));
}

#[test]
fn context_and_disclosure_contract_fail_closed() {
    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let mut context = verification_context_from_fixture();
    context.expires_at_unix_ms = 1_766_000_000_000;
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("expired"));

    let context = verification_context_from_fixture();
    package.selective_disclosure_proof.projection_version =
        "chio.bbs-projection.workflow.v0".to_string();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("projection version"));

    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    package.selective_disclosure_proof.disclosed_indices.push(4);
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("duplicate disclosed index"));

    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    package.selective_disclosure_proof.ciphersuite = "unsupported".to_string();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("ciphersuite"));
}

#[test]
fn trusted_issuer_registry_rejects_invalid_empty_and_duplicate_documents() {
    let wrong_schema = TrustedIssuerRegistryDocument {
        schema: "chio.attest.trusted-issuer-registry.v0".to_string(),
        issuers: vec![TrustedBbsIssuer {
            issuer_fingerprint: "a".repeat(64),
            public_key_hex: "aa".repeat(48),
        }],
    };
    let error = TrustedIssuerRegistry::from_document(wrong_schema).unwrap_err();
    assert!(error.to_string().contains("unsupported"));

    let empty = TrustedIssuerRegistryDocument {
        schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
        issuers: Vec::new(),
    };
    let error = TrustedIssuerRegistry::from_document(empty).unwrap_err();
    assert!(error.to_string().contains("empty"));

    let duplicate = TrustedIssuerRegistryDocument {
        schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
        issuers: vec![
            TrustedBbsIssuer {
                issuer_fingerprint: "a".repeat(64),
                public_key_hex: "aa".repeat(48),
            },
            TrustedBbsIssuer {
                issuer_fingerprint: "a".repeat(64),
                public_key_hex: "bb".repeat(48),
            },
        ],
    };
    let error = TrustedIssuerRegistry::from_document(duplicate).unwrap_err();
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn verifier_trust_bundle_rejects_empty_and_duplicate_documents() {
    let mut empty = trust_bundle_document_from_fixture();
    empty.trusted_bbs_issuers.clear();
    let error = ChioVerifierTrustBundle::from_document(empty).unwrap_err();
    assert!(error.to_string().contains("must contain"));

    let mut duplicate_peer = trust_bundle_document_from_fixture();
    duplicate_peer.peers.push(duplicate_peer.peers[0].clone());
    let error = ChioVerifierTrustBundle::from_document(duplicate_peer).unwrap_err();
    assert!(error.to_string().contains("duplicate trusted peer"));

    let mut duplicate_vendor = trust_bundle_document_from_fixture();
    duplicate_vendor
        .vendors
        .push(duplicate_vendor.vendors[0].clone());
    let error = ChioVerifierTrustBundle::from_document(duplicate_vendor).unwrap_err();
    assert!(error.to_string().contains("duplicate trusted vendor"));

    let mut duplicate_action = trust_bundle_document_from_fixture();
    duplicate_action
        .action_classes
        .push(duplicate_action.action_classes[0].clone());
    let error = ChioVerifierTrustBundle::from_document(duplicate_action).unwrap_err();
    assert!(error.to_string().contains("duplicate trusted action class"));

    let mut duplicate_intersection = trust_bundle_document_from_fixture();
    duplicate_intersection
        .workflow_intersections
        .push(duplicate_intersection.workflow_intersections[0].clone());
    let error = ChioVerifierTrustBundle::from_document(duplicate_intersection).unwrap_err();
    assert!(error
        .to_string()
        .contains("duplicate trusted workflow intersection"));
}

#[test]
fn verifier_trust_bundle_requires_reference_workflow_classes() {
    let mut missing_grant = trust_bundle_document_from_fixture();
    missing_grant
        .action_classes
        .retain(|class| class.action_class_id != WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID);
    let error = ChioVerifierTrustBundle::from_document(missing_grant).unwrap_err();
    assert!(error
        .to_string()
        .contains(WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID));

    let mut missing_aggregate = trust_bundle_document_from_fixture();
    missing_aggregate
        .action_classes
        .retain(|class| class.action_class_id != WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID);
    let error = ChioVerifierTrustBundle::from_document(missing_aggregate).unwrap_err();
    assert!(error
        .to_string()
        .contains(WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID));
}

#[test]
fn verifier_trust_bundle_v3_requires_authority_roots() {
    let mut document = serde_json::to_value(trust_bundle_document_from_fixture())
        .expect("trust bundle serializes");
    document["leaseAuthorities"] = serde_json::Value::Array(Vec::new());
    document["governanceAuthorities"] = serde_json::Value::Array(Vec::new());

    let error = verifier_trust_bundle_from_json(
        &serde_json::to_string(&document).expect("trust bundle json serializes"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("authorit"));
}

#[test]
#[ignore = "v1-only collapse: v1 is now the strict schema, not a historical one"]
fn historical_v1_trust_bundle_is_not_strict_verifier_input() {
    // Ignored while v1 is the only trust-bundle schema: there is no older
    // version for the strict verifier to reject. Guards the rejection
    // contract for any future revision that reintroduces multiple versions.
    let mut document = trust_bundle_document_from_fixture();
    document.schema = VERIFIER_TRUST_BUNDLE_SCHEMA.to_string();

    let error = ChioVerifierTrustBundle::from_document(document).unwrap_err();
    assert!(error.to_string().contains("historical"));
}

#[test]
fn forged_lease_signer_fails_even_when_embedded_signature_is_valid() {
    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let forged_key = Keypair::from_seed(&[88; 32]);
    package.capability_leases[0] =
        SignedExportEnvelope::sign(package.capability_leases[0].body.clone(), &forged_key)
            .expect("lease re-signs");

    let context = verification_context_from_fixture();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("lease authority"));
}

#[test]
fn forged_governance_signer_fails_even_when_embedded_signature_is_valid() {
    let mut package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let forged_key = Keypair::from_seed(&[89; 32]);
    package.governance_receipts[0] =
        SignedExportEnvelope::sign(package.governance_receipts[0].body.clone(), &forged_key)
            .expect("governance receipt re-signs");

    let context = verification_context_from_fixture();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("governance authority"));
}

#[test]
fn package_bbs_issuer_must_be_externally_trusted() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let mut document = trust_bundle_document_from_fixture();
    document.trusted_bbs_issuers[0].issuer_fingerprint = "f".repeat(64);
    document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(48);
    let trust_bundle =
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");

    let context = verification_context_from_fixture();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("issuer"));
    assert!(error.to_string().contains("trusted"));
}

#[test]
fn package_bbs_issuer_key_must_match_trusted_registry() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let mut document = trust_bundle_document_from_fixture();
    document.trusted_bbs_issuers[0].issuer_fingerprint = package
        .selective_disclosure_proof
        .issuer_fingerprint
        .clone();
    document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(96);
    let trust_bundle =
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");

    let context = verification_context_from_fixture();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("issuer public key"));
}

#[test]
fn wrong_verifier_context_nonce_fails_and_report_keeps_prior_checks() {
    let package = proof_package_from_json(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    ))
    .expect("package fixture parses");
    let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
    let mut context = verification_context_from_fixture();
    context.challenge = "challenge-mismatch".to_string();

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("proof nonce"));

    let report = verify_package_report(&package, &trust_bundle, &context);
    assert!(!report.accepted);
    assert_eq!(
        report.failure.as_ref().expect("failure").code,
        "bbs.context_nonce"
    );
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "trust.bbs_issuer"));
}
