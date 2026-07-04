use chio_attest_buyer::{
    buyer_attestation_packet_from_json, buyer_attestation_review_package_from_json,
    verify_buyer_attestation_review_package,
    verify_buyer_attestation_review_package_with_proof_replay_json, BuyerAttestationError,
    BuyerAttestationReviewPackage,
};

#[test]
fn buyer_public_data_types_are_chio_owned() {
    for type_name in [
        std::any::type_name::<chio_attest_buyer::BuyerAttestationPacket>(),
        std::any::type_name::<chio_attest_buyer::BuyerAttestationReviewPackage>(),
        std::any::type_name::<chio_attest_buyer::ReceiptLineageStatement>(),
        std::any::type_name::<chio_attest_buyer::BilateralInvocation>(),
    ] {
        assert!(
            type_name.starts_with("chio_attest_buyer::types::"),
            "buyer public type should be defined in the Chio-owned types module: {type_name}"
        );
        assert!(
            !type_name.contains("chio_runtime_core"),
            "buyer public type must not resolve to a runtime-core type: {type_name}"
        );
    }
}

#[test]
fn buyer_boundary_does_not_reexport_runtime_core_types() {
    let lib = include_str!("../src/lib.rs");
    assert!(!lib.contains("pub use chio_runtime_core::{"));
}

#[test]
fn buyer_error_boundary_is_chio_owned() {
    let error_type = std::any::type_name::<BuyerAttestationError>();
    assert_eq!(
        error_type,
        "chio_attest_buyer::error::BuyerAttestationError"
    );

    let error = match buyer_attestation_packet_from_json("{") {
        Ok(_) => panic!("invalid packet JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "runtime_admission_json");
}

#[test]
fn json_constructors_reject_malformed_typed_values() -> Result<(), Box<dyn std::error::Error>> {
    let packet_json = serde_json::json!({
        "schema": "chio.attest.buyer-attestation-packet.v0",
        "packetId": "buyer-packet:constructor-boundary",
        "buyerId": "did:chio:buyer",
        "capabilityId": "capability:buyer:constructor-boundary",
        "treatyScopeSha256": "11".repeat(32),
        "ladderIntersectionSha256": "22".repeat(32),
        "crossBoundaryAdmissionReportSha256": "33".repeat(32),
        "continuationSha256": "44".repeat(32),
        "receiptLineageStatementSha256": "55".repeat(32),
        "bilateralInvocationSha256": "66".repeat(32),
        "bilateralDsseSha256": "77".repeat(32),
        "workflowReceiptSha256": "88".repeat(32),
        "proofPackageSha256": "99".repeat(32),
        "verifierReportSha256": "aa".repeat(32),
        "budgetRefs": [],
        "settlementClaimed": false
    })
    .to_string();
    let Err(error) = buyer_attestation_packet_from_json(&packet_json) else {
        return Err("unsupported packet schema parsed successfully".into());
    };
    assert_eq!(error.code(), "unsupported_buyer_attestation_packet_schema");

    let package_json = serde_json::json!({
        "schema": "chio.attest.buyer-attestation-review-package.v1",
        "packageId": "buyer-review:constructor-boundary",
        "packetId": "buyer-packet:constructor-boundary",
        "buyerId": "did:chio:buyer",
        "generatedAtUnixMs": 1_766_000_000_000_u64,
        "artifacts": [{
            "role": "proof_package",
            "relativePath": "../proof-package.json",
            "artifactSha256": "bb".repeat(32),
            "byteCount": 1
        }]
    })
    .to_string();
    let Err(error) = buyer_attestation_review_package_from_json(&package_json) else {
        return Err("unsafe review artifact path parsed successfully".into());
    };
    assert_eq!(
        error.code(),
        "chio_attest_buyer_review_artifact_unsafe_path"
    );
    Ok(())
}

#[test]
fn chio_buyer_review_package_schema_emits_chio_review_report_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let package = BuyerAttestationReviewPackage {
        schema: "chio.attest.buyer-attestation-review-package.v1".to_string(),
        package_id: "buyer-review:packet:chio-schema".to_string(),
        packet_id: "packet:chio-schema".to_string(),
        buyer_id: "did:chio:buyer".to_string(),
        generated_at_unix_ms: 1_766_000_000_000,
        artifacts: Vec::new(),
    };

    let report = verify_buyer_attestation_review_package(&package, &[])?;

    assert!(!report.accepted);
    assert_eq!(
        report.schema,
        "chio.attest.buyer-attestation-review-report.v1"
    );
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_attest_buyer_review_missing_artifact_role")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| !check.code.contains("chio_buyer_review")),
        "Chio review reports must not expose runtime_core Chio check codes: {:#?}",
        report.checks
    );
    Ok(())
}

#[test]
fn chio_buyer_review_legacy_replay_api_stays_inside_attest_buyer(
) -> Result<(), Box<dyn std::error::Error>> {
    let package = BuyerAttestationReviewPackage {
        schema: "chio.attest.buyer-attestation-review-package.v1".to_string(),
        package_id: "buyer-review:packet:proof-replay-api".to_string(),
        packet_id: "packet:proof-replay-api".to_string(),
        buyer_id: "did:chio:buyer".to_string(),
        generated_at_unix_ms: 1_766_000_000_000,
        artifacts: Vec::new(),
    };

    let report =
        verify_buyer_attestation_review_package_with_proof_replay_json(&package, &[], "{}", "{}")?;

    assert!(!report.accepted);
    assert_eq!(
        report.schema,
        "chio.attest.buyer-attestation-review-report.v1"
    );
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_attest_buyer_review_missing_artifact_role")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| !check.code.contains("chio_buyer_review")),
        "Chio proof replay wrapper must keep backend internals out of public check codes: {:#?}",
        report.checks
    );
    Ok(())
}
