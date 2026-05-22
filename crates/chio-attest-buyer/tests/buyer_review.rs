use chio_attest_buyer::{
    buyer_attestation_packet_from_json, verify_buyer_attestation_review_package,
    verify_buyer_attestation_review_package_with_proof_replay_json, BuyerAttestationError,
    BuyerAttestationReviewPackage,
};

#[test]
fn buyer_public_data_types_are_chio_owned() {
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BuyerAttestationPacket>(),
        "chio_attest_buyer::BuyerAttestationPacket"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BuyerAttestationReviewPackage>(),
        "chio_attest_buyer::BuyerAttestationReviewPackage"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::ReceiptLineageStatement>(),
        "chio_attest_buyer::ReceiptLineageStatement"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BilateralInvocation>(),
        "chio_attest_buyer::BilateralInvocation"
    );
}

#[test]
fn buyer_boundary_does_not_reexport_historical_runtime_types() {
    let lib = include_str!("../src/lib.rs");
    assert!(!lib.contains("pub use chio_runtime_core::{"));
}

#[test]
fn buyer_public_review_messages_use_chio_boundary_wording() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        !lib.contains("existing Chio verifier"),
        "public buyer review messages should describe historical replay without Chio branding"
    );
}

#[test]
fn buyer_error_boundary_is_chio_owned() {
    let error_type = std::any::type_name::<BuyerAttestationError>();
    assert_eq!(error_type, "chio_attest_buyer::BuyerAttestationError");

    let error = match buyer_attestation_packet_from_json("{") {
        Ok(_) => panic!("invalid packet JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "runtime_admission_json");
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
        "Chio review reports must not expose historical Chio check codes: {:#?}",
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
