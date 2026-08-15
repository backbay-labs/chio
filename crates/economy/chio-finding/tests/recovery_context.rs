use chio_finding::{
    derive_finding_recovery_id, parse_finding_recovery_context, FindingRecoveryContext,
    FINDING_RECOVERY_CONTEXT_SCHEMA_V1,
};

fn context() -> FindingRecoveryContext {
    FindingRecoveryContext {
        schema: FINDING_RECOVERY_CONTEXT_SCHEMA_V1.to_string(),
        recovery_id: derive_finding_recovery_id(
            "capability-original",
            &"a".repeat(64),
            "receipt-original",
        ),
        original_capability_json: r#"{"id":"capability-original"}"#.to_string(),
        purchase_context_json: r#"{"schema":"chio.finding.purchase-context.v1"}"#.to_string(),
        purchase_record_envelope_json: r#"{"body":{"purchase_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#.to_string(),
        original_delivery_receipt_json: r#"{"id":"receipt-original"}"#.to_string(),
    }
}

#[test]
fn canonical_recovery_context_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let bytes = chio_finding::canonical_json_bytes(&context)?;
    assert_eq!(parse_finding_recovery_context(&bytes)?, context);
    Ok(())
}

#[test]
fn recovery_identity_is_deterministic_and_cross_bound() {
    let original = derive_finding_recovery_id("cap-a", &"a".repeat(64), "receipt-a");
    assert_eq!(
        original,
        derive_finding_recovery_id("cap-a", &"a".repeat(64), "receipt-a")
    );
    assert_ne!(
        original,
        derive_finding_recovery_id("cap-b", &"a".repeat(64), "receipt-a")
    );
    assert_ne!(
        original,
        derive_finding_recovery_id("cap-a", &"b".repeat(64), "receipt-a")
    );
    assert_ne!(
        original,
        derive_finding_recovery_id("cap-a", &"a".repeat(64), "receipt-b")
    );
}

#[test]
fn recovery_context_rejects_noncanonical_or_substituted_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let pretty = serde_json::to_vec_pretty(&context)?;
    assert!(parse_finding_recovery_context(&pretty).is_err());

    let mut value = serde_json::to_value(context)?;
    value["unexpected"] = serde_json::json!(true);
    let bytes = chio_finding::canonical_json_bytes(&value)?;
    assert!(parse_finding_recovery_context(&bytes).is_err());
    Ok(())
}
