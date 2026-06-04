use std::error::Error;

use chio_kernel::otel::{
    ATTR_CHIO_RECEIPT_ID, ATTR_GEN_AI_SYSTEM, ATTR_GEN_AI_TOOL_CALL_ID, ATTR_GEN_AI_TOOL_NAME,
};

mod support;

use support::{
    build_lookup_indexes, export_demo_span, CAPABILITY_ID, POLICY_HASH, SOURCE_RECEIPT_ID, SPAN_ID,
    TENANT_ID, TOOL_NAME, TOOL_SERVER, TRACE_ID,
};

#[test]
fn receipt_id_and_span_id_lookup_is_bidirectional() -> Result<(), Box<dyn Error>> {
    let export = export_demo_span()?;
    assert_eq!(export.summary.accepted_spans, 1);
    assert_eq!(export.summary.appended_receipts, 1);

    let receipt = export
        .receipts
        .first()
        .ok_or_else(|| std::io::Error::other("missing exported receipt"))?;
    assert_eq!(receipt.id.len(), 64);
    assert!(receipt
        .id
        .chars()
        .all(|value| matches!(value, '0'..='9' | 'a'..='f')));
    assert_ne!(receipt.id, SOURCE_RECEIPT_ID);
    assert_eq!(receipt.capability_id, CAPABILITY_ID);
    assert_eq!(receipt.tool_server, TOOL_SERVER);
    assert_eq!(receipt.tool_name, TOOL_NAME);
    assert_eq!(receipt.tenant_id.as_deref(), Some(TENANT_ID));
    assert!(receipt.verify_signature()?);

    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing receipt metadata"))?;
    assert_eq!(metadata["provenance"]["otel"]["trace_id"], TRACE_ID);
    assert_eq!(metadata["provenance"]["otel"]["span_id"], SPAN_ID);
    assert_eq!(
        metadata["correlation"]["source_chio_receipt_id"],
        SOURCE_RECEIPT_ID
    );
    assert_eq!(metadata["otel"]["attributes"][ATTR_GEN_AI_SYSTEM], "openai");
    assert_eq!(
        metadata["otel"]["attributes"][ATTR_GEN_AI_TOOL_NAME],
        TOOL_NAME
    );
    assert_eq!(
        metadata["otel"]["attributes"]["redaction_pass_id"],
        "redactors@1.5.0+default"
    );
    assert_eq!(metadata["otel"]["source_verdict"], "allow");
    assert_eq!(
        metadata["otel"]["attributes"]["chio.policy.ref"],
        POLICY_HASH
    );
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_GEN_AI_TOOL_CALL_ID)
        .is_none());
    assert!(metadata["otel"]["attributes"]
        .get(ATTR_CHIO_RECEIPT_ID)
        .is_none());

    let indexes = build_lookup_indexes(receipt)?;
    assert_eq!(
        indexes
            .receipt_to_span
            .get(receipt.id.as_str())
            .map(String::as_str),
        Some(SPAN_ID)
    );
    assert_eq!(
        indexes.span_to_receipt.get(SPAN_ID).map(String::as_str),
        Some(receipt.id.as_str())
    );

    Ok(())
}
