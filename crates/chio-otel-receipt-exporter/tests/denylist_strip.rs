use chio_kernel::otel::{ATTR_CHIO_RECEIPT_ID, ATTR_GEN_AI_TOOL_CALL_ID};
use chio_otel_receipt_exporter::{
    is_denied_attribute, strip_denied_attributes, strip_denied_batch_attributes, OtlpAttribute,
    OtlpGrpcTraceExport, OtlpSpan,
};

#[test]
fn strip_removes_high_cardinality_prometheus_attributes() {
    let attributes = vec![
        OtlpAttribute {
            key: ATTR_GEN_AI_TOOL_CALL_ID.to_string(),
            value: serde_json::json!("call-1"),
        },
        OtlpAttribute {
            key: ATTR_CHIO_RECEIPT_ID.to_string(),
            value: serde_json::json!("rcpt-1"),
        },
        OtlpAttribute {
            key: "chio.replay.run_id".to_string(),
            value: serde_json::json!("run-1"),
        },
        OtlpAttribute {
            key: "gen_ai.system".to_string(),
            value: serde_json::json!("openai"),
        },
    ];

    let stripped = strip_denied_attributes(&attributes);

    assert_eq!(stripped.len(), 1);
    assert_eq!(stripped[0].key, "gen_ai.system");
    assert!(is_denied_attribute(ATTR_GEN_AI_TOOL_CALL_ID));
    assert!(is_denied_attribute(ATTR_CHIO_RECEIPT_ID));
    assert!(is_denied_attribute("chio.replay.run_id"));
}

#[test]
fn strip_applies_to_every_span_in_batch() {
    let span = OtlpSpan::new(
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "gen_ai.tool.call",
    )
    .with_attribute(ATTR_CHIO_RECEIPT_ID, serde_json::json!("rcpt-1"))
    .with_attribute("gen_ai.system", serde_json::json!("openai"));
    let batch = OtlpGrpcTraceExport::from_spans(vec![span]);

    let stripped = strip_denied_batch_attributes(&batch);
    let keys = stripped
        .spans()
        .flat_map(|span| {
            span.attributes
                .iter()
                .map(|attribute| attribute.key.as_str())
        })
        .collect::<Vec<_>>();

    assert_eq!(keys, vec!["gen_ai.system"]);
}
