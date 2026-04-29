use chio_kernel::otel::{ATTR_CHIO_RECEIPT_ID, ATTR_GEN_AI_TOOL_CALL_ID};

use crate::ingress::{OtlpAttribute, OtlpGrpcTraceExport, OtlpResourceSpans, OtlpSpan};

pub const ATTR_CHIO_REPLAY_RUN_ID: &str = "chio.replay.run_id";

pub const PROMETHEUS_DENIED_ATTRIBUTES: [&str; 3] = [
    ATTR_GEN_AI_TOOL_CALL_ID,
    ATTR_CHIO_RECEIPT_ID,
    ATTR_CHIO_REPLAY_RUN_ID,
];

pub fn denied_attribute_keys() -> &'static [&'static str] {
    &PROMETHEUS_DENIED_ATTRIBUTES
}

pub fn is_denied_attribute(key: &str) -> bool {
    PROMETHEUS_DENIED_ATTRIBUTES.contains(&key)
}

pub fn strip_denied_attributes(attributes: &[OtlpAttribute]) -> Vec<OtlpAttribute> {
    attributes
        .iter()
        .filter(|attribute| !is_denied_attribute(&attribute.key))
        .cloned()
        .collect()
}

pub fn strip_denied_span_attributes(span: &OtlpSpan) -> OtlpSpan {
    let mut stripped = span.clone();
    stripped.attributes = strip_denied_attributes(&span.attributes);
    stripped
}

pub fn strip_denied_batch_attributes(batch: &OtlpGrpcTraceExport) -> OtlpGrpcTraceExport {
    OtlpGrpcTraceExport {
        resource_spans: batch
            .resource_spans
            .iter()
            .map(|resource| OtlpResourceSpans {
                resource_attributes: strip_denied_attributes(&resource.resource_attributes),
                spans: resource
                    .spans
                    .iter()
                    .map(strip_denied_span_attributes)
                    .collect(),
            })
            .collect(),
    }
}
