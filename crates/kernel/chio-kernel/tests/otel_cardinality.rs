#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use chio_kernel::otel::{
    attribute_cardinality, build_gen_ai_tool_call_span, is_locked_attribute, AttributeCardinality,
    GenAiToolCallSpanInput, ATTRIBUTE_VALUE_MAX_CHARS, ATTR_CHIO_RECEIPT_ID,
    ATTR_GEN_AI_RESPONSE_FINISH_REASONS, ATTR_GEN_AI_SYSTEM, ATTR_GEN_AI_TOOL_CALL_ID,
    ATTR_GEN_AI_USAGE_INPUT_TOKENS, ATTR_GEN_AI_USAGE_OUTPUT_TOKENS, FINISH_REASONS_MAX_CHARS,
    GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES, GEN_AI_TOOL_CALL_OPERATION_NAME,
    GEN_AI_TOOL_CALL_SPAN_NAME, OTEL_SEMCONV_SCHEMA_URL,
};
use proptest::prelude::*;

#[test]
fn locked_span_shape_matches_m10_contract() {
    assert_eq!(
        OTEL_SEMCONV_SCHEMA_URL,
        "https://opentelemetry.io/schemas/1.31.0"
    );
    assert_eq!(GEN_AI_TOOL_CALL_SPAN_NAME, "gen_ai.tool.call");
    assert_eq!(GEN_AI_TOOL_CALL_OPERATION_NAME, "tool.call");

    let keys: BTreeSet<&str> = GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES.into_iter().collect();
    assert_eq!(keys.len(), GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES.len());
    for key in GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES {
        assert!(is_locked_attribute(key), "locked key rejected: {key}");
        assert!(
            attribute_cardinality(key).is_some(),
            "missing cardinality class for {key}"
        );
    }
}

#[test]
fn builder_emits_only_locked_attributes() {
    let span = build_gen_ai_tool_call_span(GenAiToolCallSpanInput {
        system: "openai",
        request_model: Some("gpt-5.4"),
        tool_call_id: "call-1",
        tool_name: "file_search",
        finish_reasons: &["tool_calls"],
        usage_input_tokens: Some(11),
        usage_output_tokens: Some(7),
        chio_receipt_id: Some("rcpt-1"),
        chio_kernel_id: Some("kernel-1"),
        chio_server_id: Some("server-1"),
        chio_agent_id: Some("agent-1"),
    });

    assert_eq!(span.name, GEN_AI_TOOL_CALL_SPAN_NAME);
    assert_eq!(span.schema_url, OTEL_SEMCONV_SCHEMA_URL);
    for key in span.attribute_keys() {
        assert!(is_locked_attribute(key), "unexpected attribute {key}");
    }
}

proptest! {
    #[test]
    fn dynamic_attribute_values_are_bounded(raw in "[A-Za-z0-9_./:-]{0,512}") {
        let finish_reason = raw.as_str();
        let span = build_gen_ai_tool_call_span(GenAiToolCallSpanInput {
            system: &raw,
            request_model: Some(&raw),
            tool_call_id: &raw,
            tool_name: &raw,
            finish_reasons: &[finish_reason],
            usage_input_tokens: Some(usize::MAX as u64),
            usage_output_tokens: Some(usize::MAX as u64),
            chio_receipt_id: Some(&raw),
            chio_kernel_id: Some(&raw),
            chio_server_id: Some(&raw),
            chio_agent_id: Some(&raw),
        });

        for attribute in span.attributes {
            prop_assert!(is_locked_attribute(attribute.key));
            match &attribute.value {
                serde_json::Value::String(value) => {
                    prop_assert!(
                        value.chars().count() <= ATTRIBUTE_VALUE_MAX_CHARS,
                        "{} exceeded limit {} with {} chars",
                        attribute.key,
                        ATTRIBUTE_VALUE_MAX_CHARS,
                        value.chars().count()
                    );
                }
                serde_json::Value::Array(values) => {
                    prop_assert_eq!(attribute.key, ATTR_GEN_AI_RESPONSE_FINISH_REASONS);
                    for value in values {
                        let value = value.as_str().unwrap_or_default();
                        prop_assert!(
                            value.chars().count() <= FINISH_REASONS_MAX_CHARS,
                            "{} exceeded limit {} with {} chars",
                            attribute.key,
                            FINISH_REASONS_MAX_CHARS,
                            value.chars().count()
                        );
                    }
                }
                serde_json::Value::Number(_) => {
                    prop_assert!(
                        attribute.key == ATTR_GEN_AI_USAGE_INPUT_TOKENS
                            || attribute.key == ATTR_GEN_AI_USAGE_OUTPUT_TOKENS
                    );
                }
                other => prop_assert!(false, "unexpected value type for {}: {other:?}", attribute.key),
            }
        }
    }
}

#[test]
fn high_cardinality_keys_are_restricted_to_ids() {
    let high: BTreeSet<&str> = GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES
        .into_iter()
        .filter(|key| attribute_cardinality(key) == Some(AttributeCardinality::High))
        .collect();
    assert_eq!(
        high,
        BTreeSet::from([ATTR_GEN_AI_TOOL_CALL_ID, ATTR_CHIO_RECEIPT_ID])
    );
    assert_eq!(
        attribute_cardinality(ATTR_GEN_AI_SYSTEM),
        Some(AttributeCardinality::Low)
    );
    assert_eq!(
        attribute_cardinality(ATTR_GEN_AI_USAGE_INPUT_TOKENS),
        Some(AttributeCardinality::Bounded)
    );
    assert_eq!(
        attribute_cardinality(ATTR_GEN_AI_USAGE_OUTPUT_TOKENS),
        Some(AttributeCardinality::Bounded)
    );
}
