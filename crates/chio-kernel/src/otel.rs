//! OpenTelemetry semantic-convention helpers for Chio tool calls.

#[cfg(feature = "otel")]
use opentelemetry_semantic_conventions::attribute as semconv;

/// Schema URL carried by `opentelemetry-semantic-conventions` 0.29.0.
#[cfg(feature = "otel")]
pub const OTEL_SEMCONV_SCHEMA_URL: &str = opentelemetry_semantic_conventions::SCHEMA_URL;

/// Fallback schema URL used when the optional semconv crate is disabled.
#[cfg(not(feature = "otel"))]
pub const OTEL_SEMCONV_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.31.0";

/// Locked span name for GenAI tool calls.
pub const GEN_AI_TOOL_CALL_SPAN_NAME: &str = "gen_ai.tool.call";

/// Locked operation value for Chio mediated tool calls.
pub const GEN_AI_TOOL_CALL_OPERATION_NAME: &str = "tool.call";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_SYSTEM: &str = semconv::GEN_AI_SYSTEM;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_SYSTEM: &str = "gen_ai.system";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_OPERATION_NAME: &str = semconv::GEN_AI_OPERATION_NAME;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_OPERATION_NAME: &str = "gen_ai.operation.name";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_REQUEST_MODEL: &str = semconv::GEN_AI_REQUEST_MODEL;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_TOOL_CALL_ID: &str = semconv::GEN_AI_TOOL_CALL_ID;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_TOOL_CALL_ID: &str = "gen_ai.tool.call.id";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_TOOL_NAME: &str = semconv::GEN_AI_TOOL_NAME;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_TOOL_NAME: &str = "gen_ai.tool.name";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_RESPONSE_FINISH_REASONS: &str = semconv::GEN_AI_RESPONSE_FINISH_REASONS;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_RESPONSE_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_USAGE_INPUT_TOKENS: &str = semconv::GEN_AI_USAGE_INPUT_TOKENS;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";

#[cfg(feature = "otel")]
pub const ATTR_GEN_AI_USAGE_OUTPUT_TOKENS: &str = semconv::GEN_AI_USAGE_OUTPUT_TOKENS;
#[cfg(not(feature = "otel"))]
pub const ATTR_GEN_AI_USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";

pub const ATTR_CHIO_RECEIPT_ID: &str = "chio.receipt.id";
pub const ATTR_CHIO_KERNEL_ID: &str = "chio.kernel.id";
pub const ATTR_CHIO_SERVER_ID: &str = "chio.server.id";
pub const ATTR_CHIO_AGENT_ID: &str = "chio.agent.id";

/// Attribute names allowed on `gen_ai.tool.call` spans.
pub const GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES: [&str; 12] = [
    ATTR_GEN_AI_SYSTEM,
    ATTR_GEN_AI_OPERATION_NAME,
    ATTR_GEN_AI_REQUEST_MODEL,
    ATTR_GEN_AI_TOOL_CALL_ID,
    ATTR_GEN_AI_TOOL_NAME,
    ATTR_GEN_AI_RESPONSE_FINISH_REASONS,
    ATTR_GEN_AI_USAGE_INPUT_TOKENS,
    ATTR_GEN_AI_USAGE_OUTPUT_TOKENS,
    ATTR_CHIO_RECEIPT_ID,
    ATTR_CHIO_KERNEL_ID,
    ATTR_CHIO_SERVER_ID,
    ATTR_CHIO_AGENT_ID,
];

pub const ATTRIBUTE_VALUE_MAX_CHARS: usize = 128;
pub const FINISH_REASONS_MAX_CHARS: usize = 192;

/// Cardinality class for span attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeCardinality {
    /// Low-cardinality attribute with a small stable vocabulary.
    Low,
    /// Bounded attribute whose value is dynamic but length capped.
    Bounded,
    /// Identifier attribute. Length is capped and values must not be used
    /// for aggregation dimensions without sampling.
    High,
}

/// One OTel-compatible span attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelAttribute {
    pub key: &'static str,
    pub value: serde_json::Value,
}

/// OTel-compatible GenAI tool-call span representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenAiToolCallSpan {
    pub name: &'static str,
    pub schema_url: &'static str,
    pub attributes: Vec<OtelAttribute>,
}

/// Inputs for building a locked `gen_ai.tool.call` span.
#[derive(Debug, Clone, Copy)]
pub struct GenAiToolCallSpanInput<'a> {
    pub system: &'a str,
    pub request_model: Option<&'a str>,
    pub tool_call_id: &'a str,
    pub tool_name: &'a str,
    pub finish_reasons: &'a [&'a str],
    pub usage_input_tokens: Option<u64>,
    pub usage_output_tokens: Option<u64>,
    pub chio_receipt_id: Option<&'a str>,
    pub chio_kernel_id: Option<&'a str>,
    pub chio_server_id: Option<&'a str>,
    pub chio_agent_id: Option<&'a str>,
}

impl GenAiToolCallSpan {
    pub fn attribute_keys(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.attributes.iter().map(|attribute| attribute.key)
    }
}

/// Build a span with the locked attribute set.
pub fn build_gen_ai_tool_call_span(input: GenAiToolCallSpanInput<'_>) -> GenAiToolCallSpan {
    let mut attributes = Vec::with_capacity(GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES.len());
    push_attr(&mut attributes, ATTR_GEN_AI_SYSTEM, input.system);
    push_attr(
        &mut attributes,
        ATTR_GEN_AI_OPERATION_NAME,
        GEN_AI_TOOL_CALL_OPERATION_NAME,
    );
    if let Some(request_model) = input.request_model {
        push_attr(&mut attributes, ATTR_GEN_AI_REQUEST_MODEL, request_model);
    }
    push_attr(
        &mut attributes,
        ATTR_GEN_AI_TOOL_CALL_ID,
        input.tool_call_id,
    );
    push_attr(&mut attributes, ATTR_GEN_AI_TOOL_NAME, input.tool_name);
    if !input.finish_reasons.is_empty() {
        push_string_array_attr(
            &mut attributes,
            ATTR_GEN_AI_RESPONSE_FINISH_REASONS,
            input.finish_reasons,
        );
    }
    if let Some(tokens) = input.usage_input_tokens {
        push_u64_attr(&mut attributes, ATTR_GEN_AI_USAGE_INPUT_TOKENS, tokens);
    }
    if let Some(tokens) = input.usage_output_tokens {
        push_u64_attr(&mut attributes, ATTR_GEN_AI_USAGE_OUTPUT_TOKENS, tokens);
    }
    if let Some(receipt_id) = input.chio_receipt_id {
        push_attr(&mut attributes, ATTR_CHIO_RECEIPT_ID, receipt_id);
    }
    if let Some(kernel_id) = input.chio_kernel_id {
        push_attr(&mut attributes, ATTR_CHIO_KERNEL_ID, kernel_id);
    }
    if let Some(server_id) = input.chio_server_id {
        push_attr(&mut attributes, ATTR_CHIO_SERVER_ID, server_id);
    }
    if let Some(agent_id) = input.chio_agent_id {
        push_attr(&mut attributes, ATTR_CHIO_AGENT_ID, agent_id);
    }

    GenAiToolCallSpan {
        name: GEN_AI_TOOL_CALL_SPAN_NAME,
        schema_url: OTEL_SEMCONV_SCHEMA_URL,
        attributes,
    }
}

pub fn attribute_cardinality(key: &str) -> Option<AttributeCardinality> {
    match key {
        ATTR_GEN_AI_SYSTEM | ATTR_GEN_AI_OPERATION_NAME | ATTR_GEN_AI_RESPONSE_FINISH_REASONS => {
            Some(AttributeCardinality::Low)
        }
        ATTR_GEN_AI_REQUEST_MODEL
        | ATTR_GEN_AI_TOOL_NAME
        | ATTR_GEN_AI_USAGE_INPUT_TOKENS
        | ATTR_GEN_AI_USAGE_OUTPUT_TOKENS
        | ATTR_CHIO_KERNEL_ID
        | ATTR_CHIO_SERVER_ID
        | ATTR_CHIO_AGENT_ID => Some(AttributeCardinality::Bounded),
        ATTR_GEN_AI_TOOL_CALL_ID | ATTR_CHIO_RECEIPT_ID => Some(AttributeCardinality::High),
        _ => None,
    }
}

pub fn is_locked_attribute(key: &str) -> bool {
    GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES.contains(&key)
}

fn push_attr(attributes: &mut Vec<OtelAttribute>, key: &'static str, value: &str) {
    push_attr_with_limit(attributes, key, value, ATTRIBUTE_VALUE_MAX_CHARS);
}

fn push_attr_with_limit(
    attributes: &mut Vec<OtelAttribute>,
    key: &'static str,
    value: &str,
    max_chars: usize,
) {
    attributes.push(OtelAttribute {
        key,
        value: serde_json::Value::String(truncate_chars(value, max_chars)),
    });
}

fn push_string_array_attr(attributes: &mut Vec<OtelAttribute>, key: &'static str, values: &[&str]) {
    attributes.push(OtelAttribute {
        key,
        value: serde_json::Value::Array(
            values
                .iter()
                .map(|value| {
                    serde_json::Value::String(truncate_chars(value, FINISH_REASONS_MAX_CHARS))
                })
                .collect(),
        ),
    });
}

fn push_u64_attr(attributes: &mut Vec<OtelAttribute>, key: &'static str, value: u64) {
    attributes.push(OtelAttribute {
        key,
        value: serde_json::Value::Number(serde_json::Number::from(value)),
    });
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
