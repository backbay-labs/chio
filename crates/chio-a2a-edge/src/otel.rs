//! A2A-specific GenAI OTel span helpers.

pub use chio_kernel::otel::{
    build_gen_ai_tool_call_span, GenAiToolCallSpan, GenAiToolCallSpanInput, OtelAttribute,
    ATTR_CHIO_AGENT_ID, ATTR_CHIO_KERNEL_ID, ATTR_CHIO_RECEIPT_ID, ATTR_CHIO_SERVER_ID,
    ATTR_GEN_AI_OPERATION_NAME, ATTR_GEN_AI_REQUEST_MODEL, ATTR_GEN_AI_RESPONSE_FINISH_REASONS,
    ATTR_GEN_AI_SYSTEM, ATTR_GEN_AI_TOOL_CALL_ID, ATTR_GEN_AI_TOOL_NAME,
    ATTR_GEN_AI_USAGE_INPUT_TOKENS, ATTR_GEN_AI_USAGE_OUTPUT_TOKENS,
    GEN_AI_TOOL_CALL_LOCKED_ATTRIBUTES, GEN_AI_TOOL_CALL_OPERATION_NAME,
    GEN_AI_TOOL_CALL_SPAN_NAME, OTEL_SEMCONV_SCHEMA_URL,
};

pub const A2A_GEN_AI_SYSTEM: &str = "a2a";

pub fn a2a_tool_call_span(
    tool_call_id: &str,
    tool_name: &str,
    request_model: Option<&str>,
) -> GenAiToolCallSpan {
    build_gen_ai_tool_call_span(GenAiToolCallSpanInput {
        system: A2A_GEN_AI_SYSTEM,
        request_model,
        tool_call_id,
        tool_name,
        finish_reasons: &[],
        usage_input_tokens: None,
        usage_output_tokens: None,
        chio_receipt_id: None,
        chio_kernel_id: None,
        chio_server_id: None,
        chio_agent_id: None,
    })
}
