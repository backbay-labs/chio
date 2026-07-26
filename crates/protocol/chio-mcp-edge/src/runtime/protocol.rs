use super::framing::read_jsonrpc_frame;
use super::*;

#[path = "protocol/capabilities.rs"]
mod capabilities;
#[path = "protocol/envelope.rs"]
mod envelope;
#[path = "protocol/messaging.rs"]
mod messaging;
#[path = "protocol/metadata.rs"]
mod metadata;
#[path = "protocol/parsing.rs"]
mod parsing;
#[path = "protocol/response.rs"]
mod response;
#[path = "protocol/serialization.rs"]
mod serialization;
#[path = "protocol/tasks.rs"]
mod tasks;
#[path = "protocol/tool_results.rs"]
mod tool_results;

pub(super) use self::capabilities::{
    select_capability_for_prompt, select_capability_for_request, select_capability_for_resource,
    select_capability_for_resource_pattern, select_capability_for_resource_subscription,
    tool_is_authorized,
};
pub(super) use self::envelope::{
    ensure_known_request_params_object, known_notification_params_are_object,
    parse_jsonrpc_envelope, JsonRpcEnvelope,
};
pub(super) use self::messaging::{
    cancellation_matches_client_request, cancellation_matches_request, cancellation_reason,
    explicit_task_cancel_reason, next_client_message, pump_channel_messages, pump_client_messages,
    task_cancel_matches_related_task,
};
pub(super) use self::metadata::{
    attach_execution_nonce_meta_to_result, attach_related_task_meta_to_message,
    capture_accepted_url_elicitation, make_elicitation_completion_notification,
    task_outcome_to_jsonrpc, tool_call_outcome_to_jsonrpc,
};
pub(super) use self::parsing::{
    build_operation_context, build_operation_context_for_retry, parse_completion_argument,
    parse_completion_reference, parse_cursor, parse_peer_capabilities,
    parse_request_approval_artifacts, parse_request_execution_nonce, parse_request_extra_metadata,
    parse_request_governed_intent, parse_request_model_metadata, parse_request_stable_request_id,
    parse_request_supplemental_authorization, parse_task_id,
};
pub(super) use self::response::{
    adapter_jsonrpc_error, jsonrpc_error, jsonrpc_error_with_data, jsonrpc_result,
    queue_progress_notification, read_jsonrpc_line, write_jsonrpc_line,
};
pub(super) use self::serialization::{
    paginate_named_response, paginate_response, serialize_prompts, serialize_resource_contents,
    serialize_resource_templates, serialize_resources,
};
pub(super) use self::tasks::{
    cancellation_reason_from_tool_result, edge_task_status_label, iso8601_now,
    parse_requested_task, task_status_message, tool_result_is_error, unix_now_millis,
    RequestedTask,
};
pub(super) use self::tool_results::{
    kernel_response_to_tool_result, tool_error_result, KernelResponseToToolResultArgs,
};

#[cfg(test)]
pub(super) use self::messaging::is_cancellation_side_channel_signal;

#[cfg(test)]
#[path = "protocol/tests.rs"]
mod tests;
