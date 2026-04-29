# OpenAI Responses Fixture Events

Snapshot date: `2026-04-25`

These fixtures are deterministic conformance captures for the OpenAI Responses API shape supported by `crates/chio-openai` as of the pinned snapshot. They are authored from the in-repo adapter and milestone corpus shapes. They do not claim live network capture.

## Files

| Fixture | Family | Notes |
|---|---|---|
| `openai_basic_single_tool_call.ndjson` | `tool_use_basic` | Single batch `function_call` lifted into one Chio invocation. |
| `openai_basic_parallel_tool_calls.ndjson` | `tool_use_basic` | Two batch `function_call` items with two allow verdicts. |
| `openai_basic_structured_output_json_schema.ndjson` | `tool_use_basic` | Structured-output request mode plus one tool call. |
| `openai_stream_single_tool_call.ndjson` | `tool_use_with_streaming` | SSE tool call gated before `response.completed`. |
| `openai_stream_parallel_tool_calls.ndjson` | `tool_use_with_streaming` | Two streamed tool calls in one response stream. |
| `openai_stream_arguments_delta_split.ndjson` | `tool_use_with_streaming` | Arguments split across multiple delta events. |
| `openai_thinking_then_tool_call.ndjson` | `tool_use_with_thinking` | Reasoning item followed by a batch tool call. |
| `openai_thinking_interleaved_with_tool_call.ndjson` | `tool_use_with_thinking` | Reasoning and message output around a tool call. |
| `openai_thinking_streaming_with_tool_call.ndjson` | `tool_use_with_thinking` | Streaming reasoning delta before tool-call gating. |
| `openai_error_rate_limited_retry.ndjson` | `tool_use_error_recovery` | Provider rate-limit event followed by deterministic retry. |
| `openai_error_content_policy_denial.ndjson` | `tool_use_error_recovery` | Provider content-policy denial without a lifted tool call. |
| `openai_error_kernel_deny_synthetic_tool_output.ndjson` | `tool_use_error_recovery` | Kernel deny lowered into synthetic `function_call_output`. |

## Captured Event Names

The fixture corpus pins these OpenAI Responses event names for the `2026-04-25` snapshot:

- `response.created`
- `response.output_item.added`
- `response.function_call_arguments.delta`
- `response.function_call_arguments.done`
- `response.output_item.done`
- `response.completed`
- `response.error`
- `response.reasoning_text.delta`
- `response.reasoning_text.done`
- `response.output_text.delta`
- `response.output_text.done`

The batch fixtures use the same output item payloads under `upstream_response` rather than SSE frames. The streaming fixtures keep each SSE event as an `upstream_event` record so replay can evaluate when the adapter buffers or releases tool-call bytes.
