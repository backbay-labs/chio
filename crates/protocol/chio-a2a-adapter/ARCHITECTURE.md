# chio-a2a-adapter Architecture Note

## Module Boundaries

- `lib.rs` is the crate facade. It includes config, protocol, invocation, mapping, discovery, auth, transport, task-registry, and optional fuzz modules into one crate module and exposes the public A2A adapter types.
- `config.rs` owns builder-style adapter configuration: agent-card URL, auth material, TLS material, egress contract, partner policy, and durable task-registry path. It validates configured request-auth material at discovery time before any outbound A2A request can be assembled.
- `protocol.rs` owns the local serde model for A2A Agent Cards, JSON-RPC envelopes, messages, tasks, push-notification configuration, and selected protocol bindings. It preserves Agent Card `defaultInputModes` and per-skill `inputModes` as provider-supplied strings.
- `mapping.rs` is the only place that interprets input-mode strings into the internal `A2aSkillInputSurface` used by both manifest projection and send-path admission. It projects only Chio-projectable Agent Card skills into the signed `ToolManifest`. Required partner skills must correspond to skills the adapter can expose as Chio tools after input-mode projection.
- `invoke.rs` owns the runtime adapter: discovery, auth resolution, request construction, SendMessage, task follow-up operations, streaming calls, and `ToolServerConnection` integration. It resolves runtime `invoke` and `invoke_stream` targets against the signed manifest tool set, so non-projectable raw Agent Card skills cannot be invoked. It does not re-parse Agent Card mode strings.
- `auth.rs` owns HTTP dispatch, redirect validation, OAuth/OpenID token exchange, TLS construction, response-size enforcement, and typed `HttpEgressContract` checks.
- `transport.rs` owns SSE parsing, redirect header stripping helpers, auth URL composition, and response body accounting.
- `task_registry.rs` owns durable A2A task correlation for follow-up operations after restart.
- `fuzz.rs` reaches the SSE parser through the `fuzz` feature, so the parser is the shared byte-to-envelope trust boundary for streaming A2A calls.

## Task Registry Boundary

The task registry is a security boundary, not a cache. Once a task id is recorded, later `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification operations can use it as follow-up authority.

- Task observations are extracted from accepted `task`, `statusUpdate`, and `artifactUpdate` payloads. Malformed observations fail closed and leave the registry unchanged.
- Observed task ids are preserved exactly, including whitespace, after validation has proved them non-empty. Lookups use the exact observed id so distinct provider task authorities are never collapsed by local canonicalization.
- A recorded task binding includes tool, server id, interface URL, binding, tenant, and partner. `A2aTaskRegistry::validate_follow_up` denies follow-up operations whose partner, or any other binding field, differs from the recorded task authority.
- Recording errors are classified at the registry boundary. Only an actual task rebind conflict is non-fatal for the current accepted response: it leaves future follow-up authority denied by the unchanged binding. Validation, parsing, unsupported-version, lock, and storage errors return an adapter error so the current tool call fails closed rather than hiding an untrusted durable-authority state. Both blocking and streaming invoke paths share this classification.
- A validated observation batch continues persisting non-conflicting records after a rebind conflict, then returns the conflict classification for caller warning behavior. Conflicting records are never overwritten or mutated.
- Registry diagnostics and warnings carry no request credentials.

## Input Mode Admission

- `A2aSkillInputSurface::from_modes` strips MIME parameters (for example `application/json; charset=utf-8`) before alias classification. It recognizes only known aliases and MIME essences; arbitrary media types are not widened into JSON or text.
- Admission fails closed when no projectable input mode remains after normalization.
- Generated A2A part media types stay canonical: outbound text is `text/plain`, outbound structured data is `application/json`.

## SSE Stream Parsing

`parse_sse_stream_with_limit` enforces per-line, per-event, total-response, and chunk-count ceilings before any `ToolCallChunk` enters the kernel stream path. It reads each line through `read_sse_line`, a bounded line reader that consumes at most the admitted bytes per line and charges every consumed byte to the total response budget before an oversized-line error can return. Oversized newline-delimited and delimiterless lines are rejected before buffering beyond the line ceiling; the total response-byte ceiling is authoritative and is enforced even when a line is also oversized. The parser preserves SSE semantics for blank-line event delimiters, comment lines, multiline `data:` payloads, terminal-state completion, incomplete streams, UTF-8 validation, and binding-specific JSON-RPC unwrapping. Stream chunks still pass full A2A stream-response validation before registry persistence is considered. All outbound HTTP dispatch remains gated by `HttpEgressContract`; framing limits apply only after the contract admits the response.

## Auth Material

- Request-auth material (header names and values, query parameter names, cookie names and values) is validated at discovery time before the first outbound A2A request. Cookie separators are rejected because cookie values are manually serialized into one `Cookie` header. Arbitrary query values are not rejected; URL encoding owns value escaping.
- Configured bearer tokens and OAuth/OpenID-issued access tokens are validated before discovery, invocation, token-cache write, or outbound `Authorization: Bearer` send. They reject empty, padded, control-character-bearing, and internal-whitespace bytes. Credential bytes are never silently trimmed or rewritten.
- Static query-parameter API keys and static bearer material are validated at the config boundary before discovery or invocation dispatch.
- No raw tokens, API keys, cookies, OAuth secrets, or mTLS private keys appear in durable task-registry data, error output, or diagnostics.

## Push Notification Callback Authority

`CreateTaskPushNotificationConfig` requests register a callback URL, optional callback token, and optional authentication descriptor as future delivery authority for both JSON-RPC and HTTP+JSON bindings.

- `validate_notification_target_url` allows HTTPS remote callbacks and localhost HTTP test callbacks, and rejects non-HTTPS remote targets, URL userinfo, and fragments before any management request is dispatched.
- Callback tokens and authentication credentials are optional, but provided empty, padded, or control-character-bearing token and credential values are malformed callback authority and fail closed. Authentication schemes must be non-empty HTTP tokens.
- Callback tokens and authentication credentials are never logged or persisted.

## Runtime Tool Input

The signed manifest advertises a closed object input schema with `additionalProperties: false` at the top level and inside follow-up operation objects. The adapter-local tool-input structs use closed-shape serde admission, so unknown top-level, follow-up, or push-notification nested keys fail closed before a remote A2A request is assembled rather than being silently discarded. Supported snake-case fields and their camelCase aliases remain accepted, and the mutually exclusive operation-mode checks are preserved.

## Security And API Constraints

- Public API compatibility is preserved: `A2aAdapterConfig` and `A2aAdapter` signatures and the generated manifest schema shape are stable. Mode parsing, registry internals, and parser helpers stay internal to the crate.
- Every outbound HTTP dispatch requires `HttpEgressContract` unless a test explicitly supplies a permissive test contract.
- Follow-up task operations stay bound to the original tool, server id, interface URL, binding, tenant, and partner.
- Unknown tool names return `ToolNotRegistered`.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` consumes this crate as a `ToolServerConnection`; adapter failures surface as `KernelError::ToolServerError`. Valid A2A streaming calls receive stream output rather than a late local persistence error; malformed direct adapter inputs surface as `ToolServerError`.
- `chio-a2a-edge` and cross-protocol docs rely on the A2A bridge preserving task lifecycle and receipt semantics; the public schema is unchanged.
- Integration tests under `crates/protocol/chio-a2a-adapter/tests` exercise discovery and invocation over loopback fake A2A servers using the public API.
