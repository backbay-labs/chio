# chio-a2a-adapter Architecture Note

## Current Boundaries

- `lib.rs` is the crate facade. It exposes the public A2A adapter types by including config, protocol, invocation, mapping, discovery, auth, transport, task-registry, and optional fuzz modules into one crate module.
- `config.rs` owns builder-style adapter configuration: agent-card URL, auth material, TLS material, egress contract, partner policy, and durable task-registry path.
- `protocol.rs` owns the local serde model for A2A Agent Cards, JSON-RPC envelopes, messages, tasks, push-notification configuration, and selected protocol bindings.
- `mapping.rs` owns projection from discovered A2A skills into Chio `ToolManifest` tool definitions and parsing of Chio tool input into adapter-local A2A operations.
- `invoke.rs` owns the runtime adapter: discovery, auth resolution, request construction, SendMessage, task follow-up operations, streaming calls, and `ToolServerConnection` integration.
- `auth.rs` owns HTTP dispatch, redirect validation, OAuth/OpenID token exchange, TLS construction, response-size enforcement, and typed `HttpEgressContract` checks.
- `transport.rs` owns SSE parsing, redirect header stripping helpers, auth URL composition, and response body accounting.
- `task_registry.rs` owns durable A2A task correlation for follow-up operations after restart.

## Pain Points

- The crate is still include-driven, so module boundaries are not visible to rustdoc or downstream readers. That is a broader cleanup target, but this slice should avoid churn for churn's sake.
- The task registry is a security boundary, not just a cache. Once a task id is recorded, later `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification operations can use it as follow-up authority.
- `A2aTaskRegistry::record_from_value` currently extracts task ids directly from arbitrary JSON values and relies on callers to have already validated response or stream-event shape. That is too brittle for a durable correlation boundary.
- The normal invoke and stream paths validate task responses today, but the registry should fail closed if a future call path or test helper tries to persist malformed observations.

## Security And API Constraints

- Public API compatibility must be preserved. This slice should not expose new public types or change `A2aAdapterConfig` / `A2aAdapter` signatures.
- Every outbound HTTP dispatch must continue to require `HttpEgressContract` unless a test explicitly supplies a permissive test contract.
- Follow-up task operations must remain bound to the original tool, server id, interface URL, binding, tenant, and partner.
- No raw tokens, API keys, cookies, OAuth secrets, or mTLS private keys may be written to durable task-registry data or error output.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` sees this crate as a `ToolServerConnection`; the outward behavior should stay as `KernelError::ToolServerError` for adapter failures.
- `chio-a2a-edge` and cross-protocol docs rely on the A2A bridge preserving task lifecycle and receipt semantics; no transitive public schema change is planned.
- Integration tests under `crates/chio-a2a-adapter/tests` exercise discovery and invocation over loopback fake A2A servers; they should keep using the existing public API.

## Planned Material Improvement

Move task-observation extraction into a small internal registry boundary that validates recognized A2A task payloads before persistence. Malformed `task`, `statusUpdate`, or `artifactUpdate` observations should fail closed and leave the registry unchanged. This is architectural because it makes durable follow-up correlation self-defensive instead of dependent on all upstream call sites remembering to validate first.

## Input Mode Slice

### Current Boundary

- `protocol.rs` preserves Agent Card `defaultInputModes` and per-skill `inputModes` as provider-supplied strings.
- `mapping.rs` is the only place that interprets those strings into the internal `A2aSkillInputSurface` used by both manifest projection and send-path admission.
- `invoke.rs` must not re-parse Agent Card mode strings; it should only consume the already-normalized surface when deciding whether to send text or JSON parts.

### Pain Point

`A2aSkillInputSurface::from_modes` currently recognizes only exact `text/plain` and `application/json` tokens after trim and ASCII lowercase. Agent Cards can carry MIME-style parameters such as `application/json; charset=utf-8`; treating those as unknown rejects valid JSON/text surfaces during discovery and can deny runtime sends that match the remote card's advertised media type.

### Security And API Constraints

- Preserve public API compatibility and keep mode parsing internal to the crate.
- Do not widen arbitrary media types into JSON or text. Only recognized aliases and MIME essences should project.
- Continue failing closed when no projectable input mode remains after normalization.
- Keep the generated A2A part media types canonical: outbound text remains `text/plain`, outbound structured data remains `application/json`.

### Affected Dependents

- `build_manifest` depends on the parsed surface to decide whether the generated tool schema exposes `message`, `data`, or both.
- `A2aAdapter::build_send_message_request` depends on the same surface to admit text and data parts before kernel-mediated dispatch.
- No downstream crate needs a schema or public API change if the normalization boundary is kept internal.

### Planned Material Improvement

Add a small internal normalization step for skill input modes that strips MIME parameters before alias classification. Prove the boundary through both manifest projection and send-path tests so discovery and invocation stay aligned.

## Stream Registry Persistence Slice

### Current Boundary

- `transport.rs` parses A2A SSE events, unwraps JSON-RPC stream results when needed, validates every stream response, and returns a `ToolServerStreamResult`.
- `invoke.rs` records task observations from completed stream chunks after the stream has already been parsed and accepted.
- `task_registry.rs` owns durable follow-up authority. It must reject malformed observations and preserve existing task bindings.

### Pain Point

The stream path currently treats any registry persistence failure as a fatal invocation error even after the SSE parser has accepted the stream chunks. A stale or conflicting local registry entry can therefore convert an otherwise valid streaming response into `ToolServerError`, even though the safe fallback is to return the already-authorized stream and leave future follow-up authority denied by the unchanged registry.

### Security And API Constraints

- Preserve public API compatibility and keep the registry internals private.
- Keep malformed stream chunks fail-closed. Stream data must still pass the same A2A stream-response validation before registry persistence is considered.
- Do not overwrite conflicting task bindings. Future follow-up operations must remain denied unless the registry has a valid binding for the requested tool, server, interface, binding, tenant, and partner.
- Do not expose secrets in registry persistence warnings.

### Affected Dependents

- `chio-kernel` should continue to receive stream output for valid A2A streaming calls instead of a late local persistence error.
- Follow-up operations in this crate continue to depend on `A2aTaskRegistry::validate_follow_up`; no downstream schema or public API change is planned.

### Planned Material Improvement

Introduce a stream-specific recording boundary that first re-validates accepted chunks as A2A stream responses, then treats registry persistence failures as non-fatal for the current stream while preserving the registry unchanged. This keeps current stream delivery aligned with parser validation and keeps future follow-up authority fail-closed.

## Stream Registry Error Classification Slice

### Current Boundary

- `record_stream_task_activity` is the only stream path that decides whether a registry recording error is fatal for the current invocation.
- `task_registry.rs` reports malformed payloads, corrupted registry files, unsupported registry versions, poisoned locks, write failures, and binding conflicts through `AdapterError`.
- Follow-up operations still call `validate_follow_up`, so a task with no valid durable binding fails closed later.

### Pain Point

The current stream recording path swallows every registry error after stream validation. That is too broad: a stale binding conflict is safe to keep non-fatal because it leaves future follow-up denied by the unchanged binding, but a malformed or unreadable durable registry means the adapter cannot prove the local follow-up authority state it is preserving.

### Security And API Constraints

- Preserve the public `A2aAdapter` and `AdapterError` API.
- Keep valid-stream binding conflicts non-fatal for the current stream.
- Keep malformed stream chunks and unreadable durable registry state fail-closed.
- Do not log or persist request credentials while reporting registry errors.

### Affected Dependents

- `chio-kernel` should continue to receive a `ToolServerError` when A2A stream recording cannot establish a safe durable boundary.
- Existing A2A stream conflict tests must continue to prove that conflicting task ids do not overwrite the old binding and do not abort the current valid stream.

### Completed Material Improvement

Classify stream registry recording errors at the registry boundary with an
internal typed result. Only actual task rebind conflicts stay non-fatal for the
current valid stream; validation, parsing, unsupported-version, lock, and
storage errors return an adapter error so the current tool call fails closed
instead of hiding an untrusted durable-authority state. This also prevents
diagnostic text, file paths, or unrelated lifecycle errors from accidentally
matching the rebind-conflict path.

## Blocking Registry Error Classification Slice

### Current Boundary

- Blocking `SendMessage`, `GetTask`, and `CancelTask` calls validate the remote
  A2A payload before converting it into a Chio tool result.
- `record_task_activity` observes accepted blocking responses and writes durable
  task correlation through `A2aTaskRegistry::record_from_value`.
- `A2aTaskRegistry::validate_follow_up` remains the fail-closed gate for later
  task operations.

### Pain Point

The blocking path still treats every registry recording error as fatal after a
remote A2A operation has already succeeded. A stale local rebind conflict can
therefore turn a valid current `SendMessage`, `GetTask`, or `CancelTask`
response into `ToolServerError`, while streaming already classifies the same
conflict as non-fatal and preserves the unchanged registry so future follow-up
authority stays denied.

### Security And API Constraints

- Preserve public API compatibility and `ToolServerConnection` behavior.
- Keep malformed task observations, corrupted registry files, unsupported
  registry versions, lock failures, and write failures fail-closed.
- Do not overwrite conflicting task bindings or widen follow-up authority.
- Do not expose credentials in registry warnings.

### Affected Dependents

- `chio-kernel` should receive the accepted current blocking A2A response for a
  stale rebind conflict instead of a late local persistence error.
- Future A2A follow-up operations continue to depend on
  `A2aTaskRegistry::validate_follow_up`; no downstream public schema change is
  planned.

### Completed Material Improvement

Routed blocking response recording through the same internal classified registry
boundary used by streams. Rebind conflicts should be warning-only for the
current accepted response, while fatal registry errors continue to abort the
current invocation fail-closed.

## Task Registry Id Canonicalization Follow-up

### Current Boundary

- `task_registry.rs` extracts task ids from accepted `task`, `statusUpdate`,
  and `artifactUpdate` payloads before writing durable follow-up authority.
- The same registry later looks up exact task-id keys when tool calls perform
  follow-up operations.

### Pain Point

The observation validators reject all-whitespace task ids, but task ids are
provider-controlled protocol values. Normalizing them at persistence time can
collapse two distinct provider-observed task authorities into one local durable
key. Follow-up lookup must therefore use the exact observed id, including
whitespace, after validation has proved the id is non-empty.

### Completed Material Improvement

Preserve observed task ids exactly at the registry observation boundary while
continuing to reject empty or malformed observations. This keeps durable
follow-up authority keyed to the precise provider value and prevents unrelated
task ids from being collapsed by local canonicalization.

## Follow-up Partner Binding Slice

### Current Boundary

- `task_registry.rs` stores the partner label with each task observation and
  rejects partner changes when the same task id is re-observed.
- `invoke.rs` computes the partner label from the configured partner policy,
  falling back to the Agent Card host when no explicit partner id is present.
- `A2aTaskRegistry::validate_follow_up` is the durable gate for later
  `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification operations.

### Pain Point

The registry already treats partner as part of the recorded task binding, but
follow-up validation currently omits partner comparison. Two adapter instances
that share a task registry, selected tool, server id, interface, binding, and
tenant can therefore validate follow-up authority for the same task even if
their configured partner identities differ.

### Security And API Constraints

- Preserve public API compatibility. This slice must keep the partner binding
  internal to adapter and registry internals.
- Preserve exact task-id lookup and all existing tool, server, interface,
  binding, and tenant checks.
- Do not persist request credentials or include auth material in errors.
- Keep follow-up operations fail-closed when partner identity does not match the
  recorded task authority.

### Affected Dependents

- `chio-kernel` still sees the denial as a tool-server lifecycle failure through
  the existing `ToolServerConnection` path.
- `chio-a2a-edge` and conformance surfaces should not need public schema
  changes because partner comparison stays internal to this crate.
- Existing registry tests need only pass the same partner label they already
  record.

### Completed Material Improvement

Pass the resolved partner label into durable follow-up validation and reject
task operations whose partner differs from the recorded task authority. Prove
the boundary with an adapter-level restart-style test that records a task under
one partner and denies follow-up through another partner using the same durable
registry.

## Batch Rebind Persistence Slice

### Current Boundary

- `task_registry.rs` extracts all task observations from one accepted A2A
  payload, then persists them under one durable registry lock.
- Registry rebind conflicts are classified separately from fatal registry
  failures because blocking and streaming invoke paths can deliver the accepted
  current response while keeping future follow-up authority fail-closed.
- Malformed task, status-update, or artifact-update observations remain fatal
  validation errors before registry mutation starts.

### Pain Point

The current persistence loop returns immediately on the first rebind conflict
and saves nothing from that payload. If an earlier observation in the same
payload recorded a new valid task id, the warning-only conflict later in the
batch discards that valid task authority even though the invoke path still
delivers the remote response.

### Security And API Constraints

- Preserve public API compatibility and the internal classified error shape.
- Do not overwrite or mutate conflicting task records.
- Keep malformed observations, corrupted registry state, poisoned locks, and
  write failures fatal for the current invocation.
- Preserve warning-only classification for actual rebind conflicts after all
  non-conflicting observations have been durably saved.

### Affected Dependents

- `chio-kernel` should still receive accepted blocking or streaming responses
  for stale rebind conflicts.
- Later `GetTask`, `SubscribeToTask`, `CancelTask`, and push-notification calls
  should retain follow-up authority for non-conflicting task ids observed in the
  same accepted payload.
- No downstream crate or public schema change is planned.

### Completed Material Improvement

Continue scanning a validated observation batch after rebind conflicts, persist
all non-conflicting records, and then return the rebind-conflict classification
for caller warning behavior. Prove the boundary with a registry test that
combines one new valid task observation and one conflicting existing task in the
same payload.

## Bounded SSE Framing Slice

### Current Boundary

- `transport.rs` owns A2A SSE parsing for both JSON-RPC and HTTP+JSON stream
  bindings.
- `invoke.rs` supplies the binding-specific event decoder, then relies on
  `transport.rs` to validate every stream event before a `ToolCallChunk` enters
  the kernel stream path.
- `fuzz.rs` reaches the same parser through the `fuzz` feature, so the parser
  is the shared byte-to-envelope trust boundary for streaming A2A calls.

### Pain Point

`parse_sse_stream_with_limit` enforces line, event, total-byte, and chunk
ceilings, but it currently calls `BufRead::read_line` before checking the line
length. A delimiterless or oversized SSE line can therefore force allocation up
to the remote response size before the adapter reports the configured line
limit. That weakens the parser boundary even though the later validation result
is fail-closed.

### Security And API Constraints

- Preserve public API compatibility and keep parser helpers internal.
- Preserve existing SSE semantics for blank-line event delimiters, comment
  lines, multiline `data:` payloads, terminal-state completion, incomplete
  streams, and binding-specific JSON-RPC unwrapping.
- Keep all outbound HTTP dispatch gated by `HttpEgressContract`; this slice is
  only about response-body framing after the contract admits the response.
- Reject oversized lines before buffering beyond the line ceiling, and keep the
  total response-byte ceiling authoritative.
- Do not widen accepted stream event shapes or task lifecycle semantics.

### Affected Dependents

- `A2aAdapter::invoke_stream` and `SubscribeToTask` should continue returning
  the same `ToolServerStreamResult` shapes for valid streams.
- `chio-kernel` and receipt paths should see no public API or schema change.
- The fuzz feature should continue driving the same parser boundary.

### Planned Material Improvement

Replace direct `read_line` use in the SSE parser with a bounded internal line
reader that consumes at most the admitted bytes for each line, rejects
oversized lines immediately, and reports clean EOF without allocating an
unbounded delimiterless line. Prove the boundary with parser tests for valid
streams, oversized newline-delimited lines, oversized delimiterless lines, and
total response-byte enforcement.

## Request Auth Material Slice

### Current Boundary

`A2aAdapterConfig` accepts caller-supplied request headers, query parameters,
cookies, bearer/basic/API key material, OAuth client credentials, TLS material,
and task-registry configuration before discovery. `auth.rs` later applies that
material to discovery, OAuth, blocking dispatch, and streaming dispatch.

### Pain Point

The public builder methods currently store request-auth atoms without a shared
validation boundary. Header names and values eventually cross `ureq::Request`;
query names are appended to remote URLs; cookies are manually joined into a
single `Cookie` header. Empty, padded, control-character-bearing, or cookie
separator-bearing names and values should fail closed before any outbound A2A
request can be assembled.

### Security And API Constraints

- Preserve public `A2aAdapterConfig` builder signatures.
- Do not log or persist auth values while reporting malformed auth material.
- Keep normal bearer, basic, API key, query, and cookie configuration behavior
  unchanged for valid atoms.
- Do not reject arbitrary query values; URL encoding owns value escaping.
- Reject cookie separators because cookie values are manually serialized into
  one header.

### Affected Dependents

Existing callers keep using the same builder methods. Malformed auth
configuration now fails during `A2aAdapter::discover` before agent-card fetch,
OAuth negotiation, or tool invocation dispatch. No downstream crate or public
schema change is planned.

### Completed Material Improvement

Added an internal request-auth material validator at discovery time. It rejects
malformed header names/values, query parameter names, cookie names, and cookie
values without exposing secret values in diagnostics, and tests prove malformed
configuration fails before the first outbound A2A request can be assembled.

## Push Notification Callback Authority Slice

### Current Boundary

- `invoke.rs` builds `CreateTaskPushNotificationConfig` requests for both
  JSON-RPC and HTTP+JSON bindings.
- `discovery.rs` owns callback URL validation through
  `validate_notification_target_url` before the management request is sent.
- The validated callback URL is handed to the upstream A2A agent as future
  authority for task notification delivery.

### Pain Point

The callback URL validator rejects non-HTTPS remote targets, but it still
accepts URL userinfo and fragments. Userinfo embeds ambient authority in the
callback URL itself, while fragments are not sent by HTTP clients but can still
leak operator-supplied material to the upstream agent when the URL is
registered.

### Security And API Constraints

- Preserve public API compatibility and existing valid callback URL behavior.
- Continue allowing HTTPS remote callbacks and localhost HTTP test callbacks.
- Reject callback URL userinfo and fragments before any push-notification
  management request is dispatched.
- Do not log or persist callback tokens or authentication credentials.

### Affected Dependents

- A2A callers using valid callback URLs are unchanged.
- `chio-kernel` continues to see invalid callback URL inputs as
  `ToolServerError` through the existing `ToolServerConnection` path.
- No downstream crate or public schema change is planned.

### Completed Material Improvement

Harden `validate_notification_target_url` so callback URLs containing userinfo
or fragments fail closed before dispatch. Add adapter-level regressions proving
malformed callback URLs do not issue a create request to the upstream A2A
agent.

## Auth And Projected Skill Admission Slice

### Current Boundary

- `config.rs` owns caller-supplied static auth material for discovery and
  invocation, including bearer headers and API key query parameters.
- `invoke.rs` resolves static auth material against the Agent Card security
  schemes before dispatch.
- `mapping.rs` owns both Agent Card skill projection into the Chio manifest and
  partner-policy admission checks.

### Pain Point

Auth validation is split at the wrong level for two credential shapes. Query
parameter auth validates only the parameter name, so an empty or padded API key
can be appended to every outbound request. Static bearer auth stores the
formatted `Authorization` header before validation, so a padded raw token can
still produce a syntactically acceptable header. Partner `require_skill`
checks raw Agent Card skills instead of the projectable skill set, allowing a
partner to satisfy admission with a skill that the adapter later drops from
the generated manifest.

### Security And API Constraints

- Preserve public builder signatures and generated manifest schema shape.
- Keep valid bearer tokens and API key query parameters unchanged.
- Fail closed before discovery or invocation dispatch when static auth material
  is empty, padded, or otherwise malformed.
- Do not include secret values in error messages.
- Required partner skills must correspond to skills the adapter can actually
  expose as Chio tools after input-mode projection.

### Affected Dependents

- Existing callers with valid auth material and projectable required skills do
  not need any code changes.
- `chio-kernel` continues to receive adapter failures through the existing
  `ToolServerConnection` error path.
- No downstream crate or public schema change is planned.

### Planned Material Improvement

Move bearer-token and query-auth value checks into the config validation
boundary and align partner required-skill admission with the manifest
projection boundary. Prove the change with tests that malformed auth material
fails before any request is sent and that a required but non-projectable skill
is denied during discovery.

## SSE Byte Accounting Follow-up

### Current Boundary

- `transport.rs` owns bounded A2A SSE line reading and stream parsing.
- `parse_sse_stream_with_limit` owns the total response-byte budget.
- `read_sse_line` owns buffered line consumption and the per-line byte limit.

### Pain Point

The bounded line reader consumes bytes while detecting an oversized SSE line,
but total response-byte accounting is updated only after a successful line
read. A delimiterless or oversized line can therefore cross a caller-supplied
total response limit before the parser reports the response-byte violation.

### Security And API Constraints

- Preserve public API compatibility and valid SSE parsing behavior.
- Preserve per-line, per-event, total-response, and chunk-count fail-closed
  limits.
- Keep UTF-8 validation and terminal-state handling unchanged.
- Do not widen accepted stream event shapes or task lifecycle semantics.

### Affected Dependents

- `A2aAdapter::invoke_stream` and `SubscribeToTask` continue using the same
  parser boundary and `ToolServerStreamResult` shapes.
- `chio-kernel` should see the same adapter error path for invalid streams,
  with stricter response-budget precedence when a line is also oversized.
- No downstream crate or public schema change is planned.

### Planned Material Improvement

Move total-byte accounting into the same internal helper that consumes SSE line
bytes, so every consumed byte is charged before an oversized-line error can
return. Prove the boundary with parser regressions where oversized
newline-delimited and delimiterless lines exceed a smaller total response
limit.

## SSE Overflow Consumption Follow-up

### Current Boundary

- `read_sse_line` owns buffered input consumption for each line fragment.
- `parse_sse_stream_with_limit` treats total response-byte exhaustion as a
  parser-fatal condition.
- Callers do not retry a failed SSE parse, but buffered readers still must leave
  coherent consumption and accounting state when returning an error.

### Pain Point

The response-limit overflow branch returns before consuming the buffered chunk
that crossed the configured total response-byte budget. That leaves unread bytes
in the line reader despite reporting that they exhausted the stream budget.

### Security And API Constraints

- Preserve fail-closed behavior when the stream exceeds the configured response
  budget.
- Preserve line-limit precedence only when the total response budget has not
  already been crossed.
- Do not parse, decode, or accept any bytes after the response budget is
  exhausted.
- Keep the existing public parser API unchanged.

### Affected Dependents

- `A2aAdapter::invoke_stream` and task-subscription callers continue receiving
  the same adapter error type for budget exhaustion.
- Tests may now assert that the buffered reader advanced past the offending
  chunk before the error was returned.
- No downstream crate or public schema change is planned.

### Planned Material Improvement

Advance the buffered reader and charge `total_bytes` for the chunk that crosses
the configured total response-byte budget, then return the existing fail-closed
response-limit error before extending or decoding the current line.

## Projected Skill Invocation Slice

### Current Boundary

- `mapping.rs` projects only Chio-projectable Agent Card skills into the signed
  `ToolManifest`.
- `ToolServerConnection::tool_names` exposes only manifest tool names to the
  kernel.
- `invoke.rs` resolves runtime `invoke` and `invoke_stream` targets against
  the raw Agent Card skill list before dispatch.

### Pain Point

After non-projectable skills are filtered out of the manifest, runtime
invocation still accepts those raw Agent Card skill ids. A caller can target a
skill that is absent from `tool_names()` and the signed manifest, including
follow-up task operations that do not need text or JSON input.

### Security And API Constraints

- Preserve public API compatibility and valid projected skill behavior.
- Keep manifest projection as the source of truth for exposed tool authority.
- Do not widen accepted input modes or expose non-projectable skills through
  runtime dispatch.
- Preserve existing `ToolNotRegistered` behavior for unknown tool names.

### Affected Dependents

- `chio-kernel` should see non-manifest skill targets as unregistered tools.
- Existing A2A callers invoking manifest-exposed skills are unchanged.
- No downstream crate or public schema change is planned.

### Planned Material Improvement

Add one runtime skill-resolution boundary that first checks the signed manifest
tool set and only then returns the matching Agent Card skill. Use it for both
blocking and streaming invocation, and prove non-projectable raw skills cannot
be invoked through either path.

## Bearer Token Grammar Follow-up

### Current Boundary

- `config.rs` owns configured request auth validation before discovery or
  invocation can send caller-provided credentials.
- `auth.rs` owns OAuth and OpenID token response admission before access tokens
  are cached and emitted as `Authorization: Bearer` headers.
- `transport.rs` only serializes accepted request-auth material into HTTP bytes.

### Pain Point

Configured bearer tokens and OAuth-issued access tokens can contain internal
whitespace after the existing empty, padded, and control-character checks pass.
Those values are then formatted into malformed bearer Authorization headers.

### Security And API Constraints

- Preserve valid bearer, API key, cookie, Basic, OAuth, and OpenID behavior.
- Reject malformed bearer material before any discovery, invocation, token cache
  write, or outbound Authorization header send.
- Do not silently trim or rewrite configured or remotely issued credential bytes.
- Keep public config APIs unchanged.

### Affected Dependents

- A2A callers with valid bearer tokens and OAuth access tokens are unchanged.
- Callers with whitespace-bearing bearer material now fail closed with
  `AdapterError::AuthNegotiation`.
- No downstream crate or public schema change is planned.

### Planned Material Improvement

Add a bearer-token validator that reuses existing auth-value checks and also
rejects any whitespace inside bearer token bytes. Apply it to configured bearer
headers and to OAuth token responses before caching.

## Runtime Tool Input Schema Parity Slice

### Current Boundary

- `mapping.rs` generates a manifest input schema for every projected A2A skill
  with `additionalProperties: false` at the top level and inside follow-up
  operation objects.
- `parse_tool_input` deserializes runtime tool arguments into adapter-local
  structs before `invoke.rs` decides whether to send `SendMessage`, task
  follow-up, streaming, or push-notification management requests.
- Kernel-mediated callers should normally see the signed manifest schema, but
  the adapter also has direct public `ToolServerConnection` entry points and
  unit tests that bypass schema validation.

### Pain Point

The runtime serde structs currently ignore unknown keys even though the signed
manifest advertises a closed object shape. A direct adapter call or a caller
that bypasses schema validation can include misspelled or stale operation
fields, nested push-notification fields, or follow-up fields that the adapter
silently discards before dispatching the remaining valid request.

### Security And API Constraints

- Preserve public API compatibility and keep existing snake-case plus camelCase
  aliases for supported fields.
- Preserve the existing mutually exclusive operation-mode checks.
- Keep valid `SendMessage`, task follow-up, streaming, and push-notification
  management inputs unchanged.
- Fail closed on unknown runtime keys instead of silently trimming caller
  intent before a remote A2A request is assembled.

### Affected Dependents

- No downstream crate or public schema change is planned because the manifest
  already exposes a closed input schema.
- `chio-kernel` continues to receive invalid direct adapter inputs as
  `ToolServerError` through the existing `ToolServerConnection` path.
- Existing A2A callers using documented fields are unchanged.

### Completed Material Improvement

Added closed-shape serde admission to the adapter-local tool-input structs and
proved runtime parity with regressions for unknown top-level, follow-up, and
push-notification nested fields. Supported snake-case fields and camelCase
aliases remain accepted, while stale or misspelled keys now fail before any
remote A2A request is assembled.

## Push Notification Auth Material Slice

### Current Boundary

`invoke.rs` builds `CreateTaskPushNotificationConfig` requests from
adapter-local tool input before the upstream A2A agent records a callback URL,
optional callback token, and optional authentication descriptor for future task
notifications.

### Pain Point

Callback tokens and authentication credentials are optional, but a caller who
provides empty or padded values is expressing malformed callback authority, not
absence. The current builder silently drops trim-empty token and credential
values, and authentication schemes only pass through the generic non-empty id
check before being serialized into the upstream request.

### Security And API Constraints

- Preserve public API compatibility and valid push-notification configuration
  requests.
- Preserve exact task-id follow-up behavior; provider-observed task ids can
  contain whitespace and are not part of this slice.
- Reject malformed callback auth material before any push-notification
  management request is dispatched.
- Do not log or persist callback tokens or authentication credentials.

### Affected Dependents

`chio-kernel` continues to receive malformed callback auth inputs as
`ToolServerError` through the existing `ToolServerConnection` path. JSON-RPC
and HTTP+JSON A2A push-notification callers with valid callback auth material
should observe no behavior change.

### Completed Material Improvement

Added a push-notification auth-material admission helper that rejects provided
empty, padded, or control-character-bearing token and credential values, and
requires authentication schemes to be non-empty HTTP tokens before the upstream
A2A agent can record the callback configuration.
