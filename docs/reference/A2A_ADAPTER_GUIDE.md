# A2A Adapter Guide

`chio-a2a-adapter` is the first Chio bridge for the A2A v1.0.0 protocol. It is
intentionally thin: discover an Agent Card, select a supported interface, map
advertised A2A skills into Chio tools, and execute blocking or streaming A2A
message operations through the normal Chio kernel guard and receipt pipeline.

## Current Scope

- discovers `/.well-known/agent-card.json` from a base URL or consumes a full
  Agent Card URL directly
- supports A2A `JSONRPC` and `HTTP+JSON` bindings
- supports blocking `SendMessage`
- supports `SendStreamingMessage` over both bindings
- supports follow-up `GetTask` polling over both bindings
- supports follow-up `SubscribeToTask` streaming over both bindings
- supports follow-up `CancelTask` over both bindings
- supports task push-notification config create/get/list/delete over both
  bindings
- supports OAuth2 client-credentials token acquisition and OpenID Connect
  discovery when the Agent Card declares those bearer schemes
- supports HTTP Basic auth when the Agent Card declares
  `httpAuthSecurityScheme` with `scheme: basic`
- supports mutual TLS when the Agent Card declares `mtlsSecurityScheme` and
  the adapter is configured with a client certificate plus trusted root CA
- exposes one Chio tool per advertised A2A skill
- supports explicit adapter-level request headers, query params, and cookies
  for provider-specific partner integration without per-call glue
- negotiates required bearer, HTTP Basic, and API key
  header/query/cookie auth from Agent Card `securitySchemes` /
  `securityRequirements`
- supports fail-closed partner-admission policy for expected tenant, required
  skills, required security schemes, and allowed interface origins
- supports an optional durable task registry for follow-up correlation across
  adapter restarts
- fails closed when the Agent Card requires auth schemes Chio still does not
  implement
- propagates interface tenant metadata into `SendMessage` and HTTP task
  lifecycle requests
- requires `https` for remote targets and allows `http` only for localhost
  testing

## Honest Boundary

A2A v1.0.0 does not define a native `skillId` selector inside `SendMessage`.
The adapter therefore does **not** pretend that skill routing is a core A2A
field. Instead, it injects an adapter-local convention into top-level request
metadata:

```json
{
  "chio": {
    "targetSkillId": "research",
    "targetSkillName": "Research"
  }
}
```

That keeps the protocol boundary explicit while still giving Chio stable
per-skill tool names and capability scoping.

Auth negotiation is equally explicit. The adapter will only send credentials
that satisfy a declared A2A requirement set. Today that means:

- bearer-style `Authorization` headers for Agent Cards that require bearer,
  OAuth2-bearer, or OpenID-bearer semantics
- HTTP Basic `Authorization` headers for Agent Cards that declare
  `httpAuthSecurityScheme` with `scheme: basic`
- OAuth2 client-credentials token acquisition when the Agent Card declares an
  `oauth2SecurityScheme` with a token endpoint
- OpenID Connect discovery plus client-credentials token acquisition when the
  Agent Card declares an `openIdConnectSecurityScheme`
- mutual TLS transport when the Agent Card declares an
  `mtlsSecurityScheme` and the adapter is configured with a client identity
- named API keys when the Agent Card declares an `apiKeySecurityScheme` with
  `location: header`, `location: query`, or `location: cookie`

If the card requires a scheme Chio does not implement yet, the adapter denies
the invocation before sending the tool call upstream.

Task-history semantics are also fail-closed. Chio will only send
`historyLength` on `SendMessage` or `GetTask` when the Agent Card advertises
`capabilities.stateTransitionHistory = true`.

Skill input modes are projected into the generated Chio tool schema. A skill
that advertises only `application/json` accepts the `data` field but not
`message`; a skill that advertises only `text` or `text/plain` accepts
`message` but not `data`. Invocation also checks the selected skill before
serializing an A2A part, so unsupported text or JSON payloads fail locally
instead of being sent upstream.

Lifecycle payload validation is fail-closed too. `SendMessage` task responses,
`GetTask` results, streamed `task` objects, `statusUpdate` events, and
`artifactUpdate` events must contain the required lifecycle fields Chio relies
on (`id`, `status.state`, `taskId`, and `artifact` where applicable).

HTTP auth is fail-closed too. If the Agent Card requires HTTP Basic auth and
the adapter was not configured with Basic credentials, the invocation is
denied locally before the upstream call.

Partner admission is explicit too. If you configure a partner policy, discovery
fails closed unless the selected interface, tenant, skills, and required
security scheme names match the contract you expect for that partner.

When an A2A call is executed through Chio governed-transaction policy, upstream
task lineage should be bound into `governed_intent.call_chain`, not attached as
freeform operator notes. Chio preserves that delegated provenance in the signed
receipt and projects it later through `/v1/reports/authorization-context` or
`chio trust authorization-context list`, alongside derived authorization-detail
scope for commerce and metered-billing context.

## Rust Example

```rust
use chio_a2a_adapter::{A2aAdapter, A2aAdapterConfig, A2aPartnerPolicy};
use chio_core::crypto::Keypair;
use chio_kernel::ChioKernel;

let manifest_key = Keypair::generate();
let adapter = A2aAdapter::discover(
    A2aAdapterConfig::new(
        "https://agent.example.com",
        manifest_key.public_key().to_hex(),
    )
    .with_tls_root_ca_pem(include_str!("agent-root-ca.pem"))
    .with_mtls_client_auth_pem(
        include_str!("agent-client-cert-chain.pem"),
        include_str!("agent-client-key.pem"),
    )
    .with_request_header("X-Partner", "design-partner-a")
    .with_oauth_client_credentials("client-id", "client-secret")
    .with_oauth_scope("a2a.invoke")
    .with_partner_policy(
        A2aPartnerPolicy::new("design-partner-a")
            .with_required_tenant("tenant-alpha")
            .require_skill("research")
            .require_security_scheme("oauthAuth")
            .allow_interface_origin("https://agent.example.com"),
    )
    .with_task_registry_file(".chio/a2a-task-registry.json")
)?;

let mut kernel = ChioKernel::new(/* ... */);
kernel.register_tool_server(Box::new(adapter));
```

## Tool Contract

Each generated Chio tool accepts:

- `message`: plain-text content sent as an A2A text part
- `data`: structured JSON sent as an A2A data part
- `context_id`
- `task_id`
- `reference_task_ids`
- `metadata`: top-level `SendMessageRequest.metadata`
- `message_metadata`: `Message.metadata`
- `history_length`
  Requires the Agent Card to advertise `capabilities.stateTransitionHistory`.
- `return_immediately`
- `stream`: adapter-local opt-in for A2A `SendStreamingMessage`
- `get_task`: adapter-local follow-up mode with:
  - `id`
  - `history_length`
- `subscribe_task`: adapter-local streaming follow-up mode with:
  - `id`
- `cancel_task`: adapter-local follow-up mode with:
  - `id`
  - `metadata`
- `create_push_notification_config`: adapter-local follow-up mode with:
  - `task_id`
  - `id`
  - `url`
  - `token`
  - `authentication`
- `get_push_notification_config`: adapter-local follow-up mode with:
  - `task_id`
  - `id`
- `list_push_notification_configs`: adapter-local follow-up mode with:
  - `task_id`
  - `page_size`
  - `page_token`
- `delete_push_notification_config`: adapter-local follow-up mode with:
  - `task_id`
  - `id`

These follow-up and task-management modes are mutually exclusive with the
`SendMessage` fields above. When `get_task` is present, the adapter issues A2A
`GetTask` and returns the resulting `Task` under the normal Chio tool response
shape. `get_task.history_length` also requires the Agent Card to advertise
`capabilities.stateTransitionHistory`:

```json
{
  "task": {
    "id": "task-1",
    "status": {
      "state": "TASK_STATE_COMPLETED"
    }
  }
}
```

Without `get_task`, at least one of `message` or `data` is required.

When `stream: true`, the adapter issues A2A `SendStreamingMessage` and the Chio
kernel surfaces each upstream A2A `StreamResponse` as one stream chunk. The
chunk payload is the raw A2A object, for example:

```json
{
  "statusUpdate": {
    "taskId": "task-1",
    "status": {
      "state": "TASK_STATE_COMPLETED"
    }
  }
}
```

## Follow-Up Example

```json
{
  "message": "Start a longer-running task",
  "return_immediately": true
}
```

If the A2A server returns a task instead of a terminal message, poll it later
through the same Chio tool:

```json
{
  "get_task": {
    "id": "task-1",
    "history_length": 2
  }
}
```

If you want to reattach to live task updates instead of polling point-in-time
state, use `subscribe_task`:

```json
{
  "subscribe_task": {
    "id": "task-1"
  }
}
```

The adapter issues A2A `SubscribeToTask` and the Chio kernel surfaces each
upstream `StreamResponse` as one stream chunk using the same chunk semantics as
`SendStreamingMessage`.

If you need to stop the task instead of polling or streaming it, use
`cancel_task`:

```json
{
  "cancel_task": {
    "id": "task-1",
    "metadata": {
      "reason": "user-request"
    }
  }
}
```

If the upstream agent advertises `pushNotifications`, the adapter also exposes
task notification config management through the same tool surface:

```json
{
  "create_push_notification_config": {
    "task_id": "task-1",
    "url": "https://callbacks.example.com/chio",
    "token": "notify-token",
    "authentication": {
      "scheme": "bearer",
      "credentials": "callback-secret"
    }
  }
}
```

The adapter validates callback URLs fail closed: remote targets must use
`https`, while `http` is allowed only for localhost development.

## Partner Admission

Use `A2aPartnerPolicy` when a design partner has a narrow, expected contract
and you want discovery to fail closed instead of silently adapting:

- `with_required_tenant(...)` rejects the partner if the selected interface
  advertises a different tenant
- `require_skill(...)` rejects the partner if the Agent Card does not expose
  the required skill ids as Chio-projectable tools
- `require_security_scheme(...)` rejects the partner if the required scheme is
  missing or not referenced by the Agent Card security requirements
- `allow_interface_origin(...)` rejects the partner if no supported interface
  is advertised from an allowed origin

The discovery error is operator-visible and includes the failing tenant,
interface, or scheme contract.

## Durable Task Correlation

Use `with_task_registry_file(...)` when long-running A2A task follow-up needs
to survive adapter recreation or process restart.

The registry persists one fail-closed binding per observed task id:

- Chio tool name
- selected interface URL
- protocol binding
- tenant
- partner label
- last observed task state and source

When configured, follow-up `task_id` inputs and task-management calls such as
`get_task`, `subscribe_task`, `cancel_task`, and push-notification config CRUD
are rejected unless the task id was previously recorded for the same tool,
server, binding, interface, and tenant.

## Verification

The current adapter is verified by:

- direct JSON-RPC binding tests
- direct HTTP+JSON binding tests
- direct streaming `SendStreamingMessage` tests over both bindings
- direct incomplete-stream handling tests
- direct follow-up `GetTask` tests over both bindings
- direct follow-up `SubscribeToTask` tests over both bindings
- direct follow-up `CancelTask` tests over both bindings
- direct push-notification config create/get/list/delete tests over both
  bindings
- direct validation tests that reject insecure push-notification callback URLs
- direct auth-negotiation tests for required bearer auth, required API key
  headers/query params/cookies, and missing required mTLS identity
- direct provider-specific request-surface tests for explicit headers, query
  params, and cookies applied at discovery and invocation time
- direct partner-admission tests for required tenant and interface contract
  mismatch
- direct durable-task-registry tests that allow follow-up after adapter
  recreation and reject unknown task ids fail closed
- direct lifecycle-capability tests that reject `history_length` when the
  Agent Card does not advertise `stateTransitionHistory`
- direct lifecycle-validation tests that reject malformed task, status-update,
  and artifact-update payloads
- direct OAuth2 client-credentials tests that prove token acquisition and
  in-process token caching
- direct OpenID Connect discovery tests that prove discovery plus token
  acquisition before the mediated A2A call
- direct mTLS tests that prove Agent Card discovery plus mediated invocation
  through a local HTTPS A2A server that requires a client certificate
- direct tenant-shaping tests for `SendMessage` and HTTP `GetTask` requests
- a kernel end-to-end test that proves a mediated A2A call produces an allow
  receipt with the expected Chio server/tool scoping
- a kernel end-to-end streaming test that proves `SendStreamingMessage`
  produces streamed output plus a truthful allow receipt
- a kernel end-to-end incomplete-stream test that proves prematurely closed
  streams become incomplete receipts with partial output preserved
- a kernel end-to-end follow-up test that proves `GetTask` polling stays inside
  the same capability and receipt pipeline
- kernel end-to-end allow/incomplete tests that prove `SubscribeToTask`
  streaming stays inside the same capability and receipt pipeline
- a kernel end-to-end allow test that proves `CancelTask` stays inside the same
  capability and receipt pipeline
- a kernel end-to-end allow test that proves OAuth-backed A2A invocation stays
  inside the same capability and receipt pipeline
- a kernel end-to-end allow test that proves HTTP-Basic-authenticated A2A
  invocation stays inside the same capability and receipt pipeline
- a kernel end-to-end allow test that proves query-authenticated A2A
  invocation stays inside the same capability and receipt pipeline
- a kernel end-to-end allow test that proves mTLS-backed A2A invocation stays
  inside the same capability and receipt pipeline
- full `cargo test --workspace`

## Not Shipped Yet

This is no longer just the transport skeleton. The remaining A2A roadmap work
is now:

- deeper long-running task lifecycle surfaces beyond `GetTask`,
  `SubscribeToTask`, `CancelTask`, and push-notification config CRUD
- custom or non-standard auth schemes beyond bearer, HTTP Basic, API key,
  OAuth/OpenID, and mTLS
- broader federation and partner onboarding flows beyond adapter-local
  admission policy and task correlation
