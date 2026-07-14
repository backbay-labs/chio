# chio-a2a-adapter

`chio-a2a-adapter` is a thin A2A-to-Chio adapter for agent-card discovery and
`SendMessage` mediation. It fetches a remote agent's A2A Agent Card, projects
its skills into a signed Chio `ToolManifest`, and routes `SendMessage` and
task-lifecycle calls through the kernel so capability validation, the egress
contract, and receipt signing apply to every cross-agent call.

Use this crate to govern calls to an external A2A agent from inside Chio. It
is a mediation shim, not a full A2A server: the outward-facing surface that
exposes Chio tools as A2A skills is `chio-a2a-edge`.

## Responsibilities

- Discover a remote A2A Agent Card (`A2aAdapter::discover`), validate
  configured request-auth material up front, and select a supported interface
  and protocol binding (JSON-RPC or HTTP+JSON) subject to an optional
  `A2aPartnerPolicy`.
- Project every Chio-projectable Agent Card skill into a signed
  `ToolManifest`, with a closed-shape input schema covering `SendMessage` and
  six task-management follow-ups (`GetTask`, `SubscribeToTask`, `CancelTask`,
  and push-notification-config create/get/list/delete).
- Resolve per-skill A2A security requirements (bearer, HTTP Basic, OAuth2
  client-credentials, OpenID Connect discovery, API key header/query/cookie,
  mutual TLS) into request auth, caching OAuth-acquired bearer tokens.
- Gate every outbound HTTP call through a typed `HttpEgressContract`:
  DNS-resolved IP enforcement, response-byte ceilings, and manually validated
  redirect chains.
- Bind observed A2A task ids to their originating tool, server, interface,
  binding, tenant, and partner in a durable file-backed registry, and deny any
  follow-up operation whose binding disagrees.
- Parse streaming `SendMessage`/`SubscribeToTask` responses from
  Server-Sent Events into kernel `ToolCallChunk`s under bounded per-line,
  per-event, and per-stream limits.
- Implement `ToolServerConnection` so the kernel can invoke the wrapped agent
  like any native tool server.

## Public API

- `A2aAdapter::discover(config: A2aAdapterConfig) -> Result<Self, AdapterError>`
  fetches the Agent Card and builds the adapter. Accessors: `manifest()`,
  `agent_card()`, `agent_card_url()`, `selected_interface()`. Implements
  `ToolServerConnection`.
- `A2aAdapterConfig` - builder for the agent-card URL, manifest public key,
  request auth (bearer, basic, header, query param, cookie), OAuth client
  credentials, TLS root CAs and mutual-TLS identity, timeout, server id and
  version, `A2aPartnerPolicy`, task-registry file path, and
  `HttpEgressContract`.
- `A2aPartnerPolicy` - builder restricting discovery to a required tenant,
  required skills, required security-scheme names, and allowed interface
  origins.
- `AdapterError` - the crate's error type (`thiserror`), mapped to
  `KernelError::ToolServerError` at the `ToolServerConnection` boundary.
- A2A wire model: `A2aAgentCard`, `A2aAgentSkill`, `A2aAgentInterface`,
  `A2aMessage`, `A2aPart`, `A2aSendMessageRequest`/`Response`, and the task
  and push-notification-config request/response types.
- `loaded_weights::loaded_weights_unavailable() -> LoadedWeightsUnavailable` -
  the crate's `LoadedWeights` impl for `A2aAdapter`.

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Exposes `fuzz::fuzz_a2a_envelope_decode`, the libFuzzer entry point for the SSE and JSON-RPC/HTTP+JSON envelope decode paths. Off by default; pulls in `arbitrary`. Enabled only by the standalone `fuzz` workspace. |

## Testing

`cargo test -p chio-a2a-adapter`

## See also

- `chio-a2a-edge` - the outward A2A server surface (exposes Chio tools as A2A
  skills); this crate wraps the opposite direction, an external agent
  consumed by Chio.
- `chio-kernel` - consumes `A2aAdapter` as a governed `ToolServerConnection`.
- `chio-egress-contract` - supplies the `HttpEgressContract` gating every
  outbound call.
