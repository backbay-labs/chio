# 14 - Voice Agent Bridges (LiveKit, Pipecat, Vapi, Retell)

> **Historical research note (PR 652):** This file remains research input, not an implementation ticket.
>
> Task E3. Coordinates with current v1 receipt-kind semantics on `human_principal` and
> call-context receipt fields, and with X2 (latency audit) on the sub-200ms
> verdict budget. Code paths are cited repo-relative.

> **Erratum:** `human_principal` is canonically defined as a typed `HumanPrincipal` enum on `CallerIdentity` here (this doc, around the "Identity" section). Doc 15's receipt extension references it by canonical encoding rather than redefining it as `Option<String>`. The two should agree: one definition, one home. See [reviews/01-identity-credentials-review.md](reviews/01-identity-credentials-review.md).

## TL;DR

Voice agents put Chio's verdict in the user-perceived loop. All four target platforms
(LiveKit Agents, Pipecat, Vapi, Retell) expose the tool call as a request/response JSON
event distinct from the audio pipeline, which is the shape Chio already mediates.
Recommended ordering: ship a **LiveKit Python middleware** at MVP (OSS, native MCP,
biggest 2026 momentum), then a Pipecat `FrameProcessor`, then a paired Vapi+Retell
HTTP shim. Ed25519 signing (~25 us) and hybrid Ed25519+ML-DSA-65 (~150-225 us) both fit
the budget; the limiter is durability, so **sign synchronously, write asynchronously**.
New: a `human_principal` field on `CallerIdentity` plus voice-specific receipt fields
(`session_id`, `participant_id`, `audio_timestamp_estimate`, `platform`).

## 1. Per-platform survey

### 1.1 LiveKit Agents

OSS Python framework on `agents` v1.5.x as of April 2026. Tool surface is the
`@function_tool` decorator over an `async` function taking a `RunContext` and the
tool arguments ([function calling](https://docs.livekit.io/agents/voice-agent/function-calling/),
[livekit/agents](https://github.com/livekit/agents)):

```python
@function_tool
async def lookup_weather(context: RunContext, location: str):
    ...
```

Native MCP support is one line ([LiveKit MCP](https://docs.livekit.io/mcp/)); non-MCP
tools dispatch in-process. Server SDKs in Python, Node, Rust, Go, Java, Ruby; the
Agents framework itself is Python plus a TypeScript starter. **A pre-execution hook
is not first-class today.** Practical interception points:

- **Wrapping decorator**: Chio ships `@chio_function_tool(...)` that wraps
  `@function_tool` and runs the verdict before calling user code.
- **Custom `LLMService`**: subclass observes `function_call` output, runs verdict,
  dispatches or injects refusal.
- **MCP path**: when the tool is served by an MCP server, existing `chio-mcp-edge`
  (`crates/chio-mcp-edge/`) already gates it.

Known sharp edge: an interrupted tool call leaves an unmatched `function_call` in the
LLM context, breaking subsequent turns with a 400 ([livekit/agents#5092](https://github.com/livekit/agents/issues/5092)).
Chio's deny path must emit a synthetic tool result so the context stays well-formed
(same shape already in `chio-tool-call-fabric`).

### 1.2 Pipecat

OSS Python framework, frame-processor pipeline ([pipeline](https://docs.pipecat.ai/guides/learn/pipeline),
[custom processor](https://docs.pipecat.ai/guides/fundamentals/custom-frame-processor)).
Relevant frames: `FunctionCallFromLLM` (LLM emitted a tool call), `FunctionCallsStartedFrame`,
`FunctionCallCancelFrame` ([function calling](https://docs.pipecat.ai/pipecat/learn/function-calling)).
Each carries `function_name`, `tool_call_id`, `arguments`, and an LLM context handle.
A custom `FrameProcessor` overrides `async def process_frame(self, frame, direction)`,
branches on `isinstance(frame, FunctionCallFromLLM)`, and either pushes downstream or
substitutes a deny result. **Cleanest hook of the four** because Pipecat's whole model
is "insert your processor." Python only.

### 1.3 Vapi

Managed. Tool surface is a server URL set at the assistant or per-function level
([custom tools](https://docs.vapi.ai/tools/custom-tools), [server URLs](https://docs.vapi.ai/server-url/setting-server-urls)).
Vapi POSTs JSON with `message.toolCallList[]` (`id`, `name`, `arguments`),
`message.toolWithToolCallList[]`, and call context; server returns
`{ "results": [{ "toolCallId": X, "result": Y }] }`. HMAC via `X-Vapi-Signature`
([server auth](https://docs.vapi.ai/server-url/server-authentication)). The integration
surface is a plain HTTPS endpoint; Chio's job is to *be* that endpoint (or sit in front).

### 1.4 Retell

Managed, similar shape ([custom function](https://docs.retellai.com/build/single-multi-prompt/custom-function),
[webhook](https://docs.retellai.com/features/webhook)). Standard payload:
`{ "name": "...", "call": { ... }, "args": { ... } }`, with an optional "args only"
mode. Response: 2xx body becomes the function result (15000-char cap, 2 min timeout,
2 retries). HMAC via `X-Retell-Signature`. Quoted average end-to-end latency is around
600 ms with the function-call leg metered separately.

## 2. Bridge contract boundary

The repeated pattern across all four platforms: **the tool-call event is a JSON
request/response**; **the audio pipeline is not**.

**In scope**: LiveKit `@function_tool` invocation, Pipecat `FunctionCallFromLLM`,
Vapi server-URL POST + `results[].result` response, Retell custom-function POST +
string/JSON response.

**Out of scope**: audio frames (PCM, Opus, RTP), VAD events, interruption / barge-in,
STT and TTS pipelines, WebRTC signalling, session lifecycle.

Chio is not a session manager. The verdict path is a thin synchronous slice between
"LLM decided to call a tool" and "the tool actually runs." This is the same shape
already enforced for Anthropic tool use via `chio-tool-call-fabric` and the
provider adapter (`crates/chio-anthropic-tools-adapter`). OpenAI function-tool
adapter work remains deferred until v1 receipt/read-boundary gates land. The
voice bridge work is about getting the platform-native tool-call event *into*
that fabric.

## 3. Latency budget

Voice research converges on sub-500 ms end-to-end, with the function-call leg getting
a 200-300 ms slot ([Hamming AI](https://hamming.ai/resources/voice-ai-latency-whats-fast-whats-slow-how-to-fix-it),
[Smallest.ai](https://smallest.ai/blog/designing-voice-assistants-stt-llm-tts-tools-and-latency-budget)).
The 200 ms threshold matches the natural human conversational gap. Coordinate with X2
on a numeric baseline. Realistic per-stage budget for Chio's slice:

| Stage | Estimated budget |
| --- | --- |
| Network platform -> Chio (intra-region) | 2-10 ms |
| Caller identity extraction + manifest lookup | <1 ms |
| Guard evaluation (cached policy, no external fetch) | 1-5 ms |
| Receipt body construction + canonical JSON | <1 ms |
| Signing (Ed25519) | ~25 us |
| Signing (Ed25519 + ML-DSA-65 hybrid) | ~150-225 us |
| Receipt durability write | 5-50 ms (sync) or <1 ms (async enqueue) |
| Network return | 2-10 ms |

Ed25519 [benchmarks](https://medium.com/@moeghifar/post-quantum-digital-signatures-the-benchmark-of-ml-dsa-against-ecdsa-and-eddsa-d4406a5918d9)
at ~25 us per sign (~50k ops/sec/core). ML-DSA-65 adds ~100-200 us per sign, ~50 us
per verify. Both fit. The hybrid path (`crates/chio-core-types/src/pq.rs:31`) is not
the bottleneck.

The bottleneck is the durability write. Two options:

- **Sync sign + sync write**: 5-50 ms depending on backend; the high end eats the
  budget.
- **Sync sign + async write** (recommended): Chio signs inline so the platform gets
  a signed allow/deny in the response, then enqueues the durable write.

Async durability requires (1) a bounded in-process queue with fail-closed backpressure
(a missing receipt cannot mean "allow"; queue saturation must deny), (2) per-verdict
sequence numbers signed into the body so missing receipts are detectable on replay,
(3) coordination with X1 on a "deferred durability" status flag in v3. **Signing
latency is not the limiter and the post-quantum half is affordable**; the limiter is
durability, and deferring is sound given sequence numbers and a fail-closed queue.

## 4. Per-platform bridge design

### 4.1 LiveKit (priority 1 at MVP)

**Option A: `chio-livekit-py` Python package.** A `chio_function_tool(...)` decorator
wraps LiveKit's `@function_tool`. Before user code runs: build a `ToolInvocation` from
`RunContext` + args, call `chio-kernel` over the existing Python -> Rust bridge used
by `chio-streaming` and `chio-sdk-python`, emit signed `ChioReceipt`, on Deny return a
stringified refusal that keeps the LLM context well-formed (avoids
[livekit/agents#5092](https://github.com/livekit/agents/issues/5092)).

**Option B: custom `LLMService` wrapper** intercepting `function_call` output at the
stream level. More invasive but gives one insertion point covering all tools
regardless of who defined them.

Ship A at MVP, B as follow-on. Both reuse the existing kernel. The native MCP path
already routes through `chio-mcp-edge`, so MCP-served tools are covered for free.

### 4.2 Pipecat (priority 2)

`chio-pipecat` Python package exposing `ChioVerdictProcessor(FrameProcessor)`. Sits
downstream of the LLM service, intercepts `FunctionCallFromLLM`: pushes downstream on
Allow, pushes a substitute `FunctionCallResultFrame` on Deny. Receipts emit as a side
effect of the verdict call.

### 4.3 Vapi + Retell (priority 3, paired)

Two deployment shapes for both:

- **In-front-of**: Vapi/Retell points at a Chio-hosted endpoint that forwards to the
  customer's real function endpoint after the verdict. Zero code changes; one extra
  hop; HMAC key swap.
- **In-process**: customer adopts a small Chio HTTP shim wrapping their function
  handler. Verdict + tool run in-process; no extra hop.

Both verify `X-Vapi-Signature` / `X-Retell-Signature` HMAC before any work. Payload
shapes differ (`toolCallList` vs `name/call/args`, plus Retell's "args only" mode)
but the overall flow is identical, so ship a single `chio-managed-voice-shim`
crate/package with adapter shims rather than two near-identical crates. Handle the
15000-char Retell cap on Deny strings.

### 4.5 Platform/language matrix

| Platform | Required language | Existing Chio surface | Bridge type |
| --- | --- | --- | --- |
| LiveKit Agents | Python (primary), TS | `chio-sdk-python`, `chio-streaming` | Python middleware crate |
| Pipecat | Python | `chio-sdk-python` | Python `FrameProcessor` |
| Vapi | Any | `chio-mcp-remote` HTTP edge | HTTP shim (Python/Node/Go) |
| Retell | Any | `chio-mcp-remote` HTTP edge | HTTP shim (shared with Vapi) |

**Python first**: three of the four bridges are most naturally Python. A native Rust
LiveKit bridge using the `livekit` Rust SDK is feasible but lower priority because
LiveKit's agent ecosystem is Python-centric. Defer.

## 5. Identity model

Voice calls have two principals where today's `CallerIdentity`
(`crates/chio-http-core/src/identity.rs:44`) has one.

**Agent identity** is already covered by `CallerIdentity.subject` + `auth_method`:
LiveKit binds via JWT room token (bearer + token hash), Pipecat infers from session,
Vapi and Retell use API keys (`AuthMethod::ApiKey`). No schema change needed; set
`agent_id` to the platform's assistant identifier.

**Human identity** (new). The human on the call is a distinct principal. Proposal:
add `Option<HumanPrincipal>` on `CallerIdentity` (back-compat: omitted from canonical
JSON when `None` so existing signatures still verify):

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HumanPrincipal {
    PhoneNumberE164 { number_hash: String, verified: bool },
    AuthenticatedUser { subject: String, idp: String, verified: bool },
    Anonymous,
}
```

Phone numbers are SHA-256 hashed in receipts, matching the bearer-token / API-key
pattern (`identity.rs:11-19`). `verified` flips true only when SIP-side STIR/SHAKEN
attestation A or an upstream IdP signature was validated; raw caller-ID without
STIR/SHAKEN A stays `verified: false`. Anonymous covers calls without caller-ID and
unauthenticated web-WebRTC sessions. Coordinate with X1: if v3 promotes this to a
top-level receipt field rather than carrying it on `CallerIdentity`, the bridge can
populate either location since both flow into the canonical signature.

## 6. Receipt fields

Voice-specific fields land under `ChioReceiptBody.metadata` (free-form JSON today) for
v2 and graduate to typed fields in v3:

| Field | Purpose | Notes |
| --- | --- | --- |
| `session_id` / `call_id` | Stable identifier for the call | Maps to LiveKit room name, Pipecat session id, Vapi `call.id`, Retell `call.call_id` |
| `participant_id` | Identifier for the speaking participant | LiveKit participant identity; Pipecat user id; Vapi / Retell typically one human, so optional |
| `audio_timestamp_estimate` | Where in the call the tool fired (ms) | Best-effort from platform; useful for forensic replay of recorded calls |
| `human_principal` | See section 5.2 | Optional, hashed |
| `platform` | One of `livekit`, `pipecat`, `vapi`, `retell` | Enum tag for replay tooling |

All fields are optional in v2 (carried under `metadata.voice = { ... }`) so existing
verifiers stay compatible; v3 promotes them to a typed `voice_context` block. The
`audio_timestamp_estimate` is best-effort (no platform emits a guaranteed monotonic
call clock); platform-reported tool-call timestamp relative to call start is enough
for cross-correlation with recordings.

## 7. Phased rollout

**Wave V-A (MVP)**: `chio-livekit-py` Python middleware. LiveKit is OSS, has the
biggest 2026 momentum, has native MCP (MCP-served tools route through
`chio-mcp-edge` for free), and the integration is a thin decorator. Bundle the
`HumanPrincipal` field on `CallerIdentity` and the v2 `metadata.voice` block.

**Wave V-B**: `chio-pipecat` `FrameProcessor`. Mechanical once V-A is in.

**Wave V-C**: `chio-managed-voice-shim` paired Vapi+Retell HTTP adapter. Lower
priority because both are thin webhook wrappers, but the named shim standardizes HMAC
verification, payload mapping, Deny shaping within the 15000-char cap, and
replay-safety for retries.

**Defer**: native Rust LiveKit bridge. LiveKit's agent ecosystem is Python-centric in
2026. Revisit when customer demand or a `livekit-agents-rust` project appears.

## 8. Risks and watch-outs

- **Latency overrun**: budget assumes intra-region network and warm caches.
  Cross-region calls blow the budget by themselves. Mitigation: Chio sidecars
  in-region next to the voice platform, strict per-region affinity. Document the
  regional deployment requirement up front.
- **Async write failure modes**: queue saturation must fail closed (Deny). Queue
  depth becomes a first-class SLO in `crates/chio-metrics-spec`.
- **LiveKit interruption + missing tool result** ([livekit/agents#5092](https://github.com/livekit/agents/issues/5092)):
  the Deny path must always emit a synthetic tool-result payload. Highest-risk
  integration detail at MVP.
- **Cross-platform consistency**: the same tool via four bridges must produce
  structurally identical receipts. Extend `crates/chio-provider-conformance` with a
  `voice/` fixture family.
- **Audio replay attacks**: not Chio's concern. Signed receipts authenticate the
  tool-call event, not the audio. Replayed audio that produces a new tool call goes
  through its own verdict and earns its own receipt.
- **Caller-ID spoofing**: `PhoneNumberE164.verified` must be false unless STIR/SHAKEN
  attestation A is validated. Encourage policies to gate sensitive tools on
  `verified == true`.
- **HMAC key rotation**: Vapi/Retell HMAC keys live outside Chio. The shim should
  accept a key-resolver callback, not a baked key, so customers can rotate without
  redeploy.

## Sources

- LiveKit Agents framework: <https://github.com/livekit/agents>
- LiveKit function calling: <https://docs.livekit.io/agents/voice-agent/function-calling/>
- LiveKit tools overview: <https://docs.livekit.io/agents/logic/tools/>
- LiveKit MCP support: <https://docs.livekit.io/mcp/>
- LiveKit interruption bug: <https://github.com/livekit/agents/issues/5092>
- Pipecat function calling: <https://docs.pipecat.ai/pipecat/learn/function-calling>
- Pipecat custom processor: <https://docs.pipecat.ai/guides/fundamentals/custom-frame-processor>
- Pipecat frames reference: <https://reference-server.pipecat.ai/en/stable/api/pipecat.frames.frames.html>
- Vapi custom tools: <https://docs.vapi.ai/tools/custom-tools>
- Vapi server URLs: <https://docs.vapi.ai/server-url/setting-server-urls>
- Vapi server auth (HMAC): <https://docs.vapi.ai/server-url/server-authentication>
- Retell webhook: <https://docs.retellai.com/features/webhook>
- Retell custom function: <https://docs.retellai.com/build/single-multi-prompt/custom-function>
- Voice latency budgeting: <https://hamming.ai/resources/voice-ai-latency-whats-fast-whats-slow-how-to-fix-it>
- Voice latency budgeting: <https://smallest.ai/blog/designing-voice-assistants-stt-llm-tts-tools-and-latency-budget>
- Signature benchmark Ed25519 vs ML-DSA: <https://medium.com/@moeghifar/post-quantum-digital-signatures-the-benchmark-of-ml-dsa-against-ecdsa-and-eddsa-d4406a5918d9>
- Internal: `crates/chio-http-core/src/identity.rs:44` (CallerIdentity)
- Internal: `crates/chio-core-types/src/receipt.rs:159` (ChioReceiptBody)
- Internal: `crates/chio-core-types/src/pq.rs:31` (ML-DSA-65 backend)
- Internal: `crates/chio-guards/src/action.rs:16` (ToolAction)
- Internal sibling doc: `docs/research/protocol-strategy/09-event-action-schema.md`
- Internal sibling doc: `docs/research/protocol-strategy/00-overview.md`
