# Bridges & Adapters Consistency Review

Reviewer task: 6-agent swarm cluster #2 (bridges/adapters). Scope: docs 02, 08,
12, 13, 14, plus both overviews (00, 00-overview-v2) for naming and cross-doc
claims. Grounded against the branch checkout for
`research/protocol-strategy-2026`.

## TL;DR

The five bridge proposals all map onto the real `ToolServerConnection` trait
without inventing methods that do not exist, and each receipt block has a
matching `ExtensionNamespace` in doc 15. The cluster has three concrete
inconsistencies worth fixing before any of these land: doc 02 still uses the
old `chio-bridge-acp` crate name (overridden by doc 08's `chio-bridge-agntcy`),
the `tool_origin` enum has three different variant sets across docs 00-v2 /
12 / 15, and the crate-naming convention introduces a new `chio-bridge-*`
prefix that does not exist anywhere in the current workspace. Otherwise the
cluster reads as internally coherent.

## Verified `ToolServerConnection` trait shape

Trait lives at `crates/chio-kernel/src/runtime.rs:255`. Verbatim surface:

```rust
#[async_trait::async_trait]
pub trait ToolServerConnection: Send + Sync {
    fn server_id(&self) -> &str;                                  // sync, required
    fn tool_names(&self) -> Vec<String>;                          // sync, required
    async fn invoke(&self, name: &str, args: Value,
                    bridge: Option<&mut dyn NestedFlowBridge>)
        -> Result<Value, KernelError>;                            // async, required
    async fn invoke_with_cost(...)
        -> Result<(Value, Option<ToolInvocationCost>), KernelError>; // async, default
    async fn invoke_stream(...)
        -> Result<Option<ToolServerStreamResult>, KernelError>;   // async, default -> None
    async fn drain_events(&self)
        -> Result<Vec<ToolServerEvent>, KernelError>;             // async, default -> []
}
```

Supporting types: `ToolCallChunk { data: Value }` at
`crates/chio-kernel/src/runtime.rs:111`, `ToolCallStream { chunks: Vec<...> }`
at `runtime.rs:117`, `ToolServerStreamResult::{Complete, Incomplete{stream,
reason}}` at `runtime.rs:136`, `NestedFlowBridge` at `runtime.rs:156`,
`ToolServerEvent::{ElicitationCompleted, ResourceUpdated, ResourcesListChanged,
ToolsListChanged, PromptsListChanged}` at `runtime.rs:312`.

Existing reference impls: `crates/chio-mcp-adapter/src/lib.rs:410`
(`AdaptedMcpServer`), `crates/chio-mcp-adapter/src/native.rs:384`
(`NativeChioService`), `crates/chio-a2a-adapter/src/invoke.rs:1315`
(`A2aAdapter`). All five bridge proposals follow this pattern.

## Per-bridge consistency check

| Bridge (doc)              | Maps `invoke` | Maps `invoke_stream`           | Maps `drain_events`             | Trait methods invented? |
|---------------------------|---------------|--------------------------------|---------------------------------|-------------------------|
| 02 NANDA/AGNTCY/Agora     | yes (sketch)  | yes (SSE for ACP)              | not used                        | no                      |
| 08 AGNTCY ACP             | `/runs/wait`  | `/runs/stream` SSE             | empty vec MVP                   | no (but proposes new `KernelError::ToolInterrupted` variant, doc-08:122) |
| 12 OpenAI Responses       | yes           | yes (Response SSE stream)      | not used; per-event traces emitted instead | no, but adapter exposes its own `Stream<Item = AdapterEvent>` to the kernel beyond the trait (doc-12:213) |
| 13 Bedrock Agents         | yes (sub-eval)| yes (event-stream)             | not used                        | no, but sub-evaluation pattern recursively calls `invoke` from inside `invoke_stream` (doc-13:67) |
| 14 Voice (LiveKit etc.)   | yes (per-call)| not used (voice tool call is one-shot JSON) | not used                | no                      |

All five maps are sound against the real trait surface. Three caveats:

1. Doc 08 wants a new `KernelError::ToolInterrupted { interrupt_id, payload }`
   variant; `KernelError` lives at `crates/chio-kernel/src/kernel/mod.rs` (the
   exact line cited in doc 08 as `:473` was not verified line-for-line, but
   the variant is unambiguously additive). Flag this as a kernel-side change
   the AGNTCY bridge depends on.
2. Doc 12's `LlmToolAdapter` trait sketch (doc-12:255) lives at the adapter
   layer, not the kernel layer. It does not replace `ToolServerConnection`
   and is a separate refactor proposal for `chio-provider-adapter-core`.
3. Doc 13's recursive `invoke` from inside `invoke_stream` (one sub-call per
   `RETURN_CONTROL` entry) is structurally fine but worth calling out
   explicitly. The doc notes the analogy to `NestedFlowBridge`
   (`runtime.rs:156`) at line 71 but does not actually use the
   `NestedFlowBridge` parameter passed into `invoke`. See section "NestedFlow
   inventory" below.

## Naming convention recommendation

The workspace today has 100 `chio-*` crates and the bridge/adapter axis is
not "bridge"; it is direction-of-flow:

- `chio-*-edge`: expose Chio out to an external protocol consumer (Chio is
  the server, external is the client). Examples: `chio-acp-edge` (Zed ACP,
  `crates/chio-acp-edge/src/lib.rs:3-11` confirms this is Zed's Agent Client
  Protocol), `chio-a2a-edge`, `chio-mcp-edge`.
- `chio-*-adapter`: consume an external protocol as a Chio tool server (Chio
  is the client/mediator). Examples: `chio-mcp-adapter`, `chio-a2a-adapter`,
  `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`,
  `chio-cohere-tools-adapter`, `chio-gemini-tools-adapter`,
  `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`,
  `chio-ollama-tools-adapter`, `chio-openapi-mcp-bridge` (lone exception).
- `chio-*-proxy`: variant of adapter that re-frames a call. Examples:
  `chio-acp-proxy`, `chio-ag-ui-proxy`.

There is **no `chio-bridge-*` prefix in the current workspace.** Doc 08
introduces it explicitly (doc-08:432) and rejects the alternatives
`chio-acp-bridge` (collides with Zed ACP namespace) and `chio-agntcy-acp`
(breaks "Chio's existing `chio-bridge-*` prefix convention"). The latter
justification is wrong on the facts: there is no existing `chio-bridge-*`
convention. The convention is `-edge` / `-adapter` / `-proxy`.

**Recommendation:** rename to `superseded AGNTCY ACP adapter name`. Rationale:

- Functional flow matches `-adapter`: AGNTCY ACP servers are consumed as
  Chio tool servers via `impl ToolServerConnection`. Doc 08 itself models
  this as adapter-shaped (doc-08:522, `impl ToolServerConnection for
  AgntcyAcpBridge`).
- The vendor disambiguator (`agntcy-acp`) defeats the three-ACPs
  collision flagged in doc 00:69-75, without inventing a new prefix.
- Sibling crates `chio-bedrock-agents-adapter` (doc 13) and
  `chio-openai-responses-adapter` (doc 12) already match the `-adapter`
  convention. Aligning AGNTCY with them produces a coherent five-crate set.
- Doc 02's `chio-bridge-acp` (lines 132, 187, 243, 268) and
  `chio-bridge-agora` (lines 187, 268) become `superseded AGNTCY ACP adapter name`
  and `chio-agora-adapter` for consistency.
- `chio-livekit-py` (doc 14) is a Python middleware package, not a Rust
  crate; leave as-is. Pipecat and Vapi+Retell follow the same shape
  (`chio-pipecat`, `chio-managed-voice-shim`).
- `chio-directory` (doc 08) is fine as a leaf trait crate. It is not a
  bridge or adapter; the trait is generic. Sibling impls
  (`chio-directory-nanda`, eventually `chio-directory-oasf`) follow.

If reviewers insist on `chio-bridge-*`, the rule must be applied uniformly
and the eleven existing `*-adapter` / `*-edge` crates need a workspace-wide
rename. That is far more disruptive than fixing the four new docs.

## DirectoryProvider trait alignment

Doc 02 sketches the trait (lines 207-223) with `name`, `lookup`,
`allowlisted`, and a `DirectoryRecord { canonical_id, endpoints,
advisory_capabilities, signed_blob, upstream_signer }`. Doc 08 spec's it
concretely (lines 237-302) and adds: a `refresh()` method, `DirError`,
`EndpointHint { protocol, url, transport }`, `fetched_at`, and
`blob_sha256`. The shapes are compatible; doc 08 is a superset.

Crate location: doc 02 floats `chio-directory` (line 207); doc 00-overview
v1 originally implied `chio-federation` (rejected reasonably in doc-08:227
because `chio-federation` is heavier-weight: relay peering, quarantine,
observability, per `crates/chio-federation/src/lib.rs:1-30` which is mostly
bilateral-trust and gossip code). **Pick `chio-directory`.** It is a leaf
crate with a single trait and no kernel dependency. The federation crate is
about bilateral runtime trust, not read-only peer indexes.

Receipt-side: doc 02 says the `signed_blob` and directory name go into
receipt metadata as provenance. Doc 08 says the same plus `blob_sha256`,
`upstream_signer`, and `provider`. Doc 15 has a dedicated
`DirectoryTraceExtension` (line 461) which is the right home for these.

## Bridge identity stories vs. `CallerIdentity`

Verified shape at `crates/chio-http-core/src/identity.rs:8-65`:

```rust
pub enum AuthMethod { Bearer { token_hash }, ApiKey { key_name, key_hash },
    Cookie { cookie_name, cookie_hash }, MtlsCertificate { subject_dn,
    fingerprint }, Anonymous }
pub struct CallerIdentity { subject, auth_method, verified, tenant,
    agent_id }
```

| Doc | Identity claim                                                                | Maps cleanly?                                                                                          |
|-----|-------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 08  | Bearer / mTLS / API key, subject = `did:web:...`, agent_id = ACP UUID         | yes; all variants exist                                                                                |
| 12  | Bearer API key as `AuthMethod::ApiKey { key_name: "Authorization", key_hash }`| yes; consistent with `identity.rs:14-20`                                                               |
| 13  | Reuses signed `IamPrincipalsConfig` (sibling crate)                           | yes; uses existing `Principal::BedrockIam` (`chio-tool-call-fabric/src/lib.rs:233`), not `CallerIdentity` directly. Worth a cross-reference note in doc 13. |
| 14  | LiveKit JWT (Bearer), Vapi/Retell API key, plus **new `HumanPrincipal`** enum | adds a field to `CallerIdentity` (`human_principal: Option<HumanPrincipal>`). Not yet present in `identity.rs`. This is a real schema extension. |
| 02  | Falls back to HTTP substrate auth + `did:web` / `did:jwk` subject             | yes for HTTP; `did:jwk` is not standard in chio identity today (doc 02:118)                            |

Concrete inconsistency: doc 02:118 says "did:jwk", doc 08:174-181 says
"did:web" / "did:key" with explicit reservation of `did:chio` for local
kernel-attested principals. Pick one: prefer doc 08's rule
(`did:jwk` is unnecessary; `did:key` already covers raw-key cases).

The `human_principal` addition (doc 14:209) is the only proposal that
actually changes the `CallerIdentity` struct shape. Doc 15:446-452 puts it
in the `VoiceExtension` instead. Two locations is fine for v2 ->
v3 transition (doc 14 itself acknowledges this at lines 220-222), but the
final landing should pick one. Recommend: stay in `VoiceExtension` for v3;
`CallerIdentity` is HTTP-substrate-shaped and adding a voice-specific human
principal couples it to one bridge family.

## Receipt-fields cross-reference

Each per-bridge field list against doc 15's `ExtensionNamespace`:

| Bridge field set                                                        | Doc 15 extension                | Match? |
|-------------------------------------------------------------------------|---------------------------------|--------|
| 08: `acp_peer_id`, `acp_message_id`, `directory_entry_hash`             | `AgntcyExtension` (line 454)    | yes; doc 15 also has `directory_provider_id`, doc 08 calls it `provider` inside `directory_entry`. Rename one for consistency. |
| 08: full `metadata.agntcy_acp` block (doc-08:343-362)                   | `AgntcyExtension`               | doc 08 puts everything under `metadata.agntcy_acp`; doc 15 promotes this to a typed extension. Doc 08 should reference doc 15's typed shape. |
| 12: `response_id`, `model_version`, `system_fingerprint`, `tool_origin` | `OpenaiResponsesExtension` (425)| yes. `tool_origin` lives on core body per doc 00-v2:35 plus the extension. |
| 13: `agent_id`, `agent_alias_id`, `session_id`, `action_group_kind`, `return_control_payload_hash`, `trace_redaction_mode` | `BedrockAgentsExtension` (434) | yes; doc 15 also has `invocation_id`, `action_group_id`, `knowledge_base_citations`. Doc 13 enumerates a superset (doc-13:84-97). Reconcile field names: doc 13 calls one field `action_group_kind`, doc 15 calls the type `ActionGroupKind` (consistent). |
| 14: `call_id`, `participant_id`, `audio_timestamp_estimate`, `human_principal`, `platform` | `VoiceExtension` (446)          | yes; field-for-field match. |

Naming nit: doc 13 also enumerates `action_group_schema_style`,
`trace_redaction_salt_id`, `caller_chain`, `mediation_scope` (lines 91-97).
Doc 15's `BedrockAgentsExtension` does not list these. Adding them to the
extension shape is fine (extensions are independently versioned per
doc-15:481), but doc 15 should explicitly accept the larger field set or
doc 13 should mark them as optional/follow-on.

## Inconsistencies and contradictions

1. **Crate name for AGNTCY ACP bridge.** Doc 02 (lines 132, 187, 243, 268)
   still uses `chio-bridge-acp` and `chio-bridge-agora`. Doc 08 supersedes
   with `chio-bridge-agntcy`. Doc 00 (v1) line 41 still says
   `chio-bridge-acp`. Doc 00-v2 lines 23, 43, 65 use `chio-bridge-agntcy`.
   **Fix:** rewrite doc 02 sections 2.6, 5.1, 5.4 to use the agreed name.
   See naming-convention recommendation above for the further switch to
   `superseded AGNTCY ACP adapter name`.

2. **`tool_origin` variant set.** Three different versions across the
   cluster:
   - Doc 12:151-156: `CallerExecuted | HostExecutedProviderReported {
     provider_report_ref } | HostExecutedUnmediated` (struct variant).
   - Doc 15:429-431: `ToolOrigin { HostExecutedUnmediated |
     HostExecutedProviderReported | CallerExecuted }` (plain enum, no attestation
     payload).
   - Doc 00-v2:35: adds a fourth, `host-executed-redacted`, that appears
     nowhere else.
   **Fix:** pick one. Recommend doc 12's three-variant struct shape with
   `HostExecutedProviderReported { provider_report_ref: String }` and drop
   `host-executed-redacted` from doc 00-v2 unless docs 12/13/15 are updated
   to define it. A redaction state is a separate orthogonal flag, not a
   tool-origin variant.

3. **`did:jwk` vs `did:key`.** Doc 02:118 uses `did:jwk`. Doc 08:174-181
   reserves `did:web` and `did:key`. Pick doc 08.

4. **`directory_provider_id` vs `provider`.** Doc 08 uses `provider` inside
   the receipt directory_entry sub-object (doc-08:354). Doc 15's
   `AgntcyExtension` uses `directory_provider_id`. Pick one.

5. **`spec.acp.agntcy.org` archive date.** Doc 02:85 says archived
   `April 11, 2026`. Doc 08:30 says `2026-04-11`. Same date, different
   formats. Cosmetic.

6. **`chio-openapi-mcp-bridge`.** Workspace already has a `-bridge` crate
   (`crates/chio-openapi-mcp-bridge`). This contradicts the recommendation
   to ban `-bridge` from the naming convention. Either rename that crate to
   `chio-openapi-mcp-adapter` in a separate cleanup (it is currently a
   one-off, not a convention) or accept `-bridge` as a third valid suffix
   restricted to "spec-driven translation" bridges. The former is cleaner.

7. **`NestedFlowBridge` use.** Inventory in doc 00 (covered indirectly via
   the runtime trait) lists `NestedFlowBridge` for in-band server-to-client
   callbacks (`runtime.rs:156`). Of the five proposals:
   - Doc 08 references the parameter in its trait impl signature (lines
     527-533) but never uses it; ACP has no roots-list or sampling concept.
   - Doc 12 ignores it; OpenAI Responses dispatches its own internal loop.
   - Doc 13 cites it as an analog for the sub-evaluation tree (line 71)
     but does not actually consume the parameter passed into `invoke`; the
     sub-evaluation is implemented by recursively calling the kernel's tool
     registry from inside the bridge.
   - Doc 14 does not reference it.
   **Should any use it?** Doc 13's `RETURN_CONTROL` sub-evaluation pattern
   is the closest fit. Today's `NestedFlowBridge` is MCP-shaped (roots,
   elicitation, resource notifications). Bedrock's sub-evaluation would
   need a different shape (recursive tool dispatch with shared lineage).
   Either extend `NestedFlowBridge` or document the recursive-dispatch
   pattern as a separate seam. Flag for kernel-team coordination.

## MVP scope granularity

All five MVPs are realistically scoped:

- Doc 02 (NANDA/AGNTCY/Agora): three phases, ACP-only first, NANDA second,
  SLIM third, Agora deferred. Reasonable.
- Doc 08 (AGNTCY ACP): two endpoints (`/runs/wait`, `/runs/stream`), three
  validation targets, static directory. Tightest of the five.
- Doc 12 (OpenAI Responses): function tools only, streaming only,
  non-reasoning models only. Refuses host-executed tools at boundary.
  Right-sized.
- Doc 13 (Bedrock Agents): `RETURN_CONTROL` mediation only, two regions,
  summary redaction default, IAM reuse from sibling adapter. Right-sized;
  Lambda is explicitly out by trust boundary.
- Doc 14 (voice): LiveKit Python middleware first. Right-sized; Pipecat
  and Vapi+Retell are follow-on. The async-write durability decision is
  load-bearing and deserves its own coordination with X1 (already flagged).

No MVP is too ambitious or too narrow.

## Three-ACPs warning audit

Doc 00 (v1) lines 69-75 names all three ACPs and warns against
`chio-acp-*`. Doc 00-v2 implicitly endorses the fix by using
`chio-bridge-agntcy`. Doc 02 still uses `chio-bridge-acp` everywhere (lines
132, 187, 243, 268). Doc 08 explicitly handles the collision (lines 11-12,
432-444). Doc 12, 13, 14 do not touch ACP naming.

**Action:** rewrite doc 02 to remove all `chio-bridge-acp` / `chio-acp-*`
references. Replace with whichever crate name the reviewer body picks (my
recommendation: `superseded AGNTCY ACP adapter name`). Update doc 00 (v1) line 41
similarly, or supersede with v2.

## Recommended edits per doc

- **Doc 02:** rename `chio-bridge-acp` -> agreed name (sections 2.6, 5.1,
  5.4). Switch `did:jwk` -> `did:key` on line 118. Drop the section-4
  trait sketch in favor of doc 08's concrete shape with a forward
  reference.
- **Doc 08:** rename `chio-bridge-agntcy` -> agreed name throughout
  (sections 8.1, 8.2, 8.3, 8.4). Reconcile `provider` vs
  `directory_provider_id` with doc 15. Add a paragraph clarifying that
  the unused `NestedFlowBridge` parameter is intentionally accepted but
  not used (ACP has no analog).
- **Doc 12:** confirm `tool_origin` enum shape with X1 and update either
  doc 12 or doc 15 so the variant sets match. Drop reference to a fourth
  `HostExecutedRedacted` variant if it survives in doc 00-v2.
- **Doc 13:** confirm whether the recursive-dispatch sub-evaluation
  reuses `NestedFlowBridge` or introduces a new seam; document either
  way. Add cross-reference for `Principal::BedrockIam` vs
  `CallerIdentity` so readers know which identity layer applies.
- **Doc 14:** decide whether `human_principal` lives on `CallerIdentity`
  (new field) or in `VoiceExtension` (doc 15). Recommend the latter.
  Confirm v2 metadata block name (doc 14 says `metadata.voice`,
  consistent with doc 15's `VoiceExtension`).
- **Doc 00 (v1) and v2:** drop the fourth `tool_origin` variant
  (`host-executed-redacted`) from v2 line 35 unless adopted in 12/15.
  Update v1 line 41 to use the agreed AGNTCY crate name, or formally
  retire v1 in favor of v2.

## 3-line summary

1. Bridge cluster is broadly consistent: all five map onto the real
   `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:255`
   without inventing methods, and each receipt block has a matching
   `ExtensionNamespace` in doc 15.
2. Naming recommendation: drop the new `chio-bridge-*` prefix; use the
   workspace's existing `chio-<vendor>-<protocol>-adapter` convention,
   giving `superseded AGNTCY ACP adapter name`, alongside `chio-bedrock-agents-adapter`,
   `chio-openai-responses-adapter`, and `chio-directory`.
3. Output written to
   this file.
