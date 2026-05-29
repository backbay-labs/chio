# 15 - Receipt schema stress test and current v1 evolution strategy

> **Historical research note (PR 652):** This document stress-tested a design
> that was previously framed as a later receipt generation. Chio is unreleased,
> so accepted planning folds these semantics into the current v1 receipt shape.
> Treat mentions of later generations, schema compatibility limits,
> negotiation, compatibility paths, and compatibility windows below as
> historical sketches unless [18-decision-packet.md](18-decision-packet.md)
> keeps them.
>
> **Erratum - canonical current fields:**
>
> - **`policy_hash`** is the current signed receipt field. It is a hex or
>   operator-pinned `String` (RFC 8785 canonical-JSON friendly), not `[u8; 32]`.
>   Earlier `policy_digest` references are per-engine digest sketches, not a
>   current core receipt field.
> - **`tool_origin`** records execution locus, not redaction policy. ADR-0010 keeps `tool_origin` and `redaction_mode` as separate signed current v1 fields. Planning default: `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`.
> - **Extension signing, `extensions_hash`, and `must_understand` are deferred.**
>   This document explored them, but they are not current signed v1 fields and
>   require a separate accepted extension-binding design.
> - **`human_principal`** is the typed `HumanPrincipal` enum defined on `CallerIdentity` in [doc 14](14-voice-agent-bridges.md). This doc's `VoiceExtension` references it by canonical encoding, not as a duplicate `Option<String>` definition.
> - **`ActorRef`** (the actor-chain element type) needs a concrete definition stub. Proposed shape:
>
>   ```rust
>   /// Single actor in a delegation or provenance chain.
>   /// Can encode external on-behalf-of actor-chain hops when that profile is used.
>   #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
>   pub struct ActorRef {
>       /// Stable subject identifier (DID, user ID, agent ID).
>       pub subject: String,
>       /// Issuer that minted this hop's credential (URL or DID).
>       pub issuer: String,
>       /// Scopes asserted at this hop.
>       pub scopes: Vec<String>,
>       /// Hop expiry (RFC 3339 timestamp).
>       pub expires_at: String,
>       /// Optional class tag: human | agent | service.
>       pub principal_class: Option<PrincipalClass>,
>   }
>   ```
>
>   This stub should land in `chio-core-types` alongside the current v1 ReceiptBody promotion. Refine in a follow-on against the IETF draft as it stabilizes.
>
> **Post-review status:** This document is a stress test, not the implementation spec. [18-decision-packet.md](18-decision-packet.md) is the decision packet to settle before tickets are written. It supersedes historical sketches or review notes that show `policy_digest` as a current core field, redaction as a `tool_origin` variant, successor-receipt negotiation, or a decided `extensions_hash` / `must_understand` strategy.

## TL;DR

The historical `ChioReceiptBody` stress test showed that provider- and
surface-specific field piles would turn the receipt body into a 40+ field
god-struct. The accepted direction is narrower: fold receipt-kind, trace, actor
chain, tool-origin, redaction, trust, and existing `policy_hash` semantics into
the current v1 receipt shape, while treating extension signing,
`extensions_hash`, and `must_understand` as deferred until a separate accepted
extension-binding design exists. Provider-specific payloads remain sketches,
not current signed authority.

---

## Current shape audit (citations to working tree)

### `ChioReceiptBody` (the canonical signing input)

Defined at `crates/chio-core-types/src/receipt.rs:158-181`. Field list:

- `id: String`
- `timestamp: u64`
- `capability_id: String`
- `tool_server: String`
- `tool_name: String`
- `action: ToolCallAction` (parameters JSON + `parameter_hash`,
  `receipt.rs:1147-1153`)
- `decision: Decision` (allow / deny / cancelled / incomplete,
  `receipt.rs:1122-1144`)
- `content_hash: String` (SHA-256 of evaluated content)
- `policy_hash: String` (SHA-256 of applied policy,
  `receipt.rs:168`)
- `evidence: Vec<GuardEvidence>` (skip-if-empty, `receipt.rs:169-170`)
- `metadata: Option<serde_json::Value>` (untyped escape hatch,
  `receipt.rs:171-172`)
- `trust_level: TrustLevel` (default Mediated, `receipt.rs:173-174`)
- `tenant_id: Option<String>` (Phase 1.5 multi-tenant,
  `receipt.rs:175-179`)
- `kernel_key: PublicKey`

### `GuardEvidence` (referenced by doc 00 at `receipt.rs:1176`)

`crates/chio-core-types/src/receipt.rs:1174-1184`:

```rust
pub struct GuardEvidence {
    pub guard_name: String,
    pub verdict: bool,
    pub details: Option<String>,  // untyped string today
}
```

### Versioning and signing path

- Chio-owned pre-release receipt semantics are current v1 only. Earlier
  later-generation constants, feature names, and body-hash sketches are
  migration debt or historical planning notes, not a public compatibility
  surface.
- Signing path: `Keypair::sign_canonical` and `sign_canonical_with_backend`
  (`crates/chio-core-types/src/crypto.rs:206,866`) call
  `canonical_json_bytes` (`crates/chio-core-types/src/canonical.rs:102`)
  which sorts object keys by UTF-16 code-unit order per RFC 8785.
  Every body field participates in signing; there is no
  hash-then-sign-the-hash optimization today.
- Negotiation surface: current planning rejects receipt schema ceilings,
  downgrade paths, and schema-generation feature bits before release. Peers
  that cannot validate the current v1 receipt-kind semantics fail closed.
- Extension points today: zero on `ChioReceiptBody`. `metadata:
  Option<serde_json::Value>` is the only escape hatch and is untyped at
  the schema level. Several typed payloads
  (`FinancialReceiptMetadata` `receipt.rs:1210-1240`,
  `FinancialBudgetAuthorityReceiptMetadata` `receipt.rs:1274-1288`,
  `EconomicAuthorizationReceiptMetadataVersion` `receipt.rs:1304-1309`)
  already nest inside `metadata` keyed by ad-hoc strings (`"financial"`,
  `"budget_authority"`, see `receipt.rs:332-345`). This is the
  proto-pattern for what extensions should become.

---

## Proposed additions enumerated (semantic buckets)

### Policy-engine bucket (doc 04, R4)

- `engine_id: &'static str` (Cedar / OPA / OpenFGA / hand-rolled)
- `policy_hash: String` (current receipt-bound policy identifier or digest)
- `decision_id: String` (engine-issued, non-deterministic)
- `obligations: serde_json::Value`
- `diagnostics: Option<String>`

### Identity-chain bucket (doc 03)

- `actor_chain: Vec<ActorRef>` (agent on-behalf-of provenance;
  human -> agent -> sub-agent provenance)
- `dpop_cnf: Option<DpopConfirmation>` (RFC 9449 thumbprint or `jkt`)
- `rar_scope_refs: Vec<RarScopeRef>` (RFC 9396 governed-RAR profile
  references)
- `step_up_challenge: Option<StepUpChallenge>` (RFC 9470)

### Event-action bucket (R3, doc 01)

- `event_decision: EventDecision { destination_or_source: String,
  payload_hash: String, delivery_class: DeliveryClass, broker_id_hash:
  String }`

### Provider-specific buckets (E1, E2, E3, R2, doc 05)

- OpenAI Responses (E1): `tool_origin: ToolOrigin {
  HostExecutedUnmediated | HostExecutedProviderReported | CallerExecuted }`,
  `response_id`, `model_version`, `system_fingerprint`.
- Bedrock Agents (E2): `agent_id`, `agent_alias_id`, `session_id`,
  `invocation_id`, `action_group_id`, `action_group_kind`,
  `return_control_payload_hash`, `trace_redaction_mode`,
  `knowledge_base_citations`.
- Voice (E3): `call_id`, `participant_id`,
  `audio_timestamp_estimate`, `human_principal`, `platform`.
- Directory / AGNTCY identity (R2): `directory_entry_hash`,
  `directory_provider_id`, optional identity issuer metadata. ACP message
  fields are historical only and must not imply an AGNTCY ACP bridge.
- Orchestrator egress (doc 05): `provider_run_id`,
  `provider_run_url`, `validated_egress_target` (the
  `ValidatedHttpEgressTarget` shape from `chio-egress-contract`).

### Directory-trace bucket (doc 02)

- `directory_lookups: Vec<DirectoryLookupTrace>`

### Presigned-URL bucket (doc 06)

- `presigned_url: PresignedUrlEvidence { presign_kind, bucket, prefix,
  expiry_window, signed_method }`

Net new fields under Option A: **30+** on the receipt body (counting
nested structs flatly). Today's body has 13.

---

## Options

### Option A: pure additive fields on `ChioReceiptBody`

Every proposed payload becomes a new `Option<T>` field on
`ChioReceiptBody`. Pros: trivial to implement, no negotiation work, no
extension trait. Cons: the body grows to 40+ fields, RFC 8785
canonicalization sorts and emits every key on every receipt, hot-path
signing cost grows linearly with field count even when most are `None`
because each `Option` pays a `skip_serializing_if` check, and the
schema becomes architecturally vague (a struct that knows about
Bedrock, voice, AGNTCY, OpenAI, S3, and Cedar by name has the wrong
coupling). Worst, federation peers ship to kernels that hard-coded
deserialization at compile time: every new field demands a workspace
rebuild on every verifier.

### Option B: typed extensions map

Replace the untyped `metadata` blob with a typed `extensions:
BTreeMap<ExtensionNamespace, ExtensionPayload>`. Each bridge / engine /
surface registers its own namespace string (`cedar`, `bedrock_agents`,
`voice`, `agntcy`, `events`, `presigned_url`, `openai_responses`,
`directory`, `orchestrator_run`, `identity_chain`). Pros: clean
separation, per-namespace versioning, kernel core has no knowledge of
bridge-specific shapes. Cons: deserialization needs a typed-enum
dispatch (`#[serde(tag = "namespace")]` or
`untagged + try_from`), canonicalization needs deterministic ordering
(BTreeMap suffices because RFC 8785 sorts string keys anyway), and the
fields used on every receipt (`policy_hash`, `actor_chain`, receipt kind,
tool origin, redaction, and trust level) get demoted to "look it up in the
extensions map" which is awkward for replay tooling.

### Historical Option C: hard version bump

Earlier notes considered a hard receipt schema bump. That option is now
rejected for Chio-owned unreleased surfaces. The current protocol line is
v1-only: the receipt-kind, boundary, actor-chain, redaction, and trace
semantics are folded into the current v1 receipt shape instead of
creating compatibility ceilings, downgrade paths, or successor receipt
schemas.

### Option D: hybrid (historical, superseded)

Current status: the accepted pre-release plan folds current authority fields
into the current v1 receipt body. Do not create a successor receipt schema, a
later-generation floor, schema ceilings, or compatibility downgrade paths for
Chio-owned receipts before the first public release.

Promote a small set of universally relevant fields onto the current v1
receipt core body. Use a typed extensions map for everything bridge-, engine-,
or surface-specific. Do not create a successor Chio-owned receipt generation
before the first public release; new pre-release fields are current v1 fields.

Core current v1 fields confirmed by ADR-0010:

- `receipt_kind`
- `actor_chain: Vec<ActorRef>` (every governed-agent receipt has one)
- `tool_origin`, orthogonal to redaction
- `redaction_mode`
- `trust_level`
- `policy_hash`

Everything else (per-provider IDs, voice call metadata, presigned-URL
shapes, AGNTCY directory refs, directory-lookup traces, event broker hashes,
Bedrock action groups, OpenAI response IDs) lives in
deferred extension-binding sketches until a later accepted ADR lands.

---

## Recommendation: current v1 folding

Justification:

1. **Pre-release v1 folding.** Chio is unreleased, so the historical hybrid is folded into
   the current v1 receipt shape rather than shipped as a new generation. This
   keeps one authoritative receipt model while preserving fail-closed parsing.
2. **No schema-version negotiation before release.** The older sketch used
   feature bits and later compatibility limits. PR 652 now treats those as
   historical compatibility work. Verifiers that cannot validate current v1
   receipt-kind semantics fail closed.
3. **Extension binding stays blocked.** RFC 8785 canonicalization remains the
   signing baseline for current v1. Extension-map signing, hash indirection,
   and verification-mandatory extension semantics require a separate accepted
   ADR before they can affect security decisions.

### Historical migration sketch superseded

The earlier migration plan in this section described a later receipt schema and
dual production with older Chio-owned receipt shapes. That plan is superseded.
Before the first public release, Chio-owned receipt semantics are folded into
the current v1 receipt body only. There is no Chio-owned receipt generation
above v1, no schema-ceiling negotiation, no compatibility window, and no
downgrade path for trace or advisory records.

---

## Concrete spec sketch

### Current v1 receipt body Rust shape

```rust
pub const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    pub decision: Decision,
    pub content_hash: String,
    pub policy_hash: String,
    pub receipt_kind: ReceiptKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "is_default_trust_level")]
    pub trust_level: TrustLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_origin: Option<ToolOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_mode: Option<RedactionMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub kernel_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionEnvelope {
    pub version: u32,
    pub must_understand: bool,
    pub payload: ExtensionPayload,
}
```

### Deferred extension namespace and payload

The following extension shapes are sketches only. They are not current signed
v1 authority.

```rust
pub type ExtensionNamespace = String;       // "cedar", "bedrock_agents", ...

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtensionPayload {
    Cedar(CedarExtension),
    EventDecision(EventDecisionExtension),
    IdentityChain(IdentityChainExtension),
    OpenaiResponses(OpenaiResponsesExtension),
    BedrockAgents(BedrockAgentsExtension),
    Voice(VoiceExtension),
    AgntcyDirectory(AgntcyDirectoryExtension),
    DirectoryTrace(DirectoryTraceExtension),
    OrchestratorRun(OrchestratorRunExtension),
    PresignedUrl(PresignedUrlExtension),
    /// Deferred forward-compat slot. Current v1 verifiers must not treat
    /// unknown extension data as signed protocol authority.
    Unknown(serde_json::Value),
}
```

### Signing canonicalization

Extension binding is intentionally not current v1 protocol authority. A future
ADR must decide whether extension payloads are signed inline, signed through an
`extensions_hash`, or excluded from security decisions before any
security-affecting extension ships.

Verifier:

1. Validate the current v1 body shape and kind-dependent decision rules.
2. Verify signature over the current v1 canonical signing input.
3. Reject trace or advisory records that carry mediated decisions.
4. Treat extension payloads as non-authoritative until an accepted
   extension-binding ADR and tests land.

### Federation negotiation

ADR-0010 folds Chio-owned receipt-kind semantics into current v1. Do not add
receipt schema limit fields, schema-generation feature bits, or pre-release
compatibility paths.

- Current plan: one v1 receipt shape.
- Historical candidates: feature bits and schema compatibility limits.
- Federation handshake remains fail-closed: malformed feature names
  abort negotiation before either side uses an upgrade
  (`PROTOCOL.md:286-292`).
- If extension negotiation returns, it needs a new ADR, verifier tests, and
  formal target text that does not imply a successor receipt generation.

---

## Per-extension shape sketches

```rust
pub struct CedarExtension {
    pub engine_version: String,
    pub policy_set_id: String,
    pub policy_hash: String,
    pub decision_id: String,
    pub obligations: serde_json::Value,
    pub diagnostics: Option<String>,
}

pub struct EventDecisionExtension {
    pub direction: EventDirection,            // Publish | Consume
    pub destination_or_source: String,
    pub payload_hash: String,
    pub delivery_class: DeliveryClass,        // AtMostOnce | AtLeastOnce | ExactlyOnce
    pub broker_id_hash: String,
}

pub struct IdentityChainExtension {
    pub actor_chain: Vec<ActorRef>,           // duplicates body.actor_chain
                                              // when chain length > N (rare)
    pub dpop_cnf: Option<DpopConfirmation>,
    pub rar_scope_refs: Vec<RarScopeRef>,
    pub step_up_challenge: Option<StepUpChallenge>,
}

pub struct OpenaiResponsesExtension {
    pub response_id: String,
    pub model_version: String,
    pub system_fingerprint: String,
    pub tool_origin: ToolOrigin,              // HostExecutedUnmediated |
                                              // HostExecutedProviderReported |
                                              // CallerExecuted
}

pub struct BedrockAgentsExtension {
    pub agent_id: String,
    pub agent_alias_id: String,
    pub session_id: String,
    pub invocation_id: String,
    pub action_group_id: String,
    pub action_group_kind: ActionGroupKind,
    pub return_control_payload_hash: Option<String>,
    pub trace_redaction_mode: TraceRedactionMode,
    pub knowledge_base_citations: Vec<KbCitation>,
}

pub struct VoiceExtension {
    pub call_id: String,
    pub participant_id: String,
    pub audio_timestamp_estimate: u64,        // unix millis
    // Human principal is encoded once on CallerIdentity.human_principal.
    pub platform: VoicePlatform,              // Twilio | Vonage | LiveKit | ...
}

pub struct AgntcyDirectoryExtension {
    pub agent_record_id: String,
    pub directory_entry_hash: [u8; 32],
    pub directory_provider_id: String,
}

pub struct DirectoryTraceExtension {
    pub lookups: Vec<DirectoryLookupTrace>,   // see doc 02
}

pub struct OrchestratorRunExtension {
    pub provider: OrchestratorProvider,       // N8n | Zapier | Make | GhActions
    pub provider_run_id: String,
    pub provider_run_url: Option<String>,
    pub validated_egress_target: ValidatedHttpEgressTarget,
}

pub struct PresignedUrlExtension {
    pub presign_kind: PresignKind,            // S3 | Gcs | AzureSas
    pub bucket: String,
    pub prefix: String,
    pub expiry_window: u64,                   // seconds
    pub signed_method: HttpMethod,
}
```

Each extension is independently versioned (`ExtensionEnvelope.version`)
so bridges can evolve their shape without touching the current v1 receipt body,
but this remains a deferred extension-binding sketch.

---

## Open questions for sibling agents

1. **R3's broker-id encoding.** Is `broker_id_hash` a SHA-256 of a
   stable broker URI, or of the substrate's own broker identity (Kafka
   cluster ID, NATS cluster name)? Decision affects whether
   `EventDecisionExtension.broker_id_hash` is `[u8; 32]` or
   `String`.
2. **R2's directory hash shape.** Is `directory_entry_hash` a hash of
   the canonical entry document or a Merkle leaf into the directory's
   own commitment tree? Affects whether the AGNTCY directory extension needs a
   `directory_inclusion_proof` field alongside the hash.
3. **R4 (Cedar) versus body promotion.** R4 is proposing engine metadata and
   policy identifiers. ADR-0010 keeps `policy_hash` as the current core field;
   keep engine-specific policy details on the deferred extension only when the
   engine emits multiple policy sets per decision.
4. **E1's `tool_origin` versus existing `trust_level`.** The
   OpenAI Responses host-executed flag overlaps semantically with
   `TrustLevel::Mediated|Verified|Advisory` (`receipt.rs:47-62`).
   Decide whether `tool_origin` is a refinement of `trust_level` for
   the OpenAI bridge, or an orthogonal axis. Recommend: keep
   `trust_level` for kernel-mediation strength and put
   `tool_origin` in the OpenAI extension as a provider-specific
   refinement.
5. **E3 voice and replay.** Audio timestamps are not deterministic
   across replays. The voice extension must carry only stable handles
   (call_id, participant_id) in the signed body; raw audio refs and
   transcripts ride alongside but are out of scope for the signed
   receipt.
6. **Extension binding defaults.** Deferred. A future ADR must decide whether
   any extension can be verification-mandatory, how that is negotiated, and how
   verifiers fail closed before bridges carry security-critical extension state
   such as presigned-URL expiry.
7. **Hot-path indirection.** Whether `extensions_hash` indirection is
   net-positive depends on the X2 latency analysis. If the hash
   computation cost exceeds the canonicalization cost of inlining the
   extension blob, prefer inlining and keep canonical-bytes ordering
   strict.

---

## Summary (3-line)

1. Current accepted direction: ADR-0010 current v1 receipt-kind semantics,
   with typed extensions deferred until there is implementation evidence.
2. No successor receipt generation is needed before release. Chio-owned
   pre-release receipt semantics stay in current v1, with incompatible drafts
   regenerated or reset.
3. File: this file.
