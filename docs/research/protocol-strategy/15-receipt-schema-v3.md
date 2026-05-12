# 15 - Receipt schema stress test and v3 evolution strategy

> **Erratum (wave 3) - canonical types for v3 core fields:**
>
> - **`policy_hash` / `policy_digest`** is a hex `String` (matches existing [`crates/chio-core-types/src/receipt.rs:159`](crates/chio-core-types/src/receipt.rs:159); RFC 8785 canonical-JSON friendly). NOT `[u8; 32]`. Earlier references in this doc to `[u8; 32]` should be read as the hex-encoded form.
> - **`tool_origin`** records execution locus, not redaction policy. ADR-0010 keeps `tool_origin` and `redaction_mode` as separate signed v3 fields. Planning default: `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`.
> - **`human_principal`** is the typed `HumanPrincipal` enum defined on `CallerIdentity` in [doc 14](14-voice-agent-bridges.md). This doc's `VoiceExtension` references it by canonical encoding, not as a duplicate `Option<String>` definition.
> - **`ActorRef`** (the actor-chain element type) needs a concrete definition stub. Proposed shape:
>
>   ```rust
>   /// Single actor in the OAuth on-behalf-of delegation chain.
>   /// Maps to the IETF draft-oauth-ai-agents-on-behalf-of-user actor-chain JWT claim.
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
>   This stub should land in `chio-core-types` alongside the v3 ReceiptBody promotion. Refine in a follow-on against the IETF draft as it stabilizes.
>
> **Post-review status:** This document is a stress test, not the implementation spec. [18-decision-packet.md](18-decision-packet.md) is the decision packet to settle before tickets are written. It supersedes historical sketches or review notes that show `policy_digest: [u8; 32]`, redaction as a `tool_origin` variant, feature-bit-only v3 negotiation, or a decided `extensions_hash` strategy.

## TL;DR

The current `ChioReceiptBody` is too flat and too unstructured to absorb the
ten field-pile-ups proposed across docs 01-06 and the parallel agents R2-R4
and E1-E3 without becoming a 40+ field god-struct. Recommend **Option D
(hybrid candidate)**: promote a small set of universally relevant fields (`schema`,
`actor_chain`, `engine_id`, `policy_digest`, `decision_id`) into the core
v3 body, and route every bridge-, surface-, or provider-specific payload
through a typed `extensions: BTreeMap<ExtensionNamespace, ExtensionPayload>`
map keyed by stable namespace strings. Adding a core field bumps the schema
version (`chio.receipt.v3`); adding an extension does not. ADR-0010 chooses
explicit `maxReceiptSchema` plus extension support over the historical
feature-bit sketch below. A
`must_understand` flag per extension lets bridges mark namespace-specific
payloads as verification-mandatory.

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

- v1 schema constant is implicit (no top-level `schema` field on
  `ChioReceiptBody`). v2 schema constant `chio.receipt.v2` at
  `receipt.rs:30`. v2 receipts (`ChioReceiptV2`, `receipt.rs:421-430`) are
  built on top of v1 bodies via `ReceiptV2BodyHashInput::from_v1_body`
  (`receipt.rs:478-510`) and add `chain_id`, `parent_receipt_ids`,
  `parent_set_hash`, `dag_ordinal`, `hlc`. v2 is content-addressed
  (`body_hash := H(canonical_jcs(ReceiptV2BodyHashInput))`,
  `receipt.rs:703-707`).
- Signing path: `Keypair::sign_canonical` and `sign_canonical_with_backend`
  (`crates/chio-core-types/src/crypto.rs:206,866`) call
  `canonical_json_bytes` (`crates/chio-core-types/src/canonical.rs:102`)
  which sorts object keys by UTF-16 code-unit order per RFC 8785.
  Every body field participates in signing; there is no
  hash-then-sign-the-hash optimization today.
- Negotiation surface: `chio.capabilities.v1` carries a string bitset and
  `maxCapabilitySchema` (`PROTOCOL.md:286-303`). Existing feature names
  include `accepts_receipt_v2`. v3 introduces backward-compatible HTTP
  substrate extensions (`PROTOCOL.md:7-8, 117-125`).
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
- `policy_digest: String` (hex-encoded digest at the receipt boundary)
- `decision_id: String` (engine-issued, non-deterministic)
- `obligations: serde_json::Value`
- `diagnostics: Option<String>`

### Identity-chain bucket (doc 03)

- `actor_chain: Vec<ActorRef>` (IETF agent-OBO draft;
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
fields used on every receipt (`policy_digest`, `engine_id`,
`actor_chain`) get demoted to "look it up in the extensions map"
which is awkward for replay tooling.

### Option C: hard v3 bump

Coordinate a single v3 schema that hand-picks all proposed fields,
deprecate v2 with a defined transition window. Pros: clean break, one
opportunity to also fix v1/v2 wart (`metadata: Option<serde_json::Value>`
as the only typing escape hatch), strong story for audit/replay
tooling. Cons: per `PROTOCOL.md:7-8`, "v3.0 is a backward-compatible
extension of v2.0. All v2 artifacts, wire formats, and verification
rules remain valid"; a hard schema break violates that spec. Federation
peers on v2 would need dual-version handling per the negotiated-ceiling
machinery at `PROTOCOL.md:305-329`. Audit/replay tooling, the Lean
theorem `theorem.handshake.negotiation_safety`
(`formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean`), and the
conformance fixture
(`crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs`)
all need a v3 analog.

### Option D: hybrid (RECOMMEND)

Promote a small set of universally relevant fields onto the v3 core
body. Use a typed extensions map for everything bridge-, engine-, or
surface-specific. Bump schema version when adding core fields; do not
bump when registering a new extension namespace.

Core promotions (used on essentially every receipt or by every audit
replay):

- `schema: String` (new in v3, valued `chio.receipt.v3`)
- `actor_chain: Vec<ActorRef>` (every governed-agent receipt has one)
- `engine_id: String` (every policy-engine-mediated receipt; default
  `"native"` when the kernel ran no external engine)
- `policy_digest: String` (hex-encoded digest at the receipt boundary;
  promoting it as a typed field lets verifiers replay without parsing the
  aggregation rule)
- `decision_id: String` (per-receipt opaque correlation handle;
  optional, but high enough frequency it earns a top-level slot)

Everything else (per-provider IDs, voice call metadata, presigned-URL
shapes, AGNTCY peer refs, directory-lookup traces, event broker hashes,
Bedrock action groups, OpenAI response IDs) lives in
`extensions: BTreeMap<ExtensionNamespace, ExtensionPayload>`.

---

## Recommendation: Option D

Justification:

1. **Backward compat with `PROTOCOL.md:7-8`.** v3 is documented as a
   backward-compatible extension; Option D respects this by additive
   core fields plus an extensions map that v2 verifiers cannot
   misinterpret (they will refuse to parse `chio.receipt.v3` per
   schema-registry rules at `PROTOCOL.md:331-337` and stay on v2).
2. **Federation negotiation needs an ADR decision.** The older sketch used
   `accepts_receipt_v3` and `accepts_ext.<namespace>` feature bits. PR 652
   review recommends deciding an explicit `maxReceiptSchema` ceiling instead
   of relying only on feature bits, because older verifier behavior and
   downgrade semantics are security-relevant. In either shape, a v2 verifier
   negotiated with a v3 producer gets v2 receipts; producers downgrade
   gracefully.
3. **Signing canonicalization stays cheap and deterministic.** Two
   knobs:
   - The extensions map uses `BTreeMap<String, ExtensionPayload>`;
     RFC 8785 already sorts object keys by UTF-16 code units
     (`canonical.rs:8-9, 123`), so the BTreeMap insertion order is
     irrelevant on the wire.
   - One candidate is to canonicalize each `ExtensionPayload`, hash the
     extension map, and put a hex `extensions_hash` in the signed body.
     Another is to sign the full inline body. Coordinate with X2
     (hot-path latency) and the receipt-v3 ADR before treating
     `extensions_hash` as decided.

### Migration

- Add `chio.receipt.v3` to `spec/schemas/registry.json` and to
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS`.
- Continue producing `chio.receipt.v2` for any peer that has not
  advertised `accepts_receipt_v3`. v2 remains the universal floor (per
  the v1 -> v2 precedent at `PROTOCOL.md:322-324`).
- v3 production behind a kernel flag; flip the default after a
  transition window during which v3 is opt-in.
- Audit/replay tooling supports both schemas indefinitely. Current SQLite
  receipt storage keeps `raw_json` rather than a separate schema column, so
  any store-level schema index is future work.

---

## Concrete spec sketch

### v3 receipt body Rust shape

```rust
pub const CHIO_RECEIPT_V3_SCHEMA: &str = "chio.receipt.v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioReceiptV3Body {
    #[serde(default = "receipt_v3_schema")]
    pub schema: String,
    pub id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    pub decision: Decision,
    pub content_hash: String,
    pub policy_hash: String,
    pub policy_digest: String,             // hex digest
    pub engine_id: String,                 // "native" if no engine
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "is_default_trust_level")]
    pub trust_level: TrustLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub extensions_hash: Option<String>,   // candidate: hex H(canonical_jcs(extensions))
    pub kernel_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioReceiptV3 {
    pub body: ChioReceiptV3Body,
    pub extensions: BTreeMap<ExtensionNamespace, ExtensionEnvelope>,
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionEnvelope {
    pub version: u32,
    pub must_understand: bool,
    pub payload: ExtensionPayload,
}
```

### Extension namespace and payload

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
    Agntcy(AgntcyExtension),
    DirectoryTrace(DirectoryTraceExtension),
    OrchestratorRun(OrchestratorRunExtension),
    PresignedUrl(PresignedUrlExtension),
    /// Forward-compat slot. v3 verifiers that do not understand the
    /// kind tag preserve bytes for re-signing or relay, but refuse to
    /// honor `must_understand = true` for them.
    Unknown(serde_json::Value),
}
```

### Signing canonicalization

1. Compute `extensions_canonical := canonical_json_bytes(extensions)`
   (RFC 8785; BTreeMap ensures stable iteration, UTF-16 key sort
   re-confirms order).
2. If the ADR chooses hash indirection, compute `extensions_hash :=
   sha256(extensions_canonical)` and hex-encode it into
   `body.extensions_hash`.
3. If the ADR chooses inline signing, leave `body.extensions_hash` absent and
   include the extensions in the signing input.
4. Compute `signing_input` according to the ADR-selected strategy.
5. `signature := sign(signing_input)`.
6. Wire: send `body`, `extensions`, `signature`.

Verifier:

1. Validate `body.schema == chio.receipt.v3`.
2. If `extensions_hash` is present, recompute it from `extensions`; reject on
   mismatch.
3. Verify signature over the ADR-selected canonical input.
4. For each extension whose namespace is on the locally supported
   list, decode payload. For each extension marked
   `must_understand = true` whose namespace is NOT supported,
   reject fail-closed.

### Federation negotiation

The receipt-v3 ADR must choose either explicit ceilings or feature bits:

- Preferred candidate: `maxReceiptSchema` plus extension support advertised
  separately.
- Historical candidate: `accepts_receipt_v3` and `accepts_ext.<namespace>`
  features in `chio.capabilities.v1`.
- Producers MUST NOT emit `must_understand = true` extensions for any
  namespace the negotiated peer has not advertised.
- Federation handshake remains fail-closed: malformed feature names
  abort negotiation before either side uses an upgrade
  (`PROTOCOL.md:286-292`).

The Lean theorem at
`formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean` needs a v3
analog asserting that a v2-only verifier never receives a v3 receipt,
and that a v3 verifier with a smaller extension set never receives an
extension marked must-understand outside its set.

---

## Per-extension shape sketches

```rust
pub struct CedarExtension {
    pub engine_version: String,
    pub policy_set_id: String,
    pub policy_digest: String,
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
    pub human_principal: Option<String>,      // e164 or sub
    pub platform: VoicePlatform,              // Twilio | Vonage | LiveKit | ...
}

pub struct AgntcyExtension {
    pub acp_peer_id: String,
    pub acp_message_id: String,
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
so bridges can evolve their shape without touching `ChioReceiptV3Body`.

---

## Open questions for sibling agents

1. **R3's broker-id encoding.** Is `broker_id_hash` a SHA-256 of a
   stable broker URI, or of the substrate's own broker identity (Kafka
   cluster ID, NATS cluster name)? Decision affects whether
   `EventDecisionExtension.broker_id_hash` is `[u8; 32]` or
   `String`.
2. **R2's directory hash shape.** Is `directory_entry_hash` a hash of
   the canonical entry document or a Merkle leaf into the directory's
   own commitment tree? Affects whether the AGNTCY extension needs a
   `directory_inclusion_proof` field alongside the hash.
3. **R4 (Cedar) versus body promotion.** R4 is proposing `engine_id`
   and `policy_digest` for the body. If R4 lands as core fields,
   `CedarExtension.policy_digest` becomes redundant; keep it on the
   extension only when the engine emits multiple policy sets per
   decision (which Cedar can, via additive policy stores).
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
6. **`must_understand` defaults.** Should bridges default
   `must_understand = false` (extensions are advisory) or
   `must_understand = true` (extensions are load-bearing)? Recommend
   `false`-by-default to keep federation forgiving; bridges that
   carry security-critical state (e.g. presigned-URL expiry) opt in
   per their own threat model.
7. **Hot-path indirection.** Whether `extensions_hash` indirection is
   net-positive depends on the X2 latency analysis. If the hash
   computation cost exceeds the canonicalization cost of inlining the
   extension blob, prefer inlining and keep canonical-bytes ordering
   strict.

---

## Summary (3-line)

1. Recommend **Option D (hybrid)**: small set of core promotions plus a
   typed `extensions: BTreeMap<String, ExtensionEnvelope>` map.
2. **Yes**, a v3 bump is needed, but as a backward-compatible additive
   schema per `PROTOCOL.md:7-8`; `chio.receipt.v2` remains the universal
   floor and a documented transition window keeps v2 verifiers working.
3. File: `/Users/connor/backbay/arc/.claude/worktrees/silly-wu-c32126/docs/research/protocol-strategy/15-receipt-schema-v3.md`.
