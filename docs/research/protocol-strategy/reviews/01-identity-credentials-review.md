# Review 01 - Identity and Credentials Cluster

Reviewer: swarm agent 1. Scope: consistency of docs 02, 03, 07, 08, 13, 14, 15
(plus the two overviews) against the chio-http-core, chio-did,
chio-credentials, chio-federation, chio-mcp-remote, chio-kernel, and
chio-core-types crates and `spec/PROTOCOL.md`.

## TL;DR

Mostly clean. The OAuth-AS disposition is consistent across doc 03, doc 07,
and `00-overview-v2.md` (keep behind a Cargo feature, rename, scope-clamp).
The hybrid-signing and OAuth-profile spec citations resolve. did:chio matches
its description. The real consistency damage is concentrated in the identity
extension surface: `ActorRef` is referenced four times in doc 15 with no
definition, and `human_principal` has two incompatible shapes between doc 14
(typed enum on `CallerIdentity`) and doc 15 (`Option<String>` in a
`VoiceExtension`). No doc reconciles AGNTCY's zero-`securitySchemes` reality
with a normative "out-of-band auth floor" recommendation.

---

## Verified claims (citations confirmed)

1. **OAuth AS runtime gating.** Doc 07 says the AS is one CLI flag away from
   running. Confirmed: `crates/chio-mcp-remote/src/remote_mcp/http_service.rs`
   wires the well-known and `/oauth/*` routes unconditionally (see the
   `state.local_auth_server` 404 guard at the AS-only handler call sites in
   that file), and `crates/chio-mcp-remote/Cargo.toml` does NOT yet define an
   `auth-server-bridge` feature - so doc 07's recommendation (move it behind a
   Cargo feature) is genuinely outstanding work, not already done.

2. **`SessionAuthMethod::OAuthBearer` field list.** Doc 03 lists `issuer`,
   `subject`, `audience`, `scopes`, `federated_claims`, `enterprise_identity`,
   `token_fingerprint`. Confirmed at
   `crates/chio-mcp-remote/src/remote_mcp/oauth.rs:852-872`.

3. **Sequential hybrid signing at `pq.rs:166-170`.** Doc 16 and doc 14 both
   cite this. Confirmed verbatim at
   `crates/chio-core-types/src/pq.rs:166-170`:

   ```
   fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
       let classical = self.classical.sign_bytes(message)?;
       let pq = self.pq.sign_bytes(message)?;
       Signature::from_hybrid_parts(classical, &pq, self.alg_set)
   }
   ```

   Sequential, no rayon, no `tokio::join!`. Doc 16's parallelization
   recommendation is well-grounded.

4. **did:chio shape.** Doc 03 says "self-certifying Ed25519." The implicit
   "64-hex" claim is enforced at `crates/chio-did/src/lib.rs:33-34` (error
   variant requires 64 hex chars) and the `FromStr` impl at
   `crates/chio-did/src/lib.rs:130-144` checks `suffix.len() != 64` and
   ASCII-hex. The `DidChio::from_public_key` constructor at
   `crates/chio-did/src/lib.rs:51-59` refuses anything except
   `SigningAlgorithm::Ed25519`. The doc-00 inventory description matches the
   code.

5. **OAuth profile range in `spec/PROTOCOL.md:1351-1453`.** Range resolves
   inside the canonical OAuth section. Lines 1351-1353 declare the three
   `chio.oauth.*` schemas. Line 1405-1448 covers `cnf` projection, discovery
   surface, and the metadata report. Doc 03's reference to lines 1405-1434
   for sender-constraint binding is within range. Doc 07's citation
   `spec/PROTOCOL.md:1351-1453` is honest.

6. **`AuthMethod` enum variants in `CallerIdentity`.** Doc 03 lists "Bearer,
   ApiKey, Cookie, MtlsCertificate, Anonymous." Confirmed at
   `crates/chio-http-core/src/identity.rs:8-37`. Doc 03's "(`identity.rs:8-37`)"
   citation is accurate; the doc-08 references to
   `identity.rs:44` point at `pub struct CallerIdentity` (not `AuthMethod`),
   which is also correct (line 44 starts the struct).

7. **Agent Passport location.** Doc 03 line 47 says "native JSON-signed
   bundle." Confirmed at `crates/chio-credentials/src/passport.rs:1-17`
   (`pub struct AgentPassport { schema, subject, credentials, merkle_roots,
   enterprise_identity_provenance, issued_at, valid_until, trust_tier }`).
   The `include!("passport.rs")` from
   `crates/chio-credentials/src/lib.rs:86` is unusual but valid.

8. **Two-DPoP confusion is real and acknowledged.** Doc 03 line 28-30
   explicitly distinguishes "RFC 9449 JWT DPoP at the HTTP boundary"
   (proposed) from `chio.dpop_proof.v1` (the existing internal invocation
   proof at `crates/chio-kernel/src/dpop.rs:1-100`). The two are NOT the
   same. The internal one is a canonical-JSON-signed body bound to
   `capability_id`, `tool_server`, `tool_name`, `action_hash`, `nonce`,
   `issued_at`, `agent_key` - confirmed at `crates/chio-kernel/src/dpop.rs:60-78`.
   RFC 9449 is JWT-shaped with `htm`, `htu`, `jti`, `iat`, `ath`. Different
   wire shape, different binding scope.

## Inconsistencies and contradictions (punch list)

### Finding 1: `ActorRef` is undefined.

- Claim: doc 15 (`15-receipt-schema-v3.md:105, 209, 301, 418`) promotes
  `actor_chain: Vec<ActorRef>` to a v3 core body field and includes it in
  `IdentityChainExtension`.
- Reality: there is no struct definition for `ActorRef` anywhere in doc 15,
  doc 03, doc 14, or the overviews. The IETF agent-OBO draft cited in doc
  03 line 81 (`draft-oauth-ai-agents-on-behalf-of-user-00`) is the only
  hint at semantics, and the draft uses an `actor_token` JWT, not a
  flattened struct. Grep confirms: `grep -rn ActorRef
  docs/research/protocol-strategy/` returns four hits, all references, zero
  definitions.
- Recommendation: doc 15 author must commit to a shape. Minimum field set
  consistent with the draft: `did: String`, `actor_token_jti:
  Option<String>`, `is_human: bool`, `scope_constraints: Vec<String>`,
  `attested_by: Option<DpopConfirmation>`. Add to doc 15 section 8 ("Per-
  extension shape sketches") and cross-link from doc 03 open question 5.

### Finding 2: `human_principal` has two incompatible shapes.

- Doc 14 line 207-214 defines a typed enum on `CallerIdentity`:

  ```rust
  pub enum HumanPrincipal {
      PhoneNumberE164 { number_hash: String, verified: bool },
      AuthenticatedUser { subject: String, idp: String, verified: bool },
      Anonymous,
  }
  ```

  Field lives on `CallerIdentity` (doc 14 line 204).
- Doc 15 line 450 declares `pub human_principal: Option<String>` inside
  `VoiceExtension`, with comment `// e164 or sub`.
- Net: same name, two homes (`CallerIdentity` vs `extensions[voice]`), two
  types (rich enum vs untyped string), two verification stories (typed
  `verified: bool` vs nothing). Doc 14 anticipates the conflict at lines
  219-222 ("if v3 promotes this to a top-level receipt field rather than
  carrying it on `CallerIdentity`, the bridge can populate either location")
  but doc 15 silently picks the lesser shape.
- Recommendation: pick one. Recommended: keep the typed enum on
  `CallerIdentity` (extensible without a v3 bump, see Finding 9) and drop
  the field from `VoiceExtension`. Doc 15 line 450 changes to a comment
  ("see `CallerIdentity.human_principal`") or the field is renamed
  `audio_participant_label` if it carries genuinely voice-only context.

### Finding 3: `auth-server-bridge` Cargo feature does not yet exist.

- Doc 07 line 96 and `00-overview-v2.md` line 22 recommend gating the AS
  behind a Cargo feature named `auth-server-bridge`.
- Reality: `crates/chio-mcp-remote/Cargo.toml` has no `[features]` section
  at all. The recommendation is correctly characterized as future work
  ("Remaining lift is small" at doc 07 line 95), so this is not a
  contradiction with the code, but the two overviews state the outcome as
  if it were already implied by the runtime gating - it is not. The runtime
  gating is by CLI flag (`--auth-server-seed-file`), not by `cfg(feature)`.
- Recommendation: clarify in `00-overview-v2.md` line 22 that the Cargo
  feature flag is a follow-on; today's gating is runtime-only.

### Finding 4: AGNTCY zero-`securitySchemes` has no normative recommendation.

- Doc 08 section 3 correctly observes ACP declares
  `components.securitySchemes = {}`. The doc-08 mitigation lives inside the
  bridge crate spec (`chio-bridge-agntcy` requires HTTPS, optionally mTLS or
  bearer per operator config).
- Doc 02 section 2 mentions identity inheritance from the HTTP substrate
  but does not commit to a floor.
- Reality: no document declares a kernel-level "any AGNTCY bridge MUST
  present mTLS or a bound bearer" rule. `spec/PROTOCOL.md` has no AGNTCY
  text at all. So if someone deploys `chio-bridge-agntcy` with
  `AuthConfig::ApiKey` over plain bearer, doc 08 line 552-555 ("bridge MUST
  refuse non-HTTPS endpoints") is the only enforcement, and it is local to
  the bridge crate.
- Recommendation: add a one-paragraph "out-of-band gate floor" section to
  `spec/PROTOCOL.md` (under section 4 "Serialization And Identity") that
  says: protocols which decline to specify `securitySchemes` MUST be
  bridged with either (a) HTTPS plus operator-configured mTLS, or (b) HTTPS
  plus a bound bearer whose `cnf` is recorded on `CallerIdentity`. Doc 08
  cross-links the spec section. Doc 02 line 113-116 gets a one-line
  pointer.

### Finding 5: Hybrid timing numbers disagree between docs.

- Doc 14 line 116: `Signing (Ed25519 + ML-DSA-65 hybrid) | ~150-225 us`.
- Doc 16 line 134: `hybrid ~150-225 us`.
- Doc 16 line 126: `Hybrid kernel receipt | 350-600 us | Ed25519 (~50-100 us)
  + ML-DSA-65 sign (~250-400 us), sequential.`
- These look like different things being measured (per-sign primitive vs
  full kernel-receipt sign path), but neither doc says so explicitly. Doc
  14's "~150-225 us" appears to be the ML-DSA-65 primitive only; doc 16's
  "350-600 us" includes canonical JSON encoding and the classical sign.
- Recommendation: doc 14 line 116 footnote: "primitive sign only; full
  receipt path including canonical JSON encoding is ~350-600 us (doc 16)".

### Finding 6: `CallerIdentity` extensibility is the load-bearing assumption.

- Three docs propose adding fields:
  - Doc 14 line 204: `Option<HumanPrincipal>`.
  - Doc 03 line 112: `oauth: Option<OAuthCaller>` (issuer, scopes, RAR
    details, cnf, actor chain).
  - Doc 15 line 301 (indirectly): `actor_chain: Vec<ActorRef>` as a v3
    receipt body field, with doc 03's open question 5 leaving open
    whether it also lives on `CallerIdentity`.
- Reality: `crates/chio-http-core/src/identity.rs:44-65` is a plain struct
  with no extensions map. Adding a new field is back-compat only if
  `#[serde(default, skip_serializing_if = "Option::is_none")]` is applied
  (matches the existing `tenant` and `agent_id` pattern at lines 59-64).
  This works field-by-field but provides no escape hatch for
  bridge-specific data, so each new field is a fresh PR against
  `chio-http-core` and a coordination event across every consumer.
- Recommendation: either (a) add a generic
  `extensions: BTreeMap<String, serde_json::Value>` to `CallerIdentity` now
  to absorb voice, OAuth, and actor-chain shapes without churning the core
  struct, or (b) accept three independent field additions
  (`oauth`, `human_principal`, `actor_chain`) and audit the canonical-JSON
  signing path for back-compat with v2 receipts (the existing pattern
  works, just gets crowded). Doc 03 open question 5 is the right place to
  resolve this; recommend (a) for symmetry with doc 15's extensions map.

### Finding 7: `did:web:<host>:agents:<uuid>` is non-standard.

- Doc 08 line 175 declares `Subject = did:web:<acp-host>:<port?>:agents:<agent-id-uuid>`.
- W3C did:web spec resolves `did:web:example.com:path:to:resource` as
  `https://example.com/path/to/resource/did.json`. The
  `did:web:host:agents:uuid` form means the bridge expects a DID Document
  at `https://<host>/agents/<uuid>/did.json` which the operator probably
  did NOT publish.
- Recommendation: tighten doc 08 line 175 to say the bridge does NOT
  resolve this DID against the upstream host; it is a Chio-local naming
  convention for `CallerIdentity.subject`. If the operator wants real
  resolution, they pin a `did:key` from an AGNTCY identity credential
  instead (option 2 in the same paragraph). This is a doc clarity bug, not
  a code bug.

### Finding 8: Doc 03's "RFC 9449 at HTTP boundary" vs doc 16's "DPoP at dpop.rs."

- Doc 03 line 130 says "Implement RFC 9449 JWT DPoP at the HTTP edge per
  end-state-A plan." Doc 16 cites
  `crates/chio-kernel/src/dpop.rs` as the existing DPoP implementation.
- Doc 03 line 30 explicitly notes these are different: the kernel ships
  `chio.dpop_proof.v1` (chio-native), and the spec promises but does not
  yet ship RFC 9449 at the HTTP edge.
- Confirmed at `crates/chio-kernel/src/dpop.rs:44-78`: schema
  `chio.dpop_proof.v1`, body fields capability_id/tool_server/tool_name/
  action_hash/nonce/issued_at/agent_key. This is NOT RFC 9449 (no `htm`,
  `htu`, `jti`, `iat`, `ath`).
- Recommendation: doc 16's "Skip ML-DSA on voice tier" section indirectly
  assumes one DPoP. Doc 16 should add a note that "DPoP" in the latency
  budget means `chio.dpop_proof.v1`, not RFC 9449, since only the former
  is on the hot path today.

### Finding 9: `dpop_cnf: Option<DpopConfirmation>` lacks a referent.

- Doc 15 line 106 and line 420 reference `DpopConfirmation`. No definition
  in the doc; no shape in the codebase that maps directly. RFC 9449
  `cnf.jkt` is the closest analog (`{ "jkt": "<sha256-thumb>" }`).
- Recommendation: doc 15 should either (a) define `DpopConfirmation` as
  `{ jkt: String, alg: String }` per RFC 9449 5.2 or (b) reuse the
  `cnf.chioSenderKey` / `cnf["x5t#S256"]` / `cnf.chioAttestationSha256`
  triple already defined in `spec/PROTOCOL.md:1422-1430` and rename the
  field `chio_sender_cnf`. Recommend (b) for substrate alignment.

### Finding 10: Step-up vocabulary overloaded.

- Doc 03 line 51 notes `step_up` exists in `spec/PROTOCOL.md:1789` but is
  the underwriting (credit/budget) decision vocabulary, not OAuth.
- Doc 03 then proposes a second `step_up` semantics for OAuth (RFC 9470
  Step-up Authentication Challenge) without renaming the existing one.
- Doc 15 line 110 introduces `step_up_challenge: Option<StepUpChallenge>`
  in `IdentityChainExtension`. The shape is undefined, the underwriting
  collision is not addressed.
- Recommendation: rename the OAuth one. `oauth_step_up_challenge:
  Option<OAuthStepUpChallenge>` per RFC 9470 with explicit
  `acr_values`/`max_age` fields. Reserve `step_up` (without prefix) for
  the underwriting decision. Doc 03 needs to acknowledge the rename in
  recommendation 2 (line 113).

## Ungrounded claims

- **doc 03 line 23**: `crates/chio-kernel/src/operator_report.rs:71-75`.
  Not checked in this review (out of scope) but the path exists.
  Constants for the three `cnf` proof families are claimed at this line;
  worth a confirmatory grep on the next pass.
- **doc 03 line 48**: `crates/chio-credentials/src/oid4vp.rs`. File
  exists (confirmed via crate listing). Shape not audited.
- **doc 15 line 50**: `GuardEvidence at receipt.rs:1174-1184`. Not
  audited.
- **doc 08 line 614 citation map**: `kernel/src/runtime.rs:255` for
  ToolServerConnection. Not audited but plausible.

## Recommended edits per doc

| Doc | Section / line | Change |
| --- | --- | --- |
| 03 | line 113 (rec 2) | Rename `step_up` -> `oauth_step_up_challenge`. Acknowledge the underwriting collision at line 51. |
| 03 | line 128 (rec 1) | Decide between adding three top-level fields or one `extensions: BTreeMap<String, Value>` on `CallerIdentity`. Recommend the map. |
| 07 | line 95-101 | State explicitly that the Cargo feature is future work; runtime gating today is by CLI flag only. |
| 08 | line 175 | Clarify `did:web:<host>:agents:<uuid>` is a Chio-local naming convention, not a resolvable did:web. |
| 08 | new subsection between 3 and 4 | "Out-of-band gate floor": mTLS or bound bearer required when upstream protocol has no `securitySchemes`. |
| 14 | line 116 | Footnote: "ML-DSA-65 primitive only; full hybrid kernel receipt is ~350-600 us per doc 16." |
| 14 | line 204-214 | Confirm `HumanPrincipal` lives on `CallerIdentity` (typed enum); coordinate with doc 15. |
| 15 | line 105, 209, 301, 418 | Define `ActorRef` explicitly. Minimum: `{ did, actor_token_jti?, is_human, scope_constraints, attested_by? }`. |
| 15 | line 450 | Remove `human_principal: Option<String>` from `VoiceExtension`; reference `CallerIdentity.human_principal`. |
| 15 | line 106, 420 | Define `DpopConfirmation` or rename to `chio_sender_cnf` per `spec/PROTOCOL.md:1422-1430`. |
| 15 | line 110 | Define `StepUpChallenge` (RFC 9470 acr_values/max_age) and align name with doc 03 rename. |
| 02 | line 113-116 | Add pointer to the new `spec/PROTOCOL.md` out-of-band gate floor section. |
| 00-overview-v2 | line 22 | Note Cargo feature `auth-server-bridge` is proposed, not yet present. |
| spec/PROTOCOL.md | new section under 4 | "Out-of-band gate floor" normative paragraph (see Finding 4). |

## Summary (3-line)

1. Overall consistency: **mixed-clean** - the headline recommendations
   (OAuth AS Cargo-feature, hybrid signing, did:chio) all hold, but four
   undefined types (`ActorRef`, `DpopConfirmation`, `StepUpChallenge`, and
   the `human_principal` two-shape divergence) crater the identity
   extension story.
2. Top contradictions: (a) `human_principal` is a typed enum on
   `CallerIdentity` in doc 14 and an `Option<String>` inside
   `VoiceExtension` in doc 15; (b) `actor_chain: Vec<ActorRef>` is promoted
   to v3 core body with `ActorRef` undefined anywhere.
3. Output:
   `/Users/connor/backbay/arc/.claude/worktrees/protocol-research-2026/docs/research/protocol-strategy/reviews/01-identity-credentials-review.md`
